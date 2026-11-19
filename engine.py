"""Live engine: syslog listener + Windows Event Log poller -> parser -> database -> detection -> alerts,
plus the nightly report scheduler. Runs in background threads inside the Streamlit process."""
import queue
import socket
import threading
import time
from datetime import datetime, timedelta

import config
import db
import detect
import notify
import parsers
import reporting
import winlog


class Engine:
    def __init__(self):
        db.init()
        self.q = queue.Queue()
        self._stop = threading.Event()
        self._threads = []
        self._ml_last = 0.0
        self._started_at = None
        self.running = False
        self.status = {"windows": "off", "syslog": "off", "last_error": "", "ingested": 0, "last_event": "",
                       "last_detect": "", "emails": "", "last_report": db.kv_get("last_report_day", "never")}
        # The scheduler always runs, so the 23:59 report works whenever the app is open.
        threading.Thread(target=self._scheduler, daemon=True, name="scheduler").start()

    # ------------------------------------------------------------ control
    def start(self, windows=True, syslog=True):
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._started_at = datetime.now()
        self.status.update(windows="off", syslog="off", last_error="")
        self._spawn(self._processor, "processor")
        if windows:
            self._spawn(self._windows_loop, "windows")
        if syslog:
            self._spawn(self._syslog_loop, "syslog")

    def stop(self):
        self._stop.set()
        self.running = False
        self.status.update(windows="off", syslog="off")

    def _spawn(self, fn, name):
        t = threading.Thread(target=fn, daemon=True, name=name)
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------ input
    def feed_lines(self, lines, source="manual"):
        """Used by the attack simulator (and any other code that wants to push log lines in)."""
        self.q.put(("lines", list(lines), source))

    def _windows_loop(self):
        if not winlog.is_windows():
            self.status["windows"] = "unavailable (not Windows)"
            return
        last_id = None
        while not self._stop.is_set():
            rows, last_id, err = winlog.poll(last_id)
            if err:
                self.status["windows"] = "error"
                self.status["last_error"] = err
                if "Administrator" in err:
                    return
            else:
                self.status["windows"] = "listening" + ("" if winlog.is_admin() else " (not admin: Security log may be unreadable)")
                if rows:
                    self.q.put(("events", rows, "windows-eventlog"))
            self._stop.wait(5)

    def _syslog_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", config.SYSLOG_PORT))
        except OSError as e:
            self.status["syslog"] = "error"
            self.status["last_error"] = f"Syslog port {config.SYSLOG_PORT}: {e}"
            return
        sock.settimeout(1.0)
        self.status["syslog"] = f"listening on UDP {config.SYSLOG_PORT}"
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            lines = [l for l in data.decode("utf-8", "replace").splitlines() if l.strip()]
            self.q.put(("lines", lines, f"syslog:{addr[0]}"))
        sock.close()

    # ------------------------------------------------------------ processing
    def _processor(self):
        last_cycle = 0.0
        while not self._stop.is_set():
            try:
                self.process_pending()
                if time.time() - last_cycle > 10:
                    self.detect_cycle()
                    last_cycle = time.time()
            except Exception as e:  # never let the loop die
                self.status["last_error"] = f"processor: {e}"
            self._stop.wait(2)

    def process_pending(self):
        batch = []
        while len(batch) < 5000:
            try:
                kind, payload, source = self.q.get_nowait()
            except queue.Empty:
                break
            if kind == "events":
                batch.extend(payload)
            else:
                for line in payload:
                    row, _ = parsers.parse_line(line, source)
                    if row:
                        batch.append(row)
        if batch:
            n = db.insert_events(batch)
            self.status["ingested"] += n
            self.status["last_event"] = max(r["ts"] for r in batch)
            self._dirty = True
        return len(batch)

    def detect_cycle(self, force_ml=False):
        now = datetime.now()
        df = db.events_df(now - timedelta(hours=24), now + timedelta(minutes=5), live_only=True)
        self.status["last_detect"] = now.strftime("%H:%M:%S")
        if df.empty:
            return []
        alerts = detect.run_rules(df)
        if force_ml or time.time() - self._ml_last > 300:
            alerts += detect.ml_anomalies(df)
            self._ml_last = time.time()
        new = db.insert_alerts(alerts)
        important = [a for a in new if a["severity"] in ("high", "critical")]
        if important:
            self._email(important)
        return new

    def _email(self, alerts):
        ok, msg = notify.alert_email(alerts)
        self.status["emails"] = msg
        if ok:
            db.mark_emailed([a["id"] for a in alerts])

    # ------------------------------------------------------------ nightly report
    def _scheduler(self):
        while True:
            try:
                now = datetime.now()
                today = now.strftime("%Y-%m-%d")
                if now.strftime("%H:%M") >= config.REPORT_TIME and db.kv_get("last_report_day") != today \
                        and now.strftime("%H:%M") <= "23:59":
                    self.daily_report(now)
            except Exception as e:
                self.status["last_error"] = f"scheduler: {e}"
            time.sleep(20)

    def daily_report(self, now=None, use_llm=True):
        now = now or datetime.now()
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        df = db.events_df(start, now, live_only=True)
        rec = reporting.create_report(df, f"Daily report - {now:%d %b %Y}", "daily",
                                      period=f"{start:%d %b %Y %H:%M} to {now:%H:%M}", use_llm=use_llm)
        db.kv_set("last_report_day", now.strftime("%Y-%m-%d"))
        self.status["last_report"] = now.strftime("%Y-%m-%d")
        if config.EMAIL_DAILY_REPORT and notify.configured():
            ok, msg = notify.send_email(f"[LogSentinel] Daily report {now:%d %b %Y}", rec["summary"], rec["pdf_path"])
            self.status["emails"] = msg
        return rec

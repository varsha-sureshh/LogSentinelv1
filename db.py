"""SQLite storage: events, alerts, reports. A new connection per call keeps it thread-safe."""
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

import pandas as pd

import config

TS_FMT = "%Y-%m-%d %H:%M:%S"
EVENT_COLS = ["ts", "host", "user", "ip", "port", "event", "status", "bytes", "source", "detail", "raw"]
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, host TEXT, user TEXT, ip TEXT,
  port INTEGER, event TEXT, status TEXT, bytes INTEGER DEFAULT 0, source TEXT, detail TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, rule TEXT, severity TEXT, title TEXT, detail TEXT,
  entity TEXT, ip TEXT, user TEXT, mitre TEXT, dedup_key TEXT UNIQUE, created TEXT,
  acknowledged INTEGER DEFAULT 0, emailed INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT, kind TEXT, period_start TEXT, period_end TEXT,
  created TEXT, pdf_path TEXT, summary TEXT, n_events INTEGER, n_alerts INTEGER, n_incidents INTEGER);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""


@contextmanager
def conn():
    with _lock:
        c = sqlite3.connect(config.DB_PATH, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()


def init():
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def _s(dt):
    return dt.strftime(TS_FMT) if isinstance(dt, datetime) else str(dt)


# ---------------- events ----------------
def insert_events(events):
    if not events:
        return 0
    rows = [tuple(e.get(c) for c in EVENT_COLS) for e in events]
    with conn() as c:
        c.executemany(
            f"INSERT INTO events({','.join(EVENT_COLS)}) VALUES({','.join('?' * len(EVENT_COLS))})", rows)
    return len(rows)


def to_df(events):
    df = pd.DataFrame(events, columns=EVENT_COLS) if events else pd.DataFrame(columns=EVENT_COLS)
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"])
    for col in ["host", "user", "ip", "event", "status", "source", "detail", "raw"]:
        df[col] = df[col].fillna("").astype(str)
    df["port"] = pd.to_numeric(df["port"], errors="coerce")
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype("int64")
    return df.reset_index(drop=True)


def events_df(start, end, live_only=False, source=None):
    q = "SELECT " + ",".join(EVENT_COLS) + " FROM events WHERE ts>=? AND ts<=?"
    args = [_s(start), _s(end)]
    if live_only:
        q += " AND source NOT LIKE 'upload:%'"
    if source:
        q += " AND source=?"
        args.append(source)
    q += " ORDER BY ts"
    with conn() as c:
        rows = [dict(r) for r in c.execute(q, args).fetchall()]
    return to_df(rows)


def count_events(start, end, live_only=True):
    q = "SELECT COUNT(*) FROM events WHERE ts>=? AND ts<=?"
    if live_only:
        q += " AND source NOT LIKE 'upload:%'"
    with conn() as c:
        return c.execute(q, [_s(start), _s(end)]).fetchone()[0]


# ---------------- alerts ----------------
def insert_alerts(alerts):
    """Insert alerts; the unique dedup_key means an alert is only ever raised once. Returns the new ones."""
    new = []
    now = datetime.now().strftime(TS_FMT)
    with conn() as c:
        for a in alerts:
            cur = c.execute(
                "INSERT OR IGNORE INTO alerts(ts,rule,severity,title,detail,entity,ip,user,mitre,dedup_key,created)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (a["ts"], a["rule"], a["severity"], a["title"], a["detail"], a["entity"], a["ip"],
                 a["user"], a["mitre"], a["dedup_key"], now))
            if cur.rowcount:
                new.append(dict(a, id=cur.lastrowid))
    return new


def alerts_list(start, end, limit=500):
    with conn() as c:
        rows = c.execute("SELECT * FROM alerts WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT ?",
                         [_s(start), _s(end), limit]).fetchall()
    return [dict(r) for r in rows]


def unacknowledged():
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY ts DESC LIMIT 50").fetchall()]


def ack_all():
    with conn() as c:
        c.execute("UPDATE alerts SET acknowledged=1")


def mark_emailed(ids):
    with conn() as c:
        c.executemany("UPDATE alerts SET emailed=1 WHERE id=?", [(i,) for i in ids])


# ---------------- reports / kv ----------------
def save_report(label, kind, start, end, pdf_path, summary, n_events, n_alerts, n_incidents):
    with conn() as c:
        cur = c.execute(
            "INSERT INTO reports(label,kind,period_start,period_end,created,pdf_path,summary,n_events,n_alerts,n_incidents)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (label, kind, _s(start), _s(end), datetime.now().strftime(TS_FMT), str(pdf_path), summary,
             n_events, n_alerts, n_incidents))
        return cur.lastrowid


def reports_list():
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()]


def kv_get(k, default=None):
    with conn() as c:
        r = c.execute("SELECT v FROM kv WHERE k=?", [k]).fetchone()
    return r["v"] if r else default


def kv_set(k, v):
    with conn() as c:
        c.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", [k, str(v)])

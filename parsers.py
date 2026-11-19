"""Hybrid log parsing: fast regex parsers for known formats -> learned (LLM-written) formats -> generic fallback.

Every parser outputs the same schema: ts, host, user, ip, port, event, status, bytes, source, detail, raw.
Event types: login_failed, login_success, invalid_user, user_created, admin_added, account_lockout,
log_cleared, firewall_drop, firewall_allow, http_request, sudo, other.
"""
import csv
import io
import json
import re
from collections import Counter
from datetime import datetime, timedelta

import config
import llm
import winlog

FMT = "%Y-%m-%d %H:%M:%S"
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def _row(ts, event, status="", user="", ip="", port=None, nbytes=0, host="", source="", raw="", detail=""):
    return {"ts": ts.strftime(FMT), "host": host, "user": user, "ip": ip, "port": port, "event": event,
            "status": status, "bytes": int(nbytes or 0), "source": source, "detail": detail[:300],
            "raw": raw[:500]}


# ------------------------------------------------------------------ timestamps
TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
              "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p", "%d-%m-%Y %H:%M:%S",
              "%d-%m-%Y %I:%M:%S %p", "%d/%b/%Y:%H:%M:%S", "%d-%b-%Y %H:%M:%S", "%b %d %H:%M:%S",
              "%Y-%m-%d %H:%M"]


def parse_ts(value, fmt=None):
    if value is None:
        return None
    if isinstance(value, (int, float)) or re.fullmatch(r"\d{10,13}(\.\d+)?", str(value).strip()):
        v = float(value)
        v = v / 1000 if v > 1e11 else v
        try:
            return datetime.fromtimestamp(v)
        except (OverflowError, OSError, ValueError):
            return None
    s = re.sub(r"(\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?$", "", str(value).strip())
    s = re.sub(r"\s+", " ", s)
    for f in ([fmt] if fmt else []) + TS_FORMATS:
        try:
            dt = datetime.strptime(s, f)
        except (ValueError, TypeError):
            continue
        if dt.year == 1900:
            dt = dt.replace(year=datetime.now().year)
        return dt
    return None


def _bsd_ts(mon, day, hms):
    now = datetime.now()
    try:
        dt = datetime(now.year, MONTHS[mon], int(day), *map(int, hms.split(":")))
    except (KeyError, ValueError):
        return None
    return dt.replace(year=now.year - 1) if dt > now + timedelta(days=2) else dt


TS_FINDERS = [re.compile(p) for p in (
    r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d", r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d",
    r"\d{1,4}[/-]\d{1,2}[/-]\d{1,4}[ T]\d\d:\d\d:\d\d(?: [AP]M)?")]
BSD_FIND = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\b")


def find_ts(line):
    for rx in TS_FINDERS:
        m = rx.search(line)
        if m and (dt := parse_ts(m.group(0))):
            return dt
    m = BSD_FIND.search(line)
    if m and m.group(1) in MONTHS:
        return _bsd_ts(*m.groups())
    return None


# ------------------------------------------------------------------ known formats
BSD_HDR = re.compile(r"^(?:<\d{1,3}>)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d\d:\d\d:\d\d)\s+"
                     r"(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[\d+\])?:?\s*(?P<msg>.*)$")
ISO_HDR = re.compile(r"^(?:<\d{1,3}>\d?\s*)?(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:[.,]\d+)?"
                     r"(?:Z|[+-]\d\d:?\d\d)?\s+(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[\d+\])?:?\s*(?P<msg>.*)$")
RX_SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?"
                         r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?")
RX_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
RX_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
RX_SSH_PAM = re.compile(r"authentication failure;.*?rhost=(?P<ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<user>\S+))?")
RX_SSH_NOISE = re.compile(r"(?:Connection closed by|Received disconnect from|Did not receive identification string from|"
                          r"Connection reset by|reverse mapping checking getaddrinfo.*?\[|PAM \d+ more authentication failures.*?rhost=|"
                          r"Disconnecting:.*?|error: maximum authentication attempts exceeded.*?from|Bad protocol version.*?from|"
                          r"Corrupted MAC on input|fatal: Read from socket failed.*?)\s*(?P<ip>(?:\d{1,3}\\.){3}\d{1,3})?")
RX_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
RX_ADMIN = re.compile(r"(?:add '(?P<u1>[^']+)' to (?:shadow )?group '(?:sudo|wheel|admin)'"
                      r"|user (?P<u2>\S+) added by \S+ to group (?:sudo|wheel|admin))")
RX_SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")
RX_SRC = re.compile(r"SRC=(?P<ip>[0-9a-fA-F:.]+)")
RX_DPT = re.compile(r"DPT=(?P<port>\d+)")
RX_APACHE = re.compile(r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>\d{2}/\w{3}/\d{4}:\d\d:\d\d:\d\d)(?: [+-]\d{4})?\] '
                       r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)')
RX_PFW = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?P<action>ALLOW|DROP) (?P<proto>\S+) (?P<src>\S+) "
                    r"(?P<dst>\S+) (?P<sport>\S+) (?P<dport>\S+)")


def _syslog_header(line):
    m = BSD_HDR.match(line)
    if m:
        return _bsd_ts(m["mon"], m["day"], m["hms"]), m["host"], m["msg"]
    m = ISO_HDR.match(line)
    if m:
        return parse_ts(m["ts"]), m["host"], m["msg"]
    return None, "", line


def parse_known(line, source):
    # Apache / Nginx combined access log
    m = RX_APACHE.match(line)
    if m and (ts := parse_ts(m["ts"])):
        user = "" if m["user"] == "-" else m["user"]
        req = m["req"].split()
        detail = " ".join(req[:2])
        return _row(ts, "http_request", m["status"], user, m["ip"], None,
                    0 if m["bytes"] == "-" else int(m["bytes"]), "", source, line, detail)
    # Windows Firewall (pfirewall.log)
    m = RX_PFW.match(line)
    if m and (ts := parse_ts(m["ts"])):
        port = int(m["dport"]) if m["dport"].isdigit() else None
        ev = "firewall_drop" if m["action"] == "DROP" else "firewall_allow"
        return _row(ts, ev, m["action"].lower(), "", m["src"], port, 0, "", source, line,
                    f"{m['proto']} -> {m['dst']}:{m['dport']}")
    ts, host, msg = _syslog_header(line)
    ts = ts or find_ts(line)
    # iptables / UFW firewall lines
    m = RX_SRC.search(line)
    if m and RX_DPT.search(line) and ts:
        dpt = int(RX_DPT.search(line)["port"])
        ev = "firewall_drop" if re.search(r"BLOCK|DROP|REJECT|DENY", line, re.I) else "firewall_allow"
        return _row(ts, ev, "drop" if ev == "firewall_drop" else "allow", "", m["ip"], dpt, 0, host, source, line,
                    f"dst port {dpt}")
    if not ts:
        return None
    for rx, ev, st in ((RX_SSH_FAIL, "login_failed", "failure"), (RX_SSH_OK, "login_success", "success")):
        m = rx.search(msg)
        if m:
            port = int(m["port"]) if "port" in rx.groupindex and m["port"] else None
            return _row(ts, ev, st, m["user"], m["ip"], port, 0, host, source, line, "SSH authentication")
    m = RX_SSH_INVALID.search(msg)
    if m:
        return _row(ts, "invalid_user", "failure", m["user"], m["ip"], None, 0, host, source, line, "Invalid SSH user")
    m = RX_SSH_PAM.search(msg)
    if m:
        return _row(ts, "login_failed", "failure", m["user"] or "", m["ip"], None, 0, host, source, line, "PAM authentication failure")
    if "sshd" in line:
        ipm = IP_FIND.search(line)
        if ipm and RX_SSH_NOISE.search(msg):
            return _row(ts, "other", "", "", ipm.group(0), None, 0, host, source, line, "SSH connection event")
    m = RX_USERADD.search(msg)
    if m:
        return _row(ts, "user_created", "success", m["user"], "", None, 0, host, source, line, "New local account")
    m = RX_ADMIN.search(msg)
    if m:
        return _row(ts, "admin_added", "success", m["u1"] or m["u2"], "", None, 0, host, source, line,
                    "Added to privileged group")
    m = RX_SUDO.search(msg)
    if m:
        return _row(ts, "sudo", "success", m["user"], "", None, 0, host, source, line, m["cmd"][:120])
    return None


# ------------------------------------------------------------------ generic fallback
IP_FIND = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RX_USER1 = re.compile(r"(?:user(?:name)?|account(?: name)?)\s*[=:]\s*['\"]?(?P<u>[\w.\-@\\$]+)", re.I)
RX_USER2 = re.compile(r"\bfor (?:invalid user )?(?P<u>[\w.\-@]+) from\b", re.I)


def classify_text(text):
    low = text.lower()
    authish = any(k in low for k in ("login", "logon", "log on", "auth", "password", "ssh", "credential",
                                      "sign in", "signin", "user"))
    if authish and re.search(r"fail|invalid|denied|incorrect|unauthori[sz]ed|bad password|refused|reject", low):
        return "login_failed", "failure"
    if authish and re.search(r"accepted|success|logged in|session opened|authenticated", low):
        return "login_success", "success"
    if re.search(r"log.{0,12}clear|cleared the", low):
        return "log_cleared", "success"
    if re.search(r"new user|user (account )?(was )?created|account (was )?created", low):
        return "user_created", "success"
    if re.search(r"\b(drop|block|deny|denied)\w*\b", low) and re.search(r"firewall|packet|src=|ufw|iptables", low):
        return "firewall_drop", "drop"
    return "other", ""


def parse_generic(line, source, fallback_ts=None):
    ts = find_ts(line)
    ips = IP_FIND.findall(line)
    m = RX_USER1.search(line) or RX_USER2.search(line)
    user = m["u"] if m else ""
    event, status = classify_text(line)
    if ts is None and not ips and not user:
        return None, "unknown"
    port = None
    pm = RX_DPT.search(line) or re.search(r"\bport (\d+)", line)
    if pm:
        port = int(pm.group(1))
    tier = "generic"
    if ts is None or (event == "other" and not ips and not user):
        tier = "weak"
    return _row(ts or fallback_ts or datetime.now(), event, status, user, ips[0] if ips else "", port, 0, "",
                source, line, "generic parse"), tier


# ------------------------------------------------------------------ learned (LLM-written) formats
_learned_cache = {"mtime": None, "items": []}


def _load_learned():
    p = config.LEARNED_FORMATS_PATH
    if not p.exists():
        return []
    mtime = p.stat().st_mtime
    if _learned_cache["mtime"] != mtime:
        items = []
        for spec in json.loads(p.read_text() or "[]"):
            try:
                items.append((re.compile(spec["regex"]), spec.get("ts_format"), spec))
            except re.error:
                continue
        _learned_cache.update(mtime=mtime, items=items)
    return _learned_cache["items"]


def parse_learned(line, source):
    for rx, tsf, _ in _load_learned():
        m = rx.search(line)
        if not m:
            continue
        gd = m.groupdict()
        ts = parse_ts(gd.get("ts"), tsf)
        if ts is None:
            continue
        event, status = classify_text(line)
        return _row(ts, event, status, gd.get("user") or "", gd.get("ip") or "", None, 0, "", source, line,
                    "learned format")
    return None


def learn_from_samples(samples):
    """Ask the local LLM for a regex, validate it on the samples, and save it. Returns spec or None."""
    ok, _ = llm.is_available()
    if not ok or not samples:
        return None
    try:
        spec = llm.learn_format(samples[:8])
        if not spec:
            return None
        rx = re.compile(spec["regex"])
    except Exception:
        return None
    hits = [rx.search(s) for s in samples]
    good = sum(1 for m in hits if m and parse_ts(m.groupdict().get("ts"), spec.get("ts_format")))
    if good / len(samples) < 0.6:
        return None
    p = config.LEARNED_FORMATS_PATH
    items = json.loads(p.read_text() or "[]") if p.exists() else []
    items.append(spec)
    p.write_text(json.dumps(items, indent=2))
    return spec


# ------------------------------------------------------------------ JSON / CSV
KEYMAP = {
    "ts": ["timestamp", "@timestamp", "time", "datetime", "date", "_time", "eventtime", "date and time"],
    "user": ["user", "username", "user_name", "account", "accountname", "targetusername"],
    "ip": ["ip", "src_ip", "source_ip", "srcip", "sourceip", "client_ip", "remote_addr", "ipaddress", "src",
           "source address", "client"],
    "event": ["event", "action", "message", "msg", "type", "eventtype", "description"],
    "status": ["status", "result", "outcome"],
    "bytes": ["bytes", "size", "bytes_sent", "length", "bytes_out"],
}


def _from_mapping(d, source, raw):
    low = {str(k).lower().strip(): v for k, v in d.items()}

    def pick(name):
        for k in KEYMAP[name]:
            if k in low and str(low[k]).strip() not in ("", "None", "null"):
                return low[k]
        return None

    ts = parse_ts(pick("ts"))
    if ts is None:
        return None
    text = " ".join(str(pick(k) or "") for k in ("event", "status")) + " " + str(low.get("message", ""))
    event, status = classify_text(text)
    try:
        nbytes = int(float(pick("bytes") or 0))
    except ValueError:
        nbytes = 0
    return _row(ts, event, status, str(pick("user") or ""), str(pick("ip") or ""), None, nbytes, "", source,
                raw, text.strip())


def _parse_csv(text, source, stats):
    try:
        reader = csv.DictReader(io.StringIO(text))
        fields = [f.lower() for f in (reader.fieldnames or [])]
    except csv.Error:
        return []
    rows = []
    if "event id" in fields and any("date" in f for f in fields):  # Windows Event Viewer export
        for r in reader:
            r = {k.lower(): v for k, v in r.items() if k}
            try:
                eid = int(r.get("event id", 0))
            except ValueError:
                continue
            ts = parse_ts(r.get("date and time"))
            if not ts:
                continue
            msg = r.get("message") or r.get("details") or ""
            row = winlog.row_from_win(eid, winlog.data_from_message(eid, msg), ts, "", source, f"WinEvent {eid}")
            if row:
                rows.append(row)
        stats["tiers"]["windows-csv"] += len(rows)
        return rows
    for r in reader:
        row = _from_mapping(r, source, json.dumps(r)[:400])
        if row:
            rows.append(row)
    stats["tiers"]["csv"] += len(rows)
    return rows


# ------------------------------------------------------------------ main entry points
def parse_line(line, source):
    """Returns (row_or_None, tier)."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None, "empty"
    if line.lstrip().startswith("{"):
        try:
            row = _from_mapping(json.loads(line), source, line)
            if row:
                return row, "json"
        except json.JSONDecodeError:
            pass
    row = parse_known(line, source)
    if row:
        return row, "known"
    row = parse_learned(line, source)
    if row:
        return row, "learned"
    return parse_generic(line, source)


def parse_text(text, source, filename="", allow_learning=True):
    """Parse a whole file. Returns (rows, stats)."""
    stats = {"lines": 0, "tiers": Counter(), "learned_format": None, "notes": []}
    text = text.lstrip("\ufeff")
    head = text.lstrip()[:200]
    if head.startswith("<?xml") or head.startswith("<Event"):
        rows = winlog.events_from_xml(text, source)
        stats["tiers"]["windows-xml"] = len(rows)
        stats["lines"] = len(rows)
        return rows, stats
    if filename.lower().endswith(".csv"):
        rows = _parse_csv(text, source, stats)
        if rows:
            stats["lines"] = len(rows)
            return rows, stats
        stats["notes"].append("CSV not recognised, trying line-by-line parsing.")
    if head.startswith("[") and filename.lower().endswith(".json"):
        try:
            rows = [r for r in (_from_mapping(d, source, json.dumps(d)[:400]) for d in json.loads(text)) if r]
            stats["tiers"]["json"] = len(rows)
            stats["lines"] = len(rows)
            return rows, stats
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    rows, weak = [], []
    lines = text.splitlines()
    for line in lines:
        row, tier = parse_line(line, source)
        if tier == "empty":
            continue
        stats["lines"] += 1
        stats["tiers"][tier] += 1
        if tier in ("weak", "unknown"):
            weak.append(line)
        if row:
            rows.append(row)

    # Unknown format? Let the local LLM learn it once, then re-parse the unhandled lines.
    known_share = stats["tiers"].get("known", 0) / max(stats["lines"], 1)
    if allow_learning and stats["lines"] >= 5 and len(weak) / stats["lines"] >= 0.3 and known_share < 0.3:
        spec = learn_from_samples(weak[:8])
        if spec:
            stats["learned_format"] = spec
            stats["notes"].append("Unknown log format detected - the local LLM generated a parser for it.")
            weak_set = {w[:500] for w in weak}
            kept = [r for r in rows if r["raw"] not in weak_set]
            reparsed = 0
            for line in weak:
                row = parse_learned(line, source)
                if row:
                    kept.append(row)
                    reparsed += 1
            rows = kept
            stats["tiers"]["learned"] += reparsed
        else:
            stats["notes"].append("Some lines were in an unknown format; the LLM could not learn it "
                                  "(is Ollama running?). They were parsed with the generic fallback.")
    return rows, stats

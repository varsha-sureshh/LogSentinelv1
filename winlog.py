"""Windows Event Log support: live polling through wevtutil (no extra packages) and XML/CSV conversion."""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

FMT = "%Y-%m-%d %H:%M:%S"
WATCHED_IDS = (4624, 4625, 4720, 4728, 4732, 4740, 4756, 1102)
ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins"}
IGNORED_USERS = {"SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE"}


def is_windows():
    return sys.platform.startswith("win")


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _systemtime(s):
    s = re.sub(r"(\.\d{1,6})\d*", r"\1", s.strip())
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def row_from_win(eid, d, ts, host, source, raw):
    """Convert one Windows security event into LogSentinel's common schema (or None if not interesting)."""
    ip = (d.get("IpAddress") or d.get("SourceNetworkAddress") or "").strip().replace("::ffff:", "")
    if ip in ("-", "::1", "127.0.0.1", "0.0.0.0"):
        ip = ""
    target = (d.get("TargetUserName") or "").strip()
    subject = (d.get("SubjectUserName") or "").strip()
    ltype = str(d.get("LogonType") or "").strip()
    base = dict(ts=ts.strftime(FMT), host=host, ip=ip, port=None, bytes=0, source=source, raw=raw)

    if eid == 4625:
        return dict(base, user=target, event="login_failed", status="failure",
                    detail=f"Windows logon failure (type {ltype}) workstation={d.get('WorkstationName', '')}")
    if eid == 4624:
        if ltype not in ("2", "3", "7", "10", "11"):
            return None
        if (target.endswith("$") or target.upper() in IGNORED_USERS
                or target.upper().startswith(("UMFD-", "DWM-"))):
            return None
        return dict(base, user=target, event="login_success", status="success",
                    detail=f"Windows logon (type {ltype})")
    if eid == 4720:
        return dict(base, user=target, event="user_created", status="success",
                    detail=f"Account created by {subject}")
    if eid in (4728, 4732, 4756):
        if target.lower() not in ADMIN_GROUPS:
            return None
        return dict(base, user=subject, event="admin_added", status="success",
                    detail=f"Member added to privileged group '{target}' by {subject}")
    if eid == 4740:
        return dict(base, user=target, event="account_lockout", status="failure", detail="Account locked out")
    if eid == 1102:
        return dict(base, user=subject, event="log_cleared", status="success",
                    detail=f"Security log cleared by {subject}")
    return None


def events_from_xml(text, source):
    """Parse wevtutil / Event Viewer XML export into rows. Also returns the highest record id."""
    rows, _ = _xml_rows(text, source)
    return rows


def _xml_rows(text, source):
    text = re.sub(r"<\?xml[^>]*\?>", "", text)
    text = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", text)
    if "<Events" not in text[:300]:
        text = "<Events>" + text + "</Events>"
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [], 0
    rows, max_id = [], 0
    for ev in root.iter("Event"):
        sysn = ev.find("System")
        if sysn is None:
            continue
        try:
            eid = int(sysn.findtext("EventID", "0"))
            rid = int(sysn.findtext("EventRecordID", "0"))
            ts = _systemtime(sysn.find("TimeCreated").get("SystemTime"))
        except Exception:
            continue
        max_id = max(max_id, rid)
        data = {}
        for el in ev.iter():
            if el.tag == "Data" and el.get("Name"):
                data[el.get("Name")] = el.text or ""
            elif el.tag not in ("Event", "System", "EventData", "UserData", "Data") and len(el) == 0 and el.text:
                data.setdefault(el.tag, el.text)
        row = row_from_win(eid, data, ts, sysn.findtext("Computer", ""), source, f"WinEvent {eid} rec={rid}")
        if row:
            rows.append(row)
    return rows, max_id


def data_from_message(eid, msg):
    """Event Viewer CSV exports only contain the rendered message; pull out the fields we need."""
    accts = re.findall(r"Account Name:\s*(\S+)", msg)
    d = {"TargetUserName": accts[-1] if accts else "", "SubjectUserName": accts[0] if accts else ""}
    m = re.search(r"Source Network Address:\s*(\S+)", msg)
    d["IpAddress"] = m.group(1) if m else ""
    m = re.search(r"Logon Type:\s*(\d+)", msg)
    d["LogonType"] = m.group(1) if m else ""
    if eid in (4728, 4732, 4756):
        m = re.search(r"Group Name:\s*(.+)", msg)
        d["TargetUserName"] = m.group(1).strip() if m else ""
    return d


def poll(last_id):
    """Read new Security events with wevtutil. Needs Administrator rights for the Security log.
    Returns (rows, new_last_id, error_message)."""
    if not is_windows():
        return [], last_id, "Windows Event Log is only available on Windows."
    ids = " or ".join(f"EventID={i}" for i in WATCHED_IDS)
    if last_id is None:
        query = f"*[System[({ids})]]"
        extra = ["/rd:true", "/c:300"]
    else:
        query = f"*[System[({ids}) and (EventRecordID>{int(last_id)})]]"
        extra = ["/c:500"]
    cmd = ["wevtutil", "qe", "Security", f"/q:{query}", "/f:xml", "/e:Events"] + extra
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, creationflags=flags)
    except Exception as e:
        return [], last_id, f"wevtutil failed: {e}"
    if p.returncode != 0:
        err = (p.stderr or p.stdout).strip()
        if "denied" in err.lower():
            err = "Access denied - run the terminal / VS Code as Administrator to read the Security log."
        return [], last_id, err
    rows, max_id = _xml_rows(p.stdout, "windows-eventlog")
    return rows, max(max_id, last_id or 0), ""

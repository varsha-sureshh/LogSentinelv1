"""Detection engine: rules (Sigma-style) + Isolation Forest ML + correlation into incidents."""
import hashlib
import ipaddress
from collections import Counter
from datetime import timedelta

import numpy as np
import pandas as pd

import config

TS = "%Y-%m-%d %H:%M:%S"
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_WEIGHT = {"low": 10, "medium": 25, "high": 45, "critical": 70}
LOCAL = {"", "-", "::1", "127.0.0.1", "localhost", "::ffff:127.0.0.1", "0.0.0.0", "nan", "none"}

MITRE = {  # rule -> (technique id, name, tactic)
    "brute_force": ("T1110.001", "Password Guessing", "Credential Access"),
    "password_spray": ("T1110.003", "Password Spraying", "Credential Access"),
    "web_brute_force": ("T1110", "Brute Force (web)", "Credential Access"),
    "success_after_failures": ("T1078", "Valid Accounts", "Initial Access"),
    "odd_hours": ("T1078", "Valid Accounts (off-hours use)", "Initial Access"),
    "impossible_travel": ("T1078", "Valid Accounts (multiple locations)", "Initial Access"),
    "port_scan": ("T1046", "Network Service Discovery", "Discovery"),
    "web_scan": ("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
    "large_transfer": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "ml_anomaly": ("T1020", "Anomalous activity (ML)", "Exfiltration / Unknown"),
    "user_created": ("T1136.001", "Create Account: Local Account", "Persistence"),
    "admin_added": ("T1098", "Account Manipulation", "Persistence"),
    "log_cleared": ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    "account_lockout": ("T1110", "Brute Force (account lockout)", "Credential Access"),
}
STAGE = {
    "port_scan": "Reconnaissance", "web_scan": "Reconnaissance",
    "brute_force": "Credential attack", "password_spray": "Credential attack", "web_brute_force": "Credential attack",
    "account_lockout": "Credential attack",
    "success_after_failures": "Access gained", "odd_hours": "Access gained", "impossible_travel": "Access gained",
    "user_created": "Persistence", "admin_added": "Persistence", "log_cleared": "Cover tracks",
    "large_transfer": "Data exfiltration", "ml_anomaly": "Anomalous behaviour",
}
STAGE_ORDER = ["Reconnaissance", "Credential attack", "Access gained", "Persistence", "Cover tracks",
               "Data exfiltration", "Anomalous behaviour"]
POST_COMPROMISE = {"user_created", "admin_added", "log_cleared", "large_transfer", "ml_anomaly"}
HOST_LEVEL = {"user_created", "admin_added", "log_cleared"}


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _prep(df):
    d = df.copy()
    d["ip"] = d["ip"].fillna("").astype(str)
    d["user"] = d["user"].fillna("").astype(str)
    d["entity"] = np.where(d["ip"].str.lower().isin(LOCAL), d["user"], d["ip"])
    d["entity"] = d["entity"].replace("", "unknown")
    d = d.sort_values("ts").reset_index(drop=True)
    d["t"] = (d["ts"] - pd.Timestamp("1970-01-01")).dt.total_seconds()
    return d


def _alert(ts, rule, severity, title, detail, key, ip="", user="", entity=""):
    tid, name, tactic = MITRE.get(rule, ("", "", ""))
    return {"ts": pd.Timestamp(ts).strftime(TS), "rule": rule, "severity": severity, "title": title,
            "detail": detail, "entity": entity or ip or user, "ip": ip, "user": user,
            "mitre": f"{tid} {name} ({tactic})".strip() if tid else "", "dedup_key": key}


def _burst(t, vals, window, n, cooldown=600):
    """Sliding window: trigger when >= n events (or n distinct vals) fall in `window` seconds.
    After a trigger the same source stays quiet for `cooldown` seconds, so one attack = one alert."""
    out, last, j, cnt = [], None, 0, Counter()
    for i in range(len(t)):
        if vals is not None:
            cnt[vals[i]] += 1
        while t[i] - t[j] > window:
            if vals is not None:
                cnt[vals[j]] -= 1
                if cnt[vals[j]] <= 0:
                    del cnt[vals[j]]
            j += 1
        c = len(cnt) if vals is not None else i - j + 1
        if c >= n and (last is None or t[i] - last >= cooldown):
            last = t[i]
            out.append((i, j, c))
    return out


# ------------------------------------------------------------------ rules
def run_rules(df):
    if df.empty:
        return []
    d = _prep(df)
    alerts = []
    W, N = config.BRUTE_WINDOW_SEC, config.BRUTE_THRESHOLD

    failed = d[d.event == "login_failed"]
    for ent, g in failed.groupby("entity"):
        t = g["t"].to_numpy()
        for i, j, c in _burst(t, None, W, N):
            users = sorted(set(g["user"].iloc[j:i + 1]) - {""})[:5]
            alerts.append(_alert(g["ts"].iloc[i], "brute_force", "high",
                                 f"Brute-force: {c} failed logins in {W}s from {ent}",
                                 f"{c} failed logins within {W} seconds. Accounts targeted: {', '.join(users) or 'n/a'}.",
                                 f"bf:{ent}:{int(t[i])}", ip=g["ip"].iloc[i], entity=ent))
        for i, j, c in _burst(t, g["user"].tolist(), 300, 5):
            alerts.append(_alert(g["ts"].iloc[i], "password_spray", "high",
                                 f"Password spraying: {c} different accounts attacked from {ent}",
                                 f"{c} distinct usernames failed within 5 minutes from the same source.",
                                 f"spray:{ent}:{int(t[i])}", ip=g["ip"].iloc[i], entity=ent))

    # successful login right after many failures -> likely compromised account
    fails = {ent: g["t"].to_numpy() for ent, g in failed.groupby("entity")}
    for _, r in d[d.event == "login_success"].iterrows():
        arr = fails.get(r["entity"])
        if arr is None:
            continue
        c = int(np.searchsorted(arr, r["t"], side="right") - np.searchsorted(arr, r["t"] - 600, side="left"))
        if c >= 5:
            alerts.append(_alert(r["ts"], "success_after_failures", "critical",
                                 f"Successful login by '{r['user']}' after {c} failed attempts from {r['entity']}",
                                 f"Account '{r['user']}' logged in from {r['entity']} right after {c} failures "
                                 f"in the previous 10 minutes - likely compromised credentials.",
                                 f"saf:{r['entity']}:{r['user']}:{int(r['t'] // 600)}",
                                 ip=r["ip"], user=r["user"], entity=r["entity"]))

    # off-hours logins
    s, e = config.ODD_HOUR_START, config.ODD_HOUR_END
    ok = d[(d.event == "login_success") & (d.user != "")]
    for _, r in ok[ok["ts"].dt.hour.between(s, e - 1)].iterrows():
        alerts.append(_alert(r["ts"], "odd_hours", "medium",
                             f"Off-hours login: '{r['user']}' at {r['ts']:%H:%M}",
                             f"Login by '{r['user']}' from {r['ip'] or 'local console'} between {s:02d}:00 and {e:02d}:00.",
                             f"odd:{r['user']}:{r['ts']:%Y%m%d}", ip=r["ip"], user=r["user"], entity=r["entity"]))

    # impossible travel (heuristic: same user, two public IPs within 10 minutes; no GeoIP needed)
    pub = ok[ok["ip"].map(_is_public).astype(bool)] if len(ok) else ok
    for user, g in (pub.groupby("user") if len(pub) else []):
        prev = None
        for _, r in g.iterrows():
            if prev is not None and r["ip"] != prev["ip"] and r["t"] - prev["t"] <= 600:
                alerts.append(_alert(r["ts"], "impossible_travel", "high",
                                     f"Possible impossible travel for '{user}'",
                                     f"'{user}' logged in from {prev['ip']} and then {r['ip']} within "
                                     f"{int(r['t'] - prev['t'])} seconds.",
                                     f"travel:{user}:{prev['ip']}:{r['ip']}:{int(r['t'] // 600)}",
                                     ip=r["ip"], user=user, entity=r["ip"]))
            prev = r

    # port scan
    fw = d[(d.event == "firewall_drop") & d.port.notna()]
    for ent, g in fw.groupby("entity"):
        t = g["t"].to_numpy()
        for i, j, c in _burst(t, g["port"].astype(int).tolist(), 60, config.PORTSCAN_PORTS):
            alerts.append(_alert(g["ts"].iloc[i], "port_scan", "high",
                                 f"Port scan: {c} different ports probed by {ent}",
                                 f"{ent} touched {c} distinct ports in 60 seconds (blocked by the firewall).",
                                 f"scan:{ent}:{int(t[i])}", ip=g["ip"].iloc[i], entity=ent))

    # web scanning and web brute force
    http = d[d.event == "http_request"]
    for ent, g in http[http.status.isin(["404", "403"])].groupby("entity"):
        t = g["t"].to_numpy()
        for i, j, c in _burst(t, None, 60, 20):
            alerts.append(_alert(g["ts"].iloc[i], "web_scan", "medium",
                                 f"Web scanning: {c} 403/404 errors in 60s from {ent}",
                                 f"{ent} requested many non-existent or forbidden paths (e.g. {g['detail'].iloc[i]}).",
                                 f"webscan:{ent}:{int(t[i])}", ip=g["ip"].iloc[i], entity=ent))
    for ent, g in http[http.status == "401"].groupby("entity"):
        t = g["t"].to_numpy()
        for i, j, c in _burst(t, None, 60, 10):
            alerts.append(_alert(g["ts"].iloc[i], "web_brute_force", "high",
                                 f"Web login brute force: {c} HTTP 401s in 60s from {ent}",
                                 f"{ent} repeatedly failed web authentication.",
                                 f"webbf:{ent}:{int(t[i])}", ip=g["ip"].iloc[i], entity=ent))

    # large data transfer (per entity per hour)
    big = d[(d.bytes > 0) & (d.entity != "unknown")].copy()
    big["hour"] = big["ts"].dt.floor("h")
    for (ent, hour), g in big.groupby(["entity", "hour"]):
        total = int(g["bytes"].sum())
        if total >= config.EXFIL_BYTES:
            alerts.append(_alert(g["ts"].iloc[-1], "large_transfer", "high",
                                 f"Large data transfer: {total / 1048576:.0f} MB involving {ent} in one hour",
                                 f"{total / 1048576:.0f} MB transferred (largest request: "
                                 f"{g.loc[g['bytes'].idxmax(), 'detail'] or 'n/a'}). Possible data exfiltration.",
                                 f"vol:{ent}:{hour:%Y%m%d%H}", ip=g["ip"].iloc[0], entity=ent))

    # single high-value events
    singles = {"log_cleared": ("critical", "Audit log cleared by '{u}'"),
               "user_created": ("medium", "New account '{u}' created"),
               "admin_added": ("high", "Privileged group membership changed by '{u}'"),
               "account_lockout": ("medium", "Account '{u}' locked out")}
    for rule, (sev, title) in singles.items():
        for _, r in d[d.event == rule].iterrows():
            alerts.append(_alert(r["ts"], rule, sev, title.format(u=r["user"] or "unknown"),
                                 r["detail"] or r["raw"][:150],
                                 f"{rule}:{r['ts']:%Y%m%d%H%M%S}:{r['user']}:{r['host']}",
                                 ip=r["ip"], user=r["user"], entity=r["entity"]))
    return alerts


# ------------------------------------------------------------------ machine learning
def ml_anomalies(df, contamination=0.03, min_rows=30, min_events=10):
    """Isolation Forest over per-entity (IP or user) hourly behaviour. Catches unknown / unusual patterns."""
    if df.empty:
        return []
    from sklearn.ensemble import IsolationForest
    d = _prep(df)
    d = d[d.entity != "unknown"]
    d["bucket"] = d["ts"].dt.floor("h")
    d["is_fail"] = (d.event == "login_failed").astype(int)
    d["is_ok"] = (d.event == "login_success").astype(int)
    agg = d.groupby(["entity", "bucket"]).agg(n=("event", "size"), failed=("is_fail", "sum"), ok=("is_ok", "sum"),
                                              users=("user", "nunique"), ports=("port", "nunique"),
                                              nbytes=("bytes", "sum"),
                                              last=("ts", "max")).reset_index()
    if len(agg) < min_rows:
        return []
    X = np.column_stack([np.log1p(agg.n), np.log1p(agg.failed), np.log1p(agg.ok), np.log1p(agg.users),
                         np.log1p(agg.ports), np.log1p(agg.nbytes / 1e6), agg.bucket.dt.hour])
    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42).fit(X)
    pred, score = iso.predict(X), iso.score_samples(X)
    alerts = []
    for k in np.where((pred == -1) & (agg.n.to_numpy() >= min_events))[0]:
        r = agg.iloc[k]
        alerts.append(_alert(r["last"], "ml_anomaly", "medium",
                             f"Anomalous behaviour from {r.entity} (Isolation Forest)",
                             f"In the hour from {r.bucket:%H:%M}: {r.n} events, {r.failed} failed logins, "
                             f"{r.users} distinct users, {r.ports} ports, {r.nbytes / 1048576:.1f} MB. "
                             f"Unusual compared with other activity (anomaly score {score[k]:.2f}).",
                             f"ml:{r.entity}:{r.bucket:%Y%m%d%H}",
                             ip=r.entity if r.entity[:1].isdigit() else "", entity=r.entity))
    return alerts


def run_all(df, ml=True):
    alerts = run_rules(df)
    if ml:
        alerts += ml_anomalies(df)
    seen, out = set(), []
    for a in alerts:
        if a["dedup_key"] not in seen:
            seen.add(a["dedup_key"])
            out.append(a)
    return sorted(out, key=lambda a: a["ts"])


# ------------------------------------------------------------------ correlation
def _ids(a):
    return {x for x in (a.get("entity"), a.get("ip")) if x and x.lower() not in LOCAL and x != "unknown"}


def correlate(alerts, gap_minutes=30):
    """Chain related alerts (same source, close in time) into incidents."""
    incs = []
    for a in sorted(alerts, key=lambda x: x["ts"]):
        ts = pd.Timestamp(a["ts"])
        ids = _ids(a)
        target = None
        for inc in reversed(incs):
            if (ts - inc["_last"]) > timedelta(minutes=gap_minutes):
                continue
            if inc["_ids"] & ids:
                target = inc
                break
            if a["rule"] in HOST_LEVEL and "success_after_failures" in {x["rule"] for x in inc["alerts"]}:
                target = inc
                break
        if target is None:
            target = {"alerts": [], "_ids": set(), "_last": ts}
            incs.append(target)
        target["alerts"].append(a)
        target["_ids"] |= ids
        target["_last"] = max(target["_last"], ts)
    return sorted((_finalize(i) for i in incs), key=lambda i: (-i["risk"], i["start"]))


def _finalize(inc):
    alerts = sorted(inc["alerts"], key=lambda a: a["ts"])
    rules = {a["rule"] for a in alerts}
    worst = max(alerts, key=lambda a: SEV_RANK[a["severity"]])
    entity = sorted(inc["_ids"], key=lambda x: (not _is_public(x), x))[0] if inc["_ids"] else alerts[0]["entity"]

    attack = rules & {"brute_force", "password_spray", "web_brute_force"}
    if attack and "success_after_failures" in rules and rules & POST_COMPROMISE:
        title, sev, bonus = "Account compromise with post-compromise activity", "critical", 20
    elif attack and "success_after_failures" in rules:
        title, sev, bonus = "Probable account compromise (brute force succeeded)", "critical", 10
    elif "log_cleared" in rules:
        title, sev, bonus = "Anti-forensics: audit log cleared", "critical", 0
    elif attack:
        title, sev, bonus = "Brute-force attack (no successful login seen)", "high", 0
    elif rules & {"port_scan", "web_scan"}:
        title, sev, bonus = "Reconnaissance / scanning activity", worst["severity"], 0
    else:
        title, sev, bonus = worst["title"], worst["severity"], 0
    risk = min(100, SEV_WEIGHT[sev] + 5 * (len(rules) - 1) + bonus)
    stages = [s for s in STAGE_ORDER if s in {STAGE[r] for r in rules if r in STAGE}]
    mitre = sorted({a["mitre"] for a in alerts if a["mitre"]})
    start, end = alerts[0]["ts"], alerts[-1]["ts"]
    ips = sorted({a["ip"] for a in alerts if a["ip"] and a["ip"].lower() not in LOCAL})
    users = sorted({a["user"] for a in alerts if a["user"]})
    key = hashlib.md5(f"{entity}{start}".encode()).hexdigest()[:6].upper()
    return {"id": f"INC-{key}", "title": title, "severity": sev, "risk": risk, "start": start, "end": end,
            "entity": entity, "ips": ips, "users": users, "rules": sorted(rules), "stages": stages,
            "mitre": mitre, "alerts": alerts}


def timeline(inc):
    return [(a["ts"], a["severity"], a["title"]) for a in inc["alerts"]]


def recommendations(inc):
    r = set(inc["rules"])
    acts = []
    if r & {"brute_force", "password_spray", "web_brute_force", "account_lockout"}:
        acts.append("Block the attacking source at the firewall; enforce account lockout, strong passwords and MFA.")
    if "success_after_failures" in r:
        acts.append("Treat the logged-in account as compromised: reset its password, end active sessions, "
                    "revoke keys/tokens and review what it did after login.")
    if "large_transfer" in r:
        acts.append("Identify which files were transferred, assess data sensitivity and notify the data owner.")
    if r & {"user_created", "admin_added"}:
        acts.append("Verify the new account / privilege change was authorised; disable and investigate if not.")
    if "log_cleared" in r:
        acts.append("Preserve remaining evidence, find out who cleared the log, and forward logs to a remote collector.")
    if r & {"port_scan", "web_scan"}:
        acts.append("Block the scanner and confirm only required ports/services are exposed to the network.")
    if r & {"odd_hours", "impossible_travel"}:
        acts.append("Confirm with the account owner that the logins were genuine.")
    if "ml_anomaly" in r:
        acts.append("Review the raw events for this source and hour to confirm whether the behaviour is expected.")
    return acts or ["Review the related events and confirm whether the activity is expected."]


def block_commands(inc):
    out = []
    for ip in inc["ips"]:
        if _is_public(ip):
            out.append(f"iptables -A INPUT -s {ip} -j DROP")
            out.append(f'netsh advfirewall firewall add rule name="LogSentinel block {ip}" dir=in action=block remoteip={ip}')
    return out


# ------------------------------------------------------------------ summary + convenience
def summarize(df, alerts, incidents):
    s = {"events": len(df), "n_alerts": len(alerts), "n_incidents": len(incidents)}
    sev = Counter(a["severity"] for a in alerts)
    s["alerts_by_severity"] = {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low")}
    if df.empty:
        s.update(start="", end="", by_event={}, top_failed_ips={}, top_ips={}, per_hour={})
        return s
    s["start"], s["end"] = df.ts.min().strftime(TS), df.ts.max().strftime(TS)
    s["by_event"] = df.event.value_counts().to_dict()
    pubmask = ~df.ip.str.lower().isin(LOCAL)
    s["top_failed_ips"] = df[(df.event == "login_failed") & pubmask].ip.value_counts().head(8).to_dict()
    s["top_ips"] = df[pubmask].ip.value_counts().head(8).to_dict()
    ph = df.set_index("ts").resample("1h").size()
    s["per_hour"] = {k.strftime("%Y-%m-%d %H:00"): int(v) for k, v in ph.items()}
    return s


def analyze(df, ml=True):
    alerts = run_all(df, ml)
    incidents = correlate(alerts)
    return {"alerts": alerts, "incidents": incidents, "stats": summarize(df, alerts, incidents)}

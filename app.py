"""LogSentinel dashboard.  Run:  streamlit run app.py   (as Administrator to read the Windows Security log)"""
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

import assistant
import config
import db
import detect
import llm
import notify
import parsers
import reporting
import simulator
import winlog
from engine import Engine

st.set_page_config(page_title="LogSentinel", page_icon="🛡️", layout="wide")
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
COLORS = {"critical": "#b71c1c", "high": "#e65100", "medium": "#f9a825", "low": "#2e7d32"}


@st.cache_resource
def get_engine():
    return Engine()


engine = get_engine()
db.init()

# ------------------------------------------------------------------ sidebar
st.sidebar.title("🛡️ LogSentinel")
page = st.sidebar.radio("Menu", ["Live Monitor", "Upload & Analyze", "Incidents & Timeline",
                                 "Ask LogSentinel", "Reports", "Settings & Status"])
st.sidebar.divider()
st.sidebar.caption(f"Live monitoring: {'🟢 ON' if engine.running else '⚪ OFF'}")
st.sidebar.caption(f"Daily report at {config.REPORT_TIME} (last: {engine.status['last_report']})")


def sev_df(alerts):
    if not alerts:
        return pd.DataFrame(columns=["", "Time", "Severity", "Alert", "Source", "MITRE ATT&CK"])
    return pd.DataFrame([{"": ICON[a["severity"]], "Time": a["ts"], "Severity": a["severity"].upper(),
                          "Alert": a["title"], "Source": a.get("entity", ""), "MITRE ATT&CK": a.get("mitre", "")}
                         for a in alerts])


def charts(stats):
    c1, c2, c3 = st.columns(3)
    sev = stats["alerts_by_severity"]
    fig = px.bar(x=[k.title() for k in sev], y=list(sev.values()), color=[k.title() for k in sev],
                 color_discrete_map={k.title(): COLORS[k] for k in sev}, labels={"x": "", "y": "Alerts"},
                 title="Alerts by severity")
    fig.update_layout(showlegend=False, height=280, margin=dict(t=40, b=10))
    c1.plotly_chart(fig, use_container_width=True)
    ph = stats.get("per_hour", {})
    fig = px.bar(x=list(ph.keys()), y=list(ph.values()), labels={"x": "", "y": "Events"}, title="Events per hour")
    fig.update_layout(height=280, margin=dict(t=40, b=10))
    c2.plotly_chart(fig, use_container_width=True)
    ti = stats.get("top_failed_ips") or stats.get("top_ips") or {}
    fig = px.bar(x=list(ti.values()), y=list(ti.keys()), orientation="h", labels={"x": "Events", "y": ""},
                 title="Top attacking / active sources")
    fig.update_layout(height=280, margin=dict(t=40, b=10), yaxis=dict(autorange="reversed"))
    c3.plotly_chart(fig, use_container_width=True)


def show_incident(inc, info=None, expanded=False):
    with st.expander(f"{ICON[inc['severity']]} {inc['id']} - {inc['title']}  |  risk {inc['risk']}/100",
                     expanded=expanded):
        st.markdown(f"**When:** {inc['start']} → {inc['end']}  \n**Source:** {inc['entity']}  \n"
                    f"**Accounts:** {', '.join(inc['users']) or 'n/a'}  \n"
                    f"**Attack stages:** {' → '.join(inc['stages']) or 'n/a'}  \n"
                    f"**MITRE ATT&CK:** {'; '.join(inc['mitre']) or 'n/a'}")
        if info and info.get("summary"):
            st.info(info["summary"])
        st.markdown("**Recommended actions**")
        for a in detect.recommendations(inc) + ((info or {}).get("actions") or []):
            st.markdown(f"- {a}")
        cmds = detect.block_commands(inc)
        if cmds:
            st.markdown("**Suggested block commands** (review before running)")
            st.code("\n".join(cmds), language="bash")
        st.markdown("**Timeline**")
        st.dataframe(pd.DataFrame([{"Time": t, "Severity": s.upper(), "Event": x} for t, s, x in detect.timeline(inc)]),
                     hide_index=True, use_container_width=True)


# ================================================================== LIVE MONITOR
if page == "Live Monitor":
    st.title("Live Monitor")
    c1, c2, c3, c4 = st.columns([1.3, 1.3, 1, 1.3])
    use_win = c1.checkbox("Windows Event Log", value=winlog.is_windows(), disabled=not winlog.is_windows())
    use_sys = c2.checkbox(f"Syslog listener (UDP {config.SYSLOG_PORT})", value=True)
    if not engine.running:
        if c3.button("▶ Start", type="primary"):
            engine.start(windows=use_win, syslog=use_sys)
            st.rerun()
    else:
        if c3.button("■ Stop"):
            engine.stop()
            st.rerun()
    if c4.button("💥 Simulate attack"):
        engine.feed_lines(simulator.attack_lines(datetime.now()), "simulator")
        if not engine.running:
            engine.start(windows=False, syslog=False)
        st.toast("Attack simulation injected - alerts will appear within ~10 seconds")

    @st.fragment(run_every=5)
    def live_panel():
        now = datetime.now()
        day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
        alerts = db.alerts_list(day0, now + timedelta(minutes=5))
        new = db.unacknowledged()
        sc = engine.status
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Events today", db.count_events(day0, now + timedelta(minutes=5)))
        m2.metric("Alerts today", len(alerts))
        m3.metric("Critical / High", f"{sum(a['severity'] == 'critical' for a in alerts)} / "
                                     f"{sum(a['severity'] == 'high' for a in alerts)}")
        m4.metric("Last event", sc["last_event"][-8:] if sc["last_event"] else "-")
        st.caption(f"Windows: {sc['windows']} | Syslog: {sc['syslog']} | Last detection: {sc['last_detect'] or '-'} "
                   f"| Email: {sc['emails'] or '-'}")
        if sc["last_error"]:
            st.warning(sc["last_error"])
        if new:
            crit = [a for a in new if a["severity"] in ("critical", "high")]
            if crit:
                st.error(f"🚨 {len(new)} new alert(s) - {len(crit)} high/critical. Latest: {new[0]['title']}")
            else:
                st.warning(f"⚠️ {len(new)} new alert(s). Latest: {new[0]['title']}")
            if st.button("Acknowledge all"):
                db.ack_all()
                st.rerun(scope="fragment")
        st.subheader("Alert feed")
        st.dataframe(sev_df(alerts[:100]), hide_index=True, use_container_width=True, height=300)
        incs = detect.correlate(alerts)
        if incs:
            st.subheader("Active incidents")
            for inc in incs[:3]:
                st.markdown(f"{ICON[inc['severity']]} **{inc['title']}** - risk {inc['risk']}/100, source "
                            f"`{inc['entity']}`, {inc['start'][-8:]}–{inc['end'][-8:]}")
        df = db.events_df(day0, now + timedelta(minutes=5), live_only=True)
        if not df.empty:
            charts(detect.summarize(df, alerts, incs))

    live_panel()

# ================================================================== UPLOAD
elif page == "Upload & Analyze":
    st.title("Upload & Analyze")
    st.caption("Any text log (auth.log, syslog, Apache/Nginx, firewall, Windows XML/CSV export, JSON, CSV). "
               "Unknown formats are handled by the local LLM.")
    files = st.file_uploader("Log file(s)", accept_multiple_files=True)
    c1, c2 = st.columns(2)
    use_llm = c1.checkbox("Use local LLM for summaries and unknown formats", value=True)
    if c2.button("Load demo attack-day log"):
        p = simulator.write_sample()
        st.session_state["demo"] = (p.name, p.read_bytes())
    items = [(f.name, f.getvalue()) for f in (files or [])]
    if st.session_state.get("demo"):
        items.append(st.session_state["demo"])
        st.info(f"Demo file loaded: {st.session_state['demo'][0]}")
    if items and st.button("🔍 Analyze & generate report", type="primary"):
        with st.spinner("Parsing, detecting, correlating and writing the report (the LLM can take a minute)..."):
            all_rows, notes = [], []
            for name, data in items:
                rows, stats = parsers.parse_text(data.decode("utf-8", "replace"), f"upload:{name}", name,
                                                 allow_learning=use_llm)
                notes.append((name, stats))
                all_rows += rows
            if not all_rows:
                st.error("No events could be extracted from these files.")
            else:
                db.insert_events(all_rows)
                df = db.to_df(all_rows)
                label = "Uploaded logs: " + ", ".join(n for n, _ in items)
                st.session_state["upload"] = {
                    "rec": reporting.create_report(df, label, "upload", use_llm=use_llm), "notes": notes, "df": df}
    up = st.session_state.get("upload")
    if up:
        rec, res = up["rec"], up["rec"]["analysis"]
        for name, s in up["notes"]:
            st.caption(f"📄 {name}: {s['lines']} lines · parsers: {dict(s['tiers'])}")
            for n in s["notes"]:
                st.warning(n)
        sv = res["stats"]["alerts_by_severity"]
        m = st.columns(5)
        m[0].metric("Events", res["stats"]["events"])
        m[1].metric("Alerts", res["stats"]["n_alerts"])
        m[2].metric("Incidents", res["stats"]["n_incidents"])
        m[3].metric("Critical", sv["critical"])
        m[4].metric("High", sv["high"])
        st.subheader("Summary")
        if rec.get("llm_used"):
            st.success("AI summaries written by the local LLM.")
        else:
            _ok, _msg = llm.is_available()
            st.warning("Rule-based summaries (LLM not used): " + (
                "it timed out or failed - warm the model with 'ollama run " + config.OLLAMA_MODEL + "'." if _ok
                else _msg))
        st.write(rec["summary"])
        st.download_button("⬇ Download PDF report", open(rec["pdf_path"], "rb").read(),
                           file_name=rec["pdf_path"].split("\\")[-1].split("/")[-1], mime="application/pdf")
        charts(res["stats"])
        for k, inc in enumerate(res["incidents"]):
            show_incident(inc, rec["inc_summaries"].get(inc["id"]), expanded=(k == 0))
        with st.expander("All alerts"):
            st.dataframe(sev_df(res["alerts"]), hide_index=True, width="stretch")

# ================================================================== INCIDENTS
elif page == "Incidents & Timeline":
    st.title("Incidents & Timeline")
    day = st.date_input("Day", value=datetime.now().date())
    d0 = datetime.combine(day, datetime.min.time())
    alerts = db.alerts_list(d0, d0 + timedelta(days=1))
    incs = detect.correlate(alerts)
    st.caption(f"{len(alerts)} alerts → {len(incs)} incidents (live data only)")
    for k, inc in enumerate(incs):
        show_incident(inc, expanded=(k == 0))
    if not incs:
        st.success("No incidents for this day.")

# ================================================================== CHAT
elif page == "Ask LogSentinel":
    st.title("Ask LogSentinel")
    st.caption('Try: "What happened on the server last night?", "Show me failed logins today", "Any attacks in the last hour?"')
    ok, msg = llm.is_available()
    if not ok:
        st.warning(msg + " - answers will use the rule-based reconstruction instead.")
    src = st.radio("Data source", ["Live logs", "Last uploaded file"], horizontal=True)
    hist = st.session_state.setdefault("chat", [])
    for role, text in hist:
        st.chat_message(role).write(text)
    q = st.chat_input("Ask about your logs...")
    if q:
        hist.append(("user", q))
        st.chat_message("user").write(q)
        with st.chat_message("assistant"):
            with st.spinner("Reconstructing events..."):
                if src == "Last uploaded file" and st.session_state.get("upload"):
                    out = assistant.answer(q, df=st.session_state["upload"]["df"], label="the uploaded file")
                else:
                    out = assistant.answer(q)
            st.write(out["answer"])
            if out["timeline"]:
                with st.expander("Timeline reconstruction"):
                    st.dataframe(pd.DataFrame(out["timeline"], columns=["Time", "Severity", "Event"]),
                                 hide_index=True, use_container_width=True)
        hist.append(("assistant", out["answer"]))

# ================================================================== REPORTS
elif page == "Reports":
    st.title("Reports")
    st.caption(f"A report is generated automatically every day at {config.REPORT_TIME} while LogSentinel is running.")
    if st.button("📝 Generate today's report now", type="primary"):
        with st.spinner("Generating report..."):
            engine.daily_report()
        st.success("Report created.")
    for r in db.reports_list():
        with st.container(border=True):
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{r['label']}**  \n{r['period_start']} → {r['period_end']} · {r['n_events']} events · "
                        f"{r['n_alerts']} alerts · {r['n_incidents']} incidents · created {r['created']}")
            c1.caption(r["summary"])
            try:
                c2.download_button("⬇ PDF", open(r["pdf_path"], "rb").read(), file_name=r["pdf_path"].split("\\")[-1].split("/")[-1],
                                   mime="application/pdf", key=f"dl{r['id']}")
            except FileNotFoundError:
                c2.caption("file missing")

# ================================================================== SETTINGS
else:
    st.title("Settings & Status")
    ok, msg = llm.is_available()
    st.markdown(f"**Local LLM:** {'✅' if ok else '❌'} {msg}")
    st.markdown(f"**Email:** {'✅ configured' if notify.configured() else '❌ not configured'} → {config.ALERT_TO or '-'}")
    if st.button("Send test email"):
        ok2, m2 = notify.send_email("[LogSentinel] test", "This is a test alert from LogSentinel.")
        (st.success if ok2 else st.error)(m2)
    st.markdown(f"**Windows admin rights:** {'✅ yes' if winlog.is_admin() else '❌ no (Security log needs Administrator)'}")
    st.markdown(f"**Syslog UDP port:** {config.SYSLOG_PORT}  |  **Daily report:** {config.REPORT_TIME}")
    st.json({"BRUTE_THRESHOLD": config.BRUTE_THRESHOLD, "BRUTE_WINDOW_SEC": config.BRUTE_WINDOW_SEC,
             "PORTSCAN_PORTS": config.PORTSCAN_PORTS, "ODD_HOURS": f"{config.ODD_HOUR_START}-{config.ODD_HOUR_END}",
             "EXFIL_MB": config.EXFIL_BYTES // 1048576, "OLLAMA_MODEL": config.OLLAMA_MODEL})
    st.caption("Change these in the .env file and restart the app.")
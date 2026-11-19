"""'What happened on the server last night?' - natural-language questions over the logs."""
from datetime import datetime, timedelta

import db
import detect
import llm


def window_for(question, now=None):
    now = now or datetime.now()
    q = question.lower()
    today0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if "last night" in q:
        return today0 - timedelta(hours=6), today0 + timedelta(hours=9), "last night (18:00-09:00)"
    if "yesterday" in q:
        return today0 - timedelta(days=1), today0, "yesterday"
    if "last hour" in q:
        return now - timedelta(hours=1), now, "the last hour"
    if "week" in q:
        return now - timedelta(days=7), now, "the last 7 days"
    if "today" in q:
        return today0, now, "today"
    return now - timedelta(hours=24), now, "the last 24 hours"


def build_context(res, label):
    st = res["stats"]
    out = [f"Window: {label}. Events: {st['events']}. Alerts: {st['n_alerts']} {st['alerts_by_severity']}. "
           f"Incidents: {st['n_incidents']}."]
    for inc in res["incidents"][:5]:
        out.append(f"\nINCIDENT {inc['id']}: {inc['title']} | {inc['severity']} | risk {inc['risk']} | "
                   f"{inc['start']} to {inc['end']} | source {inc['entity']} | accounts {', '.join(inc['users']) or 'n/a'}")
        for ts, sv, txt in detect.timeline(inc)[:8]:
            out.append(f"  {ts} [{sv}] {txt}")
    if st.get("top_failed_ips"):
        out.append("\nTop failed-login IPs: " + ", ".join(f"{k} ({v})" for k, v in st["top_failed_ips"].items()))
    return "\n".join(out)[:5000]


def answer(question, df=None, label=None):
    """Answer from live data (default) or a supplied DataFrame (e.g. an uploaded file)."""
    if df is None:
        start, end, label = window_for(question)
        df = db.events_df(start, end, live_only=True)
        if df.empty:
            return {"answer": f"No live events were recorded for {label}.", "timeline": [], "llm_used": False}
    res = detect.analyze(df)
    context = build_context(res, label or "uploaded data")
    tl = [(ts, sv, txt) for inc in res["incidents"] for ts, sv, txt in detect.timeline(inc)]
    tl.sort()
    ok, _ = llm.is_available()
    if ok:
        try:
            return {"answer": llm.chat_with_context(question, context), "timeline": tl, "llm_used": True,
                    "context": context}
        except llm.LLMError:
            pass
    return {"answer": "(Local LLM offline - showing the rule-based reconstruction)\n\n" + context,
            "timeline": tl, "llm_used": False, "context": context}

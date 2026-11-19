"""Ties analysis + local LLM + PDF + database together."""
import time
from datetime import datetime

import config
import db
import detect
import llm
import report


def create_report(df, label, kind, period=None, use_llm=True, save=True, max_llm_incidents=None):
    max_llm_incidents = config.LLM_MAX_INCIDENTS if max_llm_incidents is None else max_llm_incidents
    t0 = time.time()
    res = detect.analyze(df)
    stats, incidents = res["stats"], res["incidents"]
    llm_ok = use_llm and llm.is_available()[0]
    llm_used = False
    inc_summaries = {}
    for k, inc in enumerate(incidents[:15]):
        info = {"summary": llm.fallback_incident_summary(inc), "actions": []}
        if llm_ok and k < max_llm_incidents and time.time() - t0 < config.LLM_BUDGET:
            try:
                info = llm.summarize_incident(inc)
                llm_used = True
            except llm.LLMError:
                llm_ok = False  # LLM too slow/unavailable: stop trying, use rule-based text for the rest
        inc_summaries[inc["id"]] = info
    exec_summary = llm.fallback_exec_summary(stats, incidents)
    if llm_ok and incidents and time.time() - t0 < config.LLM_BUDGET:
        try:
            exec_summary = llm.executive_summary(stats, incidents)
            llm_used = True
        except llm.LLMError:
            pass
    period_txt = period or f"{stats['start']} to {stats['end']}"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = config.REPORT_DIR / f"logsentinel_{kind}_{stamp}.pdf"
    report.build_pdf(path, label, period_txt, stats, incidents, res["alerts"], exec_summary, inc_summaries, llm_used)
    rec = {"pdf_path": str(path), "summary": exec_summary, "analysis": res, "inc_summaries": inc_summaries,
           "llm_used": llm_used}
    if save:
        rec["id"] = db.save_report(label, kind, stats["start"] or datetime.now(), stats["end"] or datetime.now(),
                                   path, exec_summary, stats["events"], stats["n_alerts"], stats["n_incidents"])
    return rec

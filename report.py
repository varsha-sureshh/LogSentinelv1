"""PDF incident report (reportlab)."""
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

import detect

SEV_COLOR = {"critical": colors.HexColor("#b71c1c"), "high": colors.HexColor("#e65100"),
             "medium": colors.HexColor("#f9a825"), "low": colors.HexColor("#2e7d32")}
NAVY = colors.HexColor("#14213d")


def _t(s):
    """Make text safe for reportlab's built-in fonts."""
    return escape(str(s)).encode("latin-1", "replace").decode("latin-1")


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 10 * mm, "LogSentinel - AI-assisted log analysis  |  Confidential")
    canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(path, title, period, stats, incidents, alerts, exec_summary, inc_summaries, llm_used):
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=ss["Title"], textColor=NAVY, fontSize=22, spaceAfter=4)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], textColor=NAVY, spaceBefore=10)
    B = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9.5, leading=13)
    SM = ParagraphStyle("SM", parent=B, fontSize=8, leading=10)
    CODE = ParagraphStyle("CODE", parent=B, fontName="Courier", fontSize=7.5, leading=10,
                          backColor=colors.HexColor("#f1f3f5"), borderPadding=3)
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=18 * mm, title=title)
    S = []
    S += [Paragraph("LogSentinel Incident Report", H1), Paragraph(_t(title), B),
          Paragraph(f"Generated {datetime.now():%d %b %Y %H:%M} | Period: {_t(period)}", SM), Spacer(1, 8)]

    sev = stats["alerts_by_severity"]
    rows = [["Events analysed", stats["events"], "Incidents", stats["n_incidents"]],
            ["Alerts raised", stats["n_alerts"], "Critical / High", f"{sev['critical']} / {sev['high']}"],
            ["Medium / Low", f"{sev['medium']} / {sev['low']}", "AI summaries", "Local LLM" if llm_used else "Rule-based"]]
    t = Table(rows, colWidths=[40 * mm, 40 * mm, 40 * mm, 40 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey), ("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9ecef")),
                           ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#e9ecef")),
                           ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold")]))
    S += [t, Paragraph("Executive summary", H2), Paragraph(_t(exec_summary), B)]

    d = Drawing(400, 130)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.height, bc.width = 40, 25, 85, 320
    vals = [sev["critical"], sev["high"], sev["medium"], sev["low"]]
    bc.data = [vals]
    bc.categoryAxis.categoryNames = ["Critical", "High", "Medium", "Low"]
    bc.valueAxis.valueMin, bc.valueAxis.valueMax = 0, max(vals + [1]) + 1
    bc.valueAxis.valueStep = max(1, (max(vals + [1]) + 1) // 5)
    for i, k in enumerate(["critical", "high", "medium", "low"]):
        bc.bars[(0, i)].fillColor = SEV_COLOR[k]
    d.add(bc)
    S += [Paragraph("Alerts by severity", H2), d]

    if stats.get("top_failed_ips"):
        S += [Paragraph("Top sources of failed logins", H2)]
        tt = Table([["Source IP", "Failed logins"]] + [[ip, n] for ip, n in stats["top_failed_ips"].items()],
                   colWidths=[60 * mm, 40 * mm])
        tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey), ("FONTSIZE", (0, 0), (-1, -1), 9),
                                ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]))
        S += [tt]

    S += [Paragraph("Incidents", H2)]
    if not incidents:
        S += [Paragraph("No incidents were detected in this period.", B)]
    for inc in incidents[:15]:
        info = inc_summaries.get(inc["id"], {})
        head = Table([[Paragraph(f"<b>{_t(inc['id'])}</b> - {_t(inc['title'])}", B),
                       Paragraph(f"<font color='white'><b>{inc['severity'].upper()} | risk {inc['risk']}/100</b></font>", B)]],
                     colWidths=[125 * mm, 55 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (1, 0), (1, 0), SEV_COLOR[inc["severity"]]),
                                  ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#e9ecef")),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        block = [Spacer(1, 6), head,
                 Paragraph(f"<b>When:</b> {inc['start']} to {inc['end']} &nbsp; <b>Source:</b> {_t(inc['entity'])} "
                           f"&nbsp; <b>Accounts:</b> {_t(', '.join(inc['users']) or 'n/a')}", SM),
                 Paragraph(f"<b>Attack stages:</b> {_t(' > '.join(inc['stages']) or 'n/a')}", SM),
                 Paragraph(f"<b>MITRE ATT&amp;CK:</b> {_t('; '.join(inc['mitre']) or 'n/a')}", SM),
                 Spacer(1, 3), Paragraph(_t(info.get("summary", "")), B),
                 Paragraph("<b>Recommended actions</b>", B)]
        acts = info.get("actions") or []
        for a in detect.recommendations(inc) + acts:
            block.append(Paragraph("- " + _t(a), B))
        cmds = detect.block_commands(inc)
        if cmds:
            block.append(Paragraph("<b>Suggested block commands</b> (review before running)", B))
            for c in cmds[:6]:
                block.append(Paragraph(_t(c), CODE))
        tl = [["Time", "Severity", "Event"]] + [[ts, sv.upper(), Paragraph(_t(txt), SM)] for ts, sv, txt in detect.timeline(inc)[:25]]
        tab = Table(tl, colWidths=[35 * mm, 22 * mm, 123 * mm], repeatRows=1)
        tab.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey), ("FONTSIZE", (0, 0), (-1, -1), 8),
                                 ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                 ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        block += [Paragraph("<b>Timeline</b>", B), tab]
        S.append(KeepTogether(block[:6]))
        S += block[6:]

    S += [Paragraph("All alerts (most recent 60)", H2)]
    al = [["Time", "Sev.", "Rule", "Title"]] + [[a["ts"], a["severity"].upper(), a["rule"], Paragraph(_t(a["title"]), SM)]
                                              for a in sorted(alerts, key=lambda x: x["ts"], reverse=True)[:60]]
    at = Table(al, colWidths=[33 * mm, 18 * mm, 35 * mm, 94 * mm], repeatRows=1)
    at.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                            ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    S.append(at)
    doc.build(S, onFirstPage=_footer, onLaterPages=_footer)
    return path

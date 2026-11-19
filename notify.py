"""Email notifications (SMTP)."""
import smtplib
from email.message import EmailMessage
from pathlib import Path

import config


def configured():
    return bool(config.SMTP_USER and config.SMTP_PASS and config.ALERT_TO)


def send_email(subject, body, attachment=None):
    """Returns (ok, message)."""
    if not configured():
        return False, "Email is not configured (fill SMTP_USER, SMTP_PASS, ALERT_TO in .env)."
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = config.SMTP_USER, config.ALERT_TO, subject
    msg.set_content(body)
    if attachment and Path(attachment).exists():
        msg.add_attachment(Path(attachment).read_bytes(), maintype="application", subtype="pdf",
                           filename=Path(attachment).name)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=25) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        return True, f"Email sent to {config.ALERT_TO}"
    except Exception as e:
        return False, f"Email failed: {e}"


def alert_email(alerts):
    lines = [f"LogSentinel detected {len(alerts)} new high-priority alert(s):", ""]
    for a in alerts[:15]:
        lines.append(f"[{a['severity'].upper()}] {a['ts']}  {a['title']}")
        lines.append(f"    {a['detail']}")
        if a.get("mitre"):
            lines.append(f"    MITRE: {a['mitre']}")
        lines.append("")
    lines.append("Open the LogSentinel dashboard for the full timeline and recommended actions.")
    top = max(alerts, key=lambda a: {"critical": 4, "high": 3}.get(a["severity"], 0))
    return send_email(f"[LogSentinel] {top['severity'].upper()}: {top['title'][:80]}", "\n".join(lines))

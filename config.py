"""Central configuration. Every value can be overridden from the .env file."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
SAMPLE_DIR = BASE_DIR / "sample_logs"
for _d in (DATA_DIR, REPORT_DIR, SAMPLE_DIR):
    _d.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "logsentinel.db"
LEARNED_FORMATS_PATH = DATA_DIR / "learned_formats.json"


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


# Local LLM
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

# Email
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = _int("SMTP_PORT", 587)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
ALERT_TO = os.getenv("ALERT_TO", "")
EMAIL_DAILY_REPORT = os.getenv("EMAIL_DAILY_REPORT", "true").lower() == "true"

# Live ingestion / schedule
SYSLOG_PORT = _int("SYSLOG_PORT", 5514)
REPORT_TIME = os.getenv("REPORT_TIME", "23:59")

# Detection thresholds
BRUTE_THRESHOLD = _int("BRUTE_THRESHOLD", 10)
BRUTE_WINDOW_SEC = _int("BRUTE_WINDOW_SEC", 60)
PORTSCAN_PORTS = _int("PORTSCAN_PORTS", 15)
ODD_HOUR_START = _int("ODD_HOUR_START", 0)
ODD_HOUR_END = _int("ODD_HOUR_END", 5)
EXFIL_BYTES = _int("EXFIL_MB", 100) * 1024 * 1024

# LLM speed limits (seconds). The whole report never waits longer than LLM_BUDGET for AI text.
LLM_TIMEOUT = _int("LLM_TIMEOUT", 60)
LLM_BUDGET = _int("LLM_BUDGET", 90)
LLM_MAX_INCIDENTS = _int("LLM_MAX_INCIDENTS", 2)

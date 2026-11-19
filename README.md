# LogSentinel

AI-assisted log analysis: live monitoring + upload mode, rule/ML/correlation detection, local-LLM summaries,
email + dashboard alerts, automatic daily PDF report (23:59).

## 1. One-time setup (Windows)

Python 3.15 is too new for scikit-learn / pandas wheels, so install 3.12 next to it:

```powershell
winget install Python.Python.3.12
cd path\to\logsentinel
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Local LLM (offline after the one-time download):

1. Install Ollama from https://ollama.com
2. `ollama pull llama3.2:3b`   (fast; for better summaries later: `ollama pull llama3.1:8b` and change OLLAMA_MODEL in .env)

Email alerts:

1. `copy .env.example .env`
2. Gmail account -> turn on 2-Step Verification -> create an **App password**
3. Put the sender address and app password in `.env` (SMTP_USER / SMTP_PASS). Never share this file.

## 2. Run

Open **VS Code / terminal as Administrator** (needed to read the Windows Security log):

```powershell
.venv\Scripts\activate
python smoke_test.py          # optional self-test, no Ollama needed
streamlit run app.py
```

## 3. Using it

| Page | What it does |
|---|---|
| Live Monitor | Start/stop live ingestion (Windows Event Log + syslog UDP listener), live alert feed, email on high/critical |
| Upload & Analyze | Upload any log file(s) -> detection -> incidents -> PDF report. "Load demo attack-day log" gives sample data |
| Incidents & Timeline | Correlated incidents for any day, MITRE tags, recommended fixes, block commands |
| Ask LogSentinel | "What happened on the server last night?" - local LLM over the detected incidents |
| Reports | Daily reports (auto at REPORT_TIME) and "generate now" |
| Settings & Status | LLM / email / admin checks, test email |

**Demo tip:** Live Monitor -> Start -> "Simulate attack". Within ~10 seconds you get alerts, a critical
"account compromise" incident, and an email. Then Reports -> Generate today's report now.

## 4. Live syslog from other devices

Point a router / Linux server at `<your laptop IP>` UDP port 5514 (`SYSLOG_PORT` in .env).
Linux example (rsyslog): `*.* @<laptop-ip>:5514`. Allow the port in Windows Firewall.

## 5. Automatic daily report

The report is generated at REPORT_TIME (default 23:59) **while the app is running and the laptop is awake**.
For permanent deployment run the app as a Windows service / start it with Task Scheduler at boot.

## How detection works

* **Rules:** brute force, password spraying, success-after-failures, off-hours login, impossible travel (heuristic),
  port scan, web scan/brute force, large transfers, account creation, privilege changes, audit-log clearing.
* **ML:** Isolation Forest over hourly per-source behaviour (needs about 30+ source-hours of data).
* **Correlation:** alerts from the same source close in time become one incident (e.g. failed logins -> success ->
  new account -> big download = "Account compromise").
* **Parsing:** fast regex parsers (SSH/auth.log, syslog, Apache/Nginx, UFW/iptables, Windows firewall, Windows
  XML/CSV, JSON, CSV). Unknown formats -> the local LLM writes a parser once, validates it, and caches it
  in `data/learned_formats.json`.

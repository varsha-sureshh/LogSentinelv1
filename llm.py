"""Local LLM access through Ollama (fully offline). Every function degrades gracefully if Ollama is down."""
import json
import re
import urllib.error
import urllib.request

import config


class LLMError(Exception):
    pass


def is_available(timeout=2.0):
    """Returns (ok, message)."""
    try:
        with urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=timeout) as r:
            names = [m.get("name", "") for m in json.load(r).get("models", [])]
    except Exception:
        return False, "Ollama is not running (start it, then run: ollama pull " + config.OLLAMA_MODEL + ")"
    wanted = config.OLLAMA_MODEL
    if wanted not in names and (":" in wanted or wanted + ":latest" not in names):
        return False, f"Model '{wanted}' not found. Run: ollama pull {wanted}"
    return True, f"Ollama OK - model {wanted}"


def generate(prompt, system="", max_tokens=350, temperature=0.2, timeout=config.LLM_TIMEOUT):
    body = json.dumps({
        "model": config.OLLAMA_MODEL, "prompt": prompt, "system": system, "stream": False, "keep_alive": "30m",
        "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": 4096},
    }).encode()
    req = urllib.request.Request(config.OLLAMA_URL + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r).get("response", "").strip()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise LLMError(str(e))


SYSTEM = ("You are LogSentinel, a security analyst assistant for a college IT team. "
          "Use ONLY the facts provided. Never invent IPs, users or times. Be concise and clear.")


# ---------- rule-based fallbacks (used when the LLM is offline) ----------
def fallback_incident_summary(inc):
    rules = ", ".join(sorted(set(inc["rules"])))
    return (f"Between {inc['start']} and {inc['end']}, {len(inc['alerts'])} related alert(s) were raised "
            f"involving {inc['entity']}. Detections: {rules}. Severity: {inc['severity'].upper()} "
            f"(risk score {inc['risk']}/100). Stages observed: {' -> '.join(inc['stages']) or 'n/a'}.")


def fallback_exec_summary(stats, incidents):
    sev = stats.get("alerts_by_severity", {})
    top = incidents[0]["title"] if incidents else "none"
    return (f"{stats.get('events', 0)} events were analysed, producing {stats.get('n_alerts', 0)} alert(s) "
            f"({sev.get('critical', 0)} critical, {sev.get('high', 0)} high, {sev.get('medium', 0)} medium) "
            f"grouped into {len(incidents)} incident(s). Highest-risk incident: {top}.")


# ---------- LLM features ----------
def summarize_incident(inc):
    lines = "\n".join(f"- {a['ts']} [{a['severity']}] {a['title']} :: {a['detail']}" for a in inc["alerts"][:12])
    prompt = (f"Incident: {inc['title']} (severity {inc['severity']}, risk {inc['risk']}/100)\n"
              f"Entities: {inc['entity']} | Period: {inc['start']} to {inc['end']}\n"
              f"MITRE ATT&CK: {', '.join(inc['mitre'])}\nAlerts:\n{lines}\n\n"
              "Write 3-4 plain-English sentences for a non-technical admin: what happened, how it likely "
              "happened and the potential impact. Then on a new line write 'FIX:' followed by 2-3 short "
              "recommended fixes separated by semicolons.")
    text = generate(prompt, SYSTEM, max_tokens=300)
    summary, _, fix = text.partition("FIX:")
    actions = [a.strip(" -*") for a in re.split(r";|\n", fix) if a.strip(" -*")]
    return {"summary": summary.strip() or fallback_incident_summary(inc), "actions": actions[:4]}


def executive_summary(stats, incidents):
    inc_lines = "\n".join(f"- {i['title']} (risk {i['risk']}, {i['severity']}, {i['start']} to {i['end']})"
                          for i in incidents[:6]) or "- none"
    prompt = (f"Period: {stats.get('start', '?')} to {stats.get('end', '?')}. Events analysed: {stats.get('events', 0)}. "
              f"Alerts by severity: {stats.get('alerts_by_severity')}. Incidents:\n{inc_lines}\n\n"
              "Write a 3-sentence executive summary of the security posture for the day.")
    return generate(prompt, SYSTEM, max_tokens=200)


def chat_with_context(question, context):
    prompt = f"Log analysis context:\n{context}\n\nQuestion: {question}\n\nAnswer using only the context above."
    return generate(prompt, SYSTEM, max_tokens=400)


def learn_format(samples):
    """Ask the LLM to write a regex for an unknown log format. Returns a dict or None."""
    joined = "\n".join(s[:300] for s in samples)
    prompt = ("Below are sample lines from an unknown log format.\n" + joined + "\n\n"
              "Return ONLY a JSON object with keys: \"regex\" (a Python regex with NAMED groups: ts, and where "
              "present ip, user), and \"ts_format\" (a Python strptime format for the ts group, e.g. "
              "\"%Y-%m-%d %H:%M:%S\"). No explanation, no markdown.")
    text = generate(prompt, "You output only valid JSON.", max_tokens=250, temperature=0.0)
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        spec = json.loads(m.group(0))
        return spec if "regex" in spec else None
    except json.JSONDecodeError:
        return None

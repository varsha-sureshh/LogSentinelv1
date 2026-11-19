"""Quick self-test: python smoke_test.py  (no Ollama / internet / admin rights needed)."""
import config
import db
import detect
import parsers
import simulator
from datetime import datetime

db.init()
path = simulator.write_sample()
text = open(path).read()
rows, stats = parsers.parse_text(text, "upload:demo", "demo.log", allow_learning=False)
print("parsed", len(rows), "of", stats["lines"], "lines; tiers:", dict(stats["tiers"]))
df = db.to_df(rows)
res = detect.analyze(df)
print("alerts:", len(res["alerts"]), "incidents:", len(res["incidents"]))
for inc in res["incidents"]:
    print(f"  [{inc['severity'].upper():8}] risk {inc['risk']:3} {inc['id']} {inc['title']} ({inc['entity']}) rules={inc['rules']}")
import reporting
rec = reporting.create_report(df, "Smoke test", "test", use_llm=False, save=False)
print("PDF written:", rec["pdf_path"])

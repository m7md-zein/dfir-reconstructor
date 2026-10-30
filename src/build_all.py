import json
import sys
from pathlib import Path

import pandas as pd

from sysmon_parser import read_events, sha256_file
from normalizer import normalize_event
from validator import validate_event
from entities import build_process_table
from entities_other import build_other_entities
from relations import build_relations

src = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

files = [src] if src.is_file() else sorted(src.rglob("*.evtx"))

events, rejects, manifest = [], [], []

for path in files:
    stats = {}
    valid = 0
    for raw in read_events(str(path), stats):
        ev = normalize_event(raw, str(path))
        if ev is None:
            continue
        problems = validate_event(ev)
        if problems:
            rejects.append({"problems": problems, "event": ev})
            continue
        events.append(ev)
        valid += 1
    if valid or stats["bad"]:
        manifest.append({
            "file": path.name, "sha256": sha256_file(str(path)),
            "records": stats["total"], "bad_records": stats["bad"],
            "valid_events": valid,
        })

events.sort(key=lambda e: e["timestamp_utc"])


def write_jsonl(name, rows):
    with open(out / name, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_json(name, obj):
    with open(out / name, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


write_jsonl("events.jsonl", events)
write_jsonl("relations.jsonl", build_relations(events))
write_jsonl("rejects.jsonl", rejects)
write_json("processes.json", list(build_process_table(events).values()))
write_json("entities_other.json", build_other_entities(events))
write_json("manifest.json", manifest)

df = pd.DataFrame(events)
df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True, format="ISO8601")
df["extra"] = df["extra"].apply(lambda x: json.dumps(x) if x else None)
df = df.convert_dtypes()
df.to_parquet(out / "events.parquet", index=False)

print(f"files: {len(manifest)} | events: {len(events)} | rejected: {len(rejects)}")
print("output folder:", out.resolve())
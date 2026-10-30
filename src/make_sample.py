import json
import os
from collections import defaultdict
from entities import build_process_table
from relations import build_relations

LIMITS = {
    "process_create": 11, "registry_set": 5, "file_create": 4,
    "network_connect": 4, "process_access": 1,
}

with open("output/events.jsonl", encoding="utf-8") as f:
    events = [json.loads(line) for line in f]

taken = defaultdict(int)
sample = []
for e in events:
    t = e["event_type"]
    if taken[t] < LIMITS.get(t, 0):
        sample.append(e)
        taken[t] += 1

sample.sort(key=lambda e: e["timestamp_utc"])

os.makedirs("sample", exist_ok=True)

with open("sample/events.jsonl", "w", encoding="utf-8") as f:
    for e in sample:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")

with open("sample/relations.jsonl", "w", encoding="utf-8") as f:
    for r in build_relations(sample):
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

with open("sample/processes.json", "w", encoding="utf-8") as f:
    json.dump(list(build_process_table(sample).values()), f, indent=2, ensure_ascii=False)

print("sample events:", len(sample))
print(dict(taken))
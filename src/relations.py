import json
import sys
from collections import Counter


def build_relations(events):
    rels = []
    for e in events:
        t = e["event_type"]
        if t == "process_create":
            src, rel, dst = e["parent_guid"], "spawned", e["process_guid"]
        elif t == "process_access":
            src, rel, dst = e["process_guid"], "accessed", e["target"]
        elif t == "network_connect":
            src, rel, dst = e["process_guid"], "connected_to", f'{e["dst_ip"]}:{e["dst_port"]}'
        elif t == "file_create":
            src, rel, dst = e["process_guid"], "created_file", e["target"]
        elif t == "registry_set":
            src, rel, dst = e["process_guid"], "set_registry", e["target"]
        else:
            continue
        rels.append({
            "source": src, "relation": rel, "target": dst,
            "timestamp_utc": e["timestamp_utc"], "raw_ref": e["raw_ref"],
        })
    return rels


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        events = [json.loads(line) for line in f]

    rels = build_relations(events)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        for r in rels:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("relations:", len(rels))
    for rel, n in Counter(r["relation"] for r in rels).most_common():
        print(" ", rel, n)
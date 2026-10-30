import sys
import traceback
from collections import Counter
from pathlib import Path

from sysmon_parser import read_events
from normalizer import normalize_event
from validator import validate_event
from entities import build_process_table
from entities_other import build_other_entities

root_dir = Path(sys.argv[1])

files = events_total = 0
rejects = Counter()
errors = Counter()
error_examples = {}

for path in sorted(root_dir.rglob("*.evtx")):
    stats = {}
    events = []
    try:
        for raw in read_events(str(path), stats):
            try:
                ev = normalize_event(raw, str(path))
            except Exception as exc:
                key = f"normalize: {type(exc).__name__}: {exc}"
                errors[key] += 1
                error_examples.setdefault(key, path.name)
                continue
            if ev is None:
                continue
            problems = validate_event(ev)
            if problems:
                for p in problems:
                    rejects[p] += 1
                continue
            events.append(ev)
    except Exception as exc:
        errors[f"open: {type(exc).__name__}"] += 1
        error_examples.setdefault(f"open: {type(exc).__name__}", path.name)
        continue

    if not events:
        continue

    files += 1
    events_total += len(events)

    for label, fn in (("entities", build_process_table),
                      ("entities_other", build_other_entities)):
        try:
            fn(events)
        except Exception as exc:
            key = f"{label}: {type(exc).__name__}: {exc}"
            errors[key] += 1
            error_examples.setdefault(key, path.name)

print(f"files with supported events: {files} | valid events: {events_total}")
print("\nrejection reasons:")
for k, n in rejects.most_common():
    print(" ", n, k)
print("\nerrors:")
for k, n in errors.most_common():
    print(" ", n, k, "| example file:", error_examples[k])
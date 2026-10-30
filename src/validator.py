import re
from datetime import datetime

GUID_RE = re.compile(r"^\{[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$")

COMMON = ["timestamp_utc", "host", "event_id", "event_type", "raw_ref", "source"]

REQUIRED = {
    "process_create": ["process_guid", "process_name", "parent_guid"],
    "process_access": ["process_guid", "target"],
    "network_connect": ["process_guid", "dst_ip", "dst_port"],
    "file_create": ["process_guid", "target"],
    "registry_set": ["process_guid", "target"],
}


def validate_event(ev):
    """Return a list of problems. Empty list = valid."""
    problems = []

    for field in COMMON:
        if ev.get(field) in (None, ""):
            problems.append(f"missing {field}")

    for field in REQUIRED.get(ev.get("event_type"), []):
        if ev.get(field) in (None, ""):
            problems.append(f"missing {field}")

    ts = ev.get("timestamp_utc")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            if dt.utcoffset() is None or dt.utcoffset().total_seconds() != 0:
                problems.append("timestamp is not UTC")
        except ValueError:
            problems.append("timestamp not parseable")

    guid_fields = ["process_guid", "parent_guid"]
    if ev.get("event_type") == "process_access":
        guid_fields.append("target")
    for field in guid_fields:
        value = ev.get(field)
        if value and not GUID_RE.match(value):
            problems.append(f"bad guid format in {field}")

    return problems
import os
from datetime import datetime, timezone

SCHEMA_FIELDS = [
    "timestamp_utc", "host", "event_id", "event_type",
    "user", "logon_id",
    "process_guid", "process_name", "pid", "cmdline",
    "parent_guid", "parent_name", "parent_cmdline",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "target", "raw_ref", "source", "extra",
]


def _to_utc_iso(value):
    """Sysmon UtcTime ('2020-10-05 20:43:58.350') -> ISO 8601 UTC."""
    dt = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec="microseconds")


def _norm_logon_id(value):
    """'0x000000000391e334' -> '0x391e334'"""
    if not value:
        return None
    return f"0x{int(value, 16):x}"


def _int_or_none(value):
    return int(value) if value else None


def normalize_event(raw, source_file):
    """Convert one raw event dict to the unified schema. Returns None if unsupported."""
    d = raw["data"]
    event_id = raw["event_id"]

    base = {field: None for field in SCHEMA_FIELDS}
    base.update({
        "timestamp_utc": _to_utc_iso(d["UtcTime"]),
        "host": raw["computer"],
        "event_id": event_id,
        "raw_ref": f"{os.path.basename(source_file)}#{raw['record_id']}",
        "source": "sysmon",
    })

    if event_id == 1:
        base.update({
            "event_type": "process_create",
            "user": d.get("User"),
            "logon_id": _norm_logon_id(d.get("LogonId")),
            "process_guid": d.get("ProcessGuid"),
            "process_name": d.get("Image"),
            "pid": _int_or_none(d.get("ProcessId")),
            "cmdline": d.get("CommandLine"),
            "parent_guid": d.get("ParentProcessGuid"),
            "parent_name": d.get("ParentImage"),
            "parent_cmdline": d.get("ParentCommandLine"),
            "extra": {
                "hashes": d.get("Hashes"),
                "integrity_level": d.get("IntegrityLevel"),
            },
        })
    elif event_id == 10:
        base.update({
            "event_type": "process_access",
            "process_guid": d.get("SourceProcessGUID"),
            "process_name": d.get("SourceImage"),
            "pid": _int_or_none(d.get("SourceProcessId")),
            "target": d.get("TargetProcessGUID"),
            "extra": {
                "target_image": d.get("TargetImage"),
                "target_pid": _int_or_none(d.get("TargetProcessId")),
                "granted_access": d.get("GrantedAccess"),
            },
        })
    elif event_id == 3:
        base.update({
            "event_type": "network_connect",
            "user": d.get("User"),
            "process_guid": d.get("ProcessGuid"),
            "process_name": d.get("Image"),
            "pid": _int_or_none(d.get("ProcessId")),
            "src_ip": d.get("SourceIp"),
            "src_port": _int_or_none(d.get("SourcePort")),
            "dst_ip": d.get("DestinationIp"),
            "dst_port": _int_or_none(d.get("DestinationPort")),
            "extra": {
                "protocol": d.get("Protocol"),
                "initiated": d.get("Initiated"),
                "dst_hostname": d.get("DestinationHostname"),
                "rule_name": d.get("RuleName"),
            },
        })
    elif event_id == 11:
        base.update({
            "event_type": "file_create",
            "process_guid": d.get("ProcessGuid"),
            "process_name": d.get("Image"),
            "pid": _int_or_none(d.get("ProcessId")),
            "target": d.get("TargetFilename"),
        })
    elif event_id == 13:
        base.update({
            "event_type": "registry_set",
            "process_guid": d.get("ProcessGuid"),
            "process_name": d.get("Image"),
            "pid": _int_or_none(d.get("ProcessId")),
            "target": d.get("TargetObject"),
            "extra": {
                "details": d.get("Details"),
                "registry_event": d.get("EventType"),
            },
        })
    else:
        return None

    return base
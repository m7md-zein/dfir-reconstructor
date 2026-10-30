from normalizer import normalize_event
from entities import build_process_table

RAW_CREATE = {
    "event_id": 1, "record_id": 100,
    "system_time": "2020-10-05 20:43:58.450239+00:00",
    "computer": "HOST1",
    "data": {
        "UtcTime": "2020-10-05 20:43:58.449",
        "ProcessGuid": "{AAA}", "ProcessId": "10",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe",
        "User": "HOST1\\bob", "LogonId": "0x000000000391e334",
        "ParentProcessGuid": "{BBB}",
        "ParentImage": "C:\\x\\parent.exe", "ParentCommandLine": "parent.exe",
        "Hashes": "SHA256=abc", "IntegrityLevel": "High",
    },
}


def test_process_create_fields():
    ev = normalize_event(RAW_CREATE, "D:\\x\\file.evtx")
    assert ev["event_type"] == "process_create"
    assert ev["timestamp_utc"] == "2020-10-05T20:43:58.449000+00:00"
    assert ev["logon_id"] == "0x391e334"
    assert ev["raw_ref"] == "file.evtx#100"
    assert ev["parent_guid"] == "{BBB}"


def test_unsupported_event_returns_none():
    raw = dict(RAW_CREATE, event_id=99)
    assert normalize_event(raw, "f.evtx") is None


def test_missing_optional_field_is_none():
    raw = {**RAW_CREATE, "data": {k: v for k, v in RAW_CREATE["data"].items()
                                   if k != "CommandLine"}}
    ev = normalize_event(raw, "f.evtx")
    assert ev["cmdline"] is None


def test_parent_becomes_placeholder_process():
    ev = normalize_event(RAW_CREATE, "f.evtx")
    procs = build_process_table([ev])
    assert procs["{AAA}"]["has_create_event"] is True
    assert procs["{BBB}"]["has_create_event"] is False
    assert procs["{AAA}"]["parent_guid"] == "{BBB}"

from entities import split_user

RAW_ACCESS = {
    "event_id": 10, "record_id": 99,
    "system_time": "2020-10-05 20:43:58.000+00:00", "computer": "HOST1",
    "data": {
        "UtcTime": "2020-10-05 20:43:58.000",
        "SourceProcessGUID": "{CCC}", "SourceProcessId": "5",
        "SourceImage": "C:\\x\\src.exe",
        "TargetProcessGUID": "{AAA}", "TargetProcessId": "10",
        "TargetImage": "C:\\x\\wrong.exe", "GrantedAccess": "0x1410",
    },
}


def test_split_user():
    assert split_user("HOST1\\bob") == ("HOST1", "bob")
    assert split_user("bob") == (None, "bob")
    assert split_user(None) == (None, None)


def test_conflict_recorded_when_access_comes_before_create():
    access = normalize_event(RAW_ACCESS, "f.evtx")
    create = normalize_event(RAW_CREATE, "f.evtx")
    procs = build_process_table([access, create])
    p = procs["{AAA}"]
    assert p["name"].endswith("cmd.exe")
    assert "C:\\x\\wrong.exe" in p["name_conflicts"]
    assert p["user_name"] == "bob"

from entities_other import build_other_entities


def test_session_user_host_entities():
    ev = normalize_event(RAW_CREATE, "f.evtx")
    ents = build_other_entities([ev])
    assert ents["hosts"][0]["host"] == "HOST1"
    assert ents["users"][0]["name"] == "bob"
    assert ents["sessions"][0]["session_id"] == "HOST1|0x391e334"
    assert ents["sessions"][0]["process_count"] == 1

from validator import validate_event


def test_valid_event_has_no_problems():
    ev = normalize_event(RAW_CREATE, "f.evtx")
    ev["process_guid"] = "{00247c92-858e-5f7b-0000-00105241202b}"
    ev["parent_guid"] = "{00247c92-858e-5f7b-0000-00106b29202b}"
    assert validate_event(ev) == []


def test_missing_required_field_is_reported():
    ev = normalize_event(RAW_CREATE, "f.evtx")
    ev["process_guid"] = "{00247c92-858e-5f7b-0000-00105241202b}"
    ev["parent_guid"] = None
    assert "missing parent_guid" in validate_event(ev)


def test_bad_guid_is_reported():
    ev = normalize_event(RAW_CREATE, "f.evtx")  # "{AAA}" is not a real GUID
    assert "bad guid format in process_guid" in validate_event(ev)

from normalizer import _to_utc_iso


def test_timestamp_format_is_always_same_length():
    a = _to_utc_iso("2020-10-05 20:43:58.000")
    b = _to_utc_iso("2020-10-05 20:43:58.350")
    assert len(a) == len(b)
    assert a == "2020-10-05T20:43:58.000000+00:00"
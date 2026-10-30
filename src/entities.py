import json
import sys


def split_user(user):
    """'DOMAIN\\user' -> ('DOMAIN', 'user'). No domain -> (None, user)."""
    if not user:
        return None, None
    if "\\" in user:
        domain, name = user.split("\\", 1)
        return domain, name
    return None, user


def _new_process(guid):
    return {
        "process_guid": guid, "name": None, "pid": None, "cmdline": None,
        "user": None, "user_domain": None, "user_name": None, "logon_id": None,
        "parent_guid": None, "host": None,
        "created_at": None, "create_ref": None,
        "has_create_event": False, "name_conflicts": [], "refs": [],
    }


def _add_conflict(proc, name):
    if name not in proc["name_conflicts"]:
        proc["name_conflicts"].append(name)


def _set_user(proc, user):
    if user and proc["user"] is None:
        proc["user"] = user
        proc["user_domain"], proc["user_name"] = split_user(user)


def _fill(proc, **fields):
    """Fill empty fields only; record a conflict if the name differs."""
    for key, value in fields.items():
        if value is None:
            continue
        if proc[key] is None:
            proc[key] = value
        elif key == "name" and proc[key].lower() != value.lower():
            _add_conflict(proc, value)


def build_process_table(events):
    procs = {}

    def get(guid):
        if guid not in procs:
            procs[guid] = _new_process(guid)
        return procs[guid]

    for ev in events:
        if ev["event_type"] == "process_create":
            p = get(ev["process_guid"])
            old_name = p["name"]

            # a create event is the authoritative source for these fields
            p.update(
                name=ev["process_name"], pid=ev["pid"], cmdline=ev["cmdline"],
                logon_id=ev["logon_id"], parent_guid=ev["parent_guid"],
                host=ev["host"], created_at=ev["timestamp_utc"],
                create_ref=ev["raw_ref"], has_create_event=True,
            )
            p["user"] = None
            _set_user(p, ev["user"])

            # name learned earlier from another event but different -> keep as conflict
            if old_name and old_name.lower() != ev["process_name"].lower():
                _add_conflict(p, old_name)

            p["refs"].append(ev["raw_ref"])

            parent = get(ev["parent_guid"])
            _fill(parent, name=ev["parent_name"], cmdline=ev["parent_cmdline"],
                  host=ev["host"])

        elif ev["event_type"] == "process_access":
            src = get(ev["process_guid"])
            _fill(src, name=ev["process_name"], pid=ev["pid"], host=ev["host"])
            src["refs"].append(ev["raw_ref"])

            tgt = get(ev["target"])
            _fill(tgt, name=ev["extra"]["target_image"],
                  pid=ev["extra"]["target_pid"], host=ev["host"])
            tgt["refs"].append(ev["raw_ref"])

        elif ev["event_type"] in ("file_create", "registry_set", "network_connect"):
            p = get(ev["process_guid"])
            _fill(p, name=ev["process_name"], pid=ev["pid"], host=ev["host"])
            _set_user(p, ev["user"])
            p["refs"].append(ev["raw_ref"])

    return procs


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        events = [json.loads(line) for line in f]

    procs = build_process_table(events)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(list(procs.values()), f, indent=2, ensure_ascii=False)

    base = lambda s: s.split("\\")[-1] if s else None
    for p in procs.values():
        parent = procs.get(p["parent_guid"])
        print(
            base(p["name"]), "| pid", p["pid"], "| user", p["user"],
            "| parent", base(parent["name"]) if parent else None,
            "| created:", p["has_create_event"],
            "| conflicts:", [base(c) for c in p["name_conflicts"]],
        )
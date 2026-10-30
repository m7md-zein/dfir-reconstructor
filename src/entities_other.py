import json
import sys
from datetime import datetime

from entities import split_user


def _touch(entity, ts):
    t = datetime.fromisoformat(ts)
    if entity["first_seen"] is None or t < datetime.fromisoformat(entity["first_seen"]):
        entity["first_seen"] = ts
    if entity["last_seen"] is None or t > datetime.fromisoformat(entity["last_seen"]):
        entity["last_seen"] = ts


def build_other_entities(events):
    hosts, users, sessions, ips = {}, {}, {}, {}

    def get(table, key, **init):
        if key not in table:
            table[key] = {"first_seen": None, "last_seen": None, **init}
        return table[key]

    for ev in events:
        ts = ev["timestamp_utc"]

        h = get(hosts, ev["host"], host=ev["host"], event_count=0)
        h["event_count"] += 1
        _touch(h, ts)

        if ev["event_type"] == "process_create":
            u = None
            if ev["user"]:
                domain, name = split_user(ev["user"])
                u = get(users, ev["user"], user=ev["user"], domain=domain,
                        name=name, hosts=set(), sessions=set())
                u["hosts"].add(ev["host"])
                _touch(u, ts)

            if ev["logon_id"]:
                skey = f'{ev["host"]}|{ev["logon_id"]}'
                s = get(sessions, skey, session_id=skey, host=ev["host"],
                        logon_id=ev["logon_id"], user=ev["user"], process_count=0)
                s["process_count"] += 1
                _touch(s, ts)
                if u:
                    u["sessions"].add(skey)

        elif ev["event_type"] == "network_connect":
            for ip, role in ((ev["src_ip"], "src"), (ev["dst_ip"], "dst")):
                if not ip:
                    continue
                i = get(ips, ip, ip=ip, seen_as_src=0, seen_as_dst=0,
                        ports=set(), processes=set(), hosts=set())
                i[f"seen_as_{role}"] += 1
                i["hosts"].add(ev["host"])
                i["processes"].add(ev["process_guid"])
                port = ev["dst_port"] if role == "dst" else ev["src_port"]
                if port is not None:
                    i["ports"].add(port)
                _touch(i, ts)

    def finalize(table):
        out = []
        for entity in table.values():
            for key, value in entity.items():
                if isinstance(value, set):
                    entity[key] = sorted(value)
            out.append(entity)
        return out

    return {
        "hosts": finalize(hosts), "users": finalize(users),
        "sessions": finalize(sessions), "ips": finalize(ips),
    }


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        events = [json.loads(line) for line in f]

    ents = build_other_entities(events)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(ents, f, indent=2, ensure_ascii=False)

    for name, rows in ents.items():
        print(name, len(rows))
    for s in ents["sessions"][:5]:
        print("session:", s["session_id"], "|", s["user"], "| processes:", s["process_count"])
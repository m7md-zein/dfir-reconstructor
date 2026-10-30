import hashlib
import logging
from xml.etree import ElementTree as ET
from Evtx.Evtx import Evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
log = logging.getLogger(__name__)


def sha256_file(path, chunk=1024 * 1024):
    """SHA-256 of the log file (chain of custody)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def read_events(path, stats=None):
    """Yield one raw dict per EVTX record. Bad records are counted, not fatal.

    stats: optional dict, filled with 'total' and 'bad' counters.
    """
    if stats is None:
        stats = {}
    stats.update(total=0, bad=0)

    with Evtx(path) as evtx:
        for record in evtx.records():
            stats["total"] += 1
            try:
                root = ET.fromstring(record.xml())
                system = root.find("e:System", NS)

                provider = system.find("e:Provider", NS).get("Name")
                if provider != "Microsoft-Windows-Sysmon":
                    continue

                data = {}
                for d in root.findall("e:EventData/e:Data", NS):
                    data[d.get("Name")] = d.text

                event = {
                    "event_id": int(system.find("e:EventID", NS).text),
                    "record_id": int(system.find("e:EventRecordID", NS).text),
                    "system_time": system.find("e:TimeCreated", NS).get("SystemTime"),
                    "computer": system.find("e:Computer", NS).text,
                    "data": data,
                }
            except Exception as exc:
                stats["bad"] += 1
                log.warning("bad record in %s: %s", path, exc)
                continue

            yield event
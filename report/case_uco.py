"""The case as CASE/UCO JSON-LD - the standard exchange format for digital
forensic results (CASE 1.x, https://caseontology.org).

The PS asks for standardized reporting and less dependence on
vendor-specific tools.  A CASE export is how another forensic tool reads
what this one found without parsing our own JSON: the evidence drive and
the recorder it came from, the hashes, every action in the custody ledger as
an InvestigativeAction with its tool and examiner, every extracted file with
its SHA-256, and - through DataRangeFacet - exactly which byte ranges of the
drive each recovered file came from.

Everything is taken from what the case already holds (scan report, device
record, custody ledger, extraction manifests); nothing is recomputed and
nothing new is claimed.  Identifiers are UUIDv5 from the case, so exporting
the same case twice gives the same graph.

Vocabulary checked against the CASE 1.5 documentation and the CASE example
"Owl Trafficking" (28 Sep 2026).  Stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Optional

CONTEXT = {
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-tool": "https://ontology.unifiedcyberontology.org/uco/tool/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}
HASH_NAMES = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256"}
MANIFESTS = (("carve/extracted.json", "carve/streams", "carved_streams_extracted"),
             ("carve/ps_extracted.json", "carve/ps_streams", "ps_streams_extracted"),
             ("carve/es_extracted.json", "carve/es_streams", "es_streams_extracted"))


def _load(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class _Graph:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.ns = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:ps26150:{case_id}")
        self.nodes: list[dict] = []

    def iri(self, kind: str, key: str) -> str:
        return f"kb:{kind}-{uuid.uuid5(self.ns, f'{kind}/{key}')}"

    def add(self, node: dict) -> dict:
        self.nodes.append(node)
        return node

    def facet(self, kind: str, key: str, **props) -> dict:
        return {"@id": self.iri(kind.split(":")[-1].lower(), key), "@type": kind, **props}

    def hashes(self, key: str, values: dict) -> list[dict]:
        return [{"@id": self.iri("hash", f"{key}/{a}"), "@type": "uco-types:Hash",
                 "uco-types:hashMethod": HASH_NAMES[a],
                 "uco-types:hashValue": {"@type": "xsd:hexBinary", "@value": v.upper()}}
                for a, v in sorted(values.items()) if a in HASH_NAMES and v]


def _time(ts: str) -> dict:
    return {"@type": "xsd:dateTime", "@value": ts}


def build(case_dir: str) -> dict:
    scan = _load(os.path.join(case_dir, "scan_report.json")) or {}
    info = scan.get("case") or {}
    case_id = info.get("case_id") or os.path.basename(os.path.normpath(case_dir))
    g = _Graph(case_id)
    kb = "urn:ps26150:" + re.sub(r"[^A-Za-z0-9._-]", "_", case_id) + ":"

    person = g.add({"@id": g.iri("person", info.get("investigator", "")),
                    "@type": "uco-identity:Person",
                    "uco-core:name": info.get("investigator") or "unknown examiner"})
    tool = g.add({"@id": g.iri("tool", "ps26150"), "@type": "uco-tool:Tool",
                  "uco-core:name": "ps26150-forensics",
                  "uco-tool:toolType": "DVR/NVR forensic acquisition and analysis",
                  "uco-tool:version": scan.get("tool_version") or "unknown"})

    # -- the evidence drive ---------------------------------------------------
    dev = scan.get("device") or {}
    full = {h["algorithm"]: h["value"] for h in scan.get("hashes", [])
            if h.get("scope") == "full_device" and h.get("length") == dev.get("size_bytes")}
    drive_facets = [g.facet("uco-observable:DeviceFacet", "drive",
                            **{k: v for k, v in (("uco-observable:model", dev.get("model")),
                                                 ("uco-observable:serialNumber", dev.get("serial")))
                               if v})]
    content = {"uco-observable:sizeInBytes": dev.get("size_bytes", 0)}
    if full:
        content["uco-observable:hash"] = g.hashes("drive", full)
    drive_facets.append(g.facet("uco-observable:ContentDataFacet", "drive", **content))
    drive = g.add({"@id": g.iri("device", "drive"), "@type": "uco-observable:Device",
                   "uco-core:name": f"evidence drive {dev.get('serial') or dev.get('path', '')}".strip(),
                   "uco-core:description":
                       f"acquired read-only ({dev.get('write_block_method', '')}) in one pass; "
                       f"SHA-256 block Merkle root {scan.get('merkle_root', '')}"
                       + ("" if full else "; no whole-drive hash (the pass was not complete)"),
                   "uco-core:hasFacet": drive_facets})
    exhibits = [drive["@id"]]

    # -- the recorder it came from, as the examiner read it ------------------
    rec = ((_load(os.path.join(case_dir, "device_record.json")) or {}).get("observations")
           or [None])[-1]
    if rec:
        facet = {"uco-observable:model": rec["model"]}
        if rec.get("serial"):
            facet["uco-observable:serialNumber"] = rec["serial"]
        vendor = (rec.get("identified") or {}).get("vendor")
        if vendor:
            org = g.add({"@id": g.iri("organization", vendor), "@type": "uco-identity:Organization",
                         "uco-core:name": vendor})
            facet["uco-observable:manufacturer"] = {"@id": org["@id"]}
        recorder = g.add({"@id": g.iri("device", "recorder"), "@type": "uco-observable:Device",
                          "uco-core:name": f"recorder {rec['model']}",
                          "uco-core:description": "as read off the unit by the examiner"
                                                  + (f" ({rec['read_from']})" if rec.get("read_from") else ""),
                          "uco-core:hasFacet": [g.facet("uco-observable:DeviceFacet", "recorder",
                                                        **facet)]})
        g.add({"@id": g.iri("relationship", "drive-in-recorder"),
               "@type": "uco-observable:ObservableRelationship",
               "uco-core:source": {"@id": drive["@id"]}, "uco-core:target": {"@id": recorder["@id"]},
               "uco-core:kindOfRelationship": "Contained_Within", "uco-core:isDirectional": True})
        exhibits.append(recorder["@id"])

    # -- files the case produced ---------------------------------------------
    produced: dict[str, list[str]] = {}
    for manifest, folder, action in MANIFESTS:
        m = _load(os.path.join(case_dir, manifest)) or {}
        for sid, v in sorted((m.get("streams") or {}).items()):
            files = v.get("files") or {v.get("file", sid): v}
            for name, f in sorted(files.items()):
                if not f.get("sha256"):
                    continue
                key = f"{folder}/{name}"
                node = g.add({"@id": g.iri("file", key), "@type": "uco-observable:File",
                              "uco-core:name": key,
                              "uco-core:hasFacet": [
                                  g.facet("uco-observable:FileFacet", key,
                                          **{"uco-observable:fileName": name,
                                             "uco-observable:extension": name.rsplit(".", 1)[-1],
                                             "uco-observable:sizeInBytes": f.get("bytes", 0)}),
                                  g.facet("uco-observable:ContentDataFacet", key,
                                          **{"uco-observable:hash": g.hashes(key, {"sha256": f["sha256"]})})]})
                ranges = [g.facet("uco-observable:DataRangeFacet", f"{key}/{k}",
                                  **{"uco-observable:rangeOffset": o,
                                     "uco-observable:rangeOffsetType": "image",
                                     "uco-observable:rangeSize": n})
                          for k, (o, n) in enumerate(v.get("extents") or [])]
                rel = {"@id": g.iri("relationship", key),
                       "@type": "uco-observable:ObservableRelationship",
                       "uco-core:source": {"@id": node["@id"]}, "uco-core:target": {"@id": drive["@id"]},
                       "uco-core:kindOfRelationship": "Contained_Within",
                       "uco-core:isDirectional": True}
                if ranges:
                    rel["uco-core:hasFacet"] = ranges
                g.add(rel)
                produced.setdefault(action, []).append(node["@id"])

    # -- the custody ledger, action by action ---------------------------------
    ledger_path = os.path.join(case_dir, "custody_ledger.jsonl")
    entries = []
    if os.path.exists(ledger_path):
        with open(ledger_path, "r", encoding="utf-8") as fh:
            entries = [json.loads(l) for l in fh if l.strip()]
    reports = []
    for e in entries:
        result = list(produced.pop(e["action"], []))
        if e["action"] == "report_generated":
            for kind in ("html", "json"):
                name, h = e["detail"].get(kind), e["detail"].get(f"{kind}_sha256")
                if name and h:
                    node = g.add({"@id": g.iri("file", f"report/{e['seq']}/{name}"),
                                  "@type": "uco-observable:File", "uco-core:name": name,
                                  "uco-core:hasFacet": [
                                      g.facet("uco-observable:FileFacet", f"report/{e['seq']}/{name}",
                                              **{"uco-observable:fileName": name}),
                                      g.facet("uco-observable:ContentDataFacet",
                                              f"report/{e['seq']}/{name}",
                                              **{"uco-observable:hash": g.hashes(
                                                  f"report/{e['seq']}/{name}", {"sha256": h})})]})
                    result.append(node["@id"])
                    reports.append(node["@id"])
        act = {"@id": g.iri("investigative-action", str(e["seq"])),
               "@type": "case-investigation:InvestigativeAction",
               "uco-core:name": e["action"],
               "uco-core:description": (f"custody ledger entry {e['seq']}; entry SHA-256 "
                                        f"{e['entry_hash']}; previous {e['prev_hash']}"
                                        + (f"; data SHA-256 {e['data_hash']}" if e.get("data_hash") else "")),
               "uco-action:startTime": _time(e["ts_utc"]), "uco-action:endTime": _time(e["ts_utc"]),
               "uco-action:performer": {"@id": person["@id"]},
               "uco-action:instrument": {"@id": tool["@id"]},
               "uco-action:object": [{"@id": drive["@id"]}]}
        if result:
            act["uco-action:result"] = [{"@id": r} for r in result]
        g.add(act)

    all_files = [n["@id"] for n in g.nodes if n["@type"] == "uco-observable:File"]
    g.add({"@id": g.iri("provenance-record", "drive"), "@type": "case-investigation:ProvenanceRecord",
           "case-investigation:exhibitNumber": f"{case_id}-D1",
           "uco-core:description": "the evidence drive as seized",
           "uco-core:object": [{"@id": drive["@id"]}]})
    if all_files:
        g.add({"@id": g.iri("provenance-record", "outputs"),
               "@type": "case-investigation:ProvenanceRecord",
               "case-investigation:exhibitNumber": f"{case_id}-O1",
               "uco-core:description": "files produced from the drive, each hashed and "
                                       "recorded in the custody ledger",
               "uco-core:object": [{"@id": i} for i in all_files]})
    g.add({"@id": g.iri("investigation", case_id), "@type": "case-investigation:Investigation",
           "uco-core:name": case_id,
           "case-investigation:focus": "DVR/NVR surveillance evidence",
           **({"uco-core:description": info["notes"]} if info.get("notes") else {}),
           "uco-core:object": [{"@id": i} for i in exhibits]})
    return {"@context": dict(CONTEXT, kb=kb), "@graph": g.nodes}

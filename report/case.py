"""One view of a case directory, for the report and the UI.

Everything here is READ from the files the pipeline wrote - scan report,
custody ledger, preserved-metadata manifest, parse report, carve report,
timeline.  Nothing is recomputed or re-derived, except the two checks that
must never be taken on trust: the custody chain and the preserved bundle are
re-verified every time a case is loaded.

The large lists (hundreds of thousands of extents, thousands of recordings)
are summarised, not copied: a report that embeds the whole platter index is
unreadable, and the full data stays in the files this view cites by hash.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from acquire.ledger import CustodyLedger
from core.hashing import sha256_file
from detect.signatures import PS_VENDORS

# What we can honestly say about each OEM the PS names.  `media` is real
# media the team holds; `parser` is the plugin that reads the platter.  The
# parser's status is the weakest evidence behind it - never better.
VENDOR_MATRIX = {
    "Hikvision": {
        "family": "Hikvision (HIKBTREE)", "parser": "Hikvision", "parser_status": "synthetic_only",
        "media": "second drive held - not yet read",
        "basis": "HIKBTREE layout from published analyses; field offsets corroborated only by "
                 "the synthetic fixture until the team's own drive is read"},
    "Dahua": {
        "family": "Dahua DHFS 4.1", "parser": "Dahua", "parser_status": "spec_only",
        "media": "CP Plus drive held (Dahua-family, DHFS 4.1)",
        "basis": "DHFS structures and DHAV frames read off real media and cross-checked "
                 "against ffmpeg's DHAV demuxer; not yet byte-matched to a recorder export"},
    "CP Plus": {
        "family": "Dahua-family (rebadged DHFS 4.1)", "parser": "Dahua", "parser_status": "spec_only",
        "media": "CP Plus drive held",
        "basis": "the CP Plus unit's platter carries Dahua DHFS 4.1; on disk the two are "
                 "indistinguishable, so attribution to CP Plus rests on the seized unit's label"},
    "Honeywell": {"family": "unknown", "parser": None, "parser_status": "detected_not_parsed",
                  "media": "none", "basis": "firmware/volume string signature only"},
    "TP-Link": {"family": "unknown", "parser": None, "parser_status": "detected_not_parsed",
                "media": "none", "basis": "firmware string signature only"},
    "Godrej": {"family": "unknown", "parser": None, "parser_status": "detected_not_parsed",
               "media": "none", "basis": "firmware string signature only"},
    "Uniview": {"family": "unknown", "parser": None, "parser_status": "detected_not_parsed",
                "media": "none", "basis": "firmware/volume string signature only"},
    "Matrix": {"family": "unknown", "parser": None, "parser_status": "detected_not_parsed",
               "media": "none", "basis": "firmware string signature only"},
}


def _load(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _hashed(path: str) -> Optional[str]:
    return sha256_file(path) if os.path.exists(path) else None


def vendor_matrix(detections: Optional[list[dict]] = None) -> list[dict]:
    """The eight PS vendors, with what this disk showed and what we can parse."""
    import parsers
    from detect import signatures as sig

    found = {d["vendor"]: d for d in (detections or [])}
    rows = []
    for v in PS_VENDORS:
        m = VENDOR_MATRIX.get(v, {})
        d = found.get(v)
        if v == "CP Plus" and not d and "Dahua" in found:
            d = dict(found["Dahua"], note="Dahua-family structures - consistent with CP Plus")
        rows.append({
            "vendor": v,
            "signatures": sum(1 for s in sig.ALL_SIGNATURES if s.vendor == v),
            "parser": m.get("parser") if m.get("parser") in parsers.available_vendors() else None,
            "parser_status": m.get("parser_status", "detected_not_parsed"),
            "family": m.get("family", "unknown"),
            "media": m.get("media", "none"),
            "basis": m.get("basis", ""),
            "detected_confidence": d["confidence"] if d else 0.0,
            "detected_note": (d or {}).get("note", ""),
        })
    return rows


def plugins_view() -> dict:
    import parsers
    return {"registered": sorted(parsers.available_vendors()),
            "dropped_in": parsers.LOADED_PLUGINS, "errors": parsers.PLUGIN_ERRORS,
            "plugin_dir": parsers.PLUGIN_DIR}


def load_case(case_dir: str, recordings_limit: int = 200) -> dict:
    j = lambda *p: os.path.join(case_dir, *p)
    scan = _load(j("scan_report.json"))
    state = _load(j("scan_state.json"))
    ledger = CustodyLedger(j("custody_ledger.jsonl"))
    verified = ledger.verify() if ledger.entries else {"valid": False, "message": "no ledger"}

    case: dict = {"id": os.path.basename(os.path.normpath(case_dir)), "dir": case_dir}
    first = ledger.entries[0] if ledger.entries else {}
    case["case_id"] = (scan or {}).get("case", {}).get("case_id") or first.get("case_id", "")
    case["scan"] = None
    if scan:
        case["scan"] = {k: scan.get(k) for k in ("case", "device", "hashes", "merkle_root",
                                                 "stats", "bad_regions", "detections",
                                                 "generated_utc", "tool", "tool_version")}
        case["scan"]["signature_hit_count"] = len(scan.get("signature_hits", []))
    elif state:
        size = state.get("identity", {}).get("size_bytes", 0)
        done = state.get("blocks_done", 0) * state.get("identity", {}).get("block_size", 0)
        case["in_progress"] = {"bytes_done": done, "size_bytes": size,
                               "updated_utc": state.get("updated_utc"),
                               "fraction": done / size if size else 0.0}
    case["custody"] = {"entries": ledger.entries, "verify": verified, "head": ledger.head}

    manifest = _load(j("preserved", "manifest.json"))
    if manifest:
        from recover.preserve import verify_bundle
        v = verify_bundle(j("preserved"))
        case["preserved"] = {"regions": manifest["regions"], "blocks": len(manifest["blocks"]),
                             "bytes_saved": manifest["bytes_saved"],
                             "all_blocks_match": manifest["all_blocks_match"],
                             "merkle_root": manifest["acquisition_merkle_root"],
                             "verify": v, "manifest_sha256": _hashed(j("preserved", "manifest.json"))}

    for name in ("parse_dahua.json", "parse_hikvision.json"):
        p = _load(j(name))
        if not p:
            continue
        recs = p.get("recordings", [])
        per_cam: dict[str, int] = {}
        for r in recs:
            per_cam[r["camera_id"]] = per_cam.get(r["camera_id"], 0) + 1
        case["parse"] = {"file": name, "sha256": _hashed(j(name)), "vendor": p.get("vendor"),
                         "validation_status": p.get("validation_status"),
                         "parser_rule": p.get("parser_rule"),
                         "summary": p.get("volume", {}).get("summary", []),
                         "volume_vendor": p.get("volume", {}).get("vendor"),
                         "recordings_total": len(recs), "per_camera": per_cam,
                         "recordings": recs[:recordings_limit],
                         "remnants_total": len(p.get("remnants", [])),
                         "remnants": p.get("remnants", [])[:recordings_limit],
                         "field_provenance": p.get("field_provenance", []),
                         "notes": p.get("notes", []), "errors": p.get("errors", [])}
        break

    carve = _load(j("carve", "carve_report.json"))
    if carve:
        rows = carve.get("streams", [])
        labels: dict[str, dict] = {}
        for r in rows:
            k = r.get("index_label") or "unlabelled"
            e = labels.setdefault(k, {"streams": 0, "frames": 0, "bytes": 0})
            e["streams"] += 1
            e["frames"] += r["recording"]["frame_count"]
            e["bytes"] += r["recording"]["length"]
        outside = [dict(r["recording"], index_tally=r.get("index_tally"))
                   for r in rows if r.get("index_label") == "outside_index"]
        case["carve"] = {"sha256": _hashed(j("carve", "carve_report.json")),
                         "tool": carve.get("tool"), "stats": carve.get("stats"),
                         "validation_status": carve.get("validation_status"),
                         "labels": labels, "outside_index": outside[:recordings_limit],
                         "outside_total": len(outside), "outputs": carve.get("outputs", {}),
                         "notes": carve.get("notes", [])}
        ex = _load(j("carve", "extracted.json"))
        if ex:
            case["carve"]["extracted"] = {
                "sha256": _hashed(j("carve", "extracted.json")),
                "streams": {k: {x: v[x] for x in ("label", "frames_written", "frames_carved",
                                                   "frames_match", "codec", "files")}
                            for k, v in ex.get("streams", {}).items()}}

    t = _load(j("timeline.json"))
    if t:
        case["timeline"] = {k: t.get(k) for k in ("clock", "cameras", "gaps", "correlations",
                                                  "anomalies", "counts", "notes", "inputs")}
        case["timeline"]["sha256"] = _hashed(j("timeline.json"))
        case["timeline"]["events"] = t.get("events", [])[:2000]

    case["vendors"] = vendor_matrix((scan or {}).get("detections"))
    case["files"] = {n: _hashed(j(n)) for n in ("scan_report.json", "blockmap.jsonl",
                                                "custody_ledger.jsonl")
                     if os.path.exists(j(n))}
    return case


def list_cases(root: str) -> list[dict]:
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if not os.path.isdir(d) or not os.path.exists(os.path.join(d, "custody_ledger.jsonl")):
            continue
        scan = _load(os.path.join(d, "scan_report.json")) or {}
        state = _load(os.path.join(d, "scan_state.json")) or {}
        ident = state.get("identity", {})
        done = state.get("blocks_done", 0) * ident.get("block_size", 0)
        out.append({"id": name, "case_id": scan.get("case", {}).get("case_id", ""),
                    "device": (scan.get("device") or {}).get("path") or ident.get("path", ""),
                    "size_bytes": (scan.get("device") or {}).get("size_bytes")
                    or ident.get("size_bytes", 0),
                    "complete": bool(scan),
                    "progress": done / ident["size_bytes"] if ident.get("size_bytes") else 0,
                    "has_parse": any(os.path.exists(os.path.join(d, f)) for f in
                                     ("parse_dahua.json", "parse_hikvision.json")),
                    "has_carve": os.path.exists(os.path.join(d, "carve", "carve_report.json")),
                    "has_timeline": os.path.exists(os.path.join(d, "timeline.json"))})
    return out

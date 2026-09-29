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

PARSE_BUILTIN = ("parse_dahua.json", "parse_hikvision.json")


def parse_report_names(case_dir: str) -> list[str]:
    """The case's parse reports: the built-in vendors first, then any plugin's
    `parse_<vendor>.json` as `parse --out` writes it (HeimVision, Honeywell)."""
    names = [n for n in PARSE_BUILTIN if os.path.isfile(os.path.join(case_dir, n))]
    try:
        listing = sorted(os.listdir(case_dir))
    except OSError:
        return names
    return names + [n for n in listing if n.startswith("parse_") and n.endswith(".json")
                    and n not in PARSE_BUILTIN and os.path.isfile(os.path.join(case_dir, n))]


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
    "Honeywell": {"family": "Honeywell NVR (GPT + proprietary video partition)",
                  "parser": "Honeywell", "parser_status": "spec_only", "media": "none",
                  "basis": "plugins/honeywell.py, written from Yoon & Hwang, DFRWS USA 2026 "
                           "(arXiv:2605.07430); no Honeywell disk read by the team"},
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
            # the folder an examiner drops a plugin into: next to the executable
            # in a packaged build, not the temporary folder it unpacks to
            "plugin_dir": parsers.DROP_IN_DIR or parsers.PLUGIN_DIR}


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

    for name in parse_report_names(case_dir):
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

    es = _load(j("carve", "annexb_report.json"))
    if es:
        rows = es.get("streams", [])
        case["es_carve"] = {
            "sha256": _hashed(j("carve", "annexb_report.json")), "stats": es.get("stats"),
            "validation_status": es.get("validation_status"), "notes": es.get("notes", []),
            "streams_total": len(rows), "bytes": sum(r["bytes"] for r in rows),
            "streams": [{k: r.get(k) for k in ("id", "codec", "width", "height", "offset",
                                                "bytes", "slices", "keyframes")}
                        for r in rows[:recordings_limit]],
            "extracted": _load(j("carve", "es_extracted.json"))}

    ps = _load(j("carve", "ps_report.json"))
    if ps:
        rows = ps.get("streams", [])
        dated = sorted(r["time_first_local"] for r in rows if r.get("time_first_local"))
        by_month: dict[str, int] = {}
        for d in dated:
            by_month[d[:7]] = by_month.get(d[:7], 0) + 1
        types = sorted({st["type"] for r in rows for st in r.get("streams", [])})
        case["ps_carve"] = {
            "sha256": _hashed(j("carve", "ps_report.json")), "stats": ps.get("stats"),
            "validation_status": ps.get("validation_status"), "notes": ps.get("notes", []),
            "streams_total": len(rows), "bytes": sum(r["bytes"] for r in rows),
            "duration_s": sum(r["duration_s"] for r in rows),
            "dated": len(dated), "first_local": dated[0] if dated else None,
            "last_local": dated[-1] if dated else None, "by_month": by_month,
            "stream_types": types,
            "hk_streams": sum(1 for r in rows if r.get("hk_descriptors")),
            "streams": [{k: r.get(k) for k in ("id", "offset", "bytes", "packs", "duration_s",
                                                "time_first_local", "time_last_local")}
                        for r in rows[:recordings_limit]]}
        lab = _load(j("carve", "ps_labels.json"))
        if lab:
            tally: dict[str, int] = {}
            for x in lab["streams"]:
                tally[x["label"]] = tally.get(x["label"], 0) + 1
            hidx = _load(j("carve", "hik_index.json")) or {}
            case["ps_carve"]["labels"] = {
                "sha256": _hashed(j("carve", "ps_labels.json")), "tally": dict(sorted(tally.items())),
                "index_records": len(hidx.get("records", [])),
                "index_channels": hidx.get("channels", {}), "index_base": hidx.get("base"),
                "index_headers": hidx.get("headers", [])}
            labels_by_id = {x["id"]: x["label"] for x in lab["streams"]}
            for r in case["ps_carve"]["streams"]:
                r["label"] = labels_by_id.get(r["id"])
        ex = _load(j("carve", "ps_extracted.json"))
        if ex:
            case["ps_carve"]["extracted"] = {
                "sha256": _hashed(j("carve", "ps_extracted.json")),
                "streams": {k: {x: v[x] for x in ("file", "bytes", "sha256", "bytes_match")}
                            for k, v in ex.get("streams", {}).items()}}

    t = _load(j("timeline.json"))
    if t:
        case["timeline"] = {k: t.get(k) for k in ("clock", "cameras", "gaps", "correlations",
                                                  "anomalies", "counts", "notes", "inputs",
                                                  "index_coverage")}
        case["timeline"]["sha256"] = _hashed(j("timeline.json"))
        case["timeline"]["events"] = t.get("events", [])[:2000]
        case["timeline"]["recorder_events"] = t.get("recorder_events", [])[:2000]

    rl = _load(j("hik_log.json"))
    if rl and "summary" in rl:
        case["recorder_log"] = {
            "sha256": _hashed(j("hik_log.json")), "rule": rl.get("rule"),
            "status": rl.get("validation_status"), "master": rl.get("master"),
            "master_copies": rl.get("master_copies"), "checks": rl.get("checks", []),
            "log_area": rl.get("log_area"), "init_time_local": rl.get("init_time_local"),
            "summary": rl["summary"], "clock_vs_footage": rl.get("clock_vs_footage"),
            "time_basis": rl.get("time_basis"), "notes": rl.get("notes", [])}

    act = _load(j("activity.json"))
    if act:
        case["activity"] = {
            "sha256": _hashed(j("activity.json")), "rule": act.get("rule"),
            "status": act.get("status"), "notes": act.get("notes", []),
            "peak_factor": act.get("peak_factor"),
            "cameras": {k: {"minutes": v["minutes"],
                            "median_p_bytes_per_minute": v["median_p_bytes_per_minute"]}
                        for k, v in act.get("cameras", {}).items()},
            "peaks": sorted(act.get("peaks", []), key=lambda p: -p["local_index"])[:200],
            "peaks_total": len(act.get("peaks", [])),
            "multi_camera_peaks": act.get("multi_camera_peaks", [])[:200]}

    an = _load(j("analytics", "analytics.json"))
    if an:
        hits = [dict(h, clip=c["clip"]) for c in an.get("clips", []) for h in c["detections"]]
        hits.sort(key=lambda h: -max(d["score"] for d in h["detections"]))
        case["analytics"] = {
            "sha256": _hashed(j("analytics", "analytics.json")), "status": an.get("status"),
            "models": an.get("models"), "thresholds": an.get("thresholds"),
            "notes": an.get("notes", []), "totals": an.get("frames_with_totals", {}),
            "clips": len(an.get("clips", [])),
            "frames_analysed": sum(c["frames_analysed"] for c in an.get("clips", [])),
            "top": hits[:100],
            "thumbnails": [dict(t, clip=c["clip"]) for c in an.get("clips", [])
                           for t in c.get("thumbnails", [])][:60]}

    osd = _load(j("analytics", "osd.json"))
    if osd:
        named = [s for s in osd.get("streams", []) if s.get("label")]
        named.sort(key=lambda s: -s["label"]["confidence"])
        case["osd"] = {
            "sha256": _hashed(j("analytics", "osd.json")), "rule": osd.get("rule"),
            "status": osd.get("status"), "notes": osd.get("notes", []),
            "layout": osd.get("layout"), "summary": osd.get("summary", {}),
            "frames_per_stream": osd.get("frames_per_stream"),
            "named": [{"clip": s["clip"], "title": s["label"]["title"],
                       "confidence": s["label"]["confidence"],
                       "frames": f"{s['label']['frames_agreeing']}/{s['label']['frames_read']}",
                       "clock": s.get("clock", {}).get("verdict"),
                       "offset_s": s.get("clock", {}).get("offset_s")}
                      for s in named[:200]],
            "clock_disagreements": [
                {"clip": s["clip"], "offset_s": s["clock"].get("offset_s"),
                 "detail": s["clock"].get("detail")}
                for s in osd.get("streams", [])
                if s.get("clock", {}).get("verdict") == "disagrees"][:50]}

    record = _load(j("device_record.json"))
    platter = _load(j("model.json"))
    if record or platter:
        from detect import model
        case["model"] = {
            "observations": (record or {}).get("observations", []),
            "record_sha256": _hashed(j("device_record.json")) if record else None,
            "platter": platter, "platter_sha256": _hashed(j("model.json")) if platter else None,
            "checks": model.check((record or {}).get("observations", []), platter,
                                  (scan or {}).get("detections"))}

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
                    "has_parse": bool(parse_report_names(d)),
                    "has_carve": os.path.exists(os.path.join(d, "carve", "carve_report.json")),
                    "has_timeline": os.path.exists(os.path.join(d, "timeline.json"))})
    return out

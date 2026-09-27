"""One view across several recorders - and the reasons it is usually not one.

Two DVRs seized from the same premises have nothing in common. Each has its
own crystal, its own unaudited clock, its own timezone setting, and no
recorder ever heard of the other. Drawing both on one axis says they can be
compared, and that claim has to be earned:

  * every case must state its recorder's timezone, or no UTC exists to share;
  * every case should have had its clock error measured against a trusted
    clock at seizure, or the alignment is off by an unknown amount.

When both hold, this emits a shared UTC axis and will say which recorders
were running at the same time. When they do not, it emits the same cases
side by side, each on its own recorder clock, and states per case exactly
what is missing - because side by side on separate axes is still the useful
demo view, while a single axis would be a false one.

Stdlib only, like the rest of `analyse/`. Reads each case's `timeline.json`
and `scan_report.json`; recomputes nothing and cites both by hash.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

COMBINED_RULE = "combined.v1"
# Two recorders counted as "running at the same time" only where their
# coverage overlaps by more than this; a few seconds of overlap at the edge of
# a span is not a finding.
OVERLAP_MIN_S = 60


def _load(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _span(events: list[dict], key: str) -> tuple[Optional[str], Optional[str]]:
    """First and last moment in a list of timeline events, on one time base."""
    starts = [e[f"start_{key}"] for e in events if e.get(f"start_{key}")]
    ends = [e[f"end_{key}"] for e in events if e.get(f"end_{key}")]
    return (min(starts) if starts else None, max(ends) if ends else None)


def read_case(case_dir: str) -> dict:
    """One recorder's summary, as its own files already state it."""
    from core.hashing import sha256_file

    tl = _load(os.path.join(case_dir, "timeline.json"))
    if not tl:
        raise FileNotFoundError(
            f"{case_dir} has no timeline.json - run `cli.py timeline --out {case_dir}` first")
    scan = _load(os.path.join(case_dir, "scan_report.json")) or {}
    dev = scan.get("device") or {}
    hashes = {h["algorithm"]: h["value"] for h in scan.get("hashes", [])}
    events = tl.get("events", [])
    clock = tl.get("clock", {})
    lanes = {name: {"recordings": v["recordings"], "first_local": v["first_local"],
                    "last_local": v["last_local"], "hours": round(v["covered_s"] / 3600, 2),
                    "gaps": v["gaps"]}
             for name, v in (tl.get("cameras") or {}).items()}
    lo_l, hi_l = _span(events, "local")
    lo_u, hi_u = _span(events, "utc")
    return {
        "case_id": (scan.get("case") or {}).get("case_id") or os.path.basename(case_dir.rstrip("/\\")),
        "path": case_dir,
        "device": {k: dev.get(k) for k in ("path", "model", "serial", "size_bytes")},
        "device_sha256": hashes.get("sha256"),
        "complete_pass": (scan.get("stats") or {}).get("complete_pass"),
        "clock": clock,
        "tz_stated": clock.get("tz_offset_min") is not None,
        "drift_measured": bool(clock.get("drift_source")),
        "span_local": {"first": lo_l, "last": hi_l},
        "span_utc": {"first": lo_u, "last": hi_u},
        "lanes": lanes,
        "counts": tl.get("counts", {}),
        "events": len(events),
        "gaps": len(tl.get("gaps", [])),
        "anomalies": len(tl.get("anomalies", [])),
        "timeline_sha256": sha256_file(os.path.join(case_dir, "timeline.json")),
    }


def axis_for(cases: list[dict]) -> dict:
    """May these recorders share one axis, and on whose word?

    A shared axis needs every case to state its recorder's timezone. A case
    whose clock error was never measured does not forbid the axis - the
    ClockModel still converts - but it puts an unknown offset on that
    recorder's position, so it is named as a caveat rather than buried.
    """
    no_tz = [c["case_id"] for c in cases if not c["tz_stated"]]
    no_drift = [c["case_id"] for c in cases if c["tz_stated"] and not c["drift_measured"]]
    if no_tz:
        return {
            "axis": "recorder_local",
            "shared": False,
            "reason": ("no shared axis: " + ", ".join(no_tz)
                       + (" states" if len(no_tz) == 1 else " state")
                       + " no recorder timezone, so those times are wall-clock readings "
                         "from an unaudited clock and cannot be placed against another "
                         "recorder's"),
            "needs": [f"{c}: the recorder's timezone (cli.py timeline --tz-offset)"
                      for c in no_tz],
            "caveats": [f"{c}: clock error against a trusted clock was never measured"
                        for c in no_drift],
        }
    return {
        "axis": "utc",
        "shared": True,
        "reason": ("every recorder states a timezone, so each case's own clock model "
                   "converts its times to UTC and the recorders can be placed against "
                   "one another"),
        "needs": [],
        "caveats": [f"{c}: clock error against a trusted clock was never measured, so this "
                    f"recorder's position carries an unknown offset" for c in no_drift],
    }


def overlaps(cases: list[dict]) -> list[dict]:
    """Where two recorders were recording at the same time, on the UTC axis.

    Only the coverage spans are compared. That two recorders were both running
    is a fact about the premises; what either of them saw is not decided here.
    """
    out = []
    for i, a in enumerate(cases):
        for b in cases[i + 1:]:
            s = [a["span_utc"]["first"], b["span_utc"]["first"]]
            e = [a["span_utc"]["last"], b["span_utc"]["last"]]
            if not all(s) or not all(e):
                continue
            lo, hi = max(s), min(e)
            if lo >= hi:
                continue
            secs = (_utc(hi) - _utc(lo)).total_seconds()
            if secs < OVERLAP_MIN_S:
                continue
            out.append({"cases": [a["case_id"], b["case_id"]],
                        "from_utc": lo, "to_utc": hi,
                        "duration_s": secs,
                        "lanes": {a["case_id"]: sorted(a["lanes"]),
                                  b["case_id"]: sorted(b["lanes"])},
                        "detail": f"both recorders hold footage covering {lo} to {hi}"})
    return out


def _utc(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def build(case_dirs: list[str]) -> dict:
    """The combined view over several case directories.

    The same case given twice is read once: two entries for one recorder would
    overlap themselves completely and read as two recorders running together.
    """
    seen: dict[str, str] = {}
    for d in case_dirs:
        seen.setdefault(os.path.normcase(os.path.abspath(d)), d)
    if len(seen) < 2:
        raise ValueError("a combined view needs two or more distinct case directories; "
                         "one recorder's own timeline is `cli.py timeline`")
    cases = [read_case(d) for d in seen.values()]
    ax = axis_for(cases)
    totals = {
        "recorders": len(cases),
        "lanes": sum(len(c["lanes"]) for c in cases),
        "events": sum(c["events"] for c in cases),
        "hours_recovered": round(sum(l["hours"] for c in cases for l in c["lanes"].values()), 2),
        "bytes_acquired": sum((c["device"].get("size_bytes") or 0) for c in cases),
        "gaps": sum(c["gaps"] for c in cases),
        "anomalies": sum(c["anomalies"] for c in cases),
    }
    out = {
        "rule": COMBINED_RULE,
        "axis": ax,
        "cases": cases,
        "totals": totals,
        "overlaps": overlaps(cases) if ax["shared"] else [],
        "inputs": {c["path"]: c["timeline_sha256"] for c in cases},
        "notes": [
            "Each recorder keeps its own unaudited clock. Nothing here adjusts one "
            "recorder's times to another's; each case's times are converted, or not, "
            "by its own clock model and no other.",
            "Lanes are not comparable between recorders: a camera called CH01 on one "
            "recorder has nothing to do with CH01 on another.",
            "Totals add up what was recovered from several devices. They are a case "
            "summary, not a measurement of anything that happened at the premises.",
        ],
    }
    if not ax["shared"]:
        out["notes"].insert(0,
            "These recorders are shown side by side on SEPARATE axes, each on its own "
            "recorder clock. They are not aligned with each other and the vertical "
            "position of one recorder's footage says nothing about another's.")
    else:
        out["notes"].insert(0,
            "These recorders share a UTC axis because each states its own timezone. "
            "Where a recorder's clock error was never measured, its position carries "
            "an unknown offset - see axis.caveats.")
    return out


def summary_lines(view: dict) -> list[str]:
    """The same thing as text, for the CLI and the final report."""
    ax = view["axis"]
    lines = [f"axis          {ax['axis']} - {ax['reason']}"]
    for c in view["cases"]:
        d = c["device"]
        lines.append(f"  {c['case_id']:<20} {d.get('model') or d.get('path') or '?'}"
                     f"  s/n {d.get('serial') or '?'}")
        lines.append(f"  {'':<20} {c['span_local']['first'] or '?'} -> "
                     f"{c['span_local']['last'] or '?'} (recorder clock)"
                     f"  {len(c['lanes'])} lanes, {c['events']} events")
        if c["span_utc"]["first"]:
            lines.append(f"  {'':<20} {c['span_utc']['first']} -> {c['span_utc']['last']} (UTC)")
    for n in ax["needs"]:
        lines.append(f"  needed      {n}")
    for n in ax["caveats"]:
        lines.append(f"  caveat      {n}")
    for o in view["overlaps"]:
        lines.append(f"  overlap     {' + '.join(o['cases'])}: {o['from_utc']} -> {o['to_utc']} "
                     f"({o['duration_s'] / 3600:.1f} h)")
    return lines

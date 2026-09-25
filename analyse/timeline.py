"""Camera timeline: timestamp normalization and cross-camera correlation.

A DVR's timestamps are claims made by a clock nobody audited.  The recorder
writes local wall-clock time with no zone, its clock drifts, and anyone with
the admin password can set it to anything.  So this stage never "fixes" a
time.  It records, for every event, the raw recorder-local value, the rule
used to convert it, and where each input to that rule came from:

  * the recorder's zone      - stated by the examiner (`tz_offset_min`)
  * the recorder's clock error - measured by the examiner at seizure: what the
    DVR displayed against a trusted reference at the same instant

Without the zone, `utc` stays empty and the timeline is in recorder-local
time - which is still internally consistent across cameras, because every
camera on one recorder shares that one clock.

Correlation is stated as what the data shows, never as a cause: a gap is
"no indexed footage", not "deleted"; a gap on every camera at once is
"system-wide", not "tampering".  Causes are for the examiner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

TIMELINE_RULE = "timeline.v1"
_LOCAL_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
# Recording files on the real disk are hour-bounded and a camera's next file
# starts within a second or two of the last; anything longer is a gap worth
# listing.  (Motion-only recording makes gaps normal - hence "no footage",
# never "deleted".)
GAP_MIN_S = 60
# Index and first-frame dates further apart than this are listed.
CLOCK_DISAGREE_S = 5
# DHAV dates count from 2000; footage dated in that year means an unset clock.
CLOCK_DEFAULT_YEAR = 2000


def parse_local(raw_value: str) -> Optional[datetime]:
    """'0x6A46CD75 = 2026-09-03 12:53:53 recorder-local' -> datetime."""
    m = _LOCAL_RE.search(raw_value or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def fmt(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


@dataclass
class ClockModel:
    """How recorder-local time maps to UTC, and on whose word."""
    tz_offset_min: Optional[int] = None
    drift_s: float = 0.0                 # recorder clock minus true time
    drift_source: str = ""

    @classmethod
    def from_observation(cls, tz_offset_min: Optional[int], observed: str = "",
                         reference: str = "") -> "ClockModel":
        """`observed` is what the DVR displayed; `reference` is trusted time
        (in the same zone) at the same instant, both 'YYYY-MM-DD HH:MM:SS'."""
        m = cls(tz_offset_min=tz_offset_min)
        o, r = parse_local(observed), parse_local(reference)
        if o and r:
            m.drift_s = (o - r).total_seconds()
            m.drift_source = (f"examiner observation: recorder showed {fmt(o)} when "
                              f"the reference showed {fmt(r)}")
        return m

    def to_utc(self, local: Optional[datetime]) -> Optional[str]:
        if local is None or self.tz_offset_min is None:
            return None
        t = local - timedelta(seconds=self.drift_s) - timedelta(minutes=self.tz_offset_min)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def rule(self) -> str:
        if self.tz_offset_min is None:
            return ("recorder-local time, not converted: the recorder's zone was not "
                    "stated, so no UTC is asserted")
        s = (f"utc = recorder_local - drift({self.drift_s:+.0f} s) - "
             f"zone({self.tz_offset_min:+d} min)")
        if not self.drift_source:
            s += "; recorder clock error NOT measured - assumed 0"
        return s

    def to_dict(self) -> dict:
        return {"tz_offset_min": self.tz_offset_min, "drift_s": self.drift_s,
                "drift_source": self.drift_source or None, "rule": self.rule()}


def _claims(rec: dict, source: str) -> list[datetime]:
    out = []
    for c in rec.get("timestamps", []):
        if c.get("source") == source:
            d = parse_local(c.get("raw_value", ""))
            if d:
                out.append(d)
    return out


def build(parse_report: Optional[dict], carve_report: Optional[dict],
          clock: ClockModel) -> dict:
    events: list[dict] = []
    anomalies: list[dict] = []

    def event(rec: dict, kind: str, start: datetime, end: datetime, basis: str,
              extra: Optional[dict] = None) -> dict:
        e = {"id": rec["id"], "kind": kind, "camera": rec.get("camera_id", "UNKNOWN"),
             "start_local": fmt(start), "end_local": fmt(end),
             "start_utc": clock.to_utc(start), "end_utc": clock.to_utc(end),
             "duration_s": max(0.0, (end - start).total_seconds()),
             "time_basis": basis, "confidence": rec.get("confidence", 0.0),
             "offset": rec.get("offset", 0), "length": rec.get("length", 0)}
        e.update(extra or {})
        events.append(e)
        return e

    for rec in (parse_report or {}).get("recordings", []):
        idx = _claims(rec, "index")
        if len(idx) < 2:
            continue
        e = event(rec, "indexed", idx[0], idx[1], "index")
        cont = _claims(rec, "container")
        if cont:
            # The index says when the file started; the first frame says when
            # the camera's own stream says it started.  They share one clock,
            # so a large disagreement is a finding, not rounding.
            d = (cont[0] - idx[0]).total_seconds()
            e["index_vs_frame_s"] = d
            if abs(d) > CLOCK_DISAGREE_S:
                anomalies.append({"kind": "index_frame_disagreement", "id": rec["id"],
                                  "camera": e["camera"], "delta_s": d,
                                  "detail": f"index start {fmt(idx[0])} vs first frame "
                                            f"{fmt(cont[0])}"})
    for rec in (parse_report or {}).get("remnants", []):
        c = _claims(rec, "container")
        if c:
            end = c[-1] if len(c) > 1 else c[0] + timedelta(seconds=rec.get("duration_s") or 0)
            event(rec, "remnant", c[0], end, "frame",
                  {"note": "older footage surviving in a reused cluster"})
    for row in (carve_report or {}).get("streams", []):
        if row.get("index_label") != "outside_index":
            continue            # labelled CHxx: the same footage as an indexed event
        rec = row["recording"]
        c = _claims(rec, "container")
        if len(c) >= 2:
            event(rec, "unindexed", c[0], c[-1], "frame",
                  {"note": "carved footage no index record accounts for"})
    for row in (carve_report or {}).get("streams", []):
        if row.get("index_label") == "mixed-evidence":
            anomalies.append({"kind": "mixed_evidence_stream", "id": row["recording"]["id"],
                              "detail": f"index tally {row.get('index_tally')}"})

    events.sort(key=lambda e: (e["start_local"] or "", e["camera"]))

    # -- per camera: coverage and gaps -----------------------------------
    cams: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "indexed":
            cams.setdefault(e["camera"], []).append(e)
    cameras = {}
    gaps: list[dict] = []
    for cam, evs in sorted(cams.items()):
        evs.sort(key=lambda e: e["start_local"])
        covered = 0.0
        cur_end: Optional[datetime] = None
        for e in evs:
            s, en = parse_local(e["start_local"]), parse_local(e["end_local"])
            if cur_end is not None and s < cur_end - timedelta(seconds=GAP_MIN_S):
                anomalies.append({"kind": "overlapping_recordings", "camera": cam,
                                  "id": e["id"],
                                  "detail": f"starts {fmt(s)}, before the previous file "
                                            f"ends at {fmt(cur_end)}"})
            if cur_end is not None and (s - cur_end).total_seconds() > GAP_MIN_S:
                gaps.append({"camera": cam, "start_local": fmt(cur_end), "end_local": fmt(s),
                             "start_utc": clock.to_utc(cur_end), "end_utc": clock.to_utc(s),
                             "duration_s": (s - cur_end).total_seconds()})
            covered += max(0.0, (en - s).total_seconds())
            cur_end = en if cur_end is None else max(cur_end, en)
        cameras[cam] = {"recordings": len(evs), "first_local": evs[0]["start_local"],
                        "last_local": fmt(cur_end), "covered_s": covered,
                        "gaps": sum(1 for g in gaps if g["camera"] == cam)}

    # -- across cameras --------------------------------------------------
    # A gap every camera shares is a property of the recorder (power, a
    # restart, a clock change), not of one camera.  Stated, not explained.
    correlated: list[dict] = []
    if len(cameras) > 1:
        for g in gaps:
            gs, ge = parse_local(g["start_local"]), parse_local(g["end_local"])
            also = sorted({h["camera"] for h in gaps if h is not g and h["camera"] != g["camera"]
                           and parse_local(h["start_local"]) < ge
                           and parse_local(h["end_local"]) > gs})
            g["shared_with"] = also
            g["system_wide"] = len(also) == len(cameras) - 1
        seen = set()
        for g in gaps:
            if g["system_wide"]:
                key = (g["start_local"][:16])
                if key not in seen:
                    seen.add(key)
                    correlated.append({"kind": "system_wide_gap", "start_local": g["start_local"],
                                       "end_local": g["end_local"],
                                       "detail": "no indexed footage on any camera"})
    unindexed = [e for e in events if e["kind"] in ("unindexed", "remnant")]
    for u in unindexed:
        us, ue = parse_local(u["start_local"]), parse_local(u["end_local"])
        hits = [g["camera"] for g in gaps
                if parse_local(g["start_local"]) <= ue and parse_local(g["end_local"]) >= us]
        if hits:
            u["overlaps_gap_of"] = sorted(set(hits))
            correlated.append({"kind": "unindexed_footage_in_gap", "id": u["id"],
                               "start_local": u["start_local"], "end_local": u["end_local"],
                               "cameras_with_gap": sorted(set(hits)),
                               "detail": "footage exists for a period the index has no "
                                         "recording for; which camera it came from is "
                                         "not established"})
    # A recorder whose clock was never set (or lost it with a flat RTC battery)
    # stamps footage with its epoch default - 2000-01-01 for DHAV.  That is a
    # finding about the recorder, and those times say nothing about when the
    # footage was recorded.
    for e in events:
        s0 = parse_local(e["start_local"])
        if s0 and s0.year <= CLOCK_DEFAULT_YEAR:
            anomalies.append({"kind": "clock_at_default", "id": e["id"],
                              "camera": e["camera"],
                              "detail": f"dated {fmt(s0)} - the recorder's clock was at its "
                                        f"default (unset, or reset by power loss); this "
                                        f"footage's real time is unknown"})
    dated = [parse_local(e["start_local"]) for e in events if e["kind"] == "indexed"]
    if dated:
        lo, hi = min(dated), max(dated)
        for u in unindexed:
            s = parse_local(u["start_local"])
            if s and s > hi + timedelta(days=1):
                anomalies.append({"kind": "dated_after_newest_recording", "id": u["id"],
                                  "detail": f"{fmt(s)} is after the newest indexed "
                                            f"recording ({fmt(hi)}) - clock set forward "
                                            f"at some point, or a frame date is wrong"})

    return {
        "rule": TIMELINE_RULE,
        "clock": clock.to_dict(),
        "events": events,
        "cameras": cameras,
        "gaps": gaps,
        "correlations": correlated,
        "anomalies": anomalies,
        "counts": {k: sum(1 for e in events if e["kind"] == k)
                   for k in ("indexed", "unindexed", "remnant")},
        "notes": [
            "Every camera on one recorder shares one clock, so ordering across cameras "
            "holds even where no UTC is asserted.",
            "A gap means no indexed footage for that period. Motion-only recording, "
            "power loss, overwrite and deletion all produce gaps; the timeline does not "
            "say which.",
            "'unindexed' footage was carved from the platter with no index record "
            "accounting for it; its camera is unknown.",
        ],
    }

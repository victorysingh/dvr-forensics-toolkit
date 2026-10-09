"""Plug and use, read-only side: what stage a case is at, from its files.

The station (acquire/station.py) runs every step of the problem statement on
a disk that is plugged in.  This module never touches a device: it reads a
case folder and says which of the seven stages are done, so the console can
show a station's run live, and show any finished case - the two real drives
included - as the same seven stages.

A stage is "done" because its output exists, not because a progress file
says so.  The station's own record (`station.json` in the case folder) only
adds what files cannot show: that a stage is running now, failed, or was
skipped and why, and how long each took.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

#: The stages, in the order the station runs them, each named after the
#: problem statement's module it answers (docs/PROBLEM_STATEMENT.md).
STAGES = [
    {"id": "scan", "title": "Acquire and identify",
     "module": "Acquisition, Device Identification",
     "what": "One read-only pass of the whole disk: MD5 and SHA-256, the brand "
             "scored from the disk itself, deleted footage carved and motion "
             "measured in the same pass."},
    {"id": "preserve", "title": "Preserve metadata",
     "module": "Acquisition (forensic image)",
     "what": "Every filesystem structure saved, tied to the acquisition hash."},
    {"id": "parse", "title": "Parse the filesystem",
     "module": "File System & Format Parsing",
     "what": "The recorder's own index read into recordings, cameras and times; "
             "a Hikvision disk's system log too."},
    {"id": "recover", "title": "Recover footage",
     "module": "Recovery",
     "what": "Footage found outside every index (deleted or overwritten) saved "
             "as playable files, each hashed."},
    {"id": "timeline", "title": "Timeline",
     "module": "Timeline Analysis",
     "what": "Recorder clock decoded, gaps per camera, events correlated across "
             "cameras."},
    {"id": "ml", "title": "Faces, objects, motion",
     "module": "Machine Learning",
     "what": "People, faces and vehicles found in the recovered footage. A lead "
             "for review, not evidence."},
    {"id": "report", "title": "Report",
     "module": "Reporting",
     "what": "HTML and JSON report, hashed into the custody ledger."},
]

STATION_FILE = "station.json"            # in a case folder, written by the station
STATION_DIR = ".station"                 # in the out folder: the station's own status
#: A station writes its status every couple of seconds; older than this, it
#: has stopped (closed, crashed or the machine slept).
STALE_S = 15


def _load(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _count(doc: Optional[dict], key: str) -> int:
    v = (doc or {}).get(key)
    return len(v) if isinstance(v, (list, dict)) else 0


def _from_files(d: str) -> dict[str, dict]:
    """Each stage's state and a one-line result, from the case's files alone."""
    from report.case import parse_report_names

    j = lambda *p: os.path.join(d, *p)
    out: dict[str, dict] = {}

    scan = _load(j("scan_report.json"))
    state = _load(j("scan_state.json")) or {}
    if scan:
        top = (scan.get("detections") or [{}])[0]
        out["scan"] = {"state": "done",
                       "result": (f"{top['vendor']} {round(100 * top.get('confidence', 0))}%"
                                  if top.get("vendor") else "no brand matched")}
    elif state:
        ident = state.get("identity", {})
        size = ident.get("size_bytes") or 0
        frac = state.get("blocks_done", 0) * ident.get("block_size", 0) / size if size else 0
        out["scan"] = {"state": "part", "progress": min(frac, 1.0),
                       "result": f"{round(100 * min(frac, 1.0))}% read"}

    if os.path.isdir(j("preserved")):
        out["preserve"] = {"state": "done", "result": "metadata saved"}

    # A recorder's index: a vendor parse, or Hikvision's HIKBTREE records read
    # to label carved footage (label-ps), and its own system log.
    bits = []
    names = parse_report_names(d)
    recs = sum(_count(_load(j(n)), "recordings") for n in names)
    if names:
        bits.append(f"{recs:,} recordings" if recs else "parsed")
    hik = _count(_load(j("carve", "hik_index.json")), "records")
    if hik:
        bits.append(f"{hik:,} index records")
    log = _count(_load(j("hik_log.json")), "recorder_log")
    if log:
        bits.append(f"{log:,} log events")
    if bits:
        out["parse"] = {"state": "done", "result": " · ".join(bits)}

    carved = sum(_count(_load(j("carve", r)), "streams") for r in
                 ("carve_report.json", "ps_report.json", "annexb_report.json"))
    saved = sum(_count(_load(j("carve", m)), "streams") for m in
                ("extracted.json", "ps_extracted.json", "es_extracted.json"))
    if saved:
        out["recover"] = {"state": "done",
                          "result": f"{carved:,} carved · {saved:,} saved" if carved
                          else f"{saved:,} saved"}
    elif carved:
        out["recover"] = {"state": "part", "result": f"{carved:,} carved, none saved yet"}

    if os.path.exists(j("timeline.json")):
        out["timeline"] = {"state": "done", "result": "built"}

    an = _load(j("analytics", "analytics.json"))
    if an:
        tot = an.get("frames_with_totals") or {}
        bits = [f"{k} {v:,}" for k, v in sorted(tot.items(), key=lambda kv: -kv[1]) if v]
        out["ml"] = {"state": "done",
                     "result": ("frames with " + ", ".join(bits[:3])) if bits else "nothing found"}
    elif os.path.exists(j("activity.json")):
        out["ml"] = {"state": "part", "result": "motion only"}

    if os.path.exists(j("report.html")) or os.path.exists(j("report.json")):
        out["report"] = {"state": "done", "result": "written"}
    return out


def case_stages(case_dir: str) -> dict:
    """The seven stages of one case: what its files show, with the station's
    record laid over it where the station ran it."""
    files = _from_files(case_dir)
    run = _load(os.path.join(case_dir, STATION_FILE)) or {}
    ran = {s.get("id"): s for s in run.get("stages", []) if isinstance(s, dict)}
    stages = []
    for st in STAGES:
        f = files.get(st["id"], {})
        r = ran.get(st["id"], {})
        state = f.get("state", "")
        # What files cannot show: running now, failed, skipped.  A stage the
        # files call done stays done whatever the record says.
        if state != "done" and r.get("state") in ("running", "failed", "skipped"):
            state = r["state"]
        stages.append({"id": st["id"], "title": st["title"], "state": state or "pending",
                       "result": (r.get("note") if state in ("failed", "skipped")
                                  else f.get("result", "")) or "",
                       "progress": f.get("progress"),
                       "started_utc": r.get("started_utc"), "ended_utc": r.get("ended_utc")})
    return {"id": os.path.basename(os.path.normpath(case_dir)),
            "station": bool(run), "device": run.get("device"),
            "started_utc": run.get("started_utc"), "ended_utc": run.get("ended_utc"),
            "outcome": run.get("outcome"),
            "done": sum(1 for s in stages if s["state"] == "done"),
            "stages": stages}


def station_status(out_root: str) -> Optional[dict]:
    """The station's last word, or None if none ever ran on this folder.
    `running` is false once its heartbeat is older than STALE_S."""
    st = _load(os.path.join(out_root, STATION_DIR, "status.json"))
    if not st:
        return None
    age = time.time() - float(st.get("heartbeat", 0) or 0)
    return dict(st, running=age < STALE_S, heartbeat_age_s=round(age, 1))


def station_view(out_root: str, case_ids: list[str]) -> dict:
    """What the console's Plug and use page shows: the station, the cases it
    ran, and finished cases as examples of the same stages.  `case_ids` is the
    list this request may see (viewer/server.py::visible_cases)."""
    st = station_status(out_root)
    live = st.get("case") if st and st.get("running") else None
    runs, examples = [], []
    for cid in case_ids:
        d = os.path.join(out_root, cid)
        view = case_stages(d)
        if view["station"]:
            if view["outcome"] == "running" and cid != live:
                # The station was killed or the machine slept mid-run: the
                # record never got to say so.  Plugging the disk in resumes.
                view["outcome"] = "interrupted"
                for s in view["stages"]:
                    if s["state"] == "running":
                        s.update(state="failed", result="interrupted - plug the disk "
                                 "in again to resume")
            runs.append(view)
        elif any(s["id"] == "scan" and s["state"] == "done" for s in view["stages"]):
            examples.append(view)
    runs.sort(key=lambda v: v.get("started_utc") or "", reverse=True)
    # The fullest cases make the best examples of what a run produces.
    examples.sort(key=lambda v: (-v["done"], v["id"]))
    if st and st.get("case") and st["case"] not in case_ids:
        st = dict(st, case=None, device=None)   # not this account's to see
    return {"stages": STAGES, "station": st, "runs": runs, "examples": examples[:4]}

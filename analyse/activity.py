"""Motion activity from compressed frame sizes - no decoding.

A P-frame encodes what changed since the previous frame.  When a scene is
still, P-frames are a few hundred bytes; when something moves, they grow.
Summing P-frame bytes per camera per minute therefore gives an activity
index straight from the frame headers the carve already walks, without a
video decoder and without a second read of the drive.

This is a LEAD, NOT EVIDENCE.  P-frames also grow with sensor noise in low
light, lighting changes, IR switching, rain, camera shake and encoder
settings.  A peak says "look here", never "an event happened here".  Every
output says so.

Runs as a scan tap (`scan --activity`) or over an image (`cli.py activity`).
Stdlib only.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from parsers.dahua import TYPE_I, TYPE_P, decode_date

ACTIVITY_RULE = "activity.pframe_bytes_per_minute.v2"
# A minute is a peak at this many times the median of the minutes around it
# on the same camera.  Local, not whole-period: on real footage the index is
# ~2x the camera's median all afternoon and ~0.8x at night, so a whole-period
# baseline flags "a busy afternoon" rather than a burst.
PEAK_FACTOR = 3.0
LOCAL_WINDOW = 30          # minutes either side
MIN_PEAK_FRAMES = 100      # ignore minutes with too few frames to judge


def minute_key(packed: int) -> int:
    """The packed DHAV date with its seconds field dropped: one key per minute."""
    return packed >> 6


def minute_label(key: int) -> str:
    dt = decode_date(key << 6)
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "?"


class ActivityCounter:
    """Per (camera label, minute): P-frame bytes and count, I-frame bytes."""

    def __init__(self, labeler=None):
        self.labeler = labeler
        self.cells: dict[tuple[str, int], list[int]] = {}

    def add(self, fr) -> None:
        if fr.ftype not in (TYPE_P, TYPE_I):
            return
        label = self.labeler.label(fr) if self.labeler is not None else "unlabelled"
        c = self.cells.get((label, minute_key(fr.date)))
        if c is None:
            c = self.cells[(label, minute_key(fr.date))] = [0, 0, 0, 0]
        if fr.ftype == TYPE_P:
            c[0] += fr.length
            c[1] += 1
        else:
            c[2] += fr.length
            c[3] += 1

    def result(self, peak_factor: float = PEAK_FACTOR) -> dict:
        by_label: dict[str, list[tuple[int, list[int]]]] = {}
        for (label, key), c in self.cells.items():
            by_label.setdefault(label, []).append((key, c))
        cameras = {}
        peaks = []
        for label, rows in sorted(by_label.items()):
            rows.sort()
            judged = [c[0] for _, c in rows if c[1] >= MIN_PEAK_FRAMES]
            median = sorted(judged)[len(judged) // 2] if judged else 0
            series = []
            for n, (key, c) in enumerate(rows):
                idx = round(c[0] / median, 2) if median else None
                around = sorted(x[1][0] for x in rows[max(0, n - LOCAL_WINDOW):n + LOCAL_WINDOW + 1]
                                if x[1][1] >= MIN_PEAK_FRAMES)
                local_med = around[len(around) // 2] if around else 0
                local = round(c[0] / local_med, 2) if local_med else None
                series.append({"minute": minute_label(key), "p_bytes": c[0],
                               "p_frames": c[1], "i_bytes": c[2], "index": idx,
                               "local_index": local})
                # peaks only for a single camera's view; "outside_index" mixes
                # footage of unknown cameras and has no meaningful baseline
                if (label.startswith("CH") and local is not None and local >= peak_factor
                        and c[1] >= MIN_PEAK_FRAMES):
                    peaks.append({"camera": label, "minute": minute_label(key), "key": key,
                                  "local_index": local, "index": idx})
            cameras[label] = {"minutes": len(rows), "median_p_bytes_per_minute": median,
                              "series": series}
        # Peaks in the same minute on more than one camera: activity seen from
        # several viewpoints at once - or a recorder-wide cause (lights, IR
        # switch).  Stated as a coincidence, not an explanation.
        by_min: dict[int, list[dict]] = {}
        for p in peaks:
            if p["camera"].startswith("CH"):
                by_min.setdefault(p["key"], []).append(p)
        together = [{"minute": minute_label(k), "cameras": sorted(p["camera"] for p in ps),
                     "local_indices": {p["camera"]: p["local_index"] for p in ps}}
                    for k, ps in sorted(by_min.items()) if len(ps) > 1]
        for p in peaks:
            p.pop("key", None)
        return {
            "rule": ACTIVITY_RULE, "peak_factor": peak_factor, "local_window_min": LOCAL_WINDOW,
            "cameras": cameras, "peaks": peaks, "multi_camera_peaks": together,
            "status": "lead, not evidence",
            "notes": [
                "index = P-frame bytes in a minute / that camera's median minute over "
                "the whole period (time-of-day view). local_index = the same over the "
                "median of the 30 minutes either side; peaks use local_index, so they "
                "mark bursts rather than busy hours. No video was decoded.",
                "P-frames also grow with low-light noise, lighting changes, IR "
                "switching, rain, camera shake and encoder settings. A peak marks "
                "footage worth reviewing; it is not evidence that anything happened.",
                "Minutes are the recorder's own clock.",
            ],
        }


class ActivityTap:
    """Scan tap: count frame sizes during the acquisition pass."""

    name = "activity"

    def __init__(self):
        self.counter: Optional[ActivityCounter] = None
        self.feeder = None

    def prepare(self, dev, start: int, end: int, log=print) -> None:
        from parsers.dahua import DahuaParser
        from recover.carver import FrameFeeder, IndexLabeler
        labeler = None
        p = DahuaParser()
        if p.detect(dev):
            vols, _ = p.read_partitions(dev)
            for v in vols:
                p.read_volume(dev, v)
            labeler = IndexLabeler(vols) or None
        self.counter = ActivityCounter(labeler)
        self.feeder = FrameFeeder(start, end)
        log("[*] activity P-frame sizes per camera per minute (lead, not evidence)")

    def feed(self, offset: int, data: bytes) -> None:
        for fr in self.feeder.push(offset, data):
            self.counter.add(fr)

    def finish(self, out_dir: str, info) -> dict:
        from core.hashing import sha256_file
        for fr in self.feeder.close():
            self.counter.add(fr)
        r = self.counter.result()
        r["source_device"] = info.path
        path = os.path.join(out_dir, "activity.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=1)
        return {"report": "activity.json", "sha256": sha256_file(path),
                "peaks": len(r["peaks"]), "multi_camera_peaks": len(r["multi_camera_peaks"]),
                "labels": {k: v["minutes"] for k, v in r["cameras"].items()}}

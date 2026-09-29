"""Static-detection rule for the analytics layer - stdlib only, so the core
test suite can check it without the layer's dependencies."""

from __future__ import annotations

def _iou(a: list[float], b: list[float]) -> float:
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    union = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / union if union > 0 else 0.0


# A detection whose box recurs, same label, at nearly the same place in at
# least this share of a clip's analysed frames (and in STATIC_MIN_FRAMES of
# them) is "static": on real footage, a steel pot on a table was detected as a
# face in 17 of 58 frames at the same spot. Static detections are kept and
# flagged, but not counted as moments to review.
STATIC_IOU = 0.8
STATIC_SHARE = 0.25
STATIC_MIN_FRAMES = 4


def flag_static(hits: list[dict], frames: int) -> None:
    for h in hits:
        for d in h["detections"]:
            same = sum(1 for g in hits for e in g["detections"]
                       if e["label"] == d["label"] and _iou(e["box"], d["box"]) >= STATIC_IOU)
            d["static"] = same >= STATIC_MIN_FRAMES and same >= STATIC_SHARE * frames


# A face in CCTV footage is small. On the second drive the two strongest
# "faces" (0.997 and 0.978) were boxes spanning most of the frame - a floor,
# and buckets on a ledge; 64 of 138 face boxes had a side over 60% of the
# frame. A face box wider or taller than this share of the frame is flagged
# implausible and not counted.
MAX_FACE_SIDE = 0.25


def flag_implausible(hits: list[dict]) -> None:
    for h in hits:
        for d in h["detections"]:
            x1, y1, x2, y2 = d["box"]
            d["implausible"] = d["label"] == "face" and max(x2 - x1, y2 - y1) > MAX_FACE_SIDE


def counted(d: dict) -> bool:
    return not d.get("static") and not d.get("implausible") and not d.get("weak")


# A parked car is static by definition, so the rule above removes it: on our
# own drive the car parked in view all night was seen and then removed.  A car,
# bus or truck that stays in one place is instead reported once per place, as
# a parked vehicle - a lead of its own, apart from the moving vehicles counted
# frame by frame.  Its boxes are kept from a lower score (analytics/models.py
# parked_min): a box that comes back at the same place frame after frame is
# stronger evidence than one box at that score.
PARKED_LABELS = ("car", "bus", "truck")
PARKED_PLACE_IOU = 0.5          # boxes this close are the same place


def parked_spots(hits: list[dict], key: str = "t_s") -> list[dict]:
    """Places where a static car, bus or truck was seen, strongest first:
    label (the most common), box (the strongest), best score, the number of
    frames, and the first and last hit's `key`."""
    spots: list[dict] = []
    for h in hits:
        for d in h["detections"]:
            if d["label"] not in PARKED_LABELS or not d.get("static"):
                continue
            s = next((s for s in spots if _iou(s["box"], d["box"]) >= PARKED_PLACE_IOU), None)
            if s is None:
                s = {"box": d["box"], "best": 0.0, "labels": {}, "seen": []}
                spots.append(s)
            if d["score"] > s["best"]:
                s["best"], s["box"] = d["score"], d["box"]
            s["labels"][d["label"]] = s["labels"].get(d["label"], 0) + 1
            if not s["seen"] or s["seen"][-1] != h.get(key):
                s["seen"].append(h.get(key))
    out = [{"label": max(s["labels"], key=s["labels"].get), "box": s["box"],
            "best": round(s["best"], 3), "frames": len(s["seen"]),
            "first": s["seen"][0], "last": s["seen"][-1]} for s in spots]
    return sorted(out, key=lambda s: -s["best"])


def recount(result: dict) -> dict:
    """Re-apply the static and implausible rules to a stored analytics result
    (boxes are kept, so no video needs decoding) and recompute the totals."""
    totals: dict[str, int] = {}
    flagged: dict[str, int] = {}
    for c in result["clips"]:
        hits = c["detections"]
        flag_static(hits, c["frames_analysed"])
        flag_implausible(hits)
        c["frames_with"] = {}
        for h in hits:
            for label in {d["label"] for d in h["detections"] if counted(d)}:
                c["frames_with"][label] = c["frames_with"].get(label, 0) + 1
            for label in {d["label"] for d in h["detections"] if not counted(d)}:
                flagged[label] = flagged.get(label, 0) + 1
        for k, v in c["frames_with"].items():
            totals[k] = totals.get(k, 0) + v
        c["parked_vehicles"] = parked_spots(hits)
    result["frames_with_totals"] = totals
    result["parked_vehicle_spots"] = sum(len(c["parked_vehicles"]) for c in result["clips"])
    result["flagged_not_counted"] = flagged
    result["implausible_rule"] = f"face box wider or taller than {MAX_FACE_SIDE:.0%} of the frame"
    return result

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
    return not d.get("static") and not d.get("implausible")


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
    result["frames_with_totals"] = totals
    result["flagged_not_counted"] = flagged
    result["implausible_rule"] = f"face box wider or taller than {MAX_FACE_SIDE:.0%} of the frame"
    return result

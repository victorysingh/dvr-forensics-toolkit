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

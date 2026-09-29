"""Static rule: how loose may the box match be?  STATIC_IOU 0.8 (today) vs 0.7 / 0.6, on both sets."""
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
from score_v3 import VEH, applied, fmt, set_a, set_b  # noqa: E402
import analytics.static as ST  # noqa: E402

for cfg in ("ssd_t3", "ys_t1", "ys_t2"):
    for iou in (0.8, 0.7, 0.6, 0.5):
        ST.STATIC_IOU = iou
        out = applied(cfg, 0.5, {"person"} | VEH)
        pa, va = set_a(out, "person", {"person"}), set_a(out, "vehicle", VEH)
        fb, bins, extra = set_b(out)
        found = sum(v[0] for v in bins.values())
        print(f"{cfg:<7} static IoU {iou}: A person {fmt(*pa)} | A vehicle {fmt(*va)} | "
              f"B frames {fmt(*fb)} | B people {found}/1089 | B unmatched {extra}")
ST.STATIC_IOU = 0.8

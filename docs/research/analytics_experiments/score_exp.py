import copy
import csv
import json
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics.static import flag_implausible, flag_static  # noqa: E402

CLASSES = {"person": {"person"}, "face": {"face"},
           "vehicle": {"car", "bus", "truck", "motorcycle", "bicycle"}}
data = json.load(open(r"C:/Users/JAIPREET SINGH/150/recall/exp_dets.json"))
labels = {int(r["frame"]): r for r in csv.DictReader(open(
    r"C:/Users/JAIPREET SINGH/150/recall/base/labels.csv", encoding="utf-8"))}


def apply(hits, thr, static_mode):
    hits = copy.deepcopy(hits)
    for h in hits:
        h["detections"] = [d for d in h["detections"] if d["label"] == "face" or d["score"] >= thr]
    by_clip = {}
    for h in hits:
        by_clip.setdefault(h["clip"], []).append(h)
    for clip, hs in by_clip.items():
        with_d = [x for x in hs if x["detections"]]
        flag_static(with_d, len(hs))
        flag_implausible(with_d)
    for h in hits:
        for d in h["detections"]:
            if d["label"] == "person" and d.get("static"):
                if static_mode == "exempt" or (static_mode == "confident" and d["score"] >= 0.7):
                    d["static"] = False
    return hits


def score(hits, cls):
    tp = fp = fn = tn = 0
    for h in hits:
        truth = labels[h["frame"]][cls].strip().lower() == "y"
        said = any(d["label"] in CLASSES[cls] and not d.get("static") and not d.get("implausible")
                   for d in h["detections"])
        tp += said and truth; fp += said and not truth; fn += truth and not said; tn += not said and not truth
    return tp, fp, fn, tn


print(f"{'grid':<5} {'thr':<4} {'static':<9} | person found  false | face found false | vehicle found false")
for grid in ("full", "2x2", "3x2", "3x3"):
    for thr in (0.5, 0.4, 0.6):
        for sm in ("rule", "confident", "exempt"):
            hits = apply(data["grids"][grid], thr, sm)
            row = []
            for cls in ("person", "face", "vehicle"):
                tp, fp, fn, tn = score(hits, cls)
                row.append(f"{tp:>3}/{tp + fn:<3} {fp:>4}/{fp + tn:<4}")
            print(f"{grid:<5} {thr:<4} {sm:<9} | " + " | ".join(row))

"""Score: resolution x grid, faces from the whole frame or from tiles; per-clip person breakdown."""
import copy
import csv
import json
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics.static import flag_implausible, flag_static  # noqa: E402

CLASSES = {"person": {"person"}, "face": {"face"},
           "vehicle": {"car", "bus", "truck", "motorcycle", "bicycle"}}
R = r"C:/Users/JAIPREET SINGH/150/recall/"
runs = {"native": json.load(open(R + "exp_dets.json"))["grids"],
        "640": json.load(open(R + "exp_dets_640.json"))["grids"]}
labels = {int(r["frame"]): r for r in csv.DictReader(open(R + "base/labels.csv", encoding="utf-8"))}


def combine(res, grid, face_grid, thr):
    obj, fac = res[grid], res[face_grid]
    hits = []
    for o, f in zip(obj, fac):
        assert o["frame"] == f["frame"]
        dets = [d for d in o["detections"] if d["label"] != "face" and d["score"] >= thr]
        dets += [d for d in f["detections"] if d["label"] == "face"]
        hits.append({"frame": o["frame"], "clip": o["clip"], "detections": copy.deepcopy(dets)})
    by_clip = {}
    for h in hits:
        by_clip.setdefault(h["clip"], []).append(h)
    for hs in by_clip.values():
        with_d = [x for x in hs if x["detections"]]
        flag_static(with_d, len(hs))
        flag_implausible(with_d)
    return hits


def said(h, cls, reported=True):
    return any(d["label"] in CLASSES[cls] and (not reported or (not d.get("static") and not d.get("implausible")))
               for d in h["detections"])


def score(hits, cls, reported=True):
    tp = fp = fn = tn = 0
    for h in hits:
        t = labels[h["frame"]][cls].strip().lower() == "y"
        s = said(h, cls, reported)
        tp += s and t; fp += s and not t; fn += t and not s; tn += not s and not t
    return tp, fp, fn, tn


print("res    objects faces | person      | face        | vehicle   (found/with  false/without, as reported)")
for res in ("640", "native"):
    for grid in ("full", "2x2", "3x3"):
        for fg in ("full", grid) if grid != "full" else ("full",):
            hits = combine(runs[res], grid, fg, 0.5)
            row = []
            for cls in CLASSES:
                tp, fp, fn, tn = score(hits, cls)
                row.append(f"{tp:>2}/{tp + fn:<2} {fp:>2}/{fp + tn:<3}")
            print(f"{res:<6} {grid:<7} {fg:<5} | " + " | ".join(row))

print("\nper clip, person, native 3x3 (objects) + full (faces), 0.5:")
hits = combine(runs["native"], "3x3", "full", 0.5)
base = combine(runs["640"], "full", "full", 0.5)
clips = []
for h in hits:
    if h["clip"] not in clips:
        clips.append(h["clip"])
for c in clips:
    hs = [h for h in hits if h["clip"] == c]
    bs = [h for h in base if h["clip"] == c]
    w = sum(labels[h["frame"]]["person"] == "y" for h in hs)
    f = sum(labels[h["frame"]]["person"] == "y" and said(h, "person") for h in hs)
    fm = sum(labels[h["frame"]]["person"] == "y" and said(h, "person", False) for h in hs)
    b = sum(labels[h["frame"]]["person"] == "y" and said(h, "person") for h in bs)
    st = sum(labels[h["frame"]]["person"] == "y" and said(h, "person", False) and not said(h, "person") for h in hs)
    print(f"  {c[:44]:<44} frames {len(hs):>3} with person {w:>2}  before {b:>2}  now {f:>2}  "
          f"(models {fm:>2}, of which static {st})")
    notes = [labels[h["frame"]]["notes"] for h in hs if labels[h["frame"]]["person"] == "y" and not said(h, "person", False)]
    for n in sorted(set(notes))[:6]:
        print("      missed:", n[:110])

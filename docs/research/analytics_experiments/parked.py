"""Parked vehicles: a vehicle box that stays in one place through much of a clip (the static
rule's own test) reported as its own lead, once per spot, at a lower score.  Which spots would
it report on set A (labels) and CAVIAR (no vehicles at all, so every spot is a false one)?"""
import copy
import csv
import json
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics.static import _iou, flag_static  # noqa: E402

R = r"C:/Users/JAIPREET SINGH/150/recall/"
VEH = {"car", "bus", "truck", "motorcycle", "bicycle"}


def spots(frames_dets, thr):
    """Parked-vehicle spots in one clip: static vehicle boxes >= thr, grouped by place."""
    hits = [{"detections": [copy.copy(d) for d in ds if d["label"] in VEH and d["score"] >= thr]}
            for ds in frames_dets]
    flag_static([h for h in hits if h["detections"]], len(frames_dets))
    out = []
    for f, h in enumerate(hits):
        for d in h["detections"]:
            if not d.get("static"):
                continue
            for s in out:
                if _iou(s["box"], d["box"]) >= 0.5:
                    s["frames"].add(f)
                    s["best"] = max(s["best"], d["score"])
                    break
            else:
                out.append({"box": d["box"], "frames": {f}, "best": d["score"], "label": d["label"]})
    return out


# set A: the tool's own sample (any-score boxes, current default incl. rotation)
A = json.load(open(R + "v5_rotate/detections.json"))["detections"]
lab = {int(r["frame"]): r for r in csv.DictReader(open(R + "v5_rotate/labels.csv", encoding="utf-8"))}
clips = {}
for x in A:
    clips.setdefault(lab[x["frame"]]["clip"], []).append(x)
print("SET A")
for thr in (0.5, 0.4, 0.3, 0.25):
    print(f" threshold {thr}")
    for clip, xs in clips.items():
        xs.sort(key=lambda x: x["frame"])
        for s in spots([x["any_score"] for x in xs], thr):
            fr = sorted(xs[f]["frame"] for f in s["frames"])
            yes = sum(lab[f]["vehicle"] == "y" for f in fr)
            print(f"   {clip[:28]:<28} {s['label']:<10} best {s['best']:.2f} in {len(fr):>3}/{len(xs)} frames,"
                  f" labelled vehicle in {yes}; box {[round(v, 2) for v in s['box']]}"
                  f" | {lab[fr[0]]['notes'][:50]}")

# CAVIAR: no vehicles at all; YOLOX-S 2x2 boxes kept down to 0.1 (exp_v3)
data = json.load(open(R + "exp_v3.json"))
fr = data["frames"]
dets = data["dets"]["ys_t2"]
cav = {}
for i, f in enumerate(fr):
    if f["set"] == "B":
        cav.setdefault(f["clip"], []).append(dets[i])
print("CAVIAR (no vehicles: every spot is false)")
for thr in (0.5, 0.4, 0.3, 0.25):
    n = [(c, len(s["frames"]), round(s["best"], 2), s["label"]) for c, ds in cav.items() for s in spots(ds, thr)]
    print(f" threshold {thr}: {len(n)} spots {n[:6]}")

"""Score exp_v3.json.  Set A: frame-level person / face / vehicle against #53's labels, as the
tool reports (static and implausible rules applied per clip).  Set B (CAVIAR, never used for
choosing): person frame-level recall and false alarms, and box-level recall by person height."""
import copy
import csv
import json
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics.static import _iou, counted, flag_implausible, flag_static  # noqa: E402

R = r"C:/Users/JAIPREET SINGH/150/recall/"
VEH = {"car", "bus", "truck", "motorcycle", "bicycle"}
data = json.load(open(R + "exp_v3.json"))
frames = data["frames"]
labels = {int(r["frame"]): r for r in csv.DictReader(open(R + "base/labels.csv", encoding="utf-8"))}
A = [i for i, f in enumerate(frames) if f["set"] == "A"]
B = [i for i, f in enumerate(frames) if f["set"] == "B"]


def applied(cfg, thr, keep):
    """Detections of `cfg` at `thr` (labels in `keep`), the rules applied per clip."""
    out = [[copy.copy(d) for d in ds if d["label"] in keep and d["score"] >= thr]
           for ds in data["dets"][cfg]]
    clips = {}
    for i, f in enumerate(frames):
        clips.setdefault((f["set"], f["clip"]), []).append(i)
    for idx in clips.values():
        hits = [{"detections": out[i]} for i in idx if out[i]]
        flag_static(hits, len(idx))
        flag_implausible(hits)
    return out


def frame_score(out, idx, truth, names):
    tp = fp = fn = tn = 0
    for i in idx:
        t = truth(i)
        s = any(d["label"] in names and counted(d) for d in out[i])
        tp += s and t; fp += s and not t; fn += t and not s; tn += not s and not t
    return tp, fp, fn, tn


def set_a(out, cls, names):
    return frame_score(out, A, lambda i: labels[A.index(i)][cls] == "y", names)


def set_b(out):
    fr = frame_score(out, B, lambda i: bool(frames[i]["gt"]), {"person"})
    bins = {"<40px": [0, 0], "40-80px": [0, 0], ">=80px": [0, 0]}
    extra = 0
    for i in B:
        dets = [d for d in out[i] if d["label"] == "person" and counted(d)]
        for g in frames[i]["gt"]:
            k = "<40px" if g[4] < 40 else ("40-80px" if g[4] < 80 else ">=80px")
            bins[k][1] += 1
            bins[k][0] += any(_iou(d["box"], g[:4]) >= 0.3 for d in dets)
        extra += sum(1 for d in dets if all(_iou(d["box"], g[:4]) < 0.1 for g in frames[i]["gt"]))
    return fr, bins, extra


def fmt(tp, fp, fn, tn):
    return f"{tp:>3}/{tp + fn:<3} fa {fp:>3}/{fp + tn:<3}"


secs = data["seconds"]
n = len(frames)
print(f"frames: A {len(A)}, B {len(B)} (B with a person: {sum(1 for i in B if frames[i]['gt'])})")
print("\nOBJECTS  config  thr  | A person          | A vehicle         | B person (frames)   | B boxes found by height          | B unmatched boxes | s/frame")
for cfg in ("ssd_t1", "ssd_t3", "yt_t1", "yt_t3", "ys_t1", "ys_t2", "ys_t3"):
    for thr in (0.3, 0.4, 0.5, 0.6, 0.7):
        out = applied(cfg, thr, {"person"} | VEH)
        pa = set_a(out, "person", {"person"})
        va = set_a(out, "vehicle", VEH)
        fb, bins, extra = set_b(out)
        b = "  ".join(f"{k} {v[0]:>3}/{v[1]:<3}" for k, v in bins.items())
        print(f"  {cfg:<7} {thr:<4} | {fmt(*pa)} | {fmt(*va)} | {fmt(*fb)} | {b} | {extra:>5} | {secs[cfg] / n:.2f}")
print("\nFACES  config  thr  | A face (as reported) | A face (as the model said) | s/frame")
for cfg in ("uf_t1", "uf_t3", "yn_small", "yn_big"):
    for thr in (0.5, 0.6, 0.7, 0.8, 0.9):
        out = applied(cfg, thr, {"face"})
        fa = set_a(out, "face", {"face"})
        raw = frame_score([[dict(d, static=False, implausible=False) for d in ds] for ds in out], A,
                          lambda i: labels[A.index(i)]["face"] == "y", {"face"})
        print(f"  {cfg:<8} {thr:<4} | {fmt(*fa)} | {fmt(*raw)} | {secs[cfg] / n:.3f}")

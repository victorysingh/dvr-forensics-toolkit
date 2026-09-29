"""Score exp_rot.json: base (the tool today) vs rotation, always / people+faces only, on set A
(labels) and set B (CAVIAR boxes).  Tool thresholds: face 0.7, person 0.4, other objects 0.5."""
import copy
import csv
import json
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics.models import threshold  # noqa: E402
from analytics.static import _iou, counted, flag_implausible, flag_static  # noqa: E402

R = r"C:/Users/JAIPREET SINGH/150/recall/"
VEH = {"car", "bus", "truck", "motorcycle", "bicycle"}
data = json.load(open(R + "exp_rot.json"))
frames = data["frames"]
labels = {int(r["frame"]): r for r in csv.DictReader(open(R + "base/labels.csv", encoding="utf-8"))}
A = [i for i, f in enumerate(frames) if f["set"] == "A"]
B = [i for i, f in enumerate(frames) if f["set"] == "B"]


def variant(name):
    out = []
    for i in range(len(frames)):
        if name == "base":
            ds = data["dets"]["base"][i]
        elif name == "rot":
            ds = data["dets"]["rot"][i]
        else:                                   # rotated views for people and faces only
            ds = [d for d in data["dets"]["rot"][i] if not d.get("rot") or d["label"] in ("person", "face")]
        out.append([copy.copy(d) for d in ds if d["score"] >= threshold("yolox", d["label"])])
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


def fmt(tp, fp, fn, tn):
    return f"{tp:>3}/{tp + fn:<3} fa {fp:>2}"


for name in ("base", "rot", "rot_people_faces"):
    out = variant(name)
    row = []
    for cls, names in (("person", {"person"}), ("face", {"face"}), ("vehicle", VEH)):
        row.append(f"{cls} " + fmt(*frame_score(out, A, lambda i: labels[A.index(i)][cls] == "y", names)))
    fish = [i for i in A if frames[i]["clip"].startswith("ffmpeg_t6144")]
    fp_ = frame_score(out, fish, lambda i: labels[A.index(i)]["person"] == "y", {"person"})
    ff_ = frame_score(out, fish, lambda i: labels[A.index(i)]["face"] == "y", {"face"})
    found = lab = unmatched = 0
    inria = {"Walk1.mpg", "Browse1.mpg", "Meet_WalkTogether1.mpg"}
    fi = li = 0
    for i in B:
        people = [d for d in out[i] if d["label"] == "person" and counted(d)]
        for g in frames[i]["gt"]:
            hit = any(_iou(d["box"], g[:4]) >= 0.3 for d in people)
            found += hit; lab += 1
            if frames[i]["clip"] in inria:
                fi += hit; li += 1
        unmatched += sum(1 for d in people if all(_iou(d["box"], g[:4]) < 0.1 for g in frames[i]["gt"]))
    bf = frame_score(out, B, lambda i: bool(frames[i]["gt"]), {"person"})
    print(f"{name:<17} A: {' | '.join(row)} || fisheye person {fp_[0]}/{fp_[0] + fp_[2]} face {ff_[0]}/{ff_[0] + ff_[2]}"
          f" || CAVIAR people {found}/{lab} (lobby {fi}/{li}), empty frames with a person {bf[1]}/{bf[1] + bf[3]},"
          f" unmatched {unmatched}")
print({k: round(v / len(frames), 3) for k, v in data["seconds"].items()}, "s/frame")

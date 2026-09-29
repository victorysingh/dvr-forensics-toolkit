"""How often the analytics layer is right, on real footage, against labels.

    python -m validate.analytics_eval sample CLIP --out DIR [--frames 200]
    #   ... fill in DIR/labels.csv: person, face, vehicle as y or n ...
    python -m validate.analytics_eval score DIR

`analytics/detect.py` reports faces, people and vehicles as leads, and until
now no number said how good those leads are.  This measures it, frame by
frame, the way an examiner would use it: does the tool say "someone is in
this frame" when someone is?

  sample  decodes only the clip's keyframes - fast, and spread over the whole
          recording, day and night - keeps --frames of them evenly, and runs
          both detectors exactly as the tool does: the same thresholds, and
          the same static and implausible-box rules (analytics/static.py).
          It writes frames/NNN.jpg (the plain frame, no boxes drawn, so the
          labelling is not led by the detector), sheets/SS.jpg (4 x 4 contact
          sheets of those frames, in order, left to right), detections.json,
          and labels.csv with a row per frame to fill in.
  score   per class, frame-level precision, recall, F1 and false-alarm rate
          (share of frames without the class where the tool said it was
          there) - as the tool reports (static and implausible detections not
          counted) and as the models said (everything over threshold) - and
          every frame where the detector and the label disagree, for review.
          A class no labelled frame contains has no recall: the false-alarm
          rate is then the only number the labels support.

A frame counts as positive for a class when at least one detection of it is
reported.  Labels are what a person can see in the frame at the size stored
(640 x 360): "face" means a face turned enough towards the camera to be seen
as one.  Needs what the analytics layer needs (numpy, onnxruntime, ffmpeg,
the pinned models - analytics/README.md) to sample; scoring needs only the
standard library.  Read-only on the clip.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys

from analytics.static import counted, flag_implausible, flag_static

CLASSES = {"person": {"person"}, "face": {"face"},
           "vehicle": {"car", "bus", "truck", "motorcycle", "bicycle"}}
SHEET = 4                                # contact sheets are SHEET x SHEET frames


def _codec(clip: str) -> list[str]:
    c = "h264" if clip.endswith(".h264") else ("" if clip.endswith(".ps") else "hevc")
    return ["-f", c] if c else []


def keyframes(clip: str, every: int = 1, w: int | None = None, h: int | None = None):
    """(keyframe index, RGB frame) for every `every`-th keyframe of the clip."""
    import numpy as np

    from analytics import detect
    w, h = w or detect.DECODE_W, h or detect.DECODE_H
    cmd = ["ffmpeg", "-nostdin", "-v", "quiet", "-skip_frame", "nokey", *_codec(clip),
           "-i", clip, "-vf", f"select=not(mod(n\\,{every})),scale={w}:{h}",
           "-fps_mode", "vfr", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
    n = w * h * 3
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        k = 0
        while True:
            buf = p.stdout.read(n)
            if len(buf) < n:
                break
            yield k * every, np.frombuffer(buf, np.uint8).reshape(h, w, 3)
            k += 1


def sample(clip: str, out: str, frames: int, log=print) -> dict:
    from analytics import detect
    log("counting keyframes ...")
    total = sum(1 for _ in keyframes(clip, 1, 32, 18))
    if not total:
        raise SystemExit(f"no decodable keyframe in {clip}")
    every = max(1, total // frames)
    models = detect.load_models()
    os.makedirs(os.path.join(out, "frames"), exist_ok=True)
    rows, hits, n = [], [], 0
    log(f"{total} keyframes; keeping every {every}th, running both detectors ...")
    for idx, rgb in keyframes(clip, every):
        if n >= frames:
            break
        name = f"{n:03d}.jpg"
        detect._thumbnail(rgb, [], os.path.join(out, "frames", name))
        dets = detect.faces(models["face"], rgb) + detect.objects(models["objects"], rgb)
        hits.append({"frame": n, "keyframe": idx, "detections": dets})
        rows.append({"frame": n, "file": f"frames/{name}", "sheet": n // SHEET ** 2,
                     "row": n % SHEET ** 2 // SHEET, "col": n % SHEET,
                     "position": round(idx / total, 4),
                     "person": "", "face": "", "vehicle": "", "notes": ""})
        n += 1
    # the same rules the report applies, over the sampled frames
    with_dets = [x for x in hits if x["detections"]]
    flag_static(with_dets, n)
    flag_implausible(with_dets)
    os.makedirs(os.path.join(out, "sheets"), exist_ok=True)
    subprocess.run(["ffmpeg", "-nostdin", "-v", "quiet", "-y", "-start_number", "0",
                    "-i", os.path.join(out, "frames", "%03d.jpg"),
                    "-vf", f"tile={SHEET}x{SHEET}:margin=4:padding=4",
                    os.path.join(out, "sheets", "%02d.jpg")], check=False)
    with open(os.path.join(out, "labels.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    res = {"clip": os.path.basename(clip), "clip_sha256": detect.sha256_file(clip),
           "keyframes": total, "every": every, "frames": n,
           "models": {k: m["sha256"] for k, m in detect.MODELS.items()},
           "thresholds": {"face": detect.FACE_MIN, "objects": detect.OBJECT_MIN},
           "detections": hits}
    with open(os.path.join(out, "detections.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    log(f"{n} frames in {out}: frames/, sheets/ ({(n + SHEET ** 2 - 1) // SHEET ** 2}), "
        "detections.json, labels.csv - fill in person / face / vehicle (y or n)")
    return res


def score(out: str) -> dict:
    with open(os.path.join(out, "detections.json"), encoding="utf-8") as fh:
        det = {x["frame"]: x["detections"] for x in json.load(fh)["detections"]}
    with open(os.path.join(out, "labels.csv"), newline="", encoding="utf-8") as fh:
        labels = list(csv.DictReader(fh))
    res: dict = {"frames_labelled": 0, "classes": {}}
    for cls, names in CLASSES.items():
        for view in ("as reported", "as the models said"):
            tp = fp = fn = tn = 0
            wrong = []
            for row in labels:
                truth = row[cls].strip().lower()
                if truth not in ("y", "n"):
                    continue
                ds = [d for d in det.get(int(row["frame"]), []) if d["label"] in names
                      and (view == "as the models said" or counted(d))]
                said, true = bool(ds), truth == "y"
                tp += said and true
                fp += said and not true
                fn += true and not said
                tn += not said and not true
                if said != true:
                    wrong.append({"frame": int(row["frame"]),
                                  "error": "missed" if true else "false alarm",
                                  "scores": [d["score"] for d in ds]})
            p = tp / (tp + fp) if tp + fp else None
            r = tp / (tp + fn) if tp + fn else None
            f1 = 2 * p * r / (p + r) if p and r else None
            fa = fp / (fp + tn) if fp + tn else None
            res["classes"].setdefault(cls, {})[view] = {
                "frames_with": tp + fn, "frames_without": fp + tn,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(p, 3) if p is not None else None,
                "recall": round(r, 3) if r is not None else None,
                "f1": round(f1, 3) if f1 is not None else None,
                "false_alarm_rate": round(fa, 4) if fa is not None else None,
                "disagreements": wrong}
    res["frames_labelled"] = sum(1 for row in labels
                                 if any(row[c].strip().lower() in ("y", "n") for c in CLASSES))
    with open(os.path.join(out, "score.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("clip")
    s.add_argument("--out", required=True)
    s.add_argument("--frames", type=int, default=200)
    sc = sub.add_parser("score")
    sc.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "sample":
        sample(a.clip, a.out, a.frames)
        return 0
    res = score(a.out)
    print(f"{res['frames_labelled']} frames labelled")
    for cls, views in res["classes"].items():
        for view, m in views.items():
            print(f"  {cls:<8} {view:<19} with {m['frames_with']:>3}  without "
                  f"{m['frames_without']:>3}   precision {m['precision']}   recall "
                  f"{m['recall']}   F1 {m['f1']}   false alarms {m['fp']}/{m['frames_without']}"
                  f"   (tp {m['tp']} fp {m['fp']} fn {m['fn']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

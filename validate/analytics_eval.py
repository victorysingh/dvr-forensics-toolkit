"""How often the analytics layer is right, on real footage, against labels.

    python -m validate.analytics_eval sample CLIP [CLIP ...] --out DIR [--frames 200 | --fps 2] [--tiles 3]
    #   ... fill in DIR/labels.csv: person, face, vehicle as y or n ...
    python -m validate.analytics_eval score DIR
    python -m validate.analytics_eval sweep DIR     # would another threshold do better?

A clip is a raw H.264/H.265 stream (as extracted) or any container ffmpeg
reads (.mp4, .avi, .dav, .ps ...).  Several clips go into one labelled set;
CLIP@RATE samples that clip at its own rate, so a long clip does not
outweigh the rest.

`analytics/detect.py` reports faces, people and vehicles as leads, and until
now no number said how good those leads are.  This measures it, frame by
frame, the way an examiner would use it: does the tool say "someone is in
this frame" when someone is?

  sample  decodes only the clip's keyframes - fast, and spread over the whole
          recording, day and night - keeps --frames of them evenly (or, with
          --fps, takes every clip at that rate: short clips have few
          keyframes), and runs both detectors exactly as the tool does: the
          same tiling (--tiles; the object model on a 1920 x 1080 decode,
          the face model on 640 x 360), the same thresholds, and the same
          static and implausible-box rules (analytics/static.py), applied
          per clip.  It also keeps every box down to the lowest thresholds
          in SWEEP, for `sweep`.
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
  sweep   scores each class at every threshold in SWEEP, before and after
          the rules, from the boxes `sample` kept at low scores - exactly
          the boxes the tool would report at each threshold, with nothing
          run again - whether a miss is the threshold's or the model's.

The labels behind docs/VALIDATION_REPORT.md section 8a (six public recorder
clips, 287 frames) are in validate/analytics_labels.csv.

A frame counts as positive for a class when at least one detection of it is
reported.  Labels are what a person can see in the frame at the size stored
(640 x 360): "face" means a face turned enough towards the camera to be seen
as one.  Needs what the analytics layer needs (numpy, onnxruntime, ffmpeg,
the pinned models - analytics/README.md) to sample; scoring and sweeping
need only the standard library.  Read-only on the clip.
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


RAW = {".h264": "h264", ".264": "h264", ".h265": "hevc", ".hevc": "hevc", ".265": "hevc",
       ".es": "hevc"}


def _codec(clip: str) -> list[str]:
    """A raw elementary stream needs its format named; a container (.mp4,
    .avi, .dav, .ps, ...) is left to ffmpeg to recognise."""
    fmt = RAW.get(os.path.splitext(clip)[1].lower())
    return ["-f", fmt] if fmt else []


def at_rate(clip: str, fps: float, w: int | None = None, h: int | None = None):
    """(frame index, RGB frame) at `fps` frames per second of the clip - for
    short clips, where keyframes are too few to sample."""
    import numpy as np

    from analytics import detect
    w, h = w or detect.DECODE_W, h or detect.DECODE_H
    cmd = ["ffmpeg", "-nostdin", "-v", "quiet", *_codec(clip), "-i", clip,
           "-vf", f"fps={fps},scale={w}:{h}", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
    n = w * h * 3
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        k = 0
        while True:
            buf = p.stdout.read(n)
            if len(buf) < n:
                break
            yield k, np.frombuffer(buf, np.uint8).reshape(h, w, 3)
            k += 1


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


def sample(clips, out: str, frames: int = 200, fps: float | None = None, log=print,
           tiles: int | None = None) -> dict:
    """Frames from one clip or several, both detectors run on each, as the
    tool runs them (`tiles` x `tiles` tiles, by default the tool's).  With
    `fps`, every clip is sampled at that rate; without, keyframes are spread
    evenly to `frames` per clip."""
    from analytics import detect
    clips = [clips] if isinstance(clips, str) else list(clips)
    models = detect.load_models()
    tiles = detect.TILES if tiles is None else tiles
    scale = detect.OBJECT_SCALE if tiles > 1 else 1
    w, h = detect.DECODE_W * scale, detect.DECODE_H * scale
    tool = (detect.FACE_MIN, detect.OBJECT_MIN)
    low = (min(SWEEP["face"]), min(SWEEP["objects"]))
    os.makedirs(os.path.join(out, "frames"), exist_ok=True)
    rows, hits, per_clip, n = [], [], [], 0
    default_fps = fps
    for ci, clip in enumerate(clips):
        fps = default_fps
        path, _, rate = clip.rpartition("@")      # CLIP@RATE: this clip at its own rate
        if path and rate.replace(".", "", 1).isdigit():
            clip, fps = path, float(rate)
        if fps:
            source, total, every = at_rate(clip, fps, w, h), None, None
            log(f"{os.path.basename(clip)}: {fps:g} frames a second, both detectors ...")
        else:
            total = sum(1 for _ in keyframes(clip, 1, 32, 18))
            if not total:
                raise SystemExit(f"no decodable keyframe in {clip}")
            every = max(1, total // frames)
            source = keyframes(clip, every, w, h)
            log(f"{os.path.basename(clip)}: {total} keyframes; every {every}th, both detectors ...")
        first, clip_hits = n, []
        for idx, big in source:
            if not fps and n - first >= frames:
                break
            name = f"{n:03d}.jpg"
            rgb = detect.shrink(big, scale)
            detect._thumbnail(rgb, [], os.path.join(out, "frames", name))
            try:                    # every box down to SWEEP's lowest; the tool's are a subset
                detect.FACE_MIN, detect.OBJECT_MIN = low
                any_score = detect.detect_frame(models, rgb, big, tiles)
            finally:
                detect.FACE_MIN, detect.OBJECT_MIN = tool
            dets = [dict(d) for d in any_score
                    if d["score"] >= (tool[0] if d["label"] == "face" else tool[1])]
            x = {"frame": n, "clip": ci, "index": idx, "detections": dets, "any_score": any_score}
            hits.append(x)
            clip_hits.append(x)
            rows.append({"frame": n, "file": f"frames/{name}", "clip": os.path.basename(clip),
                         "sheet": n // SHEET ** 2, "row": n % SHEET ** 2 // SHEET,
                         "col": n % SHEET,
                         "position": (f"{idx / fps:.1f} s" if fps else round(idx / total, 4)),
                         "person": "", "face": "", "vehicle": "", "notes": ""})
            n += 1
        # the same rules the report applies, over each clip's own frames
        with_dets = [x for x in clip_hits if x["detections"]]
        flag_static(with_dets, len(clip_hits))
        flag_implausible(with_dets)
        per_clip.append({"clip": os.path.basename(clip), "clip_sha256": detect.sha256_file(clip),
                         "frames": len(clip_hits), "first_frame": first,
                         "sampling": f"{fps:g} fps" if fps else f"every {every}th of {total} keyframes"})
        if not clip_hits:
            log(f"  no frame decoded from {clip}")
    os.makedirs(os.path.join(out, "sheets"), exist_ok=True)
    subprocess.run(["ffmpeg", "-nostdin", "-v", "quiet", "-y", "-start_number", "0",
                    "-i", os.path.join(out, "frames", "%03d.jpg"),
                    "-vf", f"tile={SHEET}x{SHEET}:margin=4:padding=4",
                    # numbered from 00, as labels.csv's `sheet` column is
                    "-start_number", "0",
                    os.path.join(out, "sheets", "%02d.jpg")], check=False)
    with open(os.path.join(out, "labels.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    res = {"clips": per_clip, "frames": n,
           "models": {k: m["sha256"] for k, m in detect.MODELS.items()},
           "thresholds": {"face": detect.FACE_MIN, "objects": detect.OBJECT_MIN},
           "any_score_down_to": {"face": low[0], "objects": low[1]},
           "tiles": tiles, "decoded_at": {"objects": f"{w} x {h}",
                                          "faces": f"{detect.DECODE_W} x {detect.DECODE_H}"},
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


SWEEP = {"face": (0.5, 0.6, 0.7, 0.8, 0.9), "objects": (0.2, 0.3, 0.4, 0.5, 0.6)}


def over(everything: list, clip_of: list, t_face: float, t_obj: float) -> list:
    """Each frame's detections at these thresholds, with the static and
    implausible rules applied per clip as the tool applies them.  Copies:
    the rules write their flags into the detections they are given."""
    kept = [[dict(d) for d in dets if d["score"] >= (t_face if d["label"] == "face" else t_obj)]
            for dets in everything]
    for ci in set(clip_of):
        frames = [f for f, c in enumerate(clip_of) if c == ci]
        hits = [{"detections": kept[f]} for f in frames if kept[f]]
        flag_static(hits, len(frames))
        flag_implausible(hits)
    return kept


def rescore(everything: list, clip_of: list, labels: dict) -> dict:
    """Every class scored at each threshold in SWEEP, from detections kept
    at any score: `everything[f]` is frame f's, `clip_of[f]` its clip, and
    `labels` the labels.csv rows by frame.  Standard library only."""
    res: dict = {}
    for cls, names in CLASSES.items():
        for t in SWEEP["face" if cls == "face" else "objects"]:
            kept = over(everything, clip_of, t, t)
            row = {"threshold": t}
            for view in ("as reported", "as the models said"):
                tp = fp = fn = tn = 0
                for f, lab in labels.items():
                    truth = lab[cls].strip().lower()
                    if truth not in ("y", "n") or f >= len(kept):
                        continue
                    said = any(d["label"] in names and (view == "as the models said"
                                                        or counted(d)) for d in kept[f])
                    true = truth == "y"
                    tp += said and true
                    fp += said and not true
                    fn += true and not said
                    tn += not said and not true
                row[view] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                             "recall": round(tp / (tp + fn), 3) if tp + fn else None,
                             "false_alarm_rate": round(fp / (fp + tn), 4) if fp + tn else None}
            res.setdefault(cls, []).append(row)
    return res


def sweep(out: str, log=print) -> dict:
    """Would another threshold find more?  `sample` kept every box down to
    the lowest thresholds in SWEEP.  A box is only ever dropped for a
    stronger one (face NMS, the merge of overlapping tiles), so those boxes
    filtered at a threshold are exactly what the tool reports there, and
    rescore() scores each class at every threshold, as reported and as the
    models said.  Standard library only: nothing is decoded or run again."""
    with open(os.path.join(out, "detections.json"), encoding="utf-8") as fh:
        det = json.load(fh)
    stored = sorted(det["detections"], key=lambda x: x["frame"])
    if any("any_score" not in x for x in stored):
        raise SystemExit("detections.json keeps no low-score boxes (sampled before 29 Sep 2026)"
                         " - run sample again")
    with open(os.path.join(out, "labels.csv"), newline="", encoding="utf-8") as fh:
        labels = {int(r["frame"]): r for r in csv.DictReader(fh)}
    everything = [x["any_score"] for x in stored]
    clip_of = [x.get("clip", 0) for x in stored]
    log(f"{len(everything)} frames, boxes kept down to face >= {min(SWEEP['face'])}, "
        f"objects >= {min(SWEEP['objects'])}")
    res = {"frames": len(everything), "tool_thresholds": det.get("thresholds"),
           "tiles": det.get("tiles"), "classes": rescore(everything, clip_of, labels)}
    with open(os.path.join(out, "sweep.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("clip", nargs="+", help="one clip or several: raw streams or any container")
    s.add_argument("--out", required=True)
    s.add_argument("--frames", type=int, default=200, help="keyframes kept per clip")
    s.add_argument("--fps", type=float, default=None,
                   help="sample every clip at this rate instead (short clips)")
    s.add_argument("--tiles", type=int, default=None,
                   help="n x n tiles as the tool runs them (default the tool's; 1 = untiled)")
    sc = sub.add_parser("score")
    sc.add_argument("out")
    sw = sub.add_parser("sweep")
    sw.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "sample":
        sample(a.clip, a.out, a.frames, a.fps, tiles=a.tiles)
        return 0
    if a.cmd == "sweep":
        res = sweep(a.out)
        for cls, rows in res["classes"].items():
            for row in rows:
                r, m = row["as reported"], row["as the models said"]
                print(f"  {cls:<8} >= {row['threshold']:.1f}   as reported: found "
                      f"{r['tp']:>3}/{r['tp'] + r['fn']:<3} false alarms {r['fp']:>3}   "
                      f"as the models said: found {m['tp']:>3}/{m['tp'] + m['fn']:<3} "
                      f"false alarms {m['fp']:>3}")
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

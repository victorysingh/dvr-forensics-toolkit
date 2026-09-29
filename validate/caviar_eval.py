"""The analytics layer scored on CAVIAR: footage it was never tuned on, with
every person boxed by hand.

    python -m validate.caviar_eval DIR [--models yolox|classic] [--tiles N] [--every 25]
                                       [--rotate auto|on|off] [--rotate-clips A.mpg,B.mpg]

DIR holds CAVIAR clips (.mpg) and their ground-truth files (.xml), from the
EC-funded CAVIAR project (IST 2001 37540, CC BY-SA),
https://homepages.inf.ed.ac.uk/rbf/CAVIAR/ .  Each clip is paired with the
XML whose <dataset name=...> matches it, or whose name is its only one.
docs/VALIDATION_REPORT.md section 8a used six: Walk1, Browse1 and
Meet_WalkTogether1 (INRIA lobby, a wide-angle camera looking down) and
WalkByShop1cor, OneLeaveShop1cor and ThreePastShop1cor (a shopping-centre
corridor).

`validate.analytics_eval` scores the frames #53 labelled, and every choice in
the layer (models, tiling, thresholds) was made on those.  This is the check
that the choices hold on footage that played no part in them.

It takes every 25th frame (one a second at CAVIAR's 25 fps), runs the
detectors exactly as the tool does (analytics.detect.detect_frame, the
tool's decode size, tiling and thresholds), applies the static and
implausible-box rules per clip, and scores people:
  * box level: a labelled person counts as found when a reported person box
    overlaps theirs by IoU >= 0.3, by the person's height in the 384 x 288
    picture (under 40 px, 40-80, 80 and over);
  * frame level: frames with a labelled person where the tool reported one,
    and frames with nobody labelled where it reported one;
  * reported boxes that overlap no labelled person (IoU < 0.1).  CAVIAR's
    labels miss some people (a head entering at the frame's edge, part of a
    person cut by a tile of the tool's grid), so these are an upper bound on
    false boxes, to be looked at, not a count of errors.
The ground-truth reading and the scoring need only the standard library.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from core import proc
from analytics.static import _iou, counted, flag_implausible, flag_static, parked_spots

SIZE = (384, 288)                            # CAVIAR's picture
BINS = ((0, 40, "under 40 px"), (40, 80, "40-80 px"), (80, 10 ** 6, "80 px and over"))


def ground_truth(xml: str) -> dict[int, list[list[float]]]:
    """frame number -> person boxes [x1, y1, x2, y2 (0-1), height in px]."""
    gt = {}
    for fr in ET.parse(xml).getroot().iter("frame"):
        boxes = []
        for ob in fr.iter("object"):
            b = ob.find("box")
            xc, yc, w, h = (float(b.get(k)) for k in ("xc", "yc", "w", "h"))
            boxes.append([(xc - w / 2) / SIZE[0], (yc - h / 2) / SIZE[1],
                          (xc + w / 2) / SIZE[0], (yc + h / 2) / SIZE[1], h])
        gt[int(fr.get("number"))] = boxes
    return gt


def score(frames: list[dict]) -> dict:
    """frames: {"clip", "gt": boxes, "detections": the tool's boxes, rules applied}."""
    bins = {name: {"found": 0, "labelled": 0} for _, _, name in BINS}
    tp = fp = fn = tn = unmatched = 0
    for f in frames:
        people = [d for d in f["detections"] if d["label"] == "person" and counted(d)]
        for g in f["gt"]:
            name = next(n for lo, hi, n in BINS if lo <= g[4] < hi)
            bins[name]["labelled"] += 1
            bins[name]["found"] += any(_iou(d["box"], g[:4]) >= 0.3 for d in people)
        unmatched += sum(1 for d in people if all(_iou(d["box"], g[:4]) < 0.1 for g in f["gt"]))
        said, true = bool(people), bool(f["gt"])
        tp += said and true
        fp += said and not true
        fn += true and not said
        tn += not said and not true
    found = sum(b["found"] for b in bins.values())
    labelled = sum(b["labelled"] for b in bins.values())
    return {"people_found": found, "people_labelled": labelled, "by_height": bins,
            "frames_with_person": {"found": tp, "of": tp + fn},
            "frames_without_person": {"reported": fp, "of": fp + tn},
            "boxes_matching_no_label": unmatched}


def run(folder: str, model_set: str | None = None, tiles: int | None = None,
        every: int = 25, log=print, rotate: str = "auto", rotate_clips: tuple = ()) -> dict:
    """`rotate` for every clip, or "on" for just the clips in `rotate_clips`
    (the cameras an examiner would know look down)."""
    import numpy as np

    from analytics import detect
    from analytics.models import DEFAULT_SET, MODEL_SETS
    model_set = model_set or DEFAULT_SET
    ms = MODEL_SETS[model_set]
    n = ms["tiles"] if tiles is None else tiles
    scale = detect.scale_for(model_set, n)
    w, h = detect.DECODE_W * scale, detect.DECODE_H * scale
    models = detect.load_models(model_set)
    xmls = {ET.parse(os.path.join(folder, x)).getroot().get("name"): os.path.join(folder, x)
            for x in sorted(os.listdir(folder)) if x.endswith(".xml")}
    frames, parked = [], []
    for clip in sorted(x for x in os.listdir(folder) if x.lower().endswith(".mpg")):
        stem = os.path.splitext(clip)[0]
        xml = xmls.get(stem) or (next(iter(xmls.values())) if len(xmls) == 1 else None)
        if not xml:
            log(f"{clip}: no ground truth named {stem} - skipped")
            continue
        gt = ground_truth(xml)
        cmd = ["ffmpeg", "-nostdin", "-v", "quiet", "-i", os.path.join(folder, clip), "-vf",
               f"select=not(mod(n\\,{every})),scale={w}:{h}", "-fps_mode", "vfr",
               "-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
        mine = []
        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
            for k, buf in enumerate(proc.read_chunks(p, w * h * 3)):
                if k * every in gt:
                    big = np.frombuffer(buf, np.uint8).reshape(h, w, 3)
                    rot = "on" if clip in rotate_clips else rotate
                    dets = detect.detect_frame(models, detect.shrink(big, scale), big, n,
                                               rotate=rot)
                    mine.append({"clip": clip, "frame": k * every, "gt": gt[k * every],
                                 "detections": dets})
        hits = [{"detections": f["detections"]} for f in mine if f["detections"]]
        flag_static(hits, len(mine))
        flag_implausible(hits)
        parked += [dict(s, clip=clip) for s in parked_spots(
            [dict(f, **{"frame": f["frame"]}) for f in mine if f["detections"]], key="frame")]
        frames += mine
        log(f"{clip}: {len(mine)} frames, {sum(len(f['gt']) for f in mine)} people labelled")
    return {"model_set": model_set, "tiles": n, "every": every, "rotate": rotate,
            "rotate_clips": list(rotate_clips), "frames": len(frames),
            "parked_vehicle_spots": parked,
            "score": score(frames), "per_frame": frames}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("folder", help="CAVIAR clips (.mpg) and ground truth (.xml)")
    ap.add_argument("--models", choices=("yolox", "classic"), default=None)
    ap.add_argument("--tiles", type=int, default=None)
    ap.add_argument("--every", type=int, default=25, help="every n-th frame (default 25: 1 a second)")
    ap.add_argument("--rotate", default="auto", choices=("auto", "on", "off"))
    ap.add_argument("--rotate-clips", default="",
                    help="comma-separated clips to look at turned round (ceiling cameras)")
    ap.add_argument("--out", default=None, help="write the result as JSON here")
    a = ap.parse_args()
    res = run(a.folder, a.models, a.tiles, a.every, rotate=a.rotate,
              rotate_clips=tuple(x for x in a.rotate_clips.split(",") if x))
    s = res["score"]
    print(f"\n{res['model_set']}, tiles {res['tiles']}: {res['frames']} frames")
    print(f"  people found     {s['people_found']} of {s['people_labelled']}  ("
          + ", ".join(f"{k}: {v['found']}/{v['labelled']}" for k, v in s["by_height"].items()) + ")")
    print(f"  frames           with a person: found in {s['frames_with_person']['found']} of "
          f"{s['frames_with_person']['of']}; with nobody labelled: a person reported in "
          f"{s['frames_without_person']['reported']} of {s['frames_without_person']['of']}")
    print(f"  boxes matching no labelled person: {s['boxes_matching_no_label']} (look at them: "
          "CAVIAR's labels miss some people)")
    print(f"  parked-vehicle spots: {len(res['parked_vehicle_spots'])} (CAVIAR's scenes hold no "
          "vehicle, so any spot here is a false one)")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

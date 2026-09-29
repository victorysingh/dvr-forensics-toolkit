"""Person recall experiment on #53's 287 labelled frames: tiling and static-rule variants.
Same models, same frames (at_rate at full resolution), same labels."""
import csv
import json
import os
import sys
import time

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
import numpy as np  # noqa: E402

from analytics import detect  # noqa: E402
from analytics.static import _iou, flag_implausible, flag_static  # noqa: E402
from validate.analytics_eval import at_rate  # noqa: E402

W = r"C:/Users/JAIPREET SINGH/150/recall/clips/"
CLIPS = [("ffmpeg_t6144_19.25.00-19.25.50[R].dav", 2), ("dav-sample.dav", 4),
         ("forespeed_T1P3-Swan-CH01-20210814-191120-191154-103000000000.avi", 4),
         ("forespeed_T1P4-Lorex-D862A8_ch1_main_20210814191228_20210814191230.mp4", 10),
         ("imkh_00000001541000000.mp4", 0.3), ("ffmpeg_t4182_20150327215559_ch01.mp4", 2)]
GRIDS = {"full": (1, 1), "2x2": (2, 2), "3x2": (3, 2), "3x3": (3, 3)}
OVERLAP = 0.2
LOW = 0.3                                   # keep everything down to this, threshold later


def size_of(clip):
    import subprocess
    r = subprocess.run(["ffmpeg", "-hide_banner", "-nostdin", *(["-f", "dhav"] if clip.endswith(".dav") else []),
                        "-i", clip], capture_output=True, text=True)
    import re
    m = re.search(r"Video: .*?(\d{3,5})x(\d{3,5})", r.stderr)
    w, h = (int(m.group(1)), int(m.group(2))) if m else (1920, 1080)
    if w > 1920:
        h, w = int(h * 1920 / w) // 2 * 2, 1920
    return w, h


def tiles(w, h, cols, rows):
    tw, th = int(w / (cols - (cols - 1) * OVERLAP)), int(h / (rows - (rows - 1) * OVERLAP))
    out = []
    for r in range(rows):
        for c in range(cols):
            x = 0 if cols == 1 else int(c * (w - tw) / (cols - 1))
            y = 0 if rows == 1 else int(r * (h - th) / (rows - 1))
            out.append((x, y, tw, th))
    return out


def run(models, rgb, grid):
    h, w = rgb.shape[:2]
    boxes = []
    regions = [(0, 0, w, h)] + ([] if grid == (1, 1) else tiles(w, h, *grid))
    old_o, old_f = detect.OBJECT_MIN, detect.FACE_MIN
    detect.OBJECT_MIN = LOW
    try:
        for x, y, tw, th in regions:
            crop = np.ascontiguousarray(rgb[y:y + th, x:x + tw])
            for d in detect.objects(models["objects"], crop) + detect.faces(models["face"], crop):
                x1, y1, x2, y2 = d["box"]
                boxes.append({"label": d["label"], "score": d["score"],
                              "box": [(x + x1 * tw) / w, (y + y1 * th) / h,
                                      (x + x2 * tw) / w, (y + y2 * th) / h]})
    finally:
        detect.OBJECT_MIN, detect.FACE_MIN = old_o, old_f
    boxes.sort(key=lambda d: -d["score"])
    kept = []
    for d in boxes:                                        # per-label NMS
        if all(k["label"] != d["label"] or _iou(k["box"], d["box"]) < 0.5 for k in kept):
            kept.append(d)
    return kept


def main():
    models = detect.load_models()
    labels = {int(r["frame"]): r for r in csv.DictReader(open(
        r"C:/Users/JAIPREET SINGH/150/recall/base/labels.csv", encoding="utf-8"))}
    res = {g: [] for g in GRIDS}
    base640 = []
    frame = 0
    t0 = time.time()
    for clip, rate in CLIPS:
        w, h = size_of(W + clip)
        n0 = frame
        for k, rgb in at_rate(W + clip, rate, w, h):
            for g, grid in GRIDS.items():
                res[g].append({"frame": frame, "clip": clip, "detections": run(models, rgb, grid)})
            small = np.ascontiguousarray(rgb[::max(1, h // 360)][:, ::max(1, w // 640)])
            frame += 1
        print(f"{clip[:40]:<40} {w}x{h} frames {frame - n0}  {time.time() - t0:.0f}s", flush=True)
    json.dump({"grids": res, "n": frame}, open(r"C:/Users/JAIPREET SINGH/150/recall/exp_dets.json", "w"))
    print("frames", frame, "labels", len(labels))


if __name__ == "__main__":
    main()

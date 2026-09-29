"""Rotation for overhead/fisheye cameras: people seen from above appear at every angle, and
the detectors were trained on upright people.  Run YOLOX and YuNet on the frame turned 90,
180 and 270 degrees as well, map the boxes back, merge.  Set A + set B (CAVIAR)."""
import json
import sys
import time

import numpy as np

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics import detect  # noqa: E402
from analytics.tiles import merge  # noqa: E402
from exp_v3 import EVERY, R, SET_A, SET_B, W, H, every_nth, ground_truth  # noqa: E402
from validate.analytics_eval import at_rate  # noqa: E402


def back(box, k):
    """A 0-1 box found in np.rot90(frame, k) in the frame's own 0-1 coordinates."""
    u1, v1, u2, v2 = box
    if k == 1:
        return [round(1 - v2, 4), round(u1, 4), round(1 - v1, 4), round(u2, 4)]
    if k == 2:
        return [round(1 - u2, 4), round(1 - v2, 4), round(1 - u1, 4), round(1 - v1, 4)]
    return [round(v1, 4), round(1 - u2, 4), round(v2, 4), round(1 - u1, 4)]


def selftest():
    img = np.zeros((90, 160), np.uint8)
    img[20:30, 100:140] = 1                                  # x 100-140, y 20-30
    want = [100 / 160, 20 / 90, 140 / 160, 30 / 90]
    for k in (1, 2, 3):
        r = np.rot90(img, k)
        ys, xs = np.nonzero(r)
        h, w = r.shape
        got = back([xs.min() / w, ys.min() / h, (xs.max() + 1) / w, (ys.max() + 1) / h], k)
        assert all(abs(a - b) < 1e-3 for a, b in zip(got, want)), (k, got, want)
    print("rotation mapping ok")


def rotated(models, big, low):
    out = []
    for k in (1, 2, 3):
        r = np.ascontiguousarray(np.rot90(big, k))
        for d in detect.yolox(models["objects"], r, low[1]) + detect.yunet(models["faces"], r, low[0]):
            d["box"] = back(d["box"], k)
            d["rot"] = k * 90
            out.append(d)
    return out


def main():
    selftest()
    models = detect.load_models("yolox")
    low = (0.5, 0.2)
    frames, base, rot = [], [], []
    spent = [0.0, 0.0]
    t0 = time.time()

    def run(big, meta):
        small = detect.shrink(big, 3)
        s = time.perf_counter()
        b = detect.detect_frame(models, small, big, 2, low)
        spent[0] += time.perf_counter() - s
        s = time.perf_counter()
        extra = rotated(models, big, low)
        spent[1] += time.perf_counter() - s
        base.append(b)
        rot.append(merge([dict(d) for d in b] + extra))
        frames.append(meta)

    for clip, rate in SET_A:
        for k, big in at_rate(R + "clips/" + clip, rate, W, H):
            run(big, {"set": "A", "clip": clip, "index": k})
        print("A", clip[:40], len(frames), f"{time.time() - t0:.0f}s", flush=True)
    for clip, xml in SET_B:
        gt = ground_truth(R + "caviar/" + xml)
        for n, big in every_nth(R + "caviar/" + clip, EVERY):
            if n in gt:
                run(big, {"set": "B", "clip": clip, "index": n, "gt": gt[n]})
        print("B", clip, len(frames), f"{time.time() - t0:.0f}s", flush=True)
    json.dump({"frames": frames, "dets": {"base": base, "rot": rot},
               "seconds": {"base": spent[0], "rot_extra": spent[1]}}, open(R + "exp_rot.json", "w"))
    print({k: round(v / len(frames), 3) for k, v in zip(("base", "rot_extra"), spent)})


if __name__ == "__main__":
    main()

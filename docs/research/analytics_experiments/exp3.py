"""Same frames at the tool's own decode size (640x360), with tiling - is it the tiles or the resolution?"""
import json
import sys
import time

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from exp import CLIPS, W, run  # noqa: E402
from validate.analytics_eval import at_rate  # noqa: E402
from analytics import detect  # noqa: E402

GRIDS = {"full": (1, 1), "3x3": (3, 3)}
models = detect.load_models()
res = {g: [] for g in GRIDS}
frame, t0 = 0, time.time()
for clip, rate in CLIPS:
    for k, rgb in at_rate(W + clip, rate, 1280, 720):
        for g, grid in GRIDS.items():
            res[g].append({"frame": frame, "clip": clip, "detections": run(models, rgb, grid)})
        frame += 1
    print(clip[:40], frame, f"{time.time() - t0:.0f}s", flush=True)
json.dump({"grids": res, "n": frame}, open(r"C:/Users/JAIPREET SINGH/150/recall/exp_dets_1280.json", "w"))

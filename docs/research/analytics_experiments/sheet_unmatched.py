"""Contact sheet of set-B person boxes (counted) that match no ground-truth box, with context."""
import subprocess
import sys

import numpy as np
from PIL import Image, ImageDraw

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
from score_v3 import B, applied, frames, VEH  # noqa: E402
from analytics.static import _iou, counted  # noqa: E402

cfg, thr = sys.argv[1], float(sys.argv[2])
S = ("C:/Users/JAIPRE~1/AppData/Local/Temp/claude/C--Users-JAIPREET-SINGH-Documents-"
     "business-entity-resolution/06746077-816b-4f43-8dad-e32909b38e69/scratchpad/")
out = applied(cfg, thr, {"person"} | VEH)
cells = []
for i in B:
    gt = frames[i]["gt"]
    bad = [d for d in out[i] if d["label"] == "person" and counted(d)
           and all(_iou(d["box"], g[:4]) < 0.1 for g in gt)]
    if not bad:
        continue
    f = frames[i]
    raw = subprocess.run(["ffmpeg", "-v", "quiet", "-i", "C:/Users/JAIPREET SINGH/150/recall/caviar/" + f["clip"],
                          "-vf", "select=eq(n\\," + str(f["index"]) + ")", "-fps_mode", "vfr", "-frames:v", "1",
                          "-f", "rawvideo", "-pix_fmt", "rgb24", "-"], capture_output=True).stdout
    img = Image.fromarray(np.frombuffer(raw, np.uint8).reshape(288, 384, 3).copy())
    dr = ImageDraw.Draw(img)
    for g in gt:
        dr.rectangle([g[0] * 384, g[1] * 288, g[2] * 384, g[3] * 288], outline=(0, 200, 0), width=1)
    for d in bad:
        b = d["box"]
        dr.rectangle([b[0] * 384, b[1] * 288, b[2] * 384, b[3] * 288], outline=(255, 0, 0), width=2)
        dr.text((b[0] * 384, max(0, b[1] * 288 - 10)), f"{d['score']:.2f}", fill=(255, 255, 0))
    dr.text((4, 276), f"{f['clip'][:18]} #{f['index']} gt={len(gt)}", fill=(255, 255, 0))
    cells.append(img)
print(len(cells), "frames with unmatched boxes")
cols = 4
for s in range(0, len(cells), 16):
    part = cells[s:s + 16]
    sheet = Image.new("RGB", (384 * cols, 288 * ((len(part) + cols - 1) // cols)))
    for k, c in enumerate(part):
        sheet.paste(c, ((k % cols) * 384, (k // cols) * 288))
    sheet.save(S + f"unmatched_{cfg}_{s // 16}.png")
    print(S + f"unmatched_{cfg}_{s // 16}.png")

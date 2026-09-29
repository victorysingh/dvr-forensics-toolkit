"""Zoom on the INRIA reception desk (is someone sitting there?) and list set-B frames with no
labelled person where a config reported one."""
import subprocess
import sys

import numpy as np
from PIL import Image, ImageDraw

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
from score_v3 import B, applied, frames, VEH  # noqa: E402
from analytics.static import counted  # noqa: E402

S = ("C:/Users/JAIPRE~1/AppData/Local/Temp/claude/C--Users-JAIPREET-SINGH-Documents-"
     "business-entity-resolution/06746077-816b-4f43-8dad-e32909b38e69/scratchpad/")
C = "C:/Users/JAIPREET SINGH/150/recall/caviar/"


def frame(clip, n):
    raw = subprocess.run(["ffmpeg", "-v", "quiet", "-i", C + clip, "-vf", "select=eq(n\\," + str(n) + ")",
                          "-fps_mode", "vfr", "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"],
                         capture_output=True).stdout
    return Image.fromarray(np.frombuffer(raw, np.uint8).reshape(288, 384, 3).copy())


cells = [frame("Walk1.mpg", n).crop((0, 60, 110, 170)).resize((330, 330), Image.LANCZOS) for n in (25, 150, 225)]
out = applied("ys_t2", 0.5, {"person"} | VEH)
for i in B:
    if frames[i]["gt"]:
        continue
    ps = [d for d in out[i] if d["label"] == "person" and counted(d)]
    print(frames[i]["clip"], frames[i]["index"], [(d["score"], d["box"]) for d in ps])
    if ps:
        img = frame(frames[i]["clip"], frames[i]["index"])
        dr = ImageDraw.Draw(img)
        for d in ps:
            b = d["box"]
            dr.rectangle([b[0] * 384, b[1] * 288, b[2] * 384, b[3] * 288], outline=(255, 0, 0), width=2)
        cells.append(img.resize((440, 330)))
sheet = Image.new("RGB", (sum(c.width for c in cells), 330))
x = 0
for c in cells:
    sheet.paste(c, (x, 0))
    x += c.width
sheet.save(S + "desk_check.png")

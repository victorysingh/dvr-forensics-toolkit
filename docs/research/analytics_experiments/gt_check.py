"""Draw CAVIAR ground-truth boxes on the frames ffmpeg decodes, to check the numbering lines up."""
import subprocess
import xml.etree.ElementTree as ET

import numpy as np
from PIL import Image, ImageDraw

R = "C:/Users/JAIPREET SINGH/150/recall/caviar/"
S = ("C:/Users/JAIPRE~1/AppData/Local/Temp/claude/C--Users-JAIPREET-SINGH-Documents-"
     "business-entity-resolution/06746077-816b-4f43-8dad-e32909b38e69/scratchpad/")


def gt_of(xml, n):
    for fr in ET.parse(R + xml).getroot().iter("frame"):
        if int(fr.get("number")) == n:
            return [[float(b.get(k)) for k in ("xc", "yc", "w", "h")]
                    for b in (o.find("box") for o in fr.iter("object"))]
    return []


tiles = []
for clip, xml, n in (("ThreePastShop1cor.mpg", "c3ps1gt.xml", 700), ("Browse1.mpg", "br1gt.xml", 500),
                     ("WalkByShop1cor.mpg", "cwbs1gt.xml", 1200), ("Meet_WalkTogether1.mpg", "mwt1gt.xml", 300)):
    raw = subprocess.run(["ffmpeg", "-v", "quiet", "-i", R + clip, "-vf", "select=eq(n\\," + str(n) + ")",
                          "-fps_mode", "vfr", "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"],
                         capture_output=True).stdout
    img = Image.fromarray(np.frombuffer(raw, np.uint8).reshape(288, 384, 3).copy())
    d = ImageDraw.Draw(img)
    boxes = gt_of(xml, n)
    for xc, yc, w, h in boxes:
        d.rectangle([xc - w / 2, yc - h / 2, xc + w / 2, yc + h / 2], outline=(255, 0, 0), width=2)
    d.text((4, 4), f"{clip} #{n}: {len(boxes)} gt", fill=(255, 255, 0))
    tiles.append(img)
sheet = Image.new("RGB", (768, 576))
for i, t in enumerate(tiles):
    sheet.paste(t, ((i % 2) * 384, (i // 2) * 288))
sheet.save(S + "caviar_gt_check.png")
print("ok")

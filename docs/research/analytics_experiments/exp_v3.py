"""Every candidate detector on set A (#53's 287 labelled frames) and set B (CAVIAR, one
frame a second, ground truth from its XML).  Boxes kept down to a low score; scoring
is separate (score_v3.py)."""
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import numpy as np

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
import newdet as N  # noqa: E402
from analytics import detect  # noqa: E402
from validate.analytics_eval import at_rate  # noqa: E402

R = r"C:/Users/JAIPREET SINGH/150/recall/"
SET_A = [("ffmpeg_t6144_19.25.00-19.25.50[R].dav", 2), ("dav-sample.dav", 4),
         ("forespeed_T1P3-Swan-CH01-20210814-191120-191154-103000000000.avi", 4),
         ("forespeed_T1P4-Lorex-D862A8_ch1_main_20210814191228_20210814191230.mp4", 10),
         ("imkh_00000001541000000.mp4", 0.3), ("ffmpeg_t4182_20150327215559_ch01.mp4", 2)]
SET_B = [("Walk1.mpg", "wk1gt.xml"), ("Browse1.mpg", "br1gt.xml"),
         ("Meet_WalkTogether1.mpg", "mwt1gt.xml"), ("WalkByShop1cor.mpg", "cwbs1gt.xml"),
         ("OneLeaveShop1cor.mpg", "cols1gt.xml"), ("ThreePastShop1cor.mpg", "c3ps1gt.xml")]
EVERY = 25                                   # CAVIAR is 25 fps: one frame a second
W, H = 1920, 1080


def every_nth(clip, n):
    cmd = ["ffmpeg", "-nostdin", "-v", "quiet", "-i", clip, "-vf",
           f"select=not(mod(n\\,{n})),scale={W}:{H}", "-fps_mode", "vfr",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        k = 0
        while len(buf := p.stdout.read(W * H * 3)) == W * H * 3:
            yield k * n, np.frombuffer(buf, np.uint8).reshape(H, W, 3)
            k += 1


def ground_truth(xml):
    gt = {}
    for fr in ET.parse(xml).getroot().iter("frame"):
        boxes = []
        for ob in fr.iter("object"):
            b = ob.find("box")
            xc, yc, w, h = (float(b.get(k)) for k in ("xc", "yc", "w", "h"))
            boxes.append([(xc - w / 2) / 384, (yc - h / 2) / 288, (xc + w / 2) / 384,
                          (yc + h / 2) / 288, h])
        gt[int(fr.get("number"))] = boxes
    return gt


def main():
    m = detect.load_models()
    ys, yt = N.session("yolox_s.onnx"), N.session("yolox_tiny.onnx")
    yn = N.session("face_detection_yunet_2026may.onnx")
    CONFIGS = {
        "ssd_t1": lambda big, small: N.ssd(m["objects"], small),
        "ssd_t3": lambda big, small: N.tiled(N.ssd, m["objects"], big, 3),
        "yt_t1": lambda big, small: N.yolox(yt, big),
        "yt_t3": lambda big, small: N.tiled(N.yolox, yt, big, 3),
        "ys_t1": lambda big, small: N.yolox(ys, big),
        "ys_t2": lambda big, small: N.tiled(N.yolox, ys, big, 2),
        "ys_t3": lambda big, small: N.tiled(N.yolox, ys, big, 3),
        "uf_t1": lambda big, small: N.ultraface(m["face"], small),
        "uf_t3": lambda big, small: N.tiled(N.ultraface, m["face"], small, 3),
        "yn_small": lambda big, small: N.yunet(yn, small),
        "yn_big": lambda big, small: N.yunet(yn, big),
    }
    frames, dets = [], {k: [] for k in CONFIGS}
    spent = {k: 0.0 for k in CONFIGS}
    t0 = time.time()

    def run(big, meta):
        small = detect.shrink(big, 3)
        for k, f in CONFIGS.items():
            s = time.perf_counter()
            dets[k].append(f(big, small))
            spent[k] += time.perf_counter() - s
        frames.append(meta)

    for clip, rate in SET_A:
        for k, big in at_rate(R + "clips/" + clip, rate, W, H):
            run(big, {"set": "A", "clip": clip, "index": k})
        print("A", clip[:40], len(frames), f"{time.time() - t0:.0f}s", flush=True)
    for clip, xml in SET_B:
        gt = ground_truth(R + "caviar/" + xml)
        for n, big in every_nth(R + "caviar/" + clip, EVERY):
            if n not in gt:
                continue
            run(big, {"set": "B", "clip": clip, "index": n, "gt": gt[n]})
        print("B", clip, len(frames), f"{time.time() - t0:.0f}s", flush=True)
    json.dump({"frames": frames, "dets": dets, "seconds": spent},
              open(R + "exp_v3.json", "w"))
    print({k: round(v / len(frames), 3) for k, v in spent.items()})


if __name__ == "__main__":
    main()

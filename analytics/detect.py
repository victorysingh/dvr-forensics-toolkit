"""Optional analytics layer: faces and objects in recovered footage.

NOT part of the forensic core. The core (acquire/, detect/, parsers/,
recover/, analyse/, report/) is stdlib-only and never imports this package;
this layer needs ffmpeg (decoding), numpy and onnxruntime, per
docs/TECH_STACK.md. If they are missing, the tool still acquires, recovers
and reports - it just cannot run this.

What it does: decodes extracted clips with ffmpeg at a sampled frame rate and
runs two small ONNX models on each sampled frame:
  * UltraFace RFB-320 - face DETECTION. It finds that a face is present and
    where. It does not identify anyone; there is no recognition here.
  * SSD-MobileNet v1 (COCO) - people, vehicles and carried objects.

Everything it outputs is a LEAD, NOT EVIDENCE: a ranked list of moments for
an examiner to watch. Detector confidence is the model's score, not a
probability that the finding is true. Model files are recorded by SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from typing import Optional

import numpy as np
import onnxruntime as ort

from analytics.static import (STATIC_IOU, STATIC_MIN_FRAMES, STATIC_SHARE, counted,
                              flag_implausible, flag_static)

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = {
    "face": {"file": "ultraface_rfb320.onnx",
             "name": "UltraFace version-RFB-320",
             "source": "https://github.com/onnx/models (validated/vision/body_analysis/ultraface)",
             "license": "MIT",
             "sha256": "34cd7e60aeff28744c657de7a3dc64e872d506741de66987f3426f2b79f88017"},
    "objects": {"file": "ssd_mobilenet_v1_12.onnx",
                "name": "SSD-MobileNet v1 (COCO), opset 12",
                "source": "https://github.com/onnx/models "
                          "(validated/vision/object_detection_segmentation/ssd-mobilenetv1)",
                "license": "Apache-2.0",
                "sha256": "b8fba5e404077d4048d27fcd1667e85e27e192eb9bf51e696c46a3acd7d21058"},
}
# COCO ids (1-based, as the model emits them) that matter for surveillance.
COCO = {1: "person", 2: "bicycle", 3: "car", 4: "motorcycle", 6: "bus", 8: "truck",
        27: "backpack", 31: "handbag", 33: "suitcase"}
FACE_MIN = 0.8
OBJECT_MIN = 0.5
DECODE_W, DECODE_H = 640, 360
ANALYTICS_RULE = "analytics.ultraface_ssdmobilenet.v1"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_models() -> dict:
    """Open both models, refusing any file whose hash is not the pinned one."""
    opts = ort.SessionOptions()
    opts.log_severity_level = 3
    # leave the rest of the machine to anything else running (e.g. a scan)
    opts.intra_op_num_threads = int(os.environ.get("PS26150_ANALYTICS_THREADS", "4"))
    out = {}
    for key, m in MODELS.items():
        path = os.path.join(HERE, "models", m["file"])
        if not os.path.exists(path):
            raise FileNotFoundError(f"model {m['file']} missing - see analytics/README.md")
        got = sha256_file(path)
        if got != m["sha256"]:
            raise ValueError(f"model {m['file']} hash {got} is not the pinned {m['sha256']}")
        out[key] = ort.InferenceSession(path, opts, providers=["CPUExecutionProvider"])
    return out


def decode(path: str, fps: float, codec: str = "hevc"):
    """Yield (seconds from the first decoded frame, RGB frame) at `fps`."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("ffmpeg not found - install it to use the analytics layer")
    fmt = ["-f", codec] if codec else []          # PS: let ffmpeg detect the container
    cmd = ["ffmpeg", "-v", "quiet", *fmt, "-i", path,
           "-vf", f"fps={fps},scale={DECODE_W}:{DECODE_H}",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
    n = DECODE_W * DECODE_H * 3
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        i = 0
        while True:
            buf = p.stdout.read(n)
            if len(buf) < n:
                break
            yield i / fps, np.frombuffer(buf, np.uint8).reshape(DECODE_H, DECODE_W, 3)
            i += 1


def _nms(boxes: np.ndarray, scores: np.ndarray, iou: float = 0.3) -> list[int]:
    order = scores.argsort()[::-1]
    keep = []
    while order.size:
        i = order[0]
        keep.append(int(i))
        xx1 = np.maximum(boxes[i, 0], boxes[order[1:], 0])
        yy1 = np.maximum(boxes[i, 1], boxes[order[1:], 1])
        xx2 = np.minimum(boxes[i, 2], boxes[order[1:], 2])
        yy2 = np.minimum(boxes[i, 3], boxes[order[1:], 3])
        inter = np.clip(xx2 - xx1, 0, None) * np.clip(yy2 - yy1, 0, None)
        area = lambda b: (b[..., 2] - b[..., 0]) * (b[..., 3] - b[..., 1])
        ov = inter / (area(boxes[i]) + area(boxes[order[1:]]) - inter + 1e-9)
        order = order[1:][ov <= iou]
    return keep


def faces(sess, rgb: np.ndarray) -> list[dict]:
    ys = (np.arange(240) * rgb.shape[0] / 240).astype(int)
    xs = (np.arange(320) * rgb.shape[1] / 320).astype(int)
    small = rgb[ys][:, xs].astype(np.float32)
    x = ((small - 127.0) / 128.0).transpose(2, 0, 1)[None]
    scores, boxes = sess.run(None, {"input": x})
    s = scores[0, :, 1]
    m = s >= FACE_MIN
    if not m.any():
        return []
    b, s = boxes[0][m], s[m]
    return [{"label": "face", "score": round(float(s[i]), 3),
             "box": [round(float(v), 4) for v in b[i]]} for i in _nms(b, s)]


def objects(sess, rgb: np.ndarray) -> list[dict]:
    boxes, classes, scores, num = sess.run(None, {"inputs": rgb[None]})
    out = []
    for i in range(int(num[0])):
        c, sc = int(classes[0, i]), float(scores[0, i])
        if sc >= OBJECT_MIN and c in COCO:
            y1, x1, y2, x2 = (float(v) for v in boxes[0, i])
            out.append({"label": COCO[c], "score": round(sc, 3),
                        "box": [round(x1, 4), round(y1, 4), round(x2, 4), round(y2, 4)]})
    return out


def _thumbnail(rgb: np.ndarray, dets: list[dict], path: str) -> None:
    """Frame with boxes drawn, as JPEG via ffmpeg (PPM in, no image library)."""
    img = rgb.copy()
    h, w = img.shape[:2]
    for d in dets:
        x1, y1, x2, y2 = d["box"]
        c = (255, 64, 64) if d["label"] == "face" else (64, 200, 255)
        X1, X2 = max(0, int(x1 * w)), min(w - 1, int(x2 * w))
        Y1, Y2 = max(0, int(y1 * h)), min(h - 1, int(y2 * h))
        for t in range(2):
            img[min(h - 1, Y1 + t), X1:X2] = c
            img[max(0, Y2 - t), X1:X2] = c
            img[Y1:Y2, min(w - 1, X1 + t)] = c
            img[Y1:Y2, max(0, X2 - t)] = c
    ppm = b"P6 %d %d 255\n" % (w, h) + img.tobytes()
    subprocess.run(["ffmpeg", "-v", "quiet", "-y", "-f", "image2pipe", "-c:v", "ppm",
                    "-i", "-", "-q:v", "4", path], input=ppm, check=True)


def analyse_clip(models: dict, path: str, fps: float, thumbs_dir: Optional[str],
                 max_thumbs: int = 6, codec: str = "hevc") -> dict:
    frames = 0
    hits = []
    for t, rgb in decode(path, fps, codec):
        frames += 1
        dets = faces(models["face"], rgb) + objects(models["objects"], rgb)
        if dets:
            hits.append({"t_s": round(t, 2), "detections": dets, "_rgb": rgb})
    flag_static(hits, frames)
    flag_implausible(hits)
    counts: dict[str, int] = {}
    static: dict[str, int] = {}
    for h in hits:
        for label in {d["label"] for d in h["detections"] if counted(d)}:
            counts[label] = counts.get(label, 0) + 1
        for label in {d["label"] for d in h["detections"] if not counted(d)}:
            static[label] = static.get(label, 0) + 1
    # thumbnails for the strongest frames with something that is not static
    moving = [h for h in hits if any(counted(d) for d in h["detections"])]
    moving.sort(key=lambda h: -max(d["score"] for d in h["detections"] if counted(d)))
    hits = moving + [h for h in hits if h not in moving]
    thumbs = []
    if thumbs_dir:
        os.makedirs(thumbs_dir, exist_ok=True)
        for h in moving[:max_thumbs]:
            name = f"{os.path.splitext(os.path.basename(path))[0]}_t{h['t_s']:07.1f}.jpg"
            _thumbnail(h["_rgb"], h["detections"], os.path.join(thumbs_dir, name))
            thumbs.append({"file": name, "t_s": h["t_s"],
                           "sha256": sha256_file(os.path.join(thumbs_dir, name))})
    for h in hits:
        h.pop("_rgb", None)
    hits.sort(key=lambda h: h["t_s"])
    return {"clip": os.path.basename(path), "clip_sha256": sha256_file(path),
            "frames_analysed": frames, "sample_fps": fps,
            "frames_with": counts, "static_frames": static,
            "detections": hits, "thumbnails": thumbs}


def run(clips: list[str], out_dir: str, fps: float = 1.0, log=print) -> dict:
    models = load_models()
    thumbs = os.path.join(out_dir, "thumbnails")
    results = []
    for i, c in enumerate(clips):
        codec = "h264" if c.endswith(".h264") else ("" if c.endswith(".ps") else "hevc")
        r = analyse_clip(models, c, fps, thumbs, codec=codec)
        results.append(r)
        log(f"  [{i + 1}/{len(clips)}] {r['clip']}  {r['frames_analysed']} frames  "
            + (", ".join(f"{k} {v}" for k, v in sorted(r["frames_with"].items())) or "nothing"))
    totals: dict[str, int] = {}
    static_totals: dict[str, int] = {}
    for r in results:
        for k, v in r["frames_with"].items():
            totals[k] = totals.get(k, 0) + v
        for k, v in r["static_frames"].items():
            static_totals[k] = static_totals.get(k, 0) + v
    out = {
        "rule": ANALYTICS_RULE, "status": "lead, not evidence",
        "models": {k: {x: m[x] for x in ("name", "source", "license", "sha256")}
                   for k, m in MODELS.items()},
        "thresholds": {"face": FACE_MIN, "objects": OBJECT_MIN},
        "sample_fps": fps, "clips": results, "frames_with_totals": totals,
        "static_totals": static_totals,
        "static_rule": f"same label, box IoU >= {STATIC_IOU}, in >= {STATIC_MIN_FRAMES} frames "
                       f"and >= {STATIC_SHARE:.0%} of a clip's analysed frames",
        "notes": [
            "Face DETECTION only: it marks that a face appears and where. Nobody is "
            "identified; there is no face recognition in this tool.",
            "Scores are the models' own confidence, not the probability that a "
            "detection is correct. Small, distant, dark or blurred subjects are missed; "
            "shapes are sometimes mistaken for people or vehicles.",
            "t_s is seconds from the first decodable frame of the clip, not a "
            "recorder timestamp.",
            "Every detection is a lead for an examiner to review in the footage itself.",
            "Detections that stay in the same place through most of a clip are flagged "
            "'static' and not counted: on real footage a steel pot was repeatedly detected "
            "as a face. Static flags an object - or something that did not move - not a "
            "person to review.",
        ],
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "analytics.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    return out

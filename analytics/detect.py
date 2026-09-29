"""Optional analytics layer: faces and objects in recovered footage.

NOT part of the forensic core. The core (acquire/, detect/, parsers/,
recover/, analyse/, report/) is stdlib-only and never imports this package;
this layer needs ffmpeg (decoding), numpy and onnxruntime, per
docs/TECH_STACK.md. If they are missing, the tool still acquires, recovers
and reports - it just cannot run this.

What it does: decodes extracted clips with ffmpeg at a sampled frame rate and
runs two ONNX models on each sampled frame (analytics/models.py):
  * YuNet - face DETECTION, on the whole 1920 x 1080 frame. It finds that a
    face is present and where. It does not identify anyone; there is no
    recognition here.
  * YOLOX-S (COCO) - people, vehicles and carried objects, on the whole
    1920 x 1080 frame and on each tile of a 2 x 2 grid of overlapping tiles
    (analytics/tiles.py), so that small people are seen.
The "classic" set (SSD-MobileNet v1 and UltraFace) is the tool as measured
before 29 Sep 2026, kept so those results can be reproduced.

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

from analytics.models import DEFAULT_SET, MODEL_SETS, MODELS
from analytics.static import (STATIC_IOU, STATIC_MIN_FRAMES, STATIC_SHARE, counted,
                              flag_implausible, flag_static)
from analytics.tiles import TILE_OVERLAP, merge, tiles, to_frame

HERE = os.path.dirname(os.path.abspath(__file__))
# COCO ids that matter for surveillance: SSD-MobileNet emits 1-based ids of
# the 91-id list, YOLOX 0-based ids of the 80-class list.
COCO = {1: "person", 2: "bicycle", 3: "car", 4: "motorcycle", 6: "bus", 8: "truck",
        27: "backpack", 31: "handbag", 33: "suitcase"}
COCO80 = {0: "person", 1: "bicycle", 2: "car", 3: "motorcycle", 5: "bus", 7: "truck",
          24: "backpack", 26: "handbag", 28: "suitcase"}
DECODE_W, DECODE_H = 640, 360
# The larger decode: 3 x 640 x 360 = 1920 x 1080.  On the labelled frames the
# object models found people in nearly twice as many frames from it as from
# 640 x 360 tiles.  Thumbnails, and the classic face model, use 640 x 360.
OBJECT_SCALE = 3


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_models(model_set: str = DEFAULT_SET) -> dict:
    """Open the set's two models, refusing any file whose hash is not the pinned one."""
    opts = ort.SessionOptions()
    opts.log_severity_level = 3
    # leave the rest of the machine to anything else running (e.g. a scan)
    opts.intra_op_num_threads = int(os.environ.get("PS26150_ANALYTICS_THREADS", "4"))
    s = MODEL_SETS[model_set]
    out = {"set": model_set}
    for job in ("faces", "objects"):
        m = MODELS[s[job]]
        path = os.path.join(HERE, "models", m["file"])
        if not os.path.exists(path):
            raise FileNotFoundError(f"model {m['file']} missing - see analytics/README.md")
        got = sha256_file(path)
        if got != m["sha256"]:
            raise ValueError(f"model {m['file']} hash {got} is not the pinned {m['sha256']}")
        out[job] = ort.InferenceSession(path, opts, providers=["CPUExecutionProvider"])
    return out


def scale_for(model_set: str, n: int) -> int:
    """How much larger than 640 x 360 to decode: the YOLOX set always reads
    1920 x 1080; the classic set only when tiled."""
    return OBJECT_SCALE if model_set != "classic" or n > 1 else 1


def decode(path: str, fps: float, codec: str = "hevc", scale: int = 1):
    """Yield (seconds from the first decoded frame, RGB frame) at `fps`, the
    frame `scale` times DECODE_W x DECODE_H."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("ffmpeg not found - install it to use the analytics layer")
    fmt = ["-f", codec] if codec else []          # PS: let ffmpeg detect the container
    w, h = DECODE_W * scale, DECODE_H * scale
    cmd = ["ffmpeg", "-v", "quiet", *fmt, "-i", path,
           "-vf", f"fps={fps},scale={w}:{h}",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
    n = w * h * 3
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        i = 0
        while True:
            buf = p.stdout.read(n)
            if len(buf) < n:
                break
            yield i / fps, np.frombuffer(buf, np.uint8).reshape(h, w, 3)
            i += 1


def shrink(rgb: np.ndarray, k: int) -> np.ndarray:
    """The frame 1/k the size, each pixel the mean of a k x k block."""
    if k == 1:
        return rgb
    h, w = rgb.shape[0] // k, rgb.shape[1] // k
    rows = rgb[:h * k, :w * k].reshape(h, k, w * k, 3).sum(axis=1, dtype=np.uint16)
    return (rows.reshape(h, w, k, 3).sum(axis=2, dtype=np.uint16) // (k * k)).astype(np.uint8)


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


def _box(x1, y1, x2, y2, w, h) -> list[float]:
    """Pixels to 0-1 of the frame, clipped to it."""
    return [round(float(min(max(v / s, 0.0), 1.0)), 4)
            for v, s in ((x1, w), (y1, h), (x2, w), (y2, h))]


def ultraface(sess, rgb: np.ndarray, low: float) -> list[dict]:
    ys = (np.arange(240) * rgb.shape[0] / 240).astype(int)
    xs = (np.arange(320) * rgb.shape[1] / 320).astype(int)
    small = rgb[ys][:, xs].astype(np.float32)
    x = ((small - 127.0) / 128.0).transpose(2, 0, 1)[None]
    scores, boxes = sess.run(None, {"input": x})
    s = scores[0, :, 1]
    m = s >= low
    if not m.any():
        return []
    b, s = boxes[0][m], s[m]
    return [{"label": "face", "score": round(float(s[i]), 3),
             "box": [round(float(v), 4) for v in b[i]]} for i in _nms(b, s)]


def ssd(sess, rgb: np.ndarray, low: float) -> list[dict]:
    boxes, classes, scores, num = sess.run(None, {"inputs": rgb[None]})
    out = []
    for i in range(int(num[0])):
        c, sc = int(classes[0, i]), float(scores[0, i])
        if sc >= low and c in COCO:
            y1, x1, y2, x2 = (float(v) for v in boxes[0, i])
            out.append({"label": COCO[c], "score": round(sc, 3),
                        "box": [round(x1, 4), round(y1, 4), round(x2, 4), round(y2, 4)]})
    return out


def yolox(sess, rgb: np.ndarray, low: float) -> list[dict]:
    """YOLOX-S as its authors run it: the picture scaled to fit the model's
    square input (padded with grey 114), channels BGR, values 0-255; each
    output row is a box (centre and size relative to its grid cell and
    stride), an objectness and 80 class scores, both already sigmoid."""
    size = sess.get_inputs()[0].shape[2]
    h, w = rgb.shape[:2]
    r = min(size / h, size / w)
    nh, nw = int(round(h * r)), int(round(w * r))
    ys = np.minimum((np.arange(nh) / r).astype(int), h - 1)
    xs = np.minimum((np.arange(nw) / r).astype(int), w - 1)
    pad = np.full((size, size, 3), 114, np.uint8)
    pad[:nh, :nw] = rgb[ys][:, xs][:, :, ::-1]
    out = sess.run(None, {"images": pad.transpose(2, 0, 1)[None].astype(np.float32)})[0][0]
    grids, strides = [], []
    for s in (8, 16, 32):
        g = size // s
        yv, xv = np.meshgrid(np.arange(g), np.arange(g), indexing="ij")
        grids.append(np.stack((xv, yv), 2).reshape(-1, 2))
        strides.append(np.full((g * g, 1), s))
    grid, stride = np.concatenate(grids), np.concatenate(strides)
    xy = (out[:, :2] + grid) * stride
    wh = np.exp(out[:, 2:4]) * stride
    scores = out[:, 4:5] * out[:, 5:]
    found = []
    for c, label in COCO80.items():
        sc = scores[:, c]
        m = sc >= low
        if not m.any():
            continue
        b = np.concatenate([xy[m] - wh[m] / 2, xy[m] + wh[m] / 2], 1) / r
        s = sc[m]
        found += [{"label": label, "score": round(float(s[i]), 3), "box": _box(*b[i], w, h)}
                  for i in _nms(b.astype(np.float32), s.astype(np.float32), 0.45)]
    return found


def yunet(sess, rgb: np.ndarray, low: float) -> list[dict]:
    """YuNet as OpenCV runs it: BGR, values 0-255, the picture padded to a
    multiple of 32; per stride 8/16/32 a score sqrt(class x objectness) and a
    box relative to its grid cell."""
    h, w = rgb.shape[:2]
    H, W = (h + 31) // 32 * 32, (w + 31) // 32 * 32
    img = np.zeros((H, W, 3), np.float32)
    img[:h, :w] = rgb[:, :, ::-1]
    outs = dict(zip([o.name for o in sess.get_outputs()],
                    sess.run(None, {"input": img.transpose(2, 0, 1)[None]})))
    boxes, scores = [], []
    for s in (8, 16, 32):
        cols = W // s
        sc = np.sqrt(np.clip(outs[f"cls_{s}"][0, :, 0], 0, 1) * np.clip(outs[f"obj_{s}"][0, :, 0], 0, 1))
        idx = np.nonzero(sc >= low)[0]
        if not idx.size:
            continue
        bb = outs[f"bbox_{s}"][0][idx]
        cx, cy = (idx % cols + bb[:, 0]) * s, (idx // cols + bb[:, 1]) * s
        bw, bh = np.exp(bb[:, 2]) * s, np.exp(bb[:, 3]) * s
        boxes.append(np.stack([cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2], 1))
        scores.append(sc[idx])
    if not boxes:
        return []
    b, s = np.concatenate(boxes).astype(np.float32), np.concatenate(scores).astype(np.float32)
    return [{"label": "face", "score": round(float(s[i]), 3), "box": _box(*b[i], w, h)}
            for i in _nms(b, s, 0.3)]


def _tiled(detector, sess, rgb: np.ndarray, n: int, low: float) -> list[dict]:
    """`detector` on the whole frame and on each tile of an n x n grid, boxes
    in whole-frame coordinates."""
    out = detector(sess, rgb, low)
    if n > 1:
        h, w = rgb.shape[:2]
        for t in tiles(w, h, n, TILE_OVERLAP):
            x, y, tw, th = t
            for d in detector(sess, np.ascontiguousarray(rgb[y:y + th, x:x + tw]), low):
                d["box"] = to_frame(d["box"], t, w, h)
                out.append(d)
    return out


def detect_frame(models: dict, small: np.ndarray, big: Optional[np.ndarray] = None,
                 n: Optional[int] = None, low: Optional[tuple] = None) -> list[dict]:
    """Faces and objects in one frame, as the set runs them (`small` is
    DECODE_W x DECODE_H, `big` the same frame larger, by default `small`),
    objects on an n x n grid of tiles as well as the whole frame, the same
    object boxed in two overlapping tiles merged.  `low` = (faces, objects)
    minimum scores, by default the set's thresholds.  With the classic set
    and n = 1 this is the untiled tool of 28 Sep, exactly."""
    s = MODEL_SETS[models["set"]]
    n = s["tiles"] if n is None else n
    low_f, low_o = low or (s["faces_min"], s["objects_min"])
    big = small if big is None else big
    if models["set"] == "classic":
        found = (_tiled(ultraface, models["faces"], small, n, low_f)
                 + _tiled(ssd, models["objects"], big, n, low_o))
    else:
        found = yunet(models["faces"], big, low_f) + _tiled(yolox, models["objects"], big, n, low_o)
    return found if n == 1 else merge(found)


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
                 max_thumbs: int = 6, codec: str = "hevc", tiles_n: Optional[int] = None) -> dict:
    frames = 0
    hits = []
    n = MODEL_SETS[models["set"]]["tiles"] if tiles_n is None else tiles_n
    scale = scale_for(models["set"], n)
    for t, rgb in decode(path, fps, codec, scale):
        frames += 1
        small = shrink(rgb, scale)
        dets = detect_frame(models, small, rgb, n)
        if dets:
            hits.append({"t_s": round(t, 2), "detections": dets, "_rgb": small})
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


def run(clips: list[str], out_dir: str, fps: float = 1.0, log=print,
        tiles_n: Optional[int] = None, model_set: str = DEFAULT_SET) -> dict:
    models = load_models(model_set)
    s = MODEL_SETS[model_set]
    n = s["tiles"] if tiles_n is None else tiles_n
    thumbs = os.path.join(out_dir, "thumbnails")
    results = []
    for i, c in enumerate(clips):
        codec = "h264" if c.endswith(".h264") else ("" if c.endswith(".ps") else "hevc")
        r = analyse_clip(models, c, fps, thumbs, codec=codec, tiles_n=n)
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
        "rule": s["rule"], "status": "lead, not evidence", "model_set": model_set,
        "models": {job: {x: MODELS[s[job]][x] for x in ("name", "source", "license", "sha256")}
                   for job in ("faces", "objects")},
        "thresholds": {"faces": s["faces_min"], "objects": s["objects_min"]},
        "tiling": {"grid": (f"{n} x {n} tiles and the whole frame" if n > 1
                            else "none, the whole frame only"),
                   "overlap": TILE_OVERLAP if n > 1 else None,
                   "decoded_at": f"{DECODE_W * scale_for(model_set, n)} x "
                                 f"{DECODE_H * scale_for(model_set, n)}",
                   "how": s["how"]},
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
            "An empty result does not mean nobody was there. Scored against 287 frames of "
            "real recorder footage labelled by eye, the tool reported a person in 32 of the "
            "57 frames that had one; on CAVIAR footage it found 777 of 1,089 labelled "
            "people (docs/VALIDATION_REPORT.md section 8a).",
            "Detections that stay in the same place through most of a clip are flagged "
            "'static' and not counted: on real footage a steel pot was repeatedly detected "
            "as a face. Static means the box did not move - usually an object mistaken for "
            "a face or person, but a person sitting still is flagged too. Static "
            "detections are kept in this file.",
        ],
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "analytics.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    return out

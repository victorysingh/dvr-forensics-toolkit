"""Candidate detectors for the recall experiments: YOLOX (objects) and YuNet (faces),
alongside the tool's SSD-MobileNet and UltraFace.  Every function returns boxes in
0-1 coordinates of the image it was given, label and score, kept down to a low score."""
import sys

import numpy as np
import onnxruntime as ort

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/dvr-forensics-toolkit")
from analytics import detect  # noqa: E402
from analytics.tiles import merge, tiles, to_frame  # noqa: E402

M = r"C:/Users/JAIPREET SINGH/150/recall/models/"
# COCO-80 (0-based, as YOLOX emits them) -> the tool's labels
YOLO_COCO = {0: "person", 1: "bicycle", 2: "car", 3: "motorcycle", 5: "bus", 7: "truck",
             24: "backpack", 26: "handbag", 28: "suitcase"}


def session(name):
    o = ort.SessionOptions()
    o.log_severity_level = 3
    o.intra_op_num_threads = 4
    return ort.InferenceSession(M + name, o, providers=["CPUExecutionProvider"])


def nms(boxes, scores, iou):
    if not len(boxes):
        return []
    return detect._nms(np.asarray(boxes, np.float32), np.asarray(scores, np.float32), iou)


def yolox(sess, rgb, low=0.1):
    size = sess.get_inputs()[0].shape[2]
    h, w = rgb.shape[:2]
    r = min(size / h, size / w)
    nh, nw = int(round(h * r)), int(round(w * r))
    ys = np.minimum((np.arange(nh) / r).astype(int), h - 1)
    xs = np.minimum((np.arange(nw) / r).astype(int), w - 1)
    pad = np.full((size, size, 3), 114, np.uint8)
    pad[:nh, :nw] = rgb[ys][:, xs][:, :, ::-1]                  # BGR, as YOLOX was trained
    out = sess.run(None, {"images": pad.transpose(2, 0, 1)[None].astype(np.float32)})[0][0]
    grids, strides = [], []
    for s in (8, 16, 32):
        g = size // s
        yv, xv = np.meshgrid(np.arange(g), np.arange(g), indexing="ij")
        grids.append(np.stack((xv, yv), 2).reshape(-1, 2))
        strides.append(np.full((g * g, 1), s))
    grids, strides = np.concatenate(grids), np.concatenate(strides)
    xy = (out[:, :2] + grids) * strides
    wh = np.exp(out[:, 2:4]) * strides
    scores = out[:, 4:5] * out[:, 5:]
    found = []
    for c, label in YOLO_COCO.items():
        sc = scores[:, c]
        m = sc >= low
        if not m.any():
            continue
        b = np.concatenate([xy[m] - wh[m] / 2, xy[m] + wh[m] / 2], 1) / r
        for i in nms(b, sc[m], 0.45):
            x1, y1, x2, y2 = b[i]
            found.append({"label": label, "score": round(float(sc[m][i]), 3),
                          "box": [round(float(np.clip(x1 / w, 0, 1)), 4), round(float(np.clip(y1 / h, 0, 1)), 4),
                                  round(float(np.clip(x2 / w, 0, 1)), 4), round(float(np.clip(y2 / h, 0, 1)), 4)]})
    return found


def yunet(sess, rgb, low=0.3):
    h, w = rgb.shape[:2]
    H, W = (h + 31) // 32 * 32, (w + 31) // 32 * 32
    img = np.zeros((H, W, 3), np.float32)
    img[:h, :w] = rgb[:, :, ::-1]                                  # BGR, 0-255
    outs = dict(zip([o.name for o in sess.get_outputs()],
                    sess.run(None, {"input": img.transpose(2, 0, 1)[None]})))
    boxes, scores = [], []
    for s in (8, 16, 32):
        cols, rows = W // s, H // s
        cls = np.clip(outs[f"cls_{s}"][0, :, 0], 0, 1)
        obj = np.clip(outs[f"obj_{s}"][0, :, 0], 0, 1)
        sc = np.sqrt(cls * obj)
        m = sc >= low
        if not m.any():
            continue
        idx = np.nonzero(m)[0]
        bb = outs[f"bbox_{s}"][0][idx]
        cx = (idx % cols + bb[:, 0]) * s
        cy = (idx // cols + bb[:, 1]) * s
        bw, bh = np.exp(bb[:, 2]) * s, np.exp(bb[:, 3]) * s
        boxes += list(np.stack([cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2], 1))
        scores += list(sc[m])
    return [{"label": "face", "score": round(float(scores[i]), 3),
             "box": [round(float(np.clip(boxes[i][0] / w, 0, 1)), 4), round(float(np.clip(boxes[i][1] / h, 0, 1)), 4),
                     round(float(np.clip(boxes[i][2] / w, 0, 1)), 4), round(float(np.clip(boxes[i][3] / h, 0, 1)), 4)]}
            for i in nms(boxes, scores, 0.3)]


def ssd(sess, rgb):
    old = detect.OBJECT_MIN
    detect.OBJECT_MIN = 0.3                   # the model returns nothing lower
    try:
        return detect.objects(sess, rgb)
    finally:
        detect.OBJECT_MIN = old


def ultraface(sess, rgb):
    old = detect.FACE_MIN
    detect.FACE_MIN = 0.5
    try:
        return detect.faces(sess, rgb)
    finally:
        detect.FACE_MIN = old


def tiled(fn, sess, rgb, n):
    out = fn(sess, rgb)
    if n > 1:
        h, w = rgb.shape[:2]
        for t in tiles(w, h, n):
            x, y, tw, th = t
            for d in fn(sess, np.ascontiguousarray(rgb[y:y + th, x:x + tw])):
                d["box"] = to_frame(d["box"], t, w, h)
                out.append(d)
        out = merge(out)
    return out

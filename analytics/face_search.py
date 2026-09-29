"""Face search (optional layer): rank the faces in extracted clips by how alike
they are to the face in a reference photo the examiner supplies.

NOT part of the forensic core, and not run by analyse-video: it runs only when
an examiner gives it a photo (`cli.py face-search`).  What it outputs is a list
of CANDIDATES, NOT IDENTIFICATIONS: faces for the examiner to compare by eye
with the photo.  The rules, the thresholds and the wording that goes with every
result are in analytics/face_rules.py; the measurement behind them is
docs/VALIDATION_REPORT.md section 8n.

Each sampled frame is decoded with its shape kept, enlarged or reduced to fit
1920 x 1080 (a 704 x 576 recorder picture is read at 1320 x 1080), so a face
is not stretched.  YuNet finds the faces and their five points, each face is
aligned onto the 112 x 112 template (face_rules.similarity, then a bilinear
warp), and SFace turns it into a vector compared with the photo's.  A face's
size (eye_px) is counted in pixels of the recording, not of the enlargement:
enlarging adds no detail.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Optional

import numpy as np

from analytics.detect import _thumbnail, decode, open_model, sha256_file, shrink, yunet
from analytics.face_rules import (MATCH_MIN, MIN_EYE_PX, NOTES, RULE, SIZE, eye_px, is_candidate,
                                  ranked, similarity)
from analytics.models import DEFAULT_SET, MODEL_SETS, MODELS
from core import proc

FACE_MIN = MODEL_SETS[DEFAULT_SET]["faces_min"]      # the face detector's threshold, as analyse-video
KEEP = 6                                             # pictures kept per clip, the most alike faces
CODECS = {".h264": "h264", ".264": "h264", ".h265": "hevc", ".265": "hevc", ".hevc": "hevc"}


def load() -> dict:
    return {"faces": open_model(MODEL_SETS[DEFAULT_SET]["faces"]), "sface": open_model("sface")}


def align(rgb: np.ndarray, points) -> np.ndarray:
    """The face whose five points are `points` (pixels of `rgb`), turned and
    scaled onto the template: a 112 x 112 picture, sampled bilinearly, black
    where it falls outside the frame (as OpenCV's warpAffine does)."""
    (a, _, tx), (b, _, ty) = similarity(points)
    d = a * a + b * b
    v, u = np.mgrid[0:SIZE, 0:SIZE].astype(np.float64)
    sx = (a * (u - tx) + b * (v - ty)) / d          # each template pixel, back in the frame
    sy = (-b * (u - tx) + a * (v - ty)) / d
    h, w = rgb.shape[:2]
    x0, y0 = np.floor(sx).astype(np.int64), np.floor(sy).astype(np.int64)
    fx, fy = (sx - x0)[..., None], (sy - y0)[..., None]
    out = np.zeros((SIZE, SIZE, 3))
    for dy, dx, wt in ((0, 0, (1 - fx) * (1 - fy)), (0, 1, fx * (1 - fy)),
                       (1, 0, (1 - fx) * fy), (1, 1, fx * fy)):
        yy, xx = y0 + dy, x0 + dx
        inside = ((xx >= 0) & (xx < w) & (yy >= 0) & (yy < h))[..., None]
        out += wt * inside * rgb[np.clip(yy, 0, h - 1), np.clip(xx, 0, w - 1)]
    return np.clip(np.rint(out), 0, 255).astype(np.uint8)


def embed(sess, face: np.ndarray) -> np.ndarray:
    """SFace's vector for an aligned face, unit length.  SFace takes RGB,
    values 0-255, as OpenCV feeds it."""
    v = sess.run(None, {"data": face.astype(np.float32).transpose(2, 0, 1)[None]})[0][0]
    return v / max(float(np.linalg.norm(v)), 1e-12)


def _first_frame(path: str, fmt: list) -> Optional[np.ndarray]:
    """The first picture of a photo or clip, as RGB at its own size (ffmpeg
    writes it as a PPM, whose header gives the size), or None."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("ffmpeg not found - install it to use the analytics layer")
    r = proc.run(["ffmpeg", "-v", "quiet", "-noautorotate", *fmt, "-i", path, "-frames:v", "1",
                  "-f", "image2pipe", "-c:v", "ppm", "-pix_fmt", "rgb24", "-"],
                 timeout=proc.IMAGE_S, capture_output=True)
    head = r.stdout[:64].split(maxsplit=4)
    if len(head) < 4 or head[0] != b"P6" or head[3] != b"255" or not (head[1] + head[2]).isdigit():
        return None
    w, h = int(head[1]), int(head[2])
    n = len(r.stdout) - w * h * 3
    if n <= 0 or not r.stdout[:n].endswith(b"255\n"):
        return None
    return np.frombuffer(r.stdout[n:], np.uint8).reshape(h, w, 3)


def load_picture(path: str, longest: int = 1280) -> np.ndarray:
    """A photo as RGB, made smaller (by a whole factor) until its longer side
    is at most `longest`; as stored, not turned by any orientation tag
    (reference() tries it turned)."""
    img = _first_frame(path, [])
    if img is None:
        raise ValueError(f"{path}: not a picture ffmpeg can read")
    return shrink(img, -(-max(img.shape[:2]) // longest))


def decode_size(w: int, h: int) -> tuple[int, int, float]:
    """The size a w x h recording is read at - its shape kept, enlarged or
    reduced to fit 1920 x 1080 either way round - and the factor f."""
    f = min(1920 / max(w, h), 1080 / min(w, h))
    return max(2, round(w * f / 2) * 2), max(2, round(h * f / 2) * 2), f


def faces_in(sessions: dict, rgb: np.ndarray, f: float = 1.0, low: float = FACE_MIN) -> list[dict]:
    """The faces YuNet finds in a frame decoded f times the recording's size,
    each with its aligned picture (_face) and SFace vector (_vec); eye_px in
    pixels of the recording."""
    out = []
    for d in yunet(sessions["faces"], rgb, low, points=True):
        face = align(rgb, d["points"])
        out.append({"box": d["box"], "score": d["score"], "points": d["points"],
                    "eye_px": round(eye_px(d["points"]) / f, 1),
                    "_face": face, "_vec": embed(sessions["sface"], face)})
    return out


def faces_any_size(sess, img: np.ndarray, low: float = FACE_MIN) -> list[dict]:
    """YuNet's faces with their points, trying the picture smaller when none
    is found: a face filling a photo can be too large for the detector."""
    h, w = img.shape[:2]
    for k in (1, *(n for n in (2, 4) if max(h, w) // n >= 160)):
        found = yunet(sess, np.ascontiguousarray(shrink(img, k)), low, points=True)
        if found:
            for d in found:          # a pixel of the smaller picture is k x k pixels
                d["points"] = [[x * k + (k - 1) / 2, y * k + (k - 1) / 2] for x, y in d["points"]]
            return found
    return []


def reference(sessions: dict, photo: str) -> dict:
    """The face in the photo: the largest one found, upright or turned (a
    phone photo may be stored on its side)."""
    pic = load_picture(photo)
    for k in (0, 1, 3, 2):
        img = np.ascontiguousarray(np.rot90(pic, k))
        faces = faces_any_size(sessions["faces"], img)
        if faces:
            break
    else:
        raise ValueError(f"{photo}: no face found in the photo")
    area = lambda d: (d["box"][2] - d["box"][0]) * (d["box"][3] - d["box"][1])
    best = max(faces, key=area)
    face = align(img, best["points"])
    return {"photo": os.path.basename(photo), "photo_sha256": sha256_file(photo),
            "faces_in_photo": len(faces), "turned": 90 * k, "box": best["box"],
            "score": best["score"], "eye_px": eye_px(best["points"]),
            "_vec": embed(sessions["sface"], face), "_face": face, "_img": img}


def _big(face: np.ndarray) -> np.ndarray:
    return np.repeat(np.repeat(face, 2, 0), 2, 1)      # 224 x 224, to look at


def search_clip(sessions: dict, ref: dict, path: str, fps: float, out_dir: Optional[str],
                match_min: float = MATCH_MIN, min_eye_px: float = MIN_EYE_PX,
                keep: int = KEEP) -> dict:
    """Every face YuNet finds in the sampled frames, scored against the photo."""
    codec = CODECS.get(os.path.splitext(path)[1].lower(), "")
    first = _first_frame(path, ["-f", codec] if codec else [])
    base = {"clip": os.path.basename(path), "clip_sha256": sha256_file(path)}
    if first is None:
        return dict(base, frames_analysed=0, faces_compared=0, candidates=0, too_small=0,
                    faces=[], note="no picture could be decoded")
    W, H, f = decode_size(first.shape[1], first.shape[0])
    frames, faces, best = 0, [], []
    for t, rgb in decode(path, fps, codec, size=(W, H)):
        frames += 1
        for d in faces_in(sessions, rgb, f):
            x = {"t_s": round(t, 2), "box": d["box"], "score": d["score"], "eye_px": d["eye_px"],
                 "similarity": round(float(np.dot(ref["_vec"], d["_vec"])), 3)}
            x["candidate"] = is_candidate(x, match_min, min_eye_px)
            faces.append(x)
            best.append((x["similarity"], len(faces) - 1, rgb, d["_face"]))
            best.sort(key=lambda b: -b[0])
            del best[keep:]
    stem = os.path.splitext(os.path.basename(path))[0]
    if out_dir:
        k = max(1, max(W, H) // 640)
        for _, i, rgb, face in best:
            x = faces[i]
            name = f"{stem}_t{x['t_s']:07.1f}_{i:04d}"
            _thumbnail(shrink(rgb, k), [{"label": "face", "box": x["box"]}],
                       os.path.join(out_dir, name + ".jpg"))
            _thumbnail(_big(face), [], os.path.join(out_dir, name + "_face.jpg"))
            x["picture"], x["face_picture"] = name + ".jpg", name + "_face.jpg"
            x["picture_sha256"] = sha256_file(os.path.join(out_dir, name + ".jpg"))
    return dict(base, recording_size=f"{first.shape[1]} x {first.shape[0]}",
                decoded_at=f"{W} x {H}", frames_analysed=frames, faces_compared=len(faces),
                candidates=sum(x["candidate"] for x in faces),
                too_small=sum(x["eye_px"] < min_eye_px for x in faces), faces=faces)


def run(photo: str, clips: list[str], out_dir: str, fps: float = 1.0, log=print,
        match_min: float = MATCH_MIN, min_eye_px: float = MIN_EYE_PX) -> dict:
    """Search the clips for the face in the photo; writes out_dir/face_search.json
    and the pictures in out_dir/face_search/."""
    sessions = load()
    ref = reference(sessions, photo)
    pics = os.path.join(out_dir, "face_search")
    os.makedirs(pics, exist_ok=True)
    img = ref["_img"]
    _thumbnail(shrink(img, max(1, max(img.shape[:2]) // 640)), [{"label": "face", "box": ref["box"]}],
               os.path.join(pics, "reference_photo.jpg"))
    _thumbnail(_big(ref["_face"]), [], os.path.join(pics, "reference_face.jpg"))
    log(f"  photo         {ref['photo']}: {ref['faces_in_photo']} face(s), the largest used"
        + (f", photo turned {ref['turned']} degrees" if ref["turned"] else "")
        + f"; eyes {ref['eye_px']:.0f} px apart")
    results = []
    for i, c in enumerate(clips):
        r = search_clip(sessions, ref, c, fps, pics, match_min, min_eye_px)
        results.append(r)
        top = max((x["similarity"] for x in r["faces"]), default=None)
        log(f"  [{i + 1}/{len(clips)}] {r['clip']}  {r['frames_analysed']} frames, "
            f"{r['faces_compared']} faces, {r['candidates']} candidates"
            + (f", most alike {top:.2f}" if top is not None else ""))
    m = lambda key: {x: MODELS[key][x] for x in ("name", "source", "license", "sha256")}
    out = {
        "rule": RULE, "status": "candidates for review, not identification",
        "reference": {**{x: v for x, v in ref.items() if not x.startswith("_")},
                      "picture": "reference_photo.jpg", "face_picture": "reference_face.jpg"},
        "models": {"faces": m(MODEL_SETS[DEFAULT_SET]["faces"]), "recognition": m("sface")},
        "face_min": FACE_MIN, "match_min": match_min, "min_eye_px": min_eye_px,
        "sample_fps": fps,
        "totals": {"clips": len(results),
                   "frames_analysed": sum(r["frames_analysed"] for r in results),
                   "faces_compared": sum(r["faces_compared"] for r in results),
                   "candidates": sum(r["candidates"] for r in results),
                   "too_small": sum(r["too_small"] for r in results)},
        "top": ranked(results), "clips": results, "notes": NOTES,
    }
    with open(os.path.join(out_dir, "face_search.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    return out

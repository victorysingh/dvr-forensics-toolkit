"""Does our numpy face search compute what OpenCV's FaceDetectorYN + FaceRecognizerSF compute?
Run with a separate environment holding opencv-python-headless (5.0 here), never the
tool's: python check_opencv.py photo [photo ...]"""
import os
import sys

import cv2
import numpy as np

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, REPO)
from analytics import face_search as F  # noqa: E402
from analytics.face_rules import eye_px  # noqa: E402

M = os.path.join(REPO, "analytics", "models")
S = F.load()
rec = cv2.FaceRecognizerSF.create(os.path.join(M, "face_recognition_sface_2021dec.onnx"), "")
vecs = {}
for photo in sys.argv[1:]:
    rgb = F.load_picture(photo)
    h, w = rgb.shape[:2]
    bgr = np.ascontiguousarray(rgb[:, :, ::-1])
    det = cv2.FaceDetectorYN.create(os.path.join(M, "face_detection_yunet_2026may.onnx"), "", (w, h), 0.7)
    _, cvf = det.detect(bgr)
    ours = F.yunet(S["faces"], rgb, 0.7, points=True)
    print(f"\n{os.path.basename(photo)} {w}x{h}: OpenCV {0 if cvf is None else len(cvf)} faces, ours {len(ours)}")
    if cvf is None or not ours:
        continue
    row = max(cvf, key=lambda r: r[2] * r[3])
    mine = max(ours, key=lambda d: (d["box"][2] - d["box"][0]) * (d["box"][3] - d["box"][1]))
    cvpts = row[4:14].reshape(5, 2)
    print("  points, largest gap px:", round(float(np.abs(cvpts - np.array(mine["points"])).max()), 3),
          " score cv", round(float(row[14]), 3), "ours", mine["score"], " eyes", eye_px(mine["points"]), "px")
    # alignment and vector from OpenCV, from its own points and from ours
    a_cv = rec.alignCrop(bgr, row)
    r2 = row.copy(); r2[4:14] = np.array(mine["points"]).ravel()
    a_cv_ourpts = rec.alignCrop(bgr, r2)
    a_ours = F.align(rgb, mine["points"])
    print("  aligned face vs OpenCV (same points): mean |diff|",
          round(float(np.abs(a_cv_ourpts[:, :, ::-1].astype(int) - a_ours).mean()), 3),
          " max", int(np.abs(a_cv_ourpts[:, :, ::-1].astype(int) - a_ours).max()))
    f_cv = rec.feature(a_cv).ravel(); f_cv /= np.linalg.norm(f_cv)
    f_ours = F.embed(S["sface"], a_ours)
    print("  cosine(OpenCV vector, our vector):", round(float(f_cv @ f_ours), 5))
    vecs[photo] = (f_cv, f_ours)
ks = list(vecs)
for i in range(len(ks)):
    for j in range(i + 1, len(ks)):
        a, b = vecs[ks[i]], vecs[ks[j]]
        print(f"{os.path.basename(ks[i])} vs {os.path.basename(ks[j])}: OpenCV match "
              f"{rec.match(a[0][None], b[0][None], cv2.FaceRecognizerSF_FR_COSINE):.4f}  ours {float(a[1] @ b[1]):.4f}")

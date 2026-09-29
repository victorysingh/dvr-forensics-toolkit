"""The analytics layer's models and how they are used - stdlib only, so the core
test suite can check it without the layer's dependencies.

Two sets.  "yolox" (the default): YOLOX-S for people, vehicles and bags,
YuNet for faces.  "classic": SSD-MobileNet v1 and UltraFace, the tool as
measured before 29 Sep 2026, kept so those results can be reproduced.
docs/VALIDATION_REPORT.md section 8a has both, scored on the same labelled
frames and on CAVIAR footage that played no part in the choice.
"""

from __future__ import annotations

MODELS = {
    "face": {"file": "ultraface_rfb320.onnx",
             "name": "UltraFace version-RFB-320",
             "source": "https://github.com/onnx/models (validated/vision/body_analysis/ultraface)",
             "url": "https://github.com/onnx/models/raw/main/validated/vision/body_analysis/"
                    "ultraface/models/version-RFB-320.onnx",
             "license": "MIT",
             "sha256": "34cd7e60aeff28744c657de7a3dc64e872d506741de66987f3426f2b79f88017"},
    "objects": {"file": "ssd_mobilenet_v1_12.onnx",
                "name": "SSD-MobileNet v1 (COCO), opset 12",
                "source": "https://github.com/onnx/models "
                          "(validated/vision/object_detection_segmentation/ssd-mobilenetv1)",
                "url": "https://github.com/onnx/models/raw/main/validated/vision/"
                       "object_detection_segmentation/ssd-mobilenetv1/model/ssd_mobilenet_v1_12.onnx",
                "license": "Apache-2.0",
                "sha256": "b8fba5e404077d4048d27fcd1667e85e27e192eb9bf51e696c46a3acd7d21058"},
    "yolox": {"file": "yolox_s.onnx",
              "name": "YOLOX-S (COCO), Megvii YOLOX release 0.1.1rc0",
              "source": "https://github.com/Megvii-BaseDetection/YOLOX/releases/tag/0.1.1rc0",
              "url": "https://github.com/Megvii-BaseDetection/YOLOX/releases/download/"
                     "0.1.1rc0/yolox_s.onnx",
              "license": "Apache-2.0",
              "sha256": "c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063"},
    "yunet": {"file": "face_detection_yunet_2026may.onnx",
              "name": "YuNet face detector (OpenCV Zoo, 2026may, any input size)",
              "source": "https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet",
              "url": "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/"
                     "face_detection_yunet/face_detection_yunet_2026may.onnx",
              "license": "MIT",
              "sha256": "ebafce4e3c118d6554634be5c27ab333b4c047a9a8c3faf1d7cf93101c22f0f0"},
}

# Which model does which job, at what threshold, on how many tiles by default.
# Thresholds: 0.5 for objects is the tool's standing value, not tuned. The
# YuNet threshold, 0.7, was chosen on the only frames with face labels (set A:
# 0.6 finds 13 of 27 with 1 false alarm, 0.7 finds 12 with none, 0.8 finds 10).
# class_min overrides objects_min for one class.  YOLOX people at 0.4: on set A
# 39 of 57 found (32 at 0.5) and on CAVIAR 810 of 1,089 (777), with no more
# frames falsely flagged on either; vehicles at 0.4 would add 5 false alarms on
# set A, so they stay at 0.5 (docs/VALIDATION_REPORT.md section 8a).
MODEL_SETS = {
    "yolox": {"objects": "yolox", "faces": "yunet", "objects_min": 0.5, "faces_min": 0.7,
              "class_min": {"person": 0.4},
              "tiles": 2, "rule": "analytics.yolox_yunet.v3",
              "how": "YOLOX-S on the whole 1920 x 1080 frame and on each tile of an n x n "
                     "grid; YuNet on the whole 1920 x 1080 frame"},
    "classic": {"objects": "objects", "faces": "face", "objects_min": 0.5, "faces_min": 0.8,
                "class_min": {},
                "tiles": 3, "rule": "analytics.ultraface_ssdmobilenet.v2",
                "how": "SSD-MobileNet on the whole frame and each tile of an n x n grid of a "
                       "1920 x 1080 decode; UltraFace likewise on the 640 x 360 frame"},
}
DEFAULT_SET = "yolox"


def threshold(model_set: str, label: str) -> float:
    """The score a detection of `label` needs to be reported by this set."""
    s = MODEL_SETS[model_set]
    if label == "face":
        return s["faces_min"]
    return s["class_min"].get(label, s["objects_min"])


def thresholds(model_set: str) -> dict:
    """The set's thresholds as recorded in its output."""
    s = MODEL_SETS[model_set]
    return {"faces": s["faces_min"], "objects": s["objects_min"], **s["class_min"]}

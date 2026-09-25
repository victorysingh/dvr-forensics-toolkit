"""Fetch the two ONNX models and refuse anything that is not the pinned file.

Run once on a connected machine; for an air-gapped workstation, copy the
analytics/models/ folder across and this script's --check verifies it.
"""

import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analytics.detect import HERE, MODELS, sha256_file  # noqa: E402

URLS = {
    "face": "https://github.com/onnx/models/raw/main/validated/vision/body_analysis/"
            "ultraface/models/version-RFB-320.onnx",
    "objects": "https://github.com/onnx/models/raw/main/validated/vision/"
               "object_detection_segmentation/ssd-mobilenetv1/model/ssd_mobilenet_v1_12.onnx",
}


def main() -> int:
    check_only = "--check" in sys.argv
    os.makedirs(os.path.join(HERE, "models"), exist_ok=True)
    ok = True
    for key, m in MODELS.items():
        path = os.path.join(HERE, "models", m["file"])
        if not os.path.exists(path) and not check_only:
            print(f"fetching {m['name']} ...")
            urllib.request.urlretrieve(URLS[key], path)
        got = sha256_file(path) if os.path.exists(path) else "missing"
        good = got == m["sha256"]
        ok &= good
        print(f"{'OK ' if good else 'BAD'} {m['file']}  {got}")
        if not good and os.path.exists(path) and not check_only:
            os.remove(path)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

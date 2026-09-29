"""Fetch the analytics models and refuse anything that is not the pinned file.

Run once on a connected machine; for an air-gapped workstation, copy the
analytics/models/ folder across and this script's --check verifies it.
The models, their sources, licences and hashes are in analytics/models.py.
"""

import hashlib
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analytics.models import MODELS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    check_only = "--check" in sys.argv
    os.makedirs(os.path.join(HERE, "models"), exist_ok=True)
    ok = True
    for m in MODELS.values():
        path = os.path.join(HERE, "models", m["file"])
        if not os.path.exists(path) and not check_only:
            print(f"fetching {m['name']} ...")
            urllib.request.urlretrieve(m["url"], path)
        got = sha256_file(path) if os.path.exists(path) else "missing"
        good = got == m["sha256"]
        ok &= good
        print(f"{'OK ' if good else 'BAD'} {m['file']}  {got}")
        if not good and os.path.exists(path) and not check_only:
            os.remove(path)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

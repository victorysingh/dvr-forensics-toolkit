"""How much time one pass saves: the same work done in one read of the
evidence, and in one read per task.

    python demo/bench_single_pass.py                 # 256 MiB synthetic image
    python demo/bench_single_pass.py --size-mb 1024 --json out/bench.json

It builds a synthetic DVR image - NOT evidence - holding Dahua DHAV footage,
Hikvision-style Program Stream footage and raw H.264 in an undocumented
container, then times on this machine:

  read only        the floor: touching every byte once, nothing else
  one pass         scan with --carve --carve-ps --carve-annexb --activity:
                   MD5 + SHA-256, the block Merkle map, vendor detection,
                   three carvers and motion activity, in ONE read
  one read a task  the same work the way separate tools do it: the scan
                   (hashes + detection), then each carver and the activity
                   count on its own, each reading the image again

Every repeat read here comes from the OS file cache, which flatters the
separate passes: a real drive is re-read at the speed of its USB bridge
every time.  So the result is given twice - as measured on this machine,
and projected onto a 1 TB drive at the 23.4 MiB/s the team's USB 2 bridge
actually delivered on drive 1 (931.5 GiB in 11 h 19 min, 24-25 Sep 2026),
where each pass takes whichever is slower, the drive or the CPU.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import sys
import tempfile
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acquire.device import BlockDevice                           # noqa: E402
from acquire.scanner import ScanSession                           # noqa: E402
from analyse.activity import ActivityTap                          # noqa: E402
from core.contract import CaseInfo                                # noqa: E402
from recover.annexb import AnnexBTap                              # noqa: E402
from recover.carver import CarveTap                               # noqa: E402
from recover.pscarve import PsCarveTap                            # noqa: E402
from acquire.parallel import TAPS, ProcessTap                     # noqa: E402
from tests.test_pipeline import _dav, _h26x_stream, _hik_ps, _vendor_frames  # noqa: E402

USB2_MIBS = 1_000_204_884_992 / (11 * 3600 + 19 * 60) / 2**20     # drive 1, attempt 4
ONE_TB = 1_000_204_884_992
CHUNK = 8 << 20


def build_image(path: str, size: int, seed: int = 7) -> dict:
    """A third each of DHAV, Program Stream and raw H.264, repeated to size."""
    rng = random.Random(seed)
    t0 = datetime(2026, 9, 28, 10, 0, 0)
    pieces = {"dhav": _dav(_h26x_stream(rng, 1500, "h265"), 0, t0),
              "ps": _hik_ps(_h26x_stream(rng, 1500, "h264"), 0, t0, pes_max=1400),
              "annexb": _vendor_frames(rng, 1500, "h264", 1920, 1080)}
    written = 0
    with open(path, "wb") as fh:
        while written < size:
            for p in pieces.values():
                fh.write(p[:size - written])
                written = min(size, written + len(p))
                if written >= size:
                    break
    return {k: len(v) for k, v in pieces.items()}


def read_only(img: str) -> float:
    t = time.perf_counter()
    with BlockDevice(img) as dev:
        off = 0
        while off < dev.size_bytes:
            off += len(dev.read_at(off, min(CHUNK, dev.size_bytes - off)))
    return time.perf_counter() - t


def tap_alone(img: str, tap, out: str) -> float:
    """One task as its own tool: its own read of the whole image."""
    os.makedirs(out, exist_ok=True)
    t = time.perf_counter()
    with BlockDevice(img) as dev:
        tap.prepare(dev, 0, dev.size_bytes, log=lambda *_: None)
        off = 0
        while off < dev.size_bytes:
            data = dev.read_at(off, min(CHUNK, dev.size_bytes - off))
            tap.feed(off, data)
            off += len(data)
        tap.finish(out, dev.info())
    return time.perf_counter() - t


def scan(img: str, out: str, taps: list) -> float:
    t = time.perf_counter()
    ScanSession(img, out, CaseInfo(case_id="BENCH", investigator="bench"),
                block_size=CHUNK, quiet=True, taps=taps).run()
    return time.perf_counter() - t


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--size-mb", type=int, default=256)
    ap.add_argument("--json", default="", help="also write the results here")
    args = ap.parse_args()
    size = args.size_mb << 20
    work = tempfile.mkdtemp(prefix="ps26150-bench-")
    try:
        img = os.path.join(work, "bench.img")
        print(f"building a {args.size_mb} MiB synthetic image (not evidence) ...")
        build_image(img, size)
        read_only(img)                                   # warm the cache: all runs start equal
        r = {"read only": read_only(img)}
        r["one pass"] = scan(img, os.path.join(work, "single"),
                             [CarveTap(), PsCarveTap(), AnnexBTap(), ActivityTap()])
        r["one pass, taps in parallel"] = scan(img, os.path.join(work, "parallel"),
                                               [ProcessTap(TAPS[n]) for n in TAPS])
        sep = {"scan (hashes, Merkle, detection)": scan(img, os.path.join(work, "s0"), [])}
        for name, tap in (("carve (DHAV)", CarveTap()), ("carve-ps", PsCarveTap()),
                          ("carve-annexb", AnnexBTap()), ("activity", ActivityTap())):
            sep[name] = tap_alone(img, tap, os.path.join(work, name.split()[0]))
        r["one read a task"] = sum(sep.values())
    finally:
        shutil.rmtree(work, ignore_errors=True)

    mib = size / 2**20
    speed = {k: mib / v for k, v in {**r, **sep}.items()}

    def projected(passes: dict) -> float:
        """Hours for a 1 TB drive over the USB 2 bridge: each pass is as slow
        as the slower of the drive and the CPU."""
        return sum(ONE_TB / 2**20 / min(USB2_MIBS, speed[k]) for k in passes) / 3600

    one = projected({"one pass": 1})
    one_par = projected({"one pass, taps in parallel": 1})
    many = projected(sep)
    # The usual alternative: image the drive once over the bridge, then run
    # each tool on the local image, where the CPU sets the pace.  Faster than
    # re-reading the drive, but it needs the drive's size in free space.
    image_then = (ONE_TB / 2**20 / USB2_MIBS
                  + sum(ONE_TB / 2**20 / speed[k] for k in sep)) / 3600
    usb3 = 120.0                                        # assumed, not measured by the team
    one_usb3 = ONE_TB / 2**20 / min(usb3, speed["one pass"]) / 3600
    par_usb3 = ONE_TB / 2**20 / min(usb3, speed["one pass, taps in parallel"]) / 3600
    res = {
        "machine": f"{platform.processor()}, {os.cpu_count()} logical CPUs, "
                   f"Python {platform.python_version()}, {platform.system()} {platform.release()}",
        "image_mib": args.size_mb,
        "seconds": {**{k: round(v, 2) for k, v in r.items()},
                    "separate passes": {k: round(v, 2) for k, v in sep.items()}},
        "mib_per_s": {k: round(v, 1) for k, v in speed.items()},
        "usb2_mib_per_s_measured_on_drive_1": round(USB2_MIBS, 1),
        "projected_hours_1tb_usb2": {"one pass": round(one, 1),
                                     "one read a task": round(many, 1),
                                     "image, then analyse the image": round(image_then, 1)},
        "image_then_analyse_needs_free_bytes": ONE_TB,
        "projected_hours_1tb_usb3_assumed_120_mib_s": {
            "one pass": round(one_usb3, 1),
            "one pass, taps in parallel": round(par_usb3, 1),
            "bound_by": "CPU" if speed["one pass"] < usb3 else "drive"},
        "note": "repeat reads here come from the OS cache; on a real drive each extra pass "
                "is another read over the bridge, which the projection accounts for",
    }
    print(f"\n{res['machine']}; image {args.size_mb} MiB\n")
    print(f"  {'':34} {'seconds':>8} {'MiB/s':>8}")
    print(f"  {'read only':34} {r['read only']:8.2f} {speed['read only']:8.1f}")
    print(f"  {'ONE PASS (all of the below)':34} {r['one pass']:8.2f} {speed['one pass']:8.1f}")
    print(f"  {'ONE PASS, taps in parallel':34} {r['one pass, taps in parallel']:8.2f} "
          f"{speed['one pass, taps in parallel']:8.1f}")
    for k, v in sep.items():
        print(f"  {'  separately: ' + k:34} {v:8.2f} {speed[k]:8.1f}")
    print(f"  {'ONE READ A TASK (sum)':34} {r['one read a task']:8.2f}")
    print(f"\n  on this machine: one pass takes {r['one pass'] / r['one read a task']:.0%} of "
          f"the time of one read a task")
    print(f"  a 1 TB drive over the USB 2 bridge ({USB2_MIBS:.1f} MiB/s, measured):")
    print(f"    one pass                         ~{one:5.1f} h, no free space needed")
    print(f"    one read a task                  ~{many:5.1f} h")
    print(f"    image, then analyse the image    ~{image_then:5.1f} h, and ~931 GiB free")
    print(f"  over USB 3 (assumed {usb3:.0f} MiB/s): one pass ~{one_usb3:.1f} h - bound by the "
          f"{'CPU' if speed['one pass'] < usb3 else 'drive'}, at {speed['one pass']:.0f} MiB/s;")
    print(f"    with taps in parallel ~{par_usb3:.1f} h, at "
          f"{speed['one pass, taps in parallel']:.0f} MiB/s")
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        print(f"\n[+] {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

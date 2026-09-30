"""Synthetic cases for a hosted deployment, made by the real pipeline.

    python deploy/make_demo_cases.py --out /srv/anokhidrishti/out --images /srv/anokhidrishti/images

Builds two SYNTHETIC disks - a Hikvision-layout one (tests/synth_dvr.py) and
a Dahua DHFS 4.1 one (tests/synth_dahua.py) - and runs each through scan
(with carving), parse, timeline and report, exactly as an examiner would.

They are not evidence and not vendor samples.  A hosted server is reachable
from the internet, so it never holds real drive data: the real drives carry
real people on camera and identify real units (see the 30 Sep scrub).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests import synth_dahua, synth_dvr                     # noqa: E402

CASES = [
    # (folder, case id, parser vendor, builder)
    ("demo_hikvision", "DEMO-HIK-01", "Hikvision", lambda p: synth_dvr.build(p)),
    ("demo_dahua", "DEMO-DAHUA-01", "Dahua",
     lambda p: synth_dahua.build(p, seconds=60, cameras=4)),
]
NOTE = "Synthetic disk generated for the hosted demonstration - not evidence."


def run(*args: str) -> None:
    print("  $ cli.py " + " ".join(args[:2]) + " ...")
    subprocess.run([sys.executable, os.path.join(ROOT, "cli.py"), *args],
                   check=True, stdout=subprocess.DEVNULL)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="folder the server serves cases from")
    ap.add_argument("--images", required=True, help="where the synthetic disk images go")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.images, exist_ok=True)

    for folder, case_id, vendor, build in CASES:
        case_dir = os.path.join(args.out, folder)
        if os.path.exists(os.path.join(case_dir, "report.json")):
            print(f"[=] {folder}: already made")
            continue
        image = os.path.join(args.images, folder + ".img")
        print(f"[+] {folder}: synthetic {vendor} disk -> {image}")
        build(image)
        run("scan", "--device", image, "--case", case_id,
            "--investigator", "demo operator", "--organization", "AnokhiDrishti demo",
            "--notes", NOTE, "--out", case_dir, "--carve")
        run("parse", "--device", image, "--vendor", vendor, "--out", case_dir)
        run("timeline", "--out", case_dir)
        run("report", "--out", case_dir, "--notes", NOTE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Every real-media check that needs no recorder, in one command.

    python -m validate.realmedia \\
        --case1 out/cpplus_WWD4A3NX --image1 skyhawk_WWD4A3NX_first20GiB.dd \\
        --case2 out/drive2_Z9C2632A [--image2 /dev/sdX] --work out/realchecks

Several tools have only ever run on generated data, and drive 1's
undecodable frames have a cause nobody has checked.  The two drives, their
case folders and the 20 GiB head image are enough to settle each of these
(STATUS.md §5-6).  This runs them all, skips whatever its inputs do not
allow with the reason, and writes out/realchecks/SUMMARY.md for the
validation report:

  1. identify-model  model strings outside the video, on each drive
  2. carve-annexb    the no-parser carver on real footage, scored against
                     the DHAV / MPEG-PS carvers that know the container
  3. decode-check    drive 1's undecodable frames against the DHAV counter
  4. read-osd        the OCR on the very streams whose titles and clocks were
                     read by eye (VALIDATION_REPORT 8a/8b), compared with them

Read-only like everything else: each step is a `cli.py` command, and those
never open a device for writing.  Steps 3 and 4 need ffmpeg (and 4 needs
tesseract): `sudo apt install ffmpeg tesseract-ocr`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(HERE, "cli.py")

# What an examiner read by eye (VALIDATION_REPORT.md 8a, 8b; OSD_OCR.md 6).
DRIVE1_TITLES = {"parking", "road view 1", "road view 2"}
DRIVE2_REFERENCE = [("2024-07-28 08:19:42", "camera 01"), ("2023-07-22 11:28:55", "camera 03")]


def run(args: list[str], log_path: str) -> int:
    with open(log_path, "w", encoding="utf-8") as log:
        p = subprocess.run([sys.executable, CLI] + args, stdout=log, stderr=subprocess.STDOUT,
                           cwd=HERE)
    return p.returncode


def load(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def coverage(carved: list[list[int]], found: list[list[int]], end: int) -> dict:
    """How many bytes the known carver found inside [0, end) that the
    no-parser carver also covers, and how much it found that the known
    carver did not."""
    def clip(xs):
        return sorted((o, min(o + n, end)) for o, n in xs if o < end)

    def total(xs):
        return sum(b - a for a, b in xs)

    def overlap(a, b):
        i = j = s = 0
        while i < len(a) and j < len(b):
            lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
            s += max(0, hi - lo)
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return s

    k, f = clip(carved), clip(found)
    both = overlap(k, f)
    return {"known_bytes": total(k), "found_bytes": total(f), "known_bytes_also_found": both,
            "share_of_known_found": round(both / total(k), 4) if total(k) else None,
            "found_bytes_not_known": total(f) - both}


def norm(t: str) -> str:
    return " ".join((t or "").lower().split())


def step_model(name, case, image, work, out):
    slug = name.replace(" ", "")
    if not image:
        out.append(f"- **{name} identify-model:** skipped - no device or image given")
        return
    rc = run(["identify-model", "--device", image, "--out", case],
             os.path.join(work, f"{slug}_identify_model.log"))
    res = load(os.path.join(case, "model.json")) or {}
    rec = [c for c in res.get("candidates", []) if c["kind"] == "recorder"]
    out.append(f"- **{name} identify-model** (exit {rc}): searched "
               f"{res.get('searched', {}).get('bytes', 0):,} bytes; recorder model strings: "
               + (", ".join(f"`{c['model']}` x{c['count']} at 0x{c['offsets'][0]:X}" for c in rec)
                  or "none") + ".")


def annexb_range_mb(known_extents: list[list[int]], mb: int) -> int:
    """How much of the image to carve: the first `mb` MiB - or, where the
    known carver found no footage there, `mb` MiB past the first footage it
    did find.  On drive 1 that is at 4.2 GiB, so the first 2 GiB compared
    nothing with nothing."""
    starts = [o for o, _ in known_extents]
    if not starts or min(starts) < mb << 20:
        return mb
    return (min(starts) >> 20) + mb


def step_annexb(name, case, image, work, mb, known_report, out):
    slug = name.replace(" ", "")
    if not image:
        out.append(f"- **{name} carve-annexb:** skipped - no device or image given")
        return
    known = load(os.path.join(case, "carve", known_report))
    mb = annexb_range_mb([e for r in (known or {}).get("streams", []) for e in r["extents"]], mb)
    d = os.path.join(work, f"{slug}_annexb")
    rc = run(["carve-annexb", "--device", image, "--out", d, "--max-mb", str(mb)],
             os.path.join(work, f"{slug}_carve_annexb.log"))
    rep = load(os.path.join(d, "carve", "annexb_report.json"))
    if not rep or not known:
        out.append(f"- **{name} carve-annexb** (exit {rc}): no result to compare")
        return
    end = rep.get("range", [0, rep["source_bytes"]])[1]
    ext = [e for r in known["streams"] for e in r["extents"]]
    cov = coverage(ext, [e for r in rep["streams"] for e in r["extents"]], end)
    share = cov["share_of_known_found"]
    out.append(f"- **{name} carve-annexb** (exit {rc}), first {end / 2**20:,.0f} MiB: "
               f"{len(rep['streams'])} streams; it covers "
               f"{share:.1%} of the footage the `{known_report}` carver found there"
               if share is not None else
               f"- **{name} carve-annexb** (exit {rc}): the known carver found nothing in range")
    if share is not None:
        out[-1] += (f", and {cov['found_bytes_not_known'] / 2**20:,.1f} MiB it did not "
                    f"(to be looked at: other footage, or a false stream).")
    with open(os.path.join(work, f"{slug}_annexb_coverage.json"), "w", encoding="utf-8") as fh:
        json.dump(cov, fh, indent=2)


def step_decode(case, work, out):
    if not shutil.which("ffprobe"):
        out.append("- **drive 1 decode-check:** skipped - ffprobe not installed")
        return
    rc = run(["decode-check", "--out", case], os.path.join(work, "drive1_decode_check.log"))
    s = (load(os.path.join(case, "analytics", "decode_check.json")) or {}).get("summary")
    if not s:
        out.append(f"- **drive 1 decode-check** (exit {rc}): no result")
        return
    c = s["classes"]
    out.append(f"- **drive 1 decode-check** (exit {rc}): {s['not_decoded']:,} of "
               f"{s['video_frames']:,} video frames did not decode - "
               f"{c['before_first_keyframe']:,} before the first keyframe (expected), "
               f"{c['after_a_gap']:,} after a counter gap (a frame missing from the disk), "
               f"{c['unexplained']:,} unexplained. A missing frame explains "
               + (f"{s['share_explained_by_a_gap']:.1%}" if s["share_explained_by_a_gap"]
                  is not None else "n/a") + " of the failures after a keyframe.")


def ps_reference_ids(case: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """The stream each reference frame was read from, and why any could not
    be pinned down.  Eight cameras record at once on this recorder, so a time
    alone matches several streams - six at 2024-07-28 08:19:42, the first of
    them CH07.  The camera the title names chooses among them, by the label
    `label-ps` gave each stream.  A reference that still does not come down
    to one stream is left out, never guessed."""
    rows = (load(os.path.join(case, "carve", "ps_report.json")) or {}).get("streams", [])
    labels = {s["id"]: s.get("label") for s in
              (load(os.path.join(case, "carve", "ps_labels.json")) or {}).get("streams", [])}
    out, unresolved = [], []
    for t, title in DRIVE2_REFERENCE:
        hits = [r["id"] for r in rows if r.get("time_first_local") and r.get("time_last_local")
                and r["time_first_local"] <= t <= r["time_last_local"]]
        num = title.split()[-1]
        cam = f"CH{int(num):02d}" if num.isdigit() else None
        pinned = [h for h in hits if cam and labels.get(h) == cam]
        if len(pinned) == 1:
            out.append((pinned[0], t, title))
        elif len(hits) == 1 and labels.get(hits[0]) in (None, "outside_index"):
            out.append((hits[0], t, title))          # the only footage at that time
        else:
            unresolved.append(f"\"{title}\" at {t}: {len(hits)} streams cover that time, "
                              f"{len(pinned)} labelled {cam or 'with its camera'}")
    return out, unresolved


def step_ocr(case1, case2, image2, work, limit, out):
    if not (shutil.which("ffmpeg") and shutil.which("tesseract")):
        out.append("- **read-osd:** skipped - needs ffmpeg and tesseract")
        return
    if case1:
        rc = run(["read-osd", "--out", case1, "--unlabelled", "--limit", str(limit)],
                 os.path.join(work, "drive1_read_osd.log"))
        osd = load(os.path.join(case1, "analytics", "osd.json")) or {}
        named = [norm(s["label"]["title"]) for s in osd.get("streams", []) if s.get("label")]
        right = sum(1 for t in named if t in DRIVE1_TITLES)
        out.append(f"- **drive 1 read-osd** (exit {rc}): {len(osd.get('streams', []))} streams read, "
                   f"{len(named)} named; {right} of them a title an examiner read by eye "
                   f"({', '.join(sorted(DRIVE1_TITLES))}), {len(named) - right} another title "
                   f"(each to be checked against its frame).")
    if case2:
        refs, unresolved = ps_reference_ids(case2)
        for why in unresolved:
            out.append(f"- **drive 2 read-osd:** reference not compared - {why}")
        have = [r for r in refs if os.path.exists(
            os.path.join(case2, "carve", "ps_streams", r[0] + ".ps"))]
        missing = [r for r in refs if r not in have]
        if missing:
            ids = ",".join(r[0] for r in missing)
            if image2:
                run(["extract-carved", "--device", image2, "--out", case2, "--format", "ps",
                     "--ids", ids], os.path.join(work, "drive2_extract_reference.log"))
                have = refs
            else:
                out.append(f"- **drive 2 read-osd:** reference streams {ids} are not extracted; "
                           f"with drive 2 attached run `cli.py extract-carved --device <drive> "
                           f"--out {case2} --format ps --ids {ids}` (or pass --image2)")
        if have:
            rc = run(["read-osd", "--out", case2, "--ids", ",".join(r[0] for r in have)],
                     os.path.join(work, "drive2_read_osd.log"))
            osd = {s["clip"]: s for s in (load(os.path.join(case2, "analytics", "osd.json"))
                                          or {}).get("streams", [])}
            for sid, t, title in have:
                s = next((v for k, v in osd.items() if sid in k), None)
                got = norm(((s or {}).get("label") or {}).get("title", ""))
                clock = ((s or {}).get("clock") or {}).get("verdict")
                out.append(f"- **drive 2 read-osd `{sid}`** (exit {rc}): eye read "
                           f"\"{title}\" at {t}; the OCR read \"{got or 'nothing'}\" - "
                           f"{'MATCH' if got == title else 'DIFFERENT'}; clock check: {clock}.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--case1", default="", help="drive 1 case folder")
    ap.add_argument("--image1", default="", help="drive 1 device or head image")
    ap.add_argument("--case2", default="", help="drive 2 case folder")
    ap.add_argument("--image2", default="", help="drive 2 device or image (optional)")
    ap.add_argument("--work", default="out/realchecks")
    ap.add_argument("--annexb-mb", type=int, default=2048,
                    help="how much of each image the no-parser carver reads (MiB)")
    ap.add_argument("--ocr-limit", type=int, default=40)
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    out = [f"# Real-media checks, {datetime.now().strftime('%Y-%m-%d %H:%M')}", "",
           f"Tools: ffmpeg {'yes' if shutil.which('ffmpeg') else 'no'}, "
           f"tesseract {'yes' if shutil.which('tesseract') else 'no'}. Logs in `{a.work}`.", ""]
    for name, case, image, known in (("drive 1", a.case1, a.image1, "carve_report.json"),
                                     ("drive 2", a.case2, a.image2, "ps_report.json")):
        if not case:
            continue
        print(f"[*] {name}: identify-model")
        step_model(name, case, image, a.work, out)
        print(f"[*] {name}: carve-annexb")
        step_annexb(name, case, image, a.work, a.annexb_mb, known, out)
    if a.case1:
        print("[*] drive 1: decode-check")
        step_decode(a.case1, a.work, out)
    print("[*] read-osd")
    step_ocr(a.case1, a.case2, a.image2, a.work, a.ocr_limit, out)
    path = os.path.join(a.work, "SUMMARY.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    print("\n".join(out))
    print(f"\n[+] {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

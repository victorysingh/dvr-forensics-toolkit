"""The two-minute stage demo: what the tool does, end to end, in eight steps.

    python demo/stage_demo.py

Everything runs on SYNTHETIC disks built for the demo - not evidence, and
not vendor samples.  Each step prints one line of what happened and one of
why it matters.  For the real-drive results, see docs/FINAL_REPORT.md.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import random
import shutil
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli                                                          # noqa: E402
from acquire.device import BlockDevice                              # noqa: E402
from acquire.ewf import EwfImage                                    # noqa: E402
from acquire.parallel import TAPS, ProcessTap                       # noqa: E402
from acquire.scanner import ScanSession                             # noqa: E402
from core.contract import CaseInfo                                  # noqa: E402
from parsers import get_parser                                      # noqa: E402
from parsers.dahua import DHAV_HDR, walk_frames                     # noqa: E402
from recover import annexb                                          # noqa: E402
from tests import synth_dahua, synth_ewf, synth_honeywell           # noqa: E402
from tests.test_pipeline import _vendor_frames                      # noqa: E402


def quiet(fn, *a, **kw):
    """Run a CLI command without its own output; the demo narrates."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


def say(n: int, title: str, what: str, why: str, t0: float) -> None:
    print(f"\n[{n}] {title}  ({time.perf_counter() - t0:.1f} s)")
    print(f"    {what}")
    print(f"    -> {why}")


def main() -> int:
    work = tempfile.mkdtemp(prefix="ps26150-demo-")
    start = time.perf_counter()
    print("PS26150 - multi-vendor DVR/NVR forensic tool - stage demo (synthetic disks)")
    try:
        # 1. one pass over a Dahua-format disk ---------------------------------
        t = time.perf_counter()
        img = os.path.join(work, "cpplus.img")
        synth_dahua.build(img, seconds=20)
        with open(img, "ab") as fh:                       # room for step 7's proof
            fh.write(bytes(-os.path.getsize(img) % 512))
        case = os.path.join(work, "CASE-DEMO")
        rep = ScanSession(img, case, CaseInfo(case_id="CASE-DEMO", investigator="Examiner"),
                          block_size=1 << 20, quiet=True,
                          taps=[ProcessTap(TAPS["carve"]), ProcessTap(TAPS["activity"])]).run()
        carve = json.load(open(os.path.join(case, "carve", "carve_report.json"), encoding="utf-8"))
        labels = {}
        for r in carve["streams"]:
            labels[r["index_label"] or "unlabelled"] = labels.get(r["index_label"] or "unlabelled", 0) + 1
        sha = {h.algorithm: h.value for h in rep.hashes}
        d = rep.detections[0] if rep.detections else None
        say(1, "One read-only pass: hashes, Merkle map, detection, carving",
            f"SHA-256 {sha['sha256'][:16]}..., Merkle root {rep.merkle_root[:16]}...; "
            f"{d.vendor if d else '?'} at {d.confidence:.0%}; streams {labels}",
            f"{labels.get('outside_index', 0)} stream(s) of older footage no index accounts for "
            f"- deleted footage, recovered in the same read", t)

        # 2. the model ---------------------------------------------------------
        t = time.perf_counter()
        quiet(cli.cmd_record_device, argparse.Namespace(out=case, model="CP-UNR-104F1",
                                                        serial="DEMO-1", firmware="",
                                                        read_from="label", photo=[]))
        from detect import model
        checks = model.check(json.load(open(os.path.join(case, "device_record.json")))["observations"],
                             None, [{"vendor": d.vendor, "confidence": d.confidence}] if d else [])
        say(2, "The recorder's model, checked against the disk",
            f"CP-UNR-104F1 (CP Plus recorder) on a {d.vendor if d else '?'}-format disk: "
            f"{checks[0]['verdict']}",
            "vendor AND model, from two sources that are cross-checked - a mismatch is a finding", t)

        # 3. byte-match against a "recorder export" ----------------------------
        t = time.perf_counter()
        quiet(cli.cmd_extract_carved, argparse.Namespace(device=img, out=case, format="dhav",
                                                         ids="", label="all"))
        man = json.load(open(os.path.join(case, "carve", "extracted.json"), encoding="utf-8"))
        sid = max(man["streams"], key=lambda k: man["streams"][k]["frames_written"])
        src = open(os.path.join(case, "carve", "streams", sid + ".dav"), "rb").read()
        export = bytearray(src)                           # the recorder renumbers its frames
        for fr in walk_frames(src, 0):
            struct.pack_into("<I", export, fr.offset + 8, fr.frame_number + 100000)
            export[fr.offset + 23] = sum(export[fr.offset:fr.offset + 23]) & 0xFF
        ex = os.path.join(work, "recorder_export.dav")
        open(ex, "wb").write(bytes(export))
        quiet(cli.cmd_validate_export, argparse.Namespace(
            export=ex, against=[os.path.join(case, "carve", "streams")], out=case,
            codec="auto", recorder="demo"))
        res = json.load(open(os.path.join(case, "validation", "export_recorder_export.dav.json")))
        say(3, "Byte-match against the recorder's own export",
            f"{res['match']['slices_matched']}/{res['match']['slices_total']} picture slices "
            f"identical, in order - verdict {res['match']['verdict'].upper()}; container frames "
            f"differ ({res['container'].get('frames_byte_identical', 0)} identical headers)",
            "the only route to 'validated': the pictures must match, the wrapping may not", t)

        # 4. Honeywell, formatted ---------------------------------------------
        t = time.perf_counter()
        hw_img = os.path.join(work, "honeywell_formatted.img")
        truth = synth_honeywell.build(hw_img, format=True)
        hw = get_parser("Honeywell")
        with BlockDevice(hw_img) as dev:
            parsed = hw.parse(dev)
            runs = hw.recover_video_area(dev)
        say(4, "Honeywell NVR, after a format (plugin from Yoon & Hwang, DFRWS 2026)",
            f"index: {len(parsed.recordings)} recordings left; frame headers: {len(runs)} runs, "
            f"{sum(r.frame_count for r in runs)} frames, each with its own microsecond time",
            "a format erases the index, not the footage - status spec_only, stated", t)

        # 5. a vendor with no parser -------------------------------------------
        t = time.perf_counter()
        rng = random.Random(1)
        unk = os.path.join(work, "unknown_vendor.img")
        open(unk, "wb").write(rng.randbytes(1 << 18) + _vendor_frames(rng, 90, "h265", 1920, 1080)
                              + bytes(5 << 20) + _vendor_frames(rng, 60, "h264", 1280, 720))
        with BlockDevice(unk) as dev:
            streams, _ = annexb.carve(dev)
        say(5, "A recorder nobody documented: raw H.264/H.265 without a parser",
            ", ".join(f"{s.codec} {s.sps['width']}x{s.sps['height']} ({s.vcl} slices)"
                      for s in streams),
            "footage from any vendor that stores standard video - no dates or cameras, and it says so", t)

        # 6. the same disk as an E01 --------------------------------------------
        t = time.perf_counter()
        media = open(img, "rb").read()
        e01 = synth_ewf.write(os.path.join(work, "cpplus"), media, chunks_per_segment=40)[0]
        rep2 = ScanSession(e01, os.path.join(work, "CASE-E01"),
                           CaseInfo(case_id="E01", investigator="Examiner"),
                           block_size=1 << 20, quiet=True).run()
        img_e = EwfImage(e01)
        v = img_e.verify()
        img_e.close()
        same = {h.algorithm: h.value for h in rep2.hashes} == sha
        say(6, "The same disk as an EnCase .E01",
            f"{'same' if same else 'DIFFERENT'} MD5, SHA-256 and Merkle root as the raw image; "
            f"the image's own stored MD5 {'reproduced' if v['md5_match'] else 'NOT reproduced'}",
            "reads lab and NIST-style images directly, and lets the image check the reader", t)

        # 7. tampering, localised ----------------------------------------------
        t = time.perf_counter()
        blocks = [json.loads(l) for l in open(os.path.join(case, "blockmap.jsonl"), encoding="utf-8")]
        victim = len(blocks) // 2
        forged = bytearray(media)
        forged[blocks[victim]["offset"] + 1234] ^= 0x01
        changed = [i for i, b in enumerate(blocks)
                   if hashlib.sha256(forged[b["offset"]:b["offset"] + b["length"]]).hexdigest()
                   != b["sha256"]]
        whole = hashlib.sha256(forged).hexdigest() != sha["sha256"]
        say(7, "One byte changed in the disk image",
            f"whole-drive SHA-256 {'changes' if whole else 'UNCHANGED?!'}, and the block map names "
            f"block {changed} of {len(blocks)}",
            "tampering is not just detected but localised - the Merkle map, with no blockchain needed", t)

        # 8. certificate and CASE ---------------------------------------------
        t = time.perf_counter()
        blank = {k: "" for k in ("name", "relation", "address", "designation", "date",
                                 "time", "place")}
        quiet(cli.cmd_certificate, argparse.Namespace(out=case, part="B", records="both", **blank))
        cert = json.load(open(os.path.join(case, "certificate_s63_partB.json"), encoding="utf-8"))
        quiet(cli.cmd_case_export, argparse.Namespace(out=case))
        doc = json.load(open(os.path.join(case, "case.jsonld"), encoding="utf-8"))
        from acquire.ledger import CustodyLedger
        led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"))
        say(8, "For the court and for other tools",
            f"s.63 certificate (Part B, draft) with {len(cert['fields']['hash_values'])} hash values; "
            f"CASE/UCO export of {len(doc['@graph'])} nodes; custody ledger "
            f"{len(led.entries)} entries, chain {'valid' if led.verify()['valid'] else 'BROKEN'}",
            "BSA 2023 s.63 for Indian courts, CASE for every other tool - never speaking for a person", t)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f"\nDone in {time.perf_counter() - start:.0f} s.  Real drives: docs/FINAL_REPORT.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

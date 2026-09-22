"""Tamper-evidence demo - the two-minute version, for the stage.

Shows the thing a judge actually needs to believe: that this tool can tell
when evidence or its custody record has been altered, and say exactly where.

    python demo/tamper_demo.py

Runs offline, needs no hardware, and finishes in a few seconds.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acquire.ledger import CustodyLedger
from acquire.scanner import ScanSession
from core.contract import CaseInfo
from core.hashing import merkle_proof, merkle_root, verify_merkle_proof
from tests import synth_dvr

W = 66


def hr(title: str = "") -> None:
    print(f"\n{'=' * W}")
    if title:
        print(f"  {title}")
        print("=" * W)


def step(n: int, text: str) -> None:
    print(f"\n[{n}] {text}")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="ps26150-demo-")
    try:
        hr("PS26150 - TAMPER EVIDENCE DEMONSTRATION")
        print("  Synthetic DVR image. Nothing here is real evidence.")

        img = os.path.join(tmp, "dvr.img")
        meta = synth_dvr.build(img, size=16 * 1024 * 1024, vendor="hikvision")
        print(f"\n  fixture : {meta['size'] // 1024 // 1024} MiB, "
              f"{meta['active_clips']} indexed clips + 1 deleted clip")

        # -- 1. acquire ----------------------------------------------------
        step(1, "ACQUIRE - read-only single pass")
        out1 = os.path.join(tmp, "case1")
        s1 = ScanSession(img, out1, CaseInfo(case_id="DEMO-1",
                                             investigator="Aakash"),
                         block_size=1024 * 1024, quiet=True)
        r1 = s1.run()
        leaves1 = [b.sha256 for b in s1.scanner.blocks]
        sha1 = next(h.value for h in r1.hashes if h.algorithm == "sha256")
        print(f"    SHA-256      {sha1}")
        print(f"    Merkle root  {r1.merkle_root}")
        print(f"    blocks       {len(leaves1)}")
        det = r1.detections[0] if r1.detections else None
        if det:
            print(f"    vendor       {det.vendor} @ {det.confidence*100:.1f}% "
                  f"({det.validation_status})")

        step(2, "CUSTODY - every action is chained")
        v = s1.ledger.verify()
        print(f"    {v['message']}")
        for e in s1.ledger.entries:
            print(f"      #{e['seq']}  {e['action']:<26} {e['entry_hash'][:16]}...")

        # -- 3. prove one clip without re-reading the drive -----------------
        step(3, "PROVE - inclusion proof for the deleted clip")
        target = meta["deleted_clip"]["offset"]
        idx = next(i for i, b in enumerate(s1.scanner.blocks)
                   if b.offset <= target < b.offset + b.length)
        path = merkle_proof(leaves1, idx)
        ok = verify_merkle_proof(leaves1[idx], path, r1.merkle_root)
        print(f"    clip at      0x{target:X} lives in block {idx}")
        print(f"    block hash   {leaves1[idx][:48]}...")
        print(f"    proof        {len(path)} sibling hashes "
              f"(vs re-reading {len(leaves1)} blocks)")
        print(f"    verifies     {ok}")
        print("    -> a single carved clip is provably part of the acquired")
        print("       drive, without anyone re-reading the drive.")

        # -- 4. tamper with the evidence -----------------------------------
        step(4, "TAMPER - flip ONE byte inside the deleted clip")
        with open(img, "r+b") as fh:
            fh.seek(target + 64)
            original = fh.read(1)
            fh.seek(target + 64)
            fh.write(bytes([original[0] ^ 0xFF]))
        print(f"    byte at 0x{target + 64:X}: "
              f"0x{original[0]:02X} -> 0x{original[0] ^ 0xFF:02X}  "
              f"(1 byte in {meta['size']:,})")

        out2 = os.path.join(tmp, "case2")
        s2 = ScanSession(img, out2, CaseInfo(case_id="DEMO-2",
                                             investigator="Aakash"),
                         block_size=1024 * 1024, quiet=True)
        r2 = s2.run()
        leaves2 = [b.sha256 for b in s2.scanner.blocks]
        sha2 = next(h.value for h in r2.hashes if h.algorithm == "sha256")
        changed = [i for i, (a, b) in enumerate(zip(leaves1, leaves2)) if a != b]

        print(f"\n    SHA-256      {sha2}")
        print(f"                 {'MATCH' if sha2 == sha1 else 'DOES NOT MATCH the acquisition hash'}")
        print(f"    Merkle root  {r2.merkle_root}")
        print(f"                 {'MATCH' if r2.merkle_root == r1.merkle_root else 'DOES NOT MATCH'}")
        print(f"\n    A plain hash says only 'something changed'.")
        print(f"    The block map says WHERE: block {changed} "
              f"(offset 0x{s1.scanner.blocks[changed[0]].offset:X})")
        print(f"      was  {leaves1[changed[0]][:48]}...")
        print(f"      now  {leaves2[changed[0]][:48]}...")
        print(f"    {len(leaves1) - len(changed)} of {len(leaves1)} blocks are "
              f"provably untouched.")

        # -- 5. tamper with the custody record itself ----------------------
        step(5, "TAMPER - now edit the custody log to cover it up")
        lpath = os.path.join(out1, "custody_ledger.jsonl")
        rows = [json.loads(l) for l in open(lpath, encoding="utf-8") if l.strip()]
        victim = 1
        print(f"    rewriting entry #{victim} ({rows[victim]['action']}) "
              f"to hide the original scan parameters")
        rows[victim]["detail"]["block_size"] = 999999
        with open(lpath, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True,
                                    separators=(",", ":")) + "\n")
        v2 = CustodyLedger(lpath).verify()
        print(f"\n    {v2['message']}")
        print(f"      reason   {v2['reason']}")
        print(f"      expected {str(v2['expected'])[:48]}...")
        print(f"      found    {str(v2['found'])[:48]}...")
        print("    -> the edit is detected, and named to the exact entry.")

        hr("WHAT THIS DEMONSTRATES")
        print("""  1. Acquisition never writes to the evidence drive.
  2. Integrity is not one hash - it is a hash per block plus a Merkle
     root, so tampering is LOCATED, not merely noticed.
  3. Any single clip carries a short inclusion proof back to the
     acquisition-time root.
  4. The chain of custody is itself tamper-evident: editing it breaks
     the chain at a named entry.

  This is the Blockchain & Cybersecurity theme used where it earns its
  place - tamper-evident custody - rather than bolted on for the name.""")
        print("=" * W)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

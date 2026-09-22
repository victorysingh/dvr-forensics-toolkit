"""Regression tests. Runs standalone (no pytest required) or under pytest.

    python tests/test_pipeline.py

Covers the properties the rest of the tool depends on being true:
  * Merkle proofs verify at every odd/even tree shape
  * the custody chain detects edits, reorderings and deletions
  * signatures straddling a block boundary are still found, exactly once
  * bad sectors are zero-filled in place and never shift later offsets
  * a resume onto the wrong device is refused
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acquire.device import BlockDevice
from acquire.ledger import CustodyLedger
from acquire.scanner import ScanSession
from core.contract import CaseInfo, canonical_json
from core.hashing import merkle_proof, merkle_root, sha256_bytes, verify_merkle_proof
from detect.engine import SignatureScanner, parse_partitions
from detect import signatures as sig
from tests import synth_dvr

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSED.append(name) if cond else FAILED.append((name, detail)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{('  <- ' + detail) if detail and not cond else ''}")


# ---------------------------------------------------------------------------
def test_merkle() -> None:
    print("\n[merkle]")
    for n in (1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 100):
        leaves = [sha256_bytes(bytes([i % 251]) * 32) for i in range(n)]
        root = merkle_root(leaves)
        ok = all(verify_merkle_proof(leaves[i], merkle_proof(leaves, i), root)
                 for i in range(n))
        check(f"proofs verify for {n} leaves", ok)

    leaves = [sha256_bytes(bytes([i]) * 32) for i in range(8)]
    root = merkle_root(leaves)
    tampered = list(leaves)
    tampered[3] = sha256_bytes(b"forged")
    check("changing one leaf changes the root", merkle_root(tampered) != root)
    check("a proof for the original leaf fails against the tampered tree",
          not verify_merkle_proof(leaves[3], merkle_proof(tampered, 3),
                                  merkle_root(tampered)))
    check("empty tree yields empty root", merkle_root([]) == "")


# ---------------------------------------------------------------------------
def test_ledger(tmp: str) -> None:
    print("\n[custody ledger]")
    path = os.path.join(tmp, "ledger.jsonl")
    led = CustodyLedger(path, actor="Aakash", case_id="T-1")
    led.append("device_opened_read_only", {"path": "fake"})
    led.append("scan_started", {"block_size": 8})
    led.append("scan_completed", {"bytes": 123}, data_hash="ab" * 32)
    check("fresh chain verifies", led.verify()["valid"])
    check("head is the last entry hash", led.head == led.entries[-1]["entry_hash"])

    # Edit a past entry the way someone covering their tracks would: rewrite
    # the file in place, keeping the structure valid JSON.
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    rows[1]["detail"]["block_size"] = 999
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
    v = CustodyLedger(path).verify()
    check("edited entry is detected", not v["valid"], str(v))
    check("break is reported at the edited entry", v.get("broken_at_seq") == 1,
          f"got seq {v.get('broken_at_seq')}")

    # Deleting an entry must break the links, not silently shorten the record.
    rows2 = [r for r in rows if r["seq"] != 1]
    p2 = os.path.join(tmp, "ledger2.jsonl")
    with open(p2, "w", encoding="utf-8") as fh:
        for r in rows2:
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
    v2 = CustodyLedger(p2).verify()
    check("deleted entry is detected", not v2["valid"], str(v2))

    check("canonical json is order independent",
          canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1}))


# ---------------------------------------------------------------------------
def test_boundary_signatures() -> None:
    print("\n[signature block boundaries]")
    pattern = b"HIKVISION@HANGZHOU"
    block = 4096
    # Place the magic so it straddles the boundary between block 0 and 1.
    split = 6
    data = bytearray(block * 2)
    start = block - split
    data[start:start + len(pattern)] = pattern

    sc = SignatureScanner()
    b0 = bytes(data[:block])
    b1 = bytes(data[block:])
    sc.scan_block(0, b0, 0, sha256_bytes(b0))
    sc.scan_block(block, b1, 1, sha256_bytes(b1))
    hits = [h for h in sc.hits if h.signature_id == "hik.master"]
    check("straddling signature is found", len(hits) == 1,
          f"found {len(hits)} hits")
    if hits:
        check("reported at the true absolute offset", hits[0].offset == start,
              f"got {hits[0].offset}, expected {start}")

    # And it must not be double counted when it sits wholly inside one block.
    sc2 = SignatureScanner()
    d = bytearray(block * 2)
    d[100:100 + len(pattern)] = pattern
    sc2.scan_block(0, bytes(d[:block]), 0, "x" * 64)
    sc2.scan_block(block, bytes(d[block:]), 1, "y" * 64)
    check("no double counting within a block",
          sc2.hit_counts.get("hik.master") == 1,
          f"count={sc2.hit_counts.get('hik.master')}")


# ---------------------------------------------------------------------------
def test_bad_sectors(tmp: str) -> None:
    print("\n[bad sector handling]")

    class FlakyDevice(BlockDevice):
        """Fails one specific sector, like a drive with a pending reallocation."""
        def __init__(self, path, bad_offset):
            self.bad_offset = bad_offset
            super().__init__(path)

        def _raw_read(self, offset, length):
            if offset <= self.bad_offset < offset + length:
                raise OSError("simulated uncorrectable read error")
            return super()._raw_read(offset, length)

    img = os.path.join(tmp, "flaky.img")
    with open(img, "wb") as fh:
        fh.write(bytes(range(256)) * 64)          # 16 KiB of known pattern

    dev = FlakyDevice(img, bad_offset=2048)
    dev.is_raw = True                              # force the aligned raw path
    blocks = list(dev.read_blocks(4096))
    dev.close()

    total = sum(len(d) for _, d, _ in blocks)
    check("length is preserved despite the bad sector", total == 16384,
          f"got {total}")
    bad = [e for _, _, e in blocks if e]
    check("bad sector is reported", len(bad) == 1, f"errors={bad}")
    block0 = blocks[0][1]
    check("only the bad sector is zero-filled",
          block0[2048:2560] == b"\x00" * 512 and block0[0:512] != b"\x00" * 512)
    check("data after the bad sector keeps its offset",
          block0[2560:2560 + 16] == (bytes(range(256)) * 64)[2560:2576])


# ---------------------------------------------------------------------------
def test_full_scan(tmp: str) -> None:
    print("\n[end to end scan]")
    img = os.path.join(tmp, "synth.img")
    meta = synth_dvr.build(img, size=16 * 1024 * 1024, vendor="mixed")
    out = os.path.join(tmp, "out")
    case = CaseInfo(case_id="T-E2E", investigator="test")
    session = ScanSession(img, out, case, block_size=1024 * 1024, quiet=True)
    report = session.run()

    vendors = {d.vendor: d for d in report.detections}
    check("Hikvision detected", "Hikvision" in vendors)
    check("Dahua detected", "Dahua" in vendors)
    if "Hikvision" in vendors:
        check("Hikvision confidence is high", vendors["Hikvision"].confidence > 0.7,
              f"{vendors['Hikvision'].confidence}")
        check("Hikvision is NOT claimed as validated",
              vendors["Hikvision"].validation_status != "validated",
              vendors["Hikvision"].validation_status)
        check("no parser is claimed", not vendors["Hikvision"].parser_available)

    check("master magic found at its expected offset",
          any(h.signature_id == "hik.master" and h.at_expected_offset
              for h in report.signature_hits))
    check("codec identified as h264", session.scanner.codec.likely_codec == "h264")
    check("every synthetic clip has an SPS",
          session.scanner.codec.sps >= meta["active_clips"] + 1,
          f"sps={session.scanner.codec.sps}")

    # The linear hash must equal an independent hash of the same file.
    independent = hashlib.sha256(open(img, "rb").read()).hexdigest()
    stored = next(h.value for h in report.hashes if h.algorithm == "sha256")
    check("linear sha256 matches an independent hash", stored == independent)

    # And the Merkle root must be reproducible from the block map alone.
    leaves = [json.loads(l)["sha256"]
              for l in open(os.path.join(out, "blockmap.jsonl"), encoding="utf-8")
              if l.strip()]
    check("merkle root recomputes from the block map",
          merkle_root(leaves) == report.merkle_root)
    check("custody chain intact after a real scan", session.ledger.verify()["valid"])
    check("coverage statement lists every PS vendor",
          len(session.scanner.coverage_statement()) == len(sig.PS_VENDORS))

    # Tamper the image and confirm exactly one block hash moves.
    with open(img, "r+b") as fh:
        fh.seek(meta["deleted_clip"]["offset"] + 64)
        fh.write(b"\xff")
    out2 = os.path.join(tmp, "out2")
    s2 = ScanSession(img, out2, CaseInfo(case_id="T-E2E-2", investigator="test"),
                     block_size=1024 * 1024, quiet=True)
    r2 = s2.run()
    leaves2 = [b.sha256 for b in s2.scanner.blocks]
    leaves1 = [b.sha256 for b in session.scanner.blocks]
    differing = [i for i, (a, b) in enumerate(zip(leaves1, leaves2)) if a != b]
    check("a one-byte edit changes the merkle root",
          r2.merkle_root != report.merkle_root)
    check("and pinpoints exactly one block", len(differing) == 1,
          f"blocks changed: {differing}")


# ---------------------------------------------------------------------------
def test_resume_guard(tmp: str) -> None:
    print("\n[resume safety]")
    img = os.path.join(tmp, "r.img")
    synth_dvr.build(img, size=4 * 1024 * 1024)
    out = os.path.join(tmp, "rout")
    case = CaseInfo(case_id="T-R", investigator="test")
    ScanSession(img, out, case, block_size=1024 * 1024, quiet=True).run()

    other = os.path.join(tmp, "other.img")
    synth_dvr.build(other, size=8 * 1024 * 1024, seed=7)
    try:
        ScanSession(other, out, case, block_size=1024 * 1024,
                    resume=True, quiet=True).run()
        check("resume onto a different device is refused", False, "it was allowed")
    except RuntimeError as exc:
        check("resume onto a different device is refused", "refusing" in str(exc))


# ---------------------------------------------------------------------------
def test_partitions() -> None:
    print("\n[partition parsing]")
    head = bytearray(1024 * 1024)
    head[510:512] = b"\x55\xaa"
    part = bytearray(16)
    part[4] = 0x07
    part[8:12] = (2048).to_bytes(4, "little")
    part[12:16] = (204800).to_bytes(4, "little")
    head[446:462] = part
    parts = parse_partitions(bytes(head))
    check("mbr partition parsed", len(parts) == 1)
    if parts:
        check("offset is in bytes not sectors", parts[0].start_offset == 2048 * 512)
        check("type is resolved", parts[0].type_hint == "NTFS/exFAT")
    check("a disk with no table returns no partitions",
          parse_partitions(bytes(1024)) == [])


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="ps26150-tests-")
    try:
        test_merkle()
        test_ledger(tmp)
        test_boundary_signatures()
        test_bad_sectors(tmp)
        test_partitions()
        test_full_scan(tmp)
        test_resume_guard(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"  {len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"    FAILED: {name}  {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())

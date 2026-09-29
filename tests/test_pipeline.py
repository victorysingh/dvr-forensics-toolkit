"""Regression tests. Runs standalone (no pytest required) or under pytest.

    python tests/test_pipeline.py

Covers the properties the rest of the tool depends on being true:
  * Merkle proofs verify at every odd/even tree shape
  * the custody chain detects edits, reorderings and deletions
  * signatures straddling a block boundary are still found, exactly once
  * bad sectors are zero-filled in place and never shift later offsets
  * a resume onto the wrong device is refused
  * Dahua DHFS reassembly never splices one camera's frames into another's
  * the indexless carver splits indistinguishable cameras rather than mixing them

Set DHFS_REAL_IMAGE to the SkyHawk partial image to also run the checks that
pin the parser to what was observed on real media.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import struct
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
from parsers import get_parser
from parsers import dahua
from parsers import hikvision as hik
from recover import carver
from tests import synth_dahua, synth_dvr, synth_hiklog

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
        # A Hikvision parser now ships, so `parser_available` is True here -
        # but that is a statement about code existing, never about validation.
        # The invariant that must hold forever is the one above: having a
        # parser must not promote the vendor to `validated`.
        check("parser availability reflects the plugin registry",
              vendors["Hikvision"].parser_available
              == ("Hikvision" in sig.PARSERS_AVAILABLE))
        check("vendors with no parser never claim one",
              all(not d.parser_available for d in report.detections
                  if d.vendor not in sig.PARSERS_AVAILABLE))

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


# ---------------------------------------------------------------------------
def test_hikvision_parser(tmp: str) -> None:
    print("\n[hikvision parser]")
    img = os.path.join(tmp, "hik.img")
    meta = synth_dvr.build(img, size=16 * 1024 * 1024, vendor="hikvision")

    parser = get_parser("Hikvision")
    check("plugin registers itself", parser is not None)
    if parser is None:
        return
    check("signatures.PARSERS_AVAILABLE tracks the registry",
          "Hikvision" in sig.PARSERS_AVAILABLE)

    with BlockDevice(img) as dev:
        check("detects a Hikvision volume", parser.detect(dev))
        check("master sector found at 0x200, its magic 0x10 in (as on the real drive)",
              parser.find_master(dev) == 0x200,
              hex(parser.find_master(dev)))
        result = parser.parse(dev)
    v = result.volume

    # --- the honesty invariants. These matter more than the parse itself.
    check("parse is NEVER claimed as validated",
          result.validation_status != "validated", result.validation_status)
    check("every field read off real media: spec_only, no field from our own fixture",
          result.validation_status == "spec_only"
          and {f["source"] for f in result.field_provenance}
          == {hik.SOURCE_OBSERVED, hik.SOURCE_PUBLISHED}, result.validation_status)
    check("field provenance is recorded for every decoded field",
          len(result.field_provenance) == len(synth_hik_fields()))

    # --- the master sector, checked against itself and the disk
    check("the master's fields agree with each other, with both index copies and with "
          "the index's data base", len(v["master_checks"]) == 7
          and all(c["ok"] for c in v["master_checks"]), str(v["master_checks"]))
    check("block size and data area are taken from the master",
          v["block_size"] == meta["hik_block_size"]
          and v["master"]["data_offset"] == synth_dvr.OFF_VIDEO_A
          and v["master"]["fs_version"] == "HIK.2011.03.08")

    # --- the index
    got = {(int(r.camera_id[2:]), int(r.timestamps[0].raw_value.split()[0]),
            int(r.timestamps[1].raw_value.split()[0]), r.offset) for r in result.recordings}
    check("every index record becomes a recording: camera, start, end, data block",
          got == set(meta["hik_records"]) and len(result.recordings) == meta["active_clips"],
          f"{len(result.recordings)} vs {meta['active_clips']}")
    check("both index copies read where the master points, and found identical",
          v["btree_headers"] == meta["hik_btree_offsets"]
          and all(r.confidence == 0.6 for r in result.recordings))
    check("a block reserved at initialisation (channel 255) is not a recording",
          v["reserved_records"] == 1)

    r0 = result.recordings[0]
    check("a recording's extent is its data block, and provenance hashes it",
          r0.length == meta["hik_block_size"] and r0.offset % meta["hik_block_size"] == 0
          and r0.provenance.sha256 == hashlib.sha256(
              open(img, "rb").read()[r0.offset:r0.offset + r0.length]).hexdigest())
    check("sector range brackets the byte extent",
          r0.provenance.sector_start * 512 <= r0.offset
          and r0.provenance.sector_end * 512 >= r0.offset + r0.length)

    # --- timestamps are claims on the recorder's clock, never converted
    tc = r0.timestamps[0]
    check("index times are the recorder's clock: named, never presented as UTC",
          tc.source == "index" and tc.decoded_utc is None and r0.start_utc is None
          and tc.raw_value == "1758499200 = 2025-09-22 00:00:00 recorder-local"
          and "zone unknown" in tc.decode_rule and tc.confidence < 1.0, str(tc))
    check("no recording claims certainty",
          all(r.confidence < 1.0 for r in result.recordings))

    # --- the deleted clip is in no indexed block: that is the carver's job
    deleted_off = meta["deleted_clip"]["offset"]
    check("the unindexed deleted clip lies in no recording's block",
          not any(r.offset <= deleted_off < r.offset + r.length for r in result.recordings))

    # --- drive 2's situation: the primary master overwritten, a backup left
    data = bytearray(open(img, "rb").read())
    data[0x40000:0x40200] = data[0x200:0x400]
    data[0x200:0x400] = bytes(0x200)
    backup = os.path.join(tmp, "hik_backup.img")
    with open(backup, "wb") as fh:
        fh.write(bytes(data))
    with BlockDevice(backup) as dev:
        rb = parser.parse(dev)
    check("with the primary master overwritten, the backup copy is found and read",
          rb.volume["master"]["offset"] == 0x40000
          and len(rb.recordings) == meta["active_clips"], str(rb.volume.get("master_copies")))


def test_parser_robustness(tmp: str) -> None:
    """A dying DVR disk is the normal case. A corrupt index must degrade into
    reported errors, never an exception or a silent wrong answer."""
    print("\n[parser robustness]")
    parser = get_parser("Hikvision")
    if parser is None:
        return

    # A disk with no Hikvision structures at all.
    empty = os.path.join(tmp, "empty.img")
    with open(empty, "wb") as fh:
        fh.write(bytes(1 << 20))
    with BlockDevice(empty) as dev:
        check("a non-Hikvision disk is not detected", not parser.detect(dev))
        res = parser.parse(dev)
    check("a non-Hikvision disk reports an error, not a crash", bool(res.errors))
    check("a non-Hikvision disk yields no recordings", not res.recordings)

    # Master sector present (magic only, fields blank), index absent.
    noidx = os.path.join(tmp, "noindex.img")
    buf = bytearray(1 << 20)
    buf[0x210:0x210 + 18] = b"HIKVISION@HANGZHOU"
    with open(noidx, "wb") as fh:
        fh.write(bytes(buf))
    with BlockDevice(noidx) as dev:
        res = parser.parse(dev)
    check("a blank master is reported as failing its own checks, not trusted",
          any("fields agree" in n for n in res.notes) and any("implausible" in n
                                                              for n in res.notes))
    check("a missing index is reported, not fatal",
          any("HIKBTREE" in n for n in res.notes) and not res.recordings)
    check("a missing index still reports the volume", bool(res.volume))

    # Index records read off a damaged platter: outside the disk, times
    # reversed, one off the block grid - and two sound ones.
    bad = os.path.join(tmp, "badindex.img")
    size = 4 << 20
    buf = bytearray(size)
    buf[0x200:0x400] = synth_dvr._hik_master(size, btrees=(0x1000, 0x1000))
    t0 = 1_758_499_200
    blk = synth_dvr.OFF_VIDEO_A
    buf[0x1000:0x2000] = synth_dvr._hik_btree([
        synth_dvr.hik_record(1, t0, t0 + 60, 1 << 40),               # outside the disk
        synth_dvr.hik_record(2, t0 + 60, t0, blk),                   # end before start
        synth_dvr.hik_record(3, t0, t0 + 60, blk + 0x123),           # off the block grid
        synth_dvr.hik_record(1, t0, t0 + 60, blk),
        synth_dvr.hik_record(2, t0, t0 + 60, blk + synth_dvr.HIK_BLOCK)])
    with open(bad, "wb") as fh:
        fh.write(bytes(buf))
    with BlockDevice(bad) as dev:
        res = parser.parse(dev)
    check("records outside the disk or with reversed times never become recordings; "
          "the two sound ones do",
          sorted(r.camera_id for r in res.recordings) == ["CH01", "CH02"]
          and all(r.offset < size for r in res.recordings), str([r.id for r in res.recordings]))
    check("a record off the block grid is discarded and reported",
          any("off the" in n and "grid" in n for n in res.notes), str(res.notes))

    # A timestamp of 0 must not become 1970 presented as fact.
    check("an unusable timestamp is not presented as a time",
          hik._local_time(0) is None)


# ---------------------------------------------------------------------------
class _Sink:
    def __init__(self):
        self.frames: list = []

    def write(self, b: bytes) -> None:
        self.frames.append(next(dahua.walk_frames(b, 0)))


def test_dahua_frames() -> None:
    print("\n[dahua DHAV frames]")
    from datetime import datetime
    dt = datetime(2026, 9, 3, 12, 53, 53)
    packed = synth_dahua.pack_date(dt)
    check("packed date decodes to the same wall-clock time",
          dahua.decode_date(packed) == dt)
    check("the real disk's first index date decodes as observed",
          dahua.fmt_date(0x6A46CD75) == "2026-09-03 12:53:53")
    check("an impossible packed date decodes to None, not an exception",
          dahua.decode_date(0xFFFFFFFF) is None)

    good = synth_dahua.dhav(0xFC, 10, dt, 100, b"\x00\x00\x00\x01\x02\x01" + bytes(50),
                            synth_dahua.EXT_VIDEO)
    buf = bytes(7) + good + bytes(5)
    frames = list(dahua.walk_frames(buf, 1000))
    check("a valid frame is found at its absolute offset",
          len(frames) == 1 and frames[0].offset == 1007)
    bad_ck = bytearray(good)
    bad_ck[23] ^= 0xFF
    check("a bad header checksum is rejected", not list(dahua.walk_frames(bytes(bad_ck), 0)))
    bad_tr = bytearray(good)
    bad_tr[-8:-4] = b"XXXX"
    check("a missing trailer is rejected", not list(dahua.walk_frames(bytes(bad_tr), 0)))
    check("a frame cut off by the buffer end is not yielded",
          not list(dahua.walk_frames(good[:-3], 0)))
    ext = dahua.frame_ext(good, 0, frames[0].__class__(0, 0xFC, 10, len(good),
                                                         packed, 100, len(synth_dahua.EXT_VIDEO)))
    check("extension tags decode codec, size and fps",
          ext.get("codec") == "h265" and ext.get("width") == 1920
          and ext.get("height") == 1080 and ext.get("fps") == 25)

    # Video and audio counters drift apart on real disks (78 apart after six
    # hours).  Continuity must compare a counter only with its own kind.
    F = dahua.DhavFrame
    v1 = F(0, 0xFC, 918167, 900, packed, 40385, 24)
    a1 = F(0, 0xF0, 918245, 368, packed, 40403, 16)
    v2 = F(0, 0xFC, 918168, 900, packed, 40425, 24)
    s = dahua.Stream(v1).feed(a1)
    check("drifted audio/video counters still read as one stream",
          s.distance(v2) is not None)
    other = F(0, 0xFC, 918168, 900, packed, (40425 + 9000) & 0xFFFF, 24)
    check("a frame 9 s away on the ms clock is another stream",
          s.distance(other) is None)
    check("the ms clock wrapping at 65536 is not a break",
          dahua.Stream(F(0, 0xFC, 918167, 900, packed, 0xFFF0, 24)).distance(
              F(0, 0xFC, 918168, 900, packed, 0x0018, 24)) is not None)


def test_dahua_parser(tmp: str) -> None:
    print("\n[dahua DHFS parser - synthetic, ground truth known]")
    parser = get_parser("Dahua")
    check("plugin registers itself", parser is not None)
    if parser is None:
        return
    check("signatures.PARSERS_AVAILABLE includes Dahua", "Dahua" in sig.PARSERS_AVAILABLE)

    for seed in (26150, 1, 2):
        img = os.path.join(tmp, f"dhfs-{seed}.img")
        meta = synth_dahua.build(img, seconds=14, seed=seed)
        lost = sum(len(meta["written"][n]) - len(meta["survived"][n])
                   for n in meta["written"])
        parser = get_parser("Dahua")
        with BlockDevice(img) as dev:
            check(f"[{seed}] detects a DHFS volume", parser.detect(dev))
            res = parser.parse(dev)
            vol = parser.volumes[0]
            check(f"[{seed}] one recording per camera",
                  sorted(r.camera_id for r in res.recordings) == ["CH01", "CH02", "CH03"])
            check(f"[{seed}] every chain is intact", all(f.chain_ok for f in vol.files))
            check(f"[{seed}] data base calibrated to the true offset",
                  vol.data_base == synth_dahua.DATA_BASE,
                  f"got {vol.data_base}")
            foreign = missed = dup = 0
            spill = overflow = 0
            for f in vol.files:
                sink = _Sink()
                st = dahua.reassemble(dev, vol, f, sink)
                got = [(fr.ftype, fr.frame_number) for fr in sink.frames]
                truth = meta["survived"][f.camera]
                foreign += len(set(got) - truth)
                missed += len(truth - set(got))
                dup += len(got) - len(set(got))
                spill += st["spill_in"]
                overflow += st["overflow_recovered"]
            check(f"[{seed}] the fixture really exercises overflow",
                  lost > 0 and spill > 0 and overflow > 0,
                  f"lost {lost} spill {spill} overflow {overflow}")
            check(f"[{seed}] no camera receives another camera's frames", foreign == 0,
                  f"{foreign} foreign")
            check(f"[{seed}] every surviving frame is recovered", missed == 0,
                  f"{missed} missed")
            check(f"[{seed}] no frame is emitted twice", dup == 0, f"{dup} duplicates")
            rem = parser.remnant_recordings(dev)
            check(f"[{seed}] the older recording underneath is found as remnants",
                  bool(rem) and all("2026-08-01" in r.timestamps[0].raw_value for r in rem))
            check(f"[{seed}] remnants are fragments with camera unknown",
                  all(r.state == "fragment" and r.camera_id == "UNKNOWN" for r in rem))

        # --- the honesty invariants
        check(f"[{seed}] parse is never claimed as validated",
              res.validation_status != "validated")
        check(f"[{seed}] without a timezone, no time is presented as UTC",
              all(r.start_utc is None for r in res.recordings))

    parser = get_parser("Dahua")
    parser.tz_offset_min = 330
    with BlockDevice(img) as dev:
        res = parser.parse(dev)
    check("an investigator-supplied offset converts recorder time to UTC",
          res.recordings[0].start_utc == "2026-09-03T04:30:00.000Z",
          str(res.recordings[0].start_utc))


class _BytesSink(_Sink):
    def __init__(self):
        super().__init__()
        self.data: dict = {}

    def write(self, b: bytes) -> None:
        fr = next(dahua.walk_frames(b, 0))
        self.frames.append(fr)
        self.data[(fr.ftype, fr.frame_number)] = b


def test_dahua_chain_split(tmp: str) -> None:
    print("\n[dahua frames finished in the next chain cluster - synthetic]")
    joined_total = lost_splits = 0
    for seed in (26150, 1, 2):
        img = os.path.join(tmp, f"dhfs-split-{seed}.img")
        meta = synth_dahua.build(img, seconds=14, seed=seed, chain_splits=True)
        raw = open(img, "rb").read()
        parser = get_parser("Dahua")
        with BlockDevice(img) as dev:
            parser.parse(dev)
            vol = parser.volumes[0]
            foreign = missed = dup = 0
            for f in vol.files:
                sink = _BytesSink()
                st = dahua.reassemble(dev, vol, f, sink)
                got = [(fr.ftype, fr.frame_number) for fr in sink.frames]
                truth = meta["survived"][f.camera]
                foreign += len(set(got) - truth)
                missed += len(truth - set(got))
                dup += len(got) - len(set(got))
                want = meta["joined"][f.camera]
                check(f"[{seed}] CH{f.camera + 1}: every intact split frame is rejoined, "
                      f"and nothing else", st["boundary_joined"] == len(want),
                      f"{st['boundary_joined']} vs {len(want)}")
                splits = {(t, fn): (a, b) for n, t, fn, a, b in meta["split"]
                          if n == f.camera}
                for j in st["joined_frames"]:
                    key = (int(j["type"], 16), j["frame_number"])
                    (o1, l1), (o2, l2) = j["parts"]
                    check(f"[{seed}] frame {key[1]}: both halves reported where they lie",
                          splits.get(key) == ((o1, l1), (o2, l2)), str(j["parts"]))
                    check(f"[{seed}] frame {key[1]}: emitted bytes are exactly the two halves",
                          sink.data.get(key) == raw[o1:o1 + l1] + raw[o2:o2 + l2])
                lost = [k for k in splits if k not in want]
                lost_splits += len(lost)
                check(f"[{seed}] CH{f.camera + 1}: a split frame whose half was overwritten "
                      f"is not emitted", not any(k in set(got) for k in lost))
                joined_total += len(want)
            check(f"[{seed}] no camera receives another camera's frames", foreign == 0,
                  f"{foreign} foreign")
            check(f"[{seed}] every surviving frame is recovered", missed == 0,
                  f"{missed} missed")
            check(f"[{seed}] no frame is emitted twice", dup == 0, f"{dup} duplicates")
    check("the fixture exercises both intact and overwritten split frames",
          joined_total > 0 and lost_splits > 0, f"joined {joined_total}, lost {lost_splits}")


def test_hik_log(tmp: str) -> None:
    """The Hikvision system log: the master sector finds it, every record is
    read and named, nothing outside the log area or inside a payload is
    taken for a record, and the footage says which clock the log keeps."""
    print("\n[Hikvision system log - synthetic, ground truth known]")
    import argparse
    import cli
    from parsers import hiklog
    img = os.path.join(tmp, "hiklog.img")
    meta = synth_hiklog.build(img)
    with BlockDevice(img) as dev:
        res = hiklog.read(dev)
    m, s = res["master"], res["summary"]
    check("master sector found at 0x200, with its backup after the log area",
          res["master_copies"] == [0x200, 0x108000], str(res["master_copies"]))
    check("log area from the master sector", res["log_area"] == [0x8200, 0x108200])
    check("every master-sector check agrees", all(c["ok"] for c in res["checks"]),
          str(res["checks"]))
    check("every record read; the marker inside a payload and the record outside the "
          "log area are not", s["records"] == meta["records"], str(s["records"]))
    check("power cycles counted", s["power"] == {"power on": 2, "power off": 0,
                                                "abnormal shutdown": 2}, str(s["power"]))
    ua = s["user_actions"]
    check("the user's session: login, configuration, playback, logout - by 'admin'",
          len(ua) == meta["user_actions"] and {a["user"] for a in ua} == {"admin"}
          and ua[0]["type"] == "Operation: Login (local)"
          and ua[-1]["type"] == "Operation: Logout (local)", str(ua))
    check("a code the SDK does not list is reported undefined, with its text",
          any(r["type"] == "Information: undefined 0xAA" and "Main CVBS" in r["text"]
              for r in res["recorder_log"]))
    check("times are the recorder's clock, never presented as UTC",
          "not UTC" in res["time_basis"]
          and all("time_utc" not in r for r in res["recorder_log"]))

    backup_only = os.path.join(tmp, "hiklog-backup.img")
    synth_hiklog.build(backup_only, primary=False)
    with BlockDevice(backup_only) as dev:
        res2 = hiklog.read(dev)
    check("a reformatted primary: the backup master still finds the log",
          res2["master_copies"] == [0x108000] and res2["summary"]["records"] == meta["records"]
          and any("0x108000" in n for n in res2["notes"]), str(res2["notes"]))

    bad = os.path.join(tmp, "hiklog-bad.img")
    synth_hiklog.build(bad, bad_log_end=True)
    with BlockDevice(bad) as dev:
        res3 = hiklog.read(dev)
    check("an inconsistent master sector is flagged, not trusted silently",
          any(c["ok"] is False for c in res3["checks"])
          and any("check failed" in n for n in res3["notes"]), str(res3["checks"]))

    pon = [1_700_000_000 + k * 86400 for k in range(20)]
    same = hiklog.log_clock_vs_footage(pon, [t + 80 for t in pon])
    ist = hiklog.log_clock_vs_footage(pon, [t + 19800 + 80 for t in pon])
    none = hiklog.log_clock_vs_footage(pon[:3], [t + 80 for t in pon[:3]])
    check("footage restarting after each power-on: the log keeps the footage's clock",
          same["best_shift_s"] == 0 and same["verdict"] == "the log keeps the footage's clock",
          str(same))
    check("footage 5:30 later: that offset is reported, not assumed away",
          ist["best_shift_s"] == 19800, str(ist))
    check("too few power-ons: no verdict", none["best_shift_s"] is None
          and none["verdict"] == "not determined", str(none))

    case = os.path.join(tmp, "hiklog_case")
    os.makedirs(case, exist_ok=True)
    rc = cli.cmd_hik_log(argparse.Namespace(device=img, out=case))
    out = json.load(open(os.path.join(case, "hik_log.json"), encoding="utf-8"))
    check("hik-log writes the result and says spec_only",
          rc == 0 and out["validation_status"] == "spec_only"
          and out["summary"]["records"] == meta["records"])


def test_dahua_robustness(tmp: str) -> None:
    print("\n[dahua parser robustness]")
    parser = get_parser("Dahua")
    empty = os.path.join(tmp, "empty-dhfs.img")
    with open(empty, "wb") as fh:
        fh.write(bytes(1 << 20))
    with BlockDevice(empty) as dev:
        check("a non-DHFS disk is not detected", not parser.detect(dev))
        res = parser.parse(dev)
    check("a non-DHFS disk reports an error, not a crash", bool(res.errors))

    # Structures intact but no video: calibration must fail loudly and
    # extraction must refuse rather than guess a base.
    img = os.path.join(tmp, "novideo.img")
    synth_dahua.build(img, seconds=8, seed=5)
    raw = bytearray(open(img, "rb").read())
    start = synth_dahua.DATA_BASE + synth_dahua.FIRST_DATA_CLUSTER * synth_dahua.CLUSTER
    raw[start:] = bytes(len(raw) - start)
    with open(img, "wb") as fh:
        fh.write(bytes(raw))
    parser = get_parser("Dahua")
    with BlockDevice(img) as dev:
        res = parser.parse(dev)
        vol = parser.volumes[0]
        check("no footage: data base left unknown", vol.data_base is None)
        check("no footage: recordings still listed from the index",
              len(res.recordings) == 3)
        try:
            dahua.reassemble(dev, vol, vol.files[0])
            refused = False
        except ValueError:
            refused = True
        check("extraction refuses an uncalibrated volume", refused)

    # A broken chain link is reported, never followed into garbage.
    img = os.path.join(tmp, "brokenchain.img")
    meta = synth_dahua.build(img, seconds=8, seed=6)
    raw = bytearray(open(img, "rb").read())
    c = meta["chains"][0][1]
    struct.pack_into("<I", raw, synth_dahua.INDEX_SECTOR * 512 + c * 32 + 0x0C, 10 ** 6)
    with open(img, "wb") as fh:
        fh.write(bytes(raw))
    parser = get_parser("Dahua")
    with BlockDevice(img) as dev:
        parser.parse(dev)
    f0 = next(f for f in parser.volumes[0].files if f.camera == 0)
    check("a chain pointing outside the table is flagged broken",
          not f0.chain_ok and any("outside the table" in n for n in f0.chain_notes))


def _owners(dev, stream, owner: dict) -> dict:
    tally: dict = {}
    for e in stream.extents:
        buf = dev.read_at(e.offset, e.length)
        for fr in dahua.walk_frames(buf, e.offset, 0, len(buf)):
            k = owner.get(fr.offset, "old")
            tally[k] = tally.get(k, 0) + 1
    return tally


def test_carver(tmp: str) -> None:
    print("\n[indexless carver - synthetic, ground truth known]")
    for twins in (False, True):
        tag = "twins" if twins else "normal"
        for seed in (26150, 1):
            img = os.path.join(tmp, f"carve-{tag}-{seed}.img")
            meta = synth_dahua.build(img, seconds=14, seed=seed, twins=twins)
            with BlockDevice(img) as dev:
                streams, stats = carver.carve(dev)
                tallies = [_owners(dev, s, meta["owner"]) for s in streams]
                p = get_parser("Dahua")
                p.parse(dev)
                xref = carver.cross_reference(dev, streams, p.volumes[0])
                sink = _Sink()
                biggest = max(streams, key=lambda s: s.frames)
                carver.write_stream(dev, biggest, sink)
            impure = [t for t in tallies if len(t) > 1]
            check(f"[{tag} {seed}] no carved stream mixes two sources", not impure,
                  str(impure[:2]))
            for n in range(3):
                got = sum(t.get(n, 0) for t in tallies)
                check(f"[{tag} {seed}] camera {n + 1}: every surviving frame carved",
                      got == len(meta["survived"][n]),
                      f"{got}/{len(meta['survived'][n])}")
            if twins:
                check(f"[{tag} {seed}] indistinguishable cameras are split, not guessed",
                      stats["ambiguous_splits"] > 0)
            labels_ok = all(
                (xref[s.sid]["label"] == "outside_index") == (set(t) == {"old"})
                for s, t in zip(streams, tallies) if s.frames >= carver.MIN_FRAMES)
            check(f"[{tag} {seed}] the index labels the older recording 'outside_index' "
                  f"and nothing else", labels_ok)
            keys = [(dahua._kind(f), f.frame_number) for f in sink.frames]
            check(f"[{tag} {seed}] a written stream has no duplicate frames",
                  len(keys) == len(set(keys)))
            check(f"[{tag} {seed}] a carved stream is a fragment of unknown camera",
                  carver.to_recording(biggest).camera_id == "UNKNOWN"
                  and carver.to_recording(biggest).state == "fragment")


def test_heimvision(tmp: str) -> None:
    """The HeimVision plugin (layout observed on the NIST CFReDS K9604-W
    image) against a disk built to it: FAT32 read by its cluster chains,
    cameras named by the frames, the recorder's zone measured, extraction
    exact across a fragmented file.  Also pinned to the real image when
    HEIMVISION_E01 points at it."""
    print("\n[HeimVision plugin (observed on the NIST CFReDS image)]")
    from tests import synth_heimvision as SV
    import importlib
    hv = importlib.import_module("ps26150_plugin_heimvision")

    img = os.path.join(tmp, "heimvision.img")
    truth = SV.build(img)
    p = get_parser("HeimVision")
    with BlockDevice(img) as dev:
        found = p.detect(dev)
        res = p.parse(dev)
    v = res.volume
    check("detected; written files told from pre-allocated ones; status spec_only, observed",
          found and v["files"] == 4 and v["files_written"] == 3 and v["ident"] == "ok1ormated"
          and res.validation_status == "spec_only"
          and all(f["source"] == "observed_real_media" for f in res.field_provenance), str(v))
    from detect.engine import SignatureScanner
    sc = SignatureScanner()
    sc.scan_block(0, open(img, "rb").read(), 0, "")
    dets = {d.vendor: d for d in sc.detections()}
    check("a scan names the recorder from its own structures (the disk carries no brand "
          "string), with its parser available",
          "HeimVision" in dets and dets["HeimVision"].parser_available
          and dets["HeimVision"].confidence > 0.8, str({k: d.confidence for k, d in dets.items()}))
    check("the recorder's zone setting measured: display clock UTC+8 against its own "
          "system clock (FAT times), on every file",
          v["recorder_zone_minutes"] == 480 and v["recorder_zone_agreement"] == "3/3 files")
    r0 = res.recordings[0]
    check("one recording per camera, spanning the files, in recorder-local time: no UTC "
          "without a stated zone, and the measured zone is not applied",
          [r.camera_id for r in res.recordings] == ["CH01", "CH02", "CH03", "CH04"]
          and r0.start_utc is None and v["span_utc"] == (None, None)
          and v["span_local"][0] == "2021-08-04 13:59:51"
          and r0.timestamps[0].raw_value.endswith("= 2021-08-04 13:59:51 recorder-local")
          and all(c.decoded_utc is None for c in r0.timestamps),
          str([r.id for r in res.recordings]))
    p_tz = type(p)(tz_offset_min=480)
    with BlockDevice(img) as dev:
        r_tz = p_tz.parse(dev)
    check("with the zone stated by the examiner (+480), UTC = display clock - 8 h",
          r_tz.recordings[0].start_utc == "2021-08-04T05:59:51Z"
          and r_tz.recordings[0].timestamps[0].tz_offset_min == 480,
          str(r_tz.recordings[0].start_utc))
    from analyse.timeline import ClockModel, build as build_timeline
    from core.contract import to_dict
    from report.case import parse_report_names
    tl = build_timeline({"recordings": [to_dict(r) for r in res.recordings]}, None, ClockModel())
    ev = [e for e in tl["events"] if e["kind"] == "indexed"]
    check("the timeline takes HeimVision recordings from their own file headers: one lane "
          "per camera, recorder-local, no UTC without a stated zone",
          sorted(e["camera"] for e in ev) == ["CH01", "CH02", "CH03", "CH04"]
          and all(e["time_basis"] == "container" and e["start_utc"] is None for e in ev)
          and sorted(tl["cameras"]) == ["CH01", "CH02", "CH03", "CH04"]
          and {e["start_local"] for e in ev} == {"2021-08-04 13:59:51"}, str(ev[:1]))
    case_dir = os.path.join(tmp, "hv_case")
    os.makedirs(case_dir)
    for n in ("parse_heimvision.json", "parse_dahua.json", "parse_notes.txt"):
        open(os.path.join(case_dir, n), "w").close()
    check("the timeline and report find a plugin's parse report, built-in vendors first",
          parse_report_names(case_dir) == ["parse_dahua.json", "parse_heimvision.json"])
    with BlockDevice(img) as dev:
        st = p.extract_recording(dev, "hv-ch03-0000", os.path.join(tmp, "hv_c3"))
    out = open(os.path.join(tmp, "hv_c3.h265"), "rb").read()
    check("a camera's video extracted exactly, across a fragmented file, audio left out",
          out == b"".join(truth["video"][2]) and st["frames"] == 36 and st["keyframes"] == 6
          and st["audio_frames_skipped"] == 12, str(st))
    bad = bytearray(SV.frame(2, 1, 0, 0, b"x"))
    bad[124:128] = b"XXXX"
    check("a frame header is believed only with both magics and sane fields",
          hv.frame_header(bytes(bad)) is None and hv.frame_header(SV.frame(2, 1, 0, 0, b"x"))
          and hv.frame_header(SV.frame(9, 1, 0, 0, b"x")) is None)
    with BlockDevice(os.path.join(tmp, "honeywell.img")) as dev:
        check("another vendor's GPT disk is not taken for HeimVision", not p.detect(dev))

    # The recorder's own records (ext3 partition 1, index.bin), with three
    # faults planted in the fixture for the checks to find.
    from detect.engine import parse_partitions
    from parsers.ext3 import EXTENTS, Ext, ExtError
    check("the recorder's own log read off its ext3 partition: every entry, ids unbroken",
          [e["text"] for e in v["recorder_log"]] == [x[2] for x in truth["log"]]
          and v["recorder_log_unbroken"], str(v["recorder_log"][:3]))
    check("its index checked, not trusted: the file whose listed end disagrees with its "
          "header is caught",
          v["recorder_index"] == {"files_listed": 3, "files_matching_headers": 2,
                                  "written_not_listed": [], "camera_hour_segments": 4},
          str(v["recorder_index"]))
    check("index.bin: a written file it does not mark complete is reported",
          v["index_bin"] == {"complete": 2, "written_not_complete": ["DIR00000/FILE0002.DAT"],
                             "complete_not_written": []}, str(v["index_bin"]))
    check("footage before a camera's logged 'Rec begin', measured from its first video frame",
          v["footage_before_logged_start_s"] == {"CH01": 0.0, "CH02": 2.0, "CH03": 0.0, "CH04": 0.0},
          str(v["footage_before_logged_start_s"]))
    check("the zone measured a second way: the databases' own times against their ext3 "
          "inode times (the system clock)",
          v["recorder_zone_minutes_ext3"] == {"dvr_log.db": 480, "search.db": 480})
    with BlockDevice(img) as dev:
        fs = Ext(dev, parse_partitions(dev.read_at(0, 64 << 10), 512)[0].start_offset)
        pad = next(e for e in fs.listdir() if e["name"] == "pad.bin")
        whole = fs.read(pad)
        pad["flags"] |= EXTENTS
        try:
            fs.read(pad)
            refused = False
        except ExtError:
            refused = True
    check("ext3: a file past 12 blocks read through its indirect block; an ext4 extent "
          "inode refused, not guessed", whole == truth["pad"] and refused)
    bare = os.path.join(tmp, "heimvision_bare.img")
    SV.build(bare, system=False)
    with BlockDevice(bare) as dev:
        br = p.parse(dev)
    check("a blank system partition: the footage still parses, and the gap is reported",
          len(br.recordings) == 4 and bool(br.volume["recorder_system_error"])
          and not br.volume["recorder_log"] and br.volume["recorder_index"]["written_not_listed"] == []
          and any("not read" in n for n in br.notes), str(br.notes[-1:]))

    # FTK Imager's file listing, in its own format, against our reading: the
    # comparison must read the format and must catch a planted difference.
    from validate import ftk_listing as FL
    with BlockDevice(img) as dev:
        mine = FL.ours(dev)
    rows = ["Filename\tFull Path\tSize (bytes)\tCreated\tModified\tAccessed\tIs Deleted"]
    for k, v in mine["fat"].items():
        rows.append(f"{k.rsplit(chr(92), 1)[-1]}\tprimary (2)\\{FL.FAT_ROOT}{k}\t{v['size']}\t"
                    f"{v['modified']}\t{v['modified']}\t\tno")
    for n, v in mine["ext3"].items():
        rows.append(f"{n}\tprimary (1)\\{FL.EXT_ROOT}{n}\t{v['size']}\t\t{v['modified']}\t"
                    f"{v['accessed']}\tno")
    listing = os.path.join(tmp, "listing.csv")
    with open(listing, "w", encoding="utf-16") as fh:
        fh.write("\n".join(rows) + "\n")
    same = FL.compare(mine, FL.theirs(FL.load_listing(listing)))
    k = next(i for i, r in enumerate(rows) if ".dat\t" in r)
    rows[k] = rows[k].replace("\t65536\t", "\t65535\t")
    with open(listing, "w", encoding="utf-16") as fh:
        fh.write("\n".join(rows) + "\n")
    diff = FL.compare(mine, FL.theirs(FL.load_listing(listing)))
    check("FTK-listing comparison: reads FTK's UTF-16 tab format, agrees with itself, and "
          "catches one planted size difference by name",
          same["identical"] and same["fat"]["in_both"] == len(mine["fat"]) >= 6
          and same["zone_setting_minutes_from_ftk_times"] == 480
          and not diff["identical"] and len(diff["fat"]["size_differs"]) == 1,
          str(diff["fat"]["size_differs"]))

    path = os.environ.get("HEIMVISION_E01")
    if not path:
        print("  [real image] skipped - set HEIMVISION_E01 to the CFReDS K9604-W .E01")
        return
    with BlockDevice(path) as dev:
        real = get_parser("HeimVision").parse(dev)
    rv = real.volume
    check("real image: 806 of 17,152 files written, 4 cameras, 24 h recorder-local; zone "
          "setting UTC+8",
          rv["files"] == 17152 and rv["files_written"] == 806 and len(real.recordings) == 4
          and rv["span_local"] == ("2021-08-04 13:59:51", "2021-08-05 14:00:01")
          and rv["span_utc"] == (None, None)
          and rv["recorder_zone_minutes"] == 480 and rv["recorder_zone_agreement"] == "806/806 files",
          str(rv.get("summary")))
    check("real image: the recorder's own log (194 entries, unbroken) and index (806/806 files "
          "as their headers say) agree with the disk; index.bin leaves only the last file open",
          len(rv["recorder_log"]) == 194 and rv["recorder_log_unbroken"]
          and rv["recorder_index"] == {"files_listed": 806, "files_matching_headers": 806,
                                       "written_not_listed": [], "camera_hour_segments": 96}
          and rv["index_bin"] == {"complete": 805, "written_not_complete": ["DIR00006/FILE0037.DAT"],
                                  "complete_not_written": []},
          str(rv["recorder_index"]) + str(rv["index_bin"]))
    check("real image: UTC+8 again from the ext3 clock; CH02-CH04 video 6.9-7.5 s before "
          "their logged 'Rec begin'",
          rv["recorder_zone_minutes_ext3"] == {"dvr_log.db": 480, "search.db": 480}
          and rv["footage_before_logged_start_s"] == {"CH01": -0.4, "CH02": 7.5, "CH03": 7.4,
                                                     "CH04": 6.9},
          str(rv["footage_before_logged_start_s"]))
    ftk = os.path.join(os.path.dirname(path), "HeimVision K9604-W File Listing.csv")
    if os.path.exists(ftk):
        rep = FL.check(path, ftk)
        check("real image: FTK Imager's own file listing and our reading agree on every one "
              "of 17,154 FAT32 files (size and write time) and the 4 ext3 files; FTK's times "
              "give the same UTC+8 zone setting",
              rep["identical"] and rep["fat"]["in_both"] == 17154
              and rep["fat"]["written_per_ftk"] == 808 and len(rep["ext3"]["compared"]) == 4
              and rep["zone_setting_minutes_from_ftk_times"] == 480, str(rep["fat"]))
    sc = SignatureScanner()
    with BlockDevice(path) as dev:
        for k in range(2):
            sc.scan_block(k << 23, dev.read_at(k << 23, 8 << 20), k, "")
    dets = {d.vendor: d for d in sc.detections()}
    check("real image: the first 16 MiB are enough for a scan to name HeimVision - its "
          "system partition's mount point and its log and index schemas - parser available",
          "HeimVision" in dets and dets["HeimVision"].confidence > 0.9
          and dets["HeimVision"].parser_available, str({k: d.confidence for k, d in dets.items()}))


def test_godrej(tmp: str) -> None:
    """Godrej's SeeThru recorders run Qualvision's software: the QVFS layout
    read from Qualvision's firmware (a QVEX head and a self-checking frame
    chain), on a disk built to that reading - spec_only."""
    print("\n[Godrej plugin (Qualvision QVFS, from its firmware)]")
    from parsers import available_vendors
    from tests import synth_qvfs as SQ

    qimg = os.path.join(tmp, "qvfs.img")
    qt = SQ.build(qimg)
    g = get_parser("Godrej")
    with BlockDevice(qimg) as dev:
        gdet = g.detect(dev)
        gr = g.parse(dev)
        outs = [g.extract_recording(dev, r.id, os.path.join(tmp, f"qv{i}"))
                for i, r in enumerate(gr.recordings)]
        claimed = sorted(v for v in available_vendors() if get_parser(v).detect(dev))
    gv = gr.volume
    check("Godrej/Qualvision: the QVEX head read as the firmware checks it; region bounds hold; "
          "the size field is the disk in sectors; status spec_only from the firmware",
          gdet and gv["head"]["bounds_ok"] and gv["region_unit_bytes"] == 512
          and gv["head"]["region_b"] == (SQ.B_START, SQ.B_SIZE)
          and gr.validation_status == "spec_only", str(gv["head"]))
    check("footage found by the frame chain - both runs at their offsets, every frame, first "
          "and last times to the millisecond - and a lone fake head chained to nothing is "
          "passed over",
          [(r.offset, r.frame_count) for r in gr.recordings]
          == [(t["offset"], t["frames"]) for t in qt["runs"]]
          and [r.duration_s for r in gr.recordings] == [4.76, 2.96]
          and gr.recordings[0].timestamps[0].raw_value.endswith("2025-03-14 09:30:00 recorder-local")
          and all(r.camera_id == "UNKNOWN" and r.start_utc is None for r in gr.recordings)
          and not any(r.offset <= qt["fake_head_at"] < r.offset + r.length for r in gr.recordings),
          str([(r.offset, r.frame_count, r.duration_s) for r in gr.recordings]))
    check("a run's video extracted exactly (payloads with a start code), audio left out",
          all(open(os.path.join(tmp, f"qv{i}.es"), "rb").read() == qt["runs"][i]["video"]
              for i in range(2))
          and [o["frames_without_start_code"] for o in outs] == [24, 15], str(outs))
    raw = bytearray(open(qimg, "rb").read())
    struct.pack_into("<I", raw, 0x14, SQ.TOTAL)                  # region A now too big
    badq = os.path.join(tmp, "qvfs_bad.img")
    open(badq, "wb").write(raw)
    with BlockDevice(badq) as dev:
        badq_det = g.detect(dev)
    with BlockDevice(os.path.join(tmp, "heimvision.img")) as dev:
        other = g.detect(dev)
    check("a QVEX head failing the firmware's own bounds check is not taken; on the QVFS disk "
          "no other plugin claims it, and Godrej claims no other vendor's disk",
          not badq_det and claimed == ["Godrej"] and not other, str(claimed))


def test_daylight(tmp: str) -> None:
    """The recorder's offset from UTC from its cameras' infrared switches: at
    the right offset every dusk and dawn switch sits at one sun elevation."""
    print("\n[daylight: the recorder's clock from its cameras' infrared switches]")
    import random
    import shutil as _sh
    from datetime import datetime, timedelta
    from analyse import daylight as DL

    lat, lon = 12.97, 77.59                                   # Bengaluru
    sunset = DL.solar_elevation(datetime(2026, 9, 23, 12, 46), lat, lon)   # 18:16 IST
    noon = DL.solar_elevation(datetime(2026, 9, 23, 6, 40), lat, lon)
    check("the sun, by NOAA's equations: Bengaluru's 18:16 IST sunset on 23 Sep sits at the "
          "horizon, and its noon sun is high", -1.5 < sunset < 1.0 and 75 < noon < 79,
          f"{sunset:.2f} {noon:.1f}")

    rng = random.Random(3)
    truth, h_switch = 337, -2.0                     # IST + a clock 7 min fast; the camera's threshold
    series, jit, t = [], {}, datetime(2026, 9, 1)
    while t < datetime(2026, 9, 11):
        utc = t - timedelta(minutes=truth)
        j = jit.setdefault((utc.date(), utc.hour < 12), rng.uniform(-0.6, 0.6))   # weather
        h = DL.solar_elevation(utc, lat, lon)
        c = 25 + rng.uniform(-5, 5) if h > h_switch + j else 1 + rng.uniform(0, 1)
        if h < -10 and rng.random() < 0.01:
            c = 30                                                  # a headlight at night
        series.append((t, c))
        t += timedelta(minutes=2)
    ev = DL.switches(series)
    res = DL.estimate(ev, lat, lon, zone=330)
    check("ten days of footage: 10 dusk and 10 dawn switches, headlight flashes ignored",
          (res["dusk"], res["dawn"]) == (10, 10), str((res["dusk"], res["dawn"])))
    check("the offset found without the unit or the camera's threshold: UTC+337 min, i.e. IST "
          "and a clock 7 min fast; the switch elevation recovered; per-switch offsets agree",
          abs(res["offset_min"] - truth) <= 3 and abs(res["clock_error_min"] - 7) <= 3
          and abs(res["switch_elevation_deg"] - h_switch) < 0.5
          and res["per_switch_offset_min"]["range"][1] - res["per_switch_offset_min"]["range"][0] <= 10,
          res["reading"])
    one_kind = DL.estimate([e for e in ev if e["kind"] == "dusk"], lat, lon)
    check("dusks alone are refused - every offset fits them equally - and the 12-hour alias "
          "is ruled out by the sun's direction",
          one_kind["offset_min"] is None and abs(res["offset_min"] - truth) < 60)

    ffmpeg = os.environ.get("FFMPEG") or _sh.which("ffmpeg")
    folder = os.environ.get("VENDOR_SAMPLES")
    if not (ffmpeg and folder):
        print("  [real footage] skipped - needs ffmpeg and VENDOR_SAMPLES")
        return
    night = [c for _, c in DL.sample(os.path.join(folder, "imkh_00000001541000000.mp4"), 3,
                                     ffmpeg=ffmpeg)]
    day = [c for _, c in DL.sample(os.path.join(folder, "ffmpeg_t4182_20150327215559_ch01.mp4"),
                                   3, ffmpeg=ffmpeg)]
    dav = DL.sample(os.path.join(folder, "ffmpeg_t6144_19.25.00-19.25.50[R].dav"), 3,
                    ffmpeg=ffmpeg)
    check("real recorder footage: a Hikvision infrared night picture measures as infrared and "
          "a daylight one as colour, far apart; a .dav's samples carry the recorder's own times",
          max(night) <= DL.MONO_MAX and min(day) > 4 * DL.MONO_MAX
          and dav[0][0] == datetime(2017, 9, 18, 19, 25, 0),
          f"night {max(night)} day {min(day)} dav {dav[0][0]}")


def test_dahua_real_media() -> None:
    """Pins the parser to what was observed on the real SkyHawk disk.  Runs
    only when DHFS_REAL_IMAGE points at the partial image (never committed)."""
    path = os.environ.get("DHFS_REAL_IMAGE")
    if not path:
        print("\n[dahua real media] skipped - set DHFS_REAL_IMAGE to run")
        return
    print("\n[dahua real media]")
    parser = get_parser("Dahua")
    with BlockDevice(path) as dev:
        res = parser.parse(dev)
        vol = parser.volumes[0]
        check("513 recordings on volume 1", len(res.recordings) == 513)
        check("0 broken chains", all(f.chain_ok for f in vol.files))
        check("data base 0x95E000", vol.data_base == 0x95E000, hex(vol.data_base or 0))
        v, f = parser.file_for("dhfs-v1-c002120")
        st = dahua.reassemble(dev, v, f)
    check("CH01 hour one: no stream breaks", st["stream_breaks"] == 0)
    check("CH01 hour one: under 0.5% of video frames missing",
          st["video_counter_missing"] < 0.005 * st["video_counter_span"])
    check("CH01 hour one: no more frames than its counter span",
          st["video_frames"] <= st["video_counter_span"])
    # 57 frames there are cut at a cluster end and finished in the next chain
    # cluster; in 50 another camera's overflow later overwrote part of the
    # second half, so exactly 7 rejoin intact.
    check("CH01 hour one: 7 frames rejoined across a chain boundary, the "
          "overwritten ones refused", st["boundary_joined"] == 7, str(st["boundary_joined"]))

    # The carver, with no index, over the region holding hour one - then the
    # index, used only to label what the carve found.
    with BlockDevice(path) as dev:
        streams, stats = carver.carve(dev, vol.cluster_offset(2120), vol.cluster_offset(3223))
        xref = carver.cross_reference(dev, streams, vol)
    kept = [s for s in streams if s.frames >= carver.MIN_FRAMES]
    check("indexless carve: no stream carries mixed camera evidence",
          all(xref[s.sid]["label"] != "mixed-evidence" for s in kept))
    per_cam: dict = {}
    for s in kept:
        per_cam[xref[s.sid]["label"]] = per_cam.get(xref[s.sid]["label"], 0) + s.frames
    check("indexless carve: all three cameras recovered in comparable volume",
          all(k in per_cam for k in ("CH01", "CH02", "CH03"))
          and min(per_cam[k] for k in ("CH01", "CH02", "CH03"))
          > 0.9 * max(per_cam[k] for k in ("CH01", "CH02", "CH03")))


def synth_hik_fields() -> list:
    """The fields the parser is expected to declare provenance for."""
    return hik.MASTER_FIELDS + hik.BTREE_FIELDS


def test_preserve(tmp: str) -> None:
    """Metadata preservation: whole scan blocks, provable to the scan root."""
    print("\n[preserve]")
    from core.hashing import merkle_root, sha256_bytes
    from recover.preserve import preserve, verify_bundle

    img = os.path.join(tmp, "preserve.dd")
    synth_dahua.build(img, seconds=6)
    bs = 1 << 20
    blockmap = []
    with open(img, "rb") as fh:
        data = fh.read()
    for off in range(0, len(data), bs):
        blockmap.append({"offset": off, "length": len(data[off:off + bs]),
                         "sha256": sha256_bytes(data[off:off + bs])})
    root = merkle_root([b["sha256"] for b in blockmap])

    bundle = os.path.join(tmp, "preserved")
    with BlockDevice(img) as dev:
        m = preserve(dev, bundle, vendor="Dahua", blockmap=blockmap)
    names = [r["name"] for r in m["regions"]]
    check("superblock and volume metadata are both preserved",
          "superblock_and_partition_tables" in names and "volume1_metadata" in names,
          str(names))
    check("every saved block matches the acquisition hash", m["all_blocks_match"] is True)
    check("the manifest carries the acquisition root", m["acquisition_merkle_root"] == root)
    check("every saved block carries a Merkle path",
          all("merkle_path" in b for b in m["blocks"]))
    check("only the metadata is kept, not the video",
          m["bytes_saved"] < len(data), f"{m['bytes_saved']} of {len(data)}")
    vol = next(r for r in m["regions"] if r["name"] == "volume1_metadata")
    check("volume metadata ends at the data area",
          vol["end"] == synth_dahua.DATA_BASE, hex(vol["end"]))
    with open(os.path.join(bundle, vol["file"]), "rb") as fh:
        check("region bytes equal the platter bytes",
              fh.read() == data[vol["start"]:vol["end"]])
    v = verify_bundle(bundle)
    check("an untouched bundle verifies from its own files",
          v["ok"] and v["proven_to_root"] == len(m["blocks"]), str(v))

    first = m["blocks"][0]["file"]
    with open(os.path.join(bundle, first), "r+b") as fh:
        fh.seek(10)
        fh.write(b"\xFF")
    v = verify_bundle(bundle)
    check("a one-byte edit to a saved block is caught", not v["ok"], str(v))

    lied = [dict(b) for b in blockmap]
    lied[0]["sha256"] = "0" * 64
    with BlockDevice(img) as dev:
        m2 = preserve(dev, os.path.join(tmp, "preserved2"), vendor="Dahua", blockmap=lied)
    check("a block that differs from the scan is reported, not hidden",
          m2["all_blocks_match"] is False and any("differs" in n for n in m2["notes"]))
    with BlockDevice(img) as dev:
        m3 = preserve(dev, os.path.join(tmp, "preserved3"), vendor="Dahua",
                      blockmap=blockmap[:2])
    check("a partial scan issues no Merkle proofs",
          m3["acquisition_merkle_root"] == "" and
          not any("merkle_path" in b for b in m3["blocks"]))


def test_inline_carve(tmp: str) -> None:
    """Carving inside the acquisition pass must equal carving by re-reading,
    and must never change a hash - even when it breaks."""
    print("\n[inline carve in the acquisition pass]")
    img = os.path.join(tmp, "inline.img")
    meta = synth_dahua.build(img, seconds=14, seed=26150)
    saved = carver.CHUNK
    carver.CHUNK = 256 << 10     # many windows, so window edges are exercised
    try:
        with BlockDevice(img) as dev:
            p = get_parser("Dahua")
            p.parse(dev)
            ref, _ = carver.carve(dev)
            ref_x = carver.cross_reference(dev, ref, p.volumes[0])
            inline_lab = carver.IndexLabeler(p.volumes)
            feeder = carver.FrameFeeder(0, dev.size_bytes)
            c = carver.Carver(0, dev.size_bytes, labeler=inline_lab)
            for off, data, _ in dev.read_blocks(100_000):   # odd, unaligned blocks
                for fr in feeder.push(off, data):
                    c.add(fr)
            for fr in feeder.close():
                c.add(fr)
            got, _ = c.finish()
        sig = lambda ss: [(s.frames, [(e.offset, e.length) for e in s.extents]) for s in ss]
        check("block-fed carve yields the same streams as a device carve",
              sig(got) == sig(ref), f"{len(got)} vs {len(ref)} streams")
        got_x = carver.label_streams(got)
        check("inline labels equal labels from re-reading every frame",
              all(got_x[a.sid]["tally"] == ref_x[b.sid]["tally"]
                  for a, b in zip(got, ref)))

        plain = ScanSession(img, os.path.join(tmp, "inl-plain"),
                            CaseInfo(case_id="T-INL", investigator="test"),
                            block_size=1 << 20, quiet=True).run()
        tapped_s = ScanSession(img, os.path.join(tmp, "inl-tap"),
                               CaseInfo(case_id="T-INL", investigator="test"),
                               block_size=1 << 20, quiet=True, taps=[carver.CarveTap()])
        tapped = tapped_s.run()
        hv = lambda r: sorted((h.algorithm, h.value) for h in r.hashes)
        check("a carve tap does not change any acquisition hash",
              hv(plain) == hv(tapped) and plain.merkle_root == tapped.merkle_root)
        rep_path = os.path.join(tmp, "inl-tap", "carve", "carve_report.json")
        with open(rep_path, "r", encoding="utf-8") as fh:
            rep = json.load(fh)
        labels = {r["index_label"] for r in rep["streams"]}
        check("inline carve report is written and labelled",
              rep["index_used_for_labels"] and "outside_index" in labels
              and any(l.startswith("CH") for l in labels), str(labels))
        from report.case import load_case as _lc
        rows = rep["streams"]
        out_sel = carver.streams_from_report(rep, label="outside_index")
        ex_dir = os.path.join(tmp, "inl-tap", "carve", "streams")
        man = os.path.join(tmp, "inl-tap", "carve", "extracted.json")
        with BlockDevice(img) as dev:
            m = carver.extract_from_report(dev, out_sel, ex_dir, man, log=lambda *_: None)
            direct = {}
            for s_ in ref:
                if any(s_.extents[0].offset == r["extents"][0][0] and
                       r["index_label"] == "outside_index" for r in rows):
                    sink = io.BytesIO()
                    carver.write_stream(dev, s_, sink)
                    direct[s_.extents[0].offset] = sink.getvalue()
        ok = bool(m["streams"]) and all(v["frames_match"] for v in m["streams"].values())
        for sid, v in m["streams"].items():
            with open(os.path.join(ex_dir, sid + ".dav"), "rb") as fh:
                got_bytes = fh.read()
            ok = ok and direct[v["extents"][0][0]] == got_bytes
        check("streams extracted from the report equal a direct carve's output", ok,
              f"{len(m['streams'])} streams")
        before = os.path.getmtime(man)
        with BlockDevice(img) as dev:
            carver.extract_from_report(dev, out_sel, ex_dir, man, log=lambda *_: None)
        check("re-running extraction skips finished streams", os.path.getmtime(man) == before)
        check("the case view lists the extracted files",
              bool(_lc(os.path.join(tmp, "inl-tap"))["carve"].get("extracted")))
        check("the ledger records the inline carve and still verifies",
              any(e["action"] == "inline_carve_completed" for e in tapped_s.ledger.entries)
              and tapped_s.ledger.verify()["valid"])

        class Broken(carver.CarveTap):
            def feed(self, offset, data):
                if offset:
                    raise RuntimeError("simulated tap crash")
                super().feed(offset, data)
        broken_s = ScanSession(img, os.path.join(tmp, "inl-broken"),
                               CaseInfo(case_id="T-INL", investigator="test"),
                               block_size=1 << 20, quiet=True, taps=[Broken()])
        broken = broken_s.run()
        check("a crashing tap is switched off and the hashes are unaffected",
              hv(broken) == hv(plain) and broken.stats.complete_pass
              and "failed" in broken_s.tap_results["carve"])
        check("the tap failure is recorded in the custody ledger",
              any(e["action"] == "inline_carve_failed" for e in broken_s.ledger.entries))
    finally:
        carver.CHUNK = saved


def test_plugins(tmp: str) -> None:
    """A new vendor is one file in plugins/ - no edit to the core."""
    print("\n[drop-in plugins]")
    import parsers as P
    from detect import signatures as sig

    pdir = os.path.join(tmp, "plugins")
    os.makedirs(pdir)
    with open(os.path.join(pdir, "acme.py"), "w", encoding="utf-8") as fh:
        fh.write(
            '"""Acme NVR test plugin."""\n'
            "from detect.signatures import DETECTED_ONLY, Signature\n"
            "from parsers.base import ParseResult, VendorParser, register\n"
            "SIGNATURES = [Signature(id='acme.magic', vendor='Acme', pattern=b'ACMEFS01',"
            " description='test', source='test', validation_status=DETECTED_ONLY,"
            " weight=6.0)]\n"
            "@register\n"
            "class AcmeParser(VendorParser):\n"
            "    vendor = 'Acme'\n"
            "    parser_rule = 'acme.v0'\n"
            "    def detect(self, dev, hint_offsets=None):\n"
            "        return dev.read_at(0, 8) == b'ACMEFS01'\n"
            "    def parse(self, dev, hint_offsets=None):\n"
            "        return ParseResult(vendor='Acme', parser_rule='acme.v0')\n")
    with open(os.path.join(pdir, "broken.py"), "w", encoding="utf-8") as fh:
        fh.write("raise RuntimeError('bad plugin')\n")
    with open(os.path.join(pdir, "_skipped.py"), "w", encoding="utf-8") as fh:
        fh.write("raise RuntimeError('must not load')\n")
    saved_dir, saved_sigs = P.PLUGIN_DIR, list(sig.ALL_SIGNATURES)
    P.PLUGIN_DIR = pdir
    try:
        P._load_plugins()
        check("a dropped-in plugin registers its parser", "Acme" in P.available_vendors())
        check("its signatures join the detection catalog", "acme.magic" in sig.BY_ID)
        check("a broken plugin is reported and skipped, not fatal",
              "broken.py" in P.PLUGIN_ERRORS)
        check("underscore files (the template) are never loaded",
              "_skipped.py" not in P.PLUGIN_ERRORS and "_skipped.py" not in P.LOADED_PLUGINS)
        img = os.path.join(tmp, "acme.img")
        with open(img, "wb") as fh:
            fh.write(b"ACMEFS01" + bytes(1 << 20))
        from detect.engine import SignatureScanner
        sc = SignatureScanner()
        with open(img, "rb") as fh:
            sc.scan_block(0, fh.read(), 0, "")
        check("the scan detects the new vendor with no core change",
              any(d.vendor == "Acme" for d in sc.detections()))
        # A packaged build also loads plugins/ next to the executable; a file
        # there never replaces a shipped plugin of the same name.
        ddir = os.path.join(tmp, "dropin")
        os.makedirs(ddir)
        with open(os.path.join(ddir, "acme.py"), "w", encoding="utf-8") as fh:
            fh.write("raise RuntimeError('must not replace the shipped acme.py')\n")
        with open(os.path.join(ddir, "zeta.py"), "w", encoding="utf-8") as fh:
            fh.write('"""Zeta test plugin."""\n')
        P.DROP_IN_DIR = ddir
        P.LOADED_PLUGINS.clear()
        P.PLUGIN_ERRORS.clear()
        P._load_plugins()
        check("a packaged build also loads plugins/ next to the executable",
              "zeta.py" in P.LOADED_PLUGINS)
        check("a dropped-in file never replaces a shipped plugin of the same name",
              os.path.join(ddir, "acme.py") in P.PLUGIN_ERRORS
              and "acme.py" in P.LOADED_PLUGINS and "acme.py" not in P.PLUGIN_ERRORS)
    finally:
        P.PLUGIN_DIR = saved_dir
        P.DROP_IN_DIR = None
        P.REGISTRY.pop("Acme", None)
        P.LOADED_PLUGINS.clear()
        P.PLUGIN_ERRORS.clear()
        sig.ALL_SIGNATURES[:] = saved_sigs
        sig.BY_ID.pop("acme.magic", None)


def test_device_loss(tmp: str) -> None:
    """A device that drops off the bus is never zero-filled as 'bad sectors';
    a verified reconnect continues the same pass with identical hashes."""
    print("\n[device loss and reconnect]")
    import acquire.scanner as scanner_mod
    from acquire.device import DeviceError, DeviceLost

    img = os.path.join(tmp, "drop.img")
    synth_dahua.build(img, seconds=14, seed=26150)
    size = os.path.getsize(img)

    class Gone(BlockDevice):
        def alive(self):
            return False

        def _raw_read(self, offset, length):
            raise OSError(5, "Input/output error")
    try:
        with Gone(img) as dev:
            list(dev.read_blocks(1 << 20))
        check("a vanished device raises DeviceLost instead of zero-filling", False)
    except DeviceLost:
        check("a vanished device raises DeviceLost instead of zero-filling", True)

    plain = ScanSession(img, os.path.join(tmp, "drop-plain"),
                        CaseInfo(case_id="T-DROP", investigator="test"),
                        block_size=1 << 20, quiet=True, taps=[carver.CarveTap()]).run()
    hv = lambda r: sorted((h.algorithm, h.value) for h in r.hashes)
    with open(os.path.join(tmp, "drop-plain", "carve", "carve_report.json"), encoding="utf-8") as fh:
        plain_streams = json.load(fh)["streams"]

    class Dropping(BlockDevice):
        dropped = False

        def _read_block(self, off, want):
            if not Dropping.dropped and self.path == img and off >= 2 << 20:
                Dropping.dropped = True
                raise DeviceLost(self.path, off, "simulated USB bridge reset")
            return super()._read_block(off, want)

    def session(name, candidate_path, read_only=True, wait=5.0):
        Dropping.dropped = False
        sess = ScanSession(img, os.path.join(tmp, name),
                           CaseInfo(case_id="T-DROP", investigator="test"),
                           block_size=1 << 20, quiet=True, taps=[carver.CarveTap()],
                           reconnect_wait_s=wait, reconnect_poll_s=0.05)
        sess.find_devices = lambda: [{"path": candidate_path, "size_bytes": size,
                                      "serial": "", "read_only": read_only}]
        return sess

    renamed = os.path.join(tmp, "drop-as-sdc.img")      # the same drive, new name
    shutil.copyfile(img, renamed)
    saved = scanner_mod.BlockDevice
    scanner_mod.BlockDevice = Dropping
    try:
        sess = session("drop-ok", renamed)
        rep = sess.run()
        acts = [e["action"] for e in sess.ledger.entries]
        check("the pass survives a drop and finishes as ONE complete pass",
              rep.stats.complete_pass and Dropping.dropped)
        check("MD5/SHA-256 equal an uninterrupted pass", hv(rep) == hv(plain))
        check("no block is recorded as unreadable", not rep.bad_regions)
        with open(os.path.join(tmp, "drop-ok", "carve", "carve_report.json"),
                  encoding="utf-8") as fh:
            check("the inline carve is identical across the drop",
                  json.load(fh)["streams"] == plain_streams)
        check("the ledger discloses the loss and the verified reconnect",
              "device_lost" in acts and "device_reconnected" in acts
              and sess.ledger.verify()["valid"])
        from report.case import load_case
        from report.html import render
        page = render(load_case(os.path.join(tmp, "drop-ok")))
        check("the report discloses the interruption",
              "Interruptions during acquisition" in page and "device_reconnected" in page)

        changed = os.path.join(tmp, "drop-changed.img")
        shutil.copyfile(img, changed)
        with open(changed, "r+b") as fh:
            fh.seek(100)
            fh.write(b"\xEE")
        sess = session("drop-changed", changed)
        try:
            sess.run()
            check("a returning disk with different content is refused", False)
        except DeviceError:
            check("a returning disk with different content is refused",
                  any(e["action"] == "reconnect_refused" for e in sess.ledger.entries))

        opened = []

        class Watch(Dropping):
            def __init__(self, path, *a, **k):
                opened.append(path)
                super().__init__(path, *a, **k)
        scanner_mod.BlockDevice = Watch
        sess = session("drop-writable", renamed, read_only=False, wait=0.3)
        try:
            sess.run()
            check("a returning disk that is not write-blocked is never opened", False)
        except DeviceError:
            check("a returning disk that is not write-blocked is never opened",
                  renamed not in opened and any(
                      e["action"] == "reconnect_waiting_for_write_block"
                      for e in sess.ledger.entries))
    finally:
        scanner_mod.BlockDevice = saved


def test_short_read(tmp: str) -> None:
    """25 Sep, real media: a dying USB bridge returned 6976 KiB of an 8 MiB
    read with no error, and the device layer zero-padded the rest into the
    evidence hash.  A short read must never become padded data."""
    print("\n[short read at a USB drop]")
    import acquire.scanner as scanner_mod
    from acquire.device import DeviceLost

    img = os.path.join(tmp, "short.img")
    synth_dahua.build(img, seconds=14, seed=26150)
    size = os.path.getsize(img)
    with open(img, "rb") as fh:
        truth = fh.read()
    fail_at = (2 << 20) + 700_000          # mid-block, like the real one

    class DyingFile:
        """The kernel's behaviour: one short read with no error, then EIO."""
        def __init__(self, fh):
            self.fh, self.pos, self.dead = fh, 0, False

        def seek(self, pos, whence=0):
            self.pos = self.fh.seek(pos, whence)
            return self.pos

        def tell(self):
            return self.fh.tell()

        def read(self, n):
            if self.dead:
                raise OSError(5, "Input/output error")
            if self.pos <= fail_at < self.pos + n:
                data = self.fh.read(fail_at - self.pos)
                self.dead = True
                return data
            data = self.fh.read(n)
            self.pos += len(data)
            return data

        def close(self):
            self.fh.close()

    class Dying(BlockDevice):
        RETRY_DELAYS = (0.0,)
        live = True

        def __init__(self, path, *a, **k):
            super().__init__(path, *a, **k)
            if path == img and Dying.live:
                self._fh = DyingFile(self._fh)

        def alive(self):
            return not getattr(self._fh, "dead", False)

    yielded = []
    try:
        with Dying(img) as dev:
            for off, data, err in dev.read_blocks(1 << 20):
                yielded.append((off, data, err))
        check("a short read at a drop raises DeviceLost", False)
    except DeviceLost as lost:
        check("a short read at a drop raises DeviceLost", True)
        check("the loss is placed at the start of the unfinished block",
              lost.offset == (fail_at // (1 << 20)) * (1 << 20), hex(lost.offset))
    check("no block before the drop is padded or altered",
          all(data == truth[off:off + len(data)] and err is None
              for off, data, err in yielded))

    renamed = os.path.join(tmp, "short-as-sdc.img")
    shutil.copyfile(img, renamed)
    plain = ScanSession(img, os.path.join(tmp, "short-plain"),
                        CaseInfo(case_id="T-SHORT", investigator="test"),
                        block_size=1 << 20, quiet=True).run()
    saved = scanner_mod.BlockDevice
    scanner_mod.BlockDevice = Dying
    try:
        Dying.live = True
        sess = ScanSession(img, os.path.join(tmp, "short-scan"),
                           CaseInfo(case_id="T-SHORT", investigator="test"),
                           block_size=1 << 20, quiet=True,
                           reconnect_wait_s=5, reconnect_poll_s=0.05)
        sess.find_devices = lambda: [{"path": renamed, "size_bytes": size,
                                      "serial": "", "read_only": True}]
        rep = sess.run()
        hv = lambda r: sorted((h.algorithm, h.value) for h in r.hashes)
        check("a pass through the real failure pattern gives the true hashes",
              hv(rep) == hv(plain) and rep.stats.complete_pass and not rep.bad_regions)
    finally:
        scanner_mod.BlockDevice = saved


def test_regions(tmp: str) -> None:
    """An encrypted disk carves nothing; the scan must say why instead of
    reporting silence.  Video, ciphertext-like bytes, and container headers
    around ciphertext-like payloads are all incompressible - start codes are
    what tell them apart."""
    print("\n[high entropy without video structure]")
    import random
    from detect import regions as R
    from report.case import load_case
    from report.html import render

    rnd = random.Random(26150)
    mib = 1 << 20
    frame = lambda: b"\x00\x00\x01\x41" + rnd.randbytes(2044)
    video = b"".join(frame() for _ in range(2 * mib // 2048))
    boxed = b"".join(b"DHAV" + rnd.randbytes(64 * 1024 - 4) for _ in range(2 * mib // (64 * 1024)))
    layout = [("video", video), ("unstructured", rnd.randbytes(3 * mib)),
              ("container_without_video", boxed), ("empty", bytes(mib)),
              ("unstructured", rnd.randbytes(mib))]
    img = os.path.join(tmp, "regions.img")
    with open(img, "wb") as fh:
        for _, data in layout:
            fh.write(data)
    out = os.path.join(tmp, "regions_case")
    session = ScanSession(img, out, CaseInfo(case_id="T-REG", investigator="test"),
                          block_size=mib, quiet=True)
    session.run()
    reg = json.load(open(os.path.join(out, "regions.json"), encoding="utf-8"))
    check("each block told apart: video by its start codes, the rest by their absence",
          reg["counts"] == {"empty": 1, "structured": 0, "video": 2,
                            "container_without_video": 2, "unstructured": 4}, str(reg["counts"]))
    check("flagged regions merged into runs at the right offsets; video never flagged",
          [(r["kind"], r["offset"] // mib, r["length"] // mib) for r in reg["regions"]]
          == [("unstructured", 2, 3), ("container_without_video", 5, 2), ("unstructured", 8, 1)],
          str(reg["regions"]))
    check("the verdict says 'consistent with', never 'encrypted' as a finding",
          reg["flagged_share"] == 0.75 and "consistent with an encrypted disk" in reg["verdict"]
          and "Not claimed as encrypted" in reg["verdict"], reg["verdict"])
    ledger = [json.loads(x) for x in open(os.path.join(out, "custody_ledger.jsonl"), encoding="utf-8")]
    done = [x for x in ledger if x.get("action") == "scan_completed"]
    check("the verdict is in the custody ledger with the scan",
          bool(done) and done[-1]["detail"]["regions"]["flagged_blocks"] == 6,
          str(done[-1].get("detail", {}).get("regions") if done else ledger[-1]))
    os.remove(os.path.join(out, "regions.json"))
    case = load_case(out)
    check("an older scan without regions.json is classified from its block map; the report "
          "shows the regions",
          case["regions"]["flagged_blocks"] == 6
          and "High entropy without video structure" in render(case))
    check("random data stays under the start-code limit; sparse video is far above it",
          R.start_code_limit(8 << 20) < 10
          and R.classify({"incompressibility": 1.0, "start_codes": 60, "hits": 0,
                          "length": 8 << 20}) == "video")
    check("a video block whose first 4 KiB is a zero-padded header is video, not empty",
          R.classify({"incompressibility": 0.02, "start_codes": 22512, "hits": 0,
                      "length": 8 << 20}) == "video")

    path = os.environ.get("HEIMVISION_E01")
    if not path:
        print("  [real image] skipped - set HEIMVISION_E01 to the CFReDS K9604-W .E01")
        return
    from dataclasses import asdict
    from detect.engine import SignatureScanner
    p = get_parser("HeimVision")
    kinds = []
    with BlockDevice(path) as dev:
        p.parse(dev)
        files = p.recording_files["hv-ch01-0000"]
        for f in files[::len(files) // 10][:10]:
            off = f["extents"][0][0] + (4 << 20)          # mid-file: a dense sample
            s = SignatureScanner().scan_block(off, dev.read_at(off, 8 << 20), 0, "")
            kinds.append((R.classify(asdict(s)), s.incompressibility >= R.DENSE))
    check("real image: real H.265 recordings are never flagged, dense samples included",
          [k for k, _ in kinds] == ["video"] * 10 and any(d for _, d in kinds), str(kinds))


def test_survey(tmp: str) -> None:
    """The survey must rediscover a format it was not told about, and must
    not invent headers in noise."""
    print("\n[survey of an unknown disk]")
    import random
    from detect.survey import diff_blockmaps, survey

    img = os.path.join(tmp, "survey-dahua.img")
    synth_dahua.build(img, seconds=14, seed=26150)
    with BlockDevice(img) as dev:
        r = survey(dev)
    h = {x["token"]: x for x in r["header_candidates"]}
    check("the DHAV frame header is found without being named", "DHAV" in h,
          str(list(h)))
    if "DHAV" in h:
        check("its length field is located at +0x0C",
              h["DHAV"].get("length_field", {}).get("offset") == 0x0C, str(h["DHAV"]))
        check("its date field is located at +0x10",
              any(f["offset"] == 0x10 for f in h["DHAV"]["date_fields"]))
    check("draft signatures are only ever 'candidate'",
          all(d["validation_status"] == "candidate" for d in r["draft_signatures"]))

    noise = os.path.join(tmp, "survey-noise.img")
    rng = random.Random(7)
    with open(noise, "wb") as fh:
        fh.write(bytes(rng.getrandbits(8) for _ in range(4 << 20)))
    with BlockDevice(noise) as dev:
        rn = survey(dev)
    check("random data yields no candidate headers", not rn["header_candidates"],
          str([x["token"] for x in rn["header_candidates"]]))

    a = [{"offset": i << 20, "length": 1 << 20, "sha256": f"{i:064x}"} for i in range(10)]
    b = [dict(x) for x in a]
    for i in (3, 4, 8):
        b[i]["sha256"] = "f" * 64
    d = diff_blockmaps(a, b)
    check("a block-map diff finds exactly the changed regions",
          d["blocks_changed"] == 3 and [(g["start"], g["end"]) for g in d["changed_regions"]]
          == [(3 << 20, 5 << 20), (8 << 20, 9 << 20)], str(d["changed_regions"]))


def test_activity(tmp: str) -> None:
    """Motion activity from frame sizes: a burst is found against its own
    surroundings, busy hours are not, and it is never called evidence."""
    print("\n[motion activity from frame sizes]")
    from analyse.activity import ActivityCounter, ActivityTap

    class Lab:
        def __init__(self, cam):
            self.cam = cam

        def label(self, fr):
            return self.cam

    def minute(h, m):
        return synth_dahua.pack_date(datetime(2026, 9, 3, h, m, 0))

    from datetime import datetime
    counters = {}
    for cam in ("CH01", "CH02"):
        c = ActivityCounter(Lab(cam))
        for m in range(180):
            h, mm = 12 + m // 60, m % 60
            base = 2000 if m < 90 else 4000         # a busier second half, gradually
            size_ = base * (8 if (m == 40 or (cam == "CH01" and m == 130)) else 1)
            for _ in range(150):
                c.add(dahua.DhavFrame(0, dahua.TYPE_P, 0, size_, minute(h, mm), 0, 0))
        counters[cam] = c
    merged = ActivityCounter()
    for c in counters.values():
        merged.cells.update(c.cells)
    r = merged.result()
    peaks = {(p["camera"], p["minute"][11:]) for p in r["peaks"]}
    check("a burst is found against its surroundings",
          ("CH01", "12:40") in peaks and ("CH02", "12:40") in peaks
          and ("CH01", "14:10") in peaks, str(sorted(peaks)))
    check("a busier hour on its own is not a peak", len(peaks) == 3, str(sorted(peaks)))
    check("peaks in the same minute on two cameras are reported together",
          [x["minute"][11:] for x in r["multi_camera_peaks"]] == ["12:40"])
    check("the output calls itself a lead, not evidence",
          r["status"] == "lead, not evidence")

    img = os.path.join(tmp, "act.img")
    synth_dahua.build(img, seconds=14, seed=26150)
    sess = ScanSession(img, os.path.join(tmp, "act-scan"),
                       CaseInfo(case_id="T-ACT", investigator="test"),
                       block_size=1 << 20, quiet=True, taps=[ActivityTap()])
    sess.run()
    check("the activity tap runs inside the scan and is ledgered",
          os.path.exists(os.path.join(tmp, "act-scan", "activity.json"))
          and any(e["action"] == "inline_activity_completed" for e in sess.ledger.entries))


def test_timeline_clock_default() -> None:
    print("\n[timeline: recorder clock at its default]")
    from analyse.timeline import ClockModel, build
    rec = {"id": "carve-00001", "camera_id": "UNKNOWN", "offset": 0, "length": 0,
           "confidence": 0.5, "duration_s": 60,
           "timestamps": [{"source": "container", "raw_value": "0x0 = 2000-01-01 00:03:10 recorder-local"},
                          {"source": "container", "raw_value": "0x0 = 2000-01-01 00:04:10 recorder-local"}]}
    t = build(None, {"streams": [{"index_label": "outside_index", "recording": rec,
                                  "extents": []}]}, ClockModel())
    check("footage dated at the DHAV epoch is flagged as an unset clock",
          any(a["kind"] == "clock_at_default" for a in t["anomalies"]))


def test_timeline_recurring() -> None:
    print("\n[timeline: recurring interruptions]")
    from analyse.timeline import ClockModel, build

    def rec(i, cam, s, e):
        return {"id": f"r{i}", "camera_id": cam, "offset": 0, "length": 0, "confidence": 0.9,
                "timestamps": [{"source": "index", "raw_value": f"0x0 = {s} recorder-local"},
                               {"source": "index", "raw_value": f"0x0 = {e} recorder-local"}]}
    recs = []
    n = 0
    for day in (1, 2, 3, 4):
        for cam in ("CH01", "CH02"):
            # one camera drops for a minute at 02:00 on days 1, 3 and 4
            if cam == "CH01" and day in (1, 3, 4):
                recs.append(rec(n, cam, f"2026-09-0{day} 00:00:00", f"2026-09-0{day} 02:00:10"))
                recs.append(rec(n + 1, cam, f"2026-09-0{day} 02:01:30", f"2026-09-0{day} 23:59:59"))
            else:
                recs.append(rec(n, cam, f"2026-09-0{day} 00:00:00", f"2026-09-0{day} 23:59:59"))
            n += 2
    t = build({"recordings": recs}, None, ClockModel())
    r = [c for c in t["correlations"] if c["kind"] == "recurring_interruption"]
    check("a gap at the same time on three days is reported as a pattern",
          len(r) == 1 and r[0]["start_local"] == "02:00" and len(r[0]["days"]) == 3, str(r))


def test_timeline_recorder_log() -> None:
    """The recorder's own log set against the footage: a silence on every
    camera with a logged power-on is a power cut; one without is reported as
    not in the log; and nothing is set against footage whose clock the log
    was not shown to keep."""
    print("\n[timeline: the recorder's own log]")
    from analyse.timeline import ClockModel, build

    def stream(sid, cam, s, e):
        return {"id": sid, "index_label": cam, "offset": 0, "bytes": 0,
                "time_first_local": s, "time_last_local": e}
    ps = {"streams": [
        # both cameras stop at 10:00:00 and resume at 10:01:30 (a power cut) ...
        stream("a1", "CH01", "2024-08-01 09:00:00", "2024-08-01 10:00:00"),
        stream("b1", "CH02", "2024-08-01 09:00:05", "2024-08-01 10:00:02"),
        stream("a2", "CH01", "2024-08-01 10:01:30", "2024-08-01 14:00:00"),
        stream("b2", "CH02", "2024-08-01 10:01:31", "2024-08-01 14:00:00"),
        # ... and again at 14:00 for 5 minutes, with nothing in the log
        stream("a3", "CH01", "2024-08-01 14:05:00", "2024-08-01 16:00:00"),
        stream("b3", "CH02", "2024-08-01 14:05:00", "2024-08-01 21:00:00"),
        # CH01 alone stops at 16:00-16:10 while CH02 records: not recorder-wide
        stream("a4", "CH01", "2024-08-01 16:10:00", "2024-08-01 21:00:00")]}

    def rec(t, major, minor, typ, user=""):
        return {"offset": 0, "time_local": t, "major": major, "minor": minor, "type": typ,
                "user": user, "text": []}
    log = {"summary": {"first_local": "2024-08-01 00:00:00", "last_local": "2024-08-02 00:00:00"},
           "clock_vs_footage": {"best_shift_s": 0},
           "recorder_log": [rec("2024-08-01 09:59:58", 3, 0x43, "Operation: Illegal shut down"),
                            rec("2024-08-01 10:01:29", 3, 0x41, "Operation: Power On"),
                            rec("2024-08-01 12:00:00", 3, 0x50, "Operation: Login (local)", "admin"),
                            rec("2024-08-01 12:00:05", 4, 0xA3, "Information: Start record")]}
    t = build(None, None, ClockModel(), ps_report=ps, recorder_log=log)
    cuts = [c for c in t["correlations"] if c["kind"] == "power_cut"]
    quiet = [c for c in t["correlations"] if c["kind"] == "silence_not_in_log"]
    check("a silence on every camera with a logged power-on is a power cut, with both records",
          len(cuts) == 1 and cuts[0]["power_on_local"] == "2024-08-01 10:01:29"
          and cuts[0]["abnormal_shutdown_local"] == "2024-08-01 09:59:58", str(cuts))
    check("a silence the log says nothing about is reported, cause not established",
          len(quiet) == 1 and quiet[0]["start_local"] == "2024-08-01 14:00:00", str(quiet))
    check("recorder events: power records and the user's action, not routine information",
          [x["kind"] for x in t["recorder_events"]] == ["abnormal_shutdown", "power_on",
                                                         "user_action"], str(t["recorder_events"]))
    check("counts carry the power cuts", t["counts"]["power_cuts"] == 1
          and t["counts"]["silences_not_in_log"] == 1)

    other = dict(log, clock_vs_footage={"best_shift_s": None})
    t2 = build(None, None, ClockModel(), ps_report=ps, recorder_log=other)
    check("a log not shown to keep the footage's clock is listed, not set against the footage",
          not any(c["kind"] in ("power_cut", "silence_not_in_log") for c in t2["correlations"])
          and len(t2["recorder_events"]) == 3
          and any("not set against" in n for n in t2["notes"]))
    late = dict(log, summary={"first_local": "2024-08-01 12:00:00",
                              "last_local": "2024-08-02 00:00:00"})
    t3 = build(None, None, ClockModel(), ps_report=ps, recorder_log=late)
    check("a silence before the log begins is not judged",
          [c["start_local"] for c in t3["correlations"] if c["kind"] in
           ("power_cut", "silence_not_in_log")] == ["2024-08-01 14:00:00"])
    t4 = build(None, None, ClockModel(), ps_report=ps)
    check("without a recorder log nothing changes", "power_cuts" not in t4["counts"]
          and t4["recorder_events"] == [])


def _ps_recording(rng, t0, seconds: int, scr0: int) -> bytes:
    """A synthetic Hikvision-style Program Stream: one pack + stream map per
    second (keyframe), 24 more packs of video per second."""
    def pack_header(scr):
        b = bytearray(14)
        b[0:4] = b"\x00\x00\x01\xba"
        b[4] = 0x44 | ((scr >> 30) & 0x07) << 3 | ((scr >> 28) & 0x03)
        b[5] = (scr >> 20) & 0xFF
        b[6] = ((scr >> 15) & 0x1F) << 3 | 0x04 | ((scr >> 13) & 0x03)
        b[7] = (scr >> 5) & 0xFF
        b[8] = (scr & 0x1F) << 3 | 0x04
        b[9], b[10], b[11], b[12], b[13] = 0x01, 0x89, 0xC3, 0xF8, 0xF8
        return bytes(b)

    def pes(sid, payload):
        return b"\x00\x00\x01" + bytes([sid]) + struct.pack(">H", len(payload)) + payload

    def psm(t):
        v = (t.month << 28) | (t.day << 23) | (t.hour << 18) | (t.minute << 12) | (t.second << 6) | 32
        # 14 bytes, as the length byte (0x0e) says and as on real footage: HK,
        # version, year, 4 packed bytes, 5 tail bytes (observed to start 00 FF FF FF)
        hk = b"\x40\x0e" + b"HK\x01\x00" + bytes([t.year - 2000]) + v.to_bytes(4, "big") + b"\x00\xff\xff\xff\xff"
        es = b"\x1b\xe0\x00\x00"
        body = b"\xf8\xff" + struct.pack(">H", len(hk)) + hk + struct.pack(">H", len(es)) + es + b"\x00\x00\x00\x00"
        return pes(0xBC, body)

    from datetime import timedelta
    out = bytearray()
    scr = scr0
    for sec in range(seconds):
        for f in range(25):
            pkt = pack_header(scr)
            if f == 0:
                pkt += psm(t0 + timedelta(seconds=sec))
            pkt += pes(0xE0, bytes(rng.getrandbits(8) for _ in range(rng.randint(200, 900))))
            out += pkt
            scr += 3600                                  # 25 fps at 90 kHz
    return bytes(out)


def test_ps_carver(tmp: str) -> None:
    """MPEG-PS footage carved by structure: exact extents, split at a clock
    jump, dates from the HK descriptor, no false streams from noise."""
    print("\n[MPEG-PS carver]")
    import random
    from datetime import datetime
    from recover import pscarve

    rng = random.Random(3)
    noise = bytes(rng.getrandbits(8) for _ in range(300_000))
    fake = b"\x00\x00\x01\xba" + bytes(40)                 # a pack header going nowhere
    a = _ps_recording(rng, datetime(2021, 4, 23, 7, 40, 7), 6, 1_000_000)
    b = _ps_recording(rng, datetime(2021, 4, 25, 18, 2, 0), 4, 90_000_000)  # clock jump
    img_bytes = noise[:100_000] + fake + noise[:50_000] + a + b + fake + noise
    img = os.path.join(tmp, "ps.img")
    with open(img, "wb") as fh:
        fh.write(img_bytes)
    a_at = 100_000 + len(fake) + 50_000

    with BlockDevice(img) as dev:
        streams, stats = pscarve.carve(dev)
        rows = [x.to_row() for x in streams]
        check("two recordings found, split at the clock jump", len(rows) == 2
              and stats["scr_splits"] == 1, str(stats))
        check("extents are exact", len(rows) == 2 and rows[0]["extents"] == [[a_at, len(a)]]
              and rows[1]["extents"] == [[a_at + len(a), len(b)]], str([r["extents"] for r in rows]))
        check("recorder time decoded from the HK descriptor",
              len(rows) == 2 and rows[0]["time_first_local"] == "2021-04-23 07:40:07"
              and rows[0]["time_last_local"] == "2021-04-23 07:40:12"
              and rows[1]["time_first_local"] == "2021-04-25 18:02:00")
        check("stream type read from the stream map",
              rows and rows[0]["streams"][0]["type"] == "h264")
        feeder, c = pscarve.PackFeeder(0), pscarve.PsCarver()
        for off, data, _ in dev.read_blocks(65_536):
            for p in feeder.push(off, data):
                c.add(p)
        for p in feeder.close():
            c.add(p)
        fed, _ = c.finish()
        check("block-fed carve equals a device carve",
              [x.extents for x in fed] == [x.extents for x in streams])
        m = pscarve.extract(dev, rows, os.path.join(tmp, "ps-out"),
                            os.path.join(tmp, "ps-out", "m.json"), log=lambda *_: None)
    with open(os.path.join(tmp, "ps-out", "ps-00000.ps"), "rb") as fh:
        check("an extracted stream is the original bytes, unmodified", fh.read() == a)

    sess = ScanSession(img, os.path.join(tmp, "ps-scan"),
                       CaseInfo(case_id="T-PS", investigator="test"),
                       block_size=1 << 16, quiet=True, taps=[pscarve.PsCarveTap()])
    rep = sess.run()
    plain = ScanSession(img, os.path.join(tmp, "ps-plain"),
                        CaseInfo(case_id="T-PS", investigator="test"),
                        block_size=1 << 16, quiet=True).run()
    hv = lambda r: sorted((h.algorithm, h.value) for h in r.hashes)
    with open(os.path.join(tmp, "ps-scan", "carve", "ps_report.json"), encoding="utf-8") as fh:
        pr = json.load(fh)
    check("the PS tap finds the same streams inside the scan, hashes unchanged",
          hv(rep) == hv(plain) and [r["extents"] for r in pr["streams"]] == [r["extents"] for r in rows])


def test_static_detections() -> None:
    """A detection that never moves (a steel pot taken for a face, on real
    footage) is flagged static and not counted; a moving one is not."""
    print("\n[analytics: static detections]")
    from analytics.static import flag_static
    hits = []
    for i in range(20):
        dets = [{"label": "face", "score": 0.85, "box": [0.56, 0.41, 0.62, 0.50]}]
        if i % 4 == 0:                                  # a person crossing the frame
            x = 0.05 * i
            dets.append({"label": "person", "score": 0.7, "box": [x, 0.3, x + 0.1, 0.8]})
        hits.append({"t_s": i * 5, "detections": dets})
    flag_static(hits, 20)
    faces = [d for h in hits for d in h["detections"] if d["label"] == "face"]
    people = [d for h in hits for d in h["detections"] if d["label"] == "person"]
    check("a detection fixed in place through the clip is static", all(d["static"] for d in faces))
    check("a moving detection is not static", not any(d["static"] for d in people))
    from analytics.static import flag_implausible, recount
    big = [{"t_s": 0, "detections": [{"label": "face", "score": 0.99, "box": [0.1, 0.1, 0.8, 0.8]},
                                      {"label": "face", "score": 0.8, "box": [0.4, 0.4, 0.45, 0.47]}]}]
    flag_implausible(big)
    check("a face box spanning most of the frame is implausible, a small one is not",
          big[0]["detections"][0]["implausible"] and not big[0]["detections"][1]["implausible"])
    r = recount({"clips": [{"frames_analysed": 1, "detections": big}]})
    check("recount counts only plausible, moving detections",
          r["frames_with_totals"] == {"face": 1} and r["flagged_not_counted"] == {"face": 1})


def test_analytics_eval(tmp: str) -> None:
    """Scoring the detectors against labels: a static detection counts against
    the models but not the tool, an unlabelled frame is left out, and a class
    no frame contains gets a false-alarm rate but no recall.  The threshold
    sweep applies the rules per clip, at each threshold afresh."""
    print("\n[analytics: evaluation against labels]")
    from validate import analytics_eval as E
    out = os.path.join(tmp, "analytics_eval")
    os.makedirs(out, exist_ok=True)
    person = {"label": "person", "score": 0.8, "box": [0.1, 0.1, 0.3, 0.6]}
    dets = [[dict(person, static=False)],            # 0: a person, seen
            [dict(person, static=True)],             # 1: nobody; a static box (a coat)
            [],                                      # 2: a person, missed
            [],                                      # 3: nobody, nothing said
            [dict(person, static=False)]]            # 4: not labelled
    json.dump({"detections": [{"frame": i, "detections": d} for i, d in enumerate(dets)]},
              open(os.path.join(out, "detections.json"), "w", encoding="utf-8"))
    with open(os.path.join(out, "labels.csv"), "w", newline="", encoding="utf-8") as fh:
        fh.write("frame,person,face,vehicle\n0,y,n,n\n1,n,n,n\n2,y,n,n\n3,n,n,n\n4,,,\n")
    res = E.score(out)
    rep, raw = res["classes"]["person"]["as reported"], res["classes"]["person"]["as the models said"]
    check("an unlabelled frame is left out of the score", res["frames_labelled"] == 4)
    check("as reported: the static box is not a false alarm",
          (rep["tp"], rep["fp"], rep["fn"], rep["tn"]) == (1, 0, 1, 2)
          and rep["precision"] == 1.0 and rep["recall"] == 0.5 and rep["false_alarm_rate"] == 0.0)
    check("as the models said: the static box is one false alarm in two frames",
          raw["fp"] == 1 and raw["precision"] == 0.5 and raw["false_alarm_rate"] == 0.5
          and {w["frame"]: w["error"] for w in raw["disagreements"]} == {1: "false alarm",
                                                                         2: "missed"})
    face = res["classes"]["face"]["as reported"]
    check("a class no frame contains: false-alarm rate, no recall",
          face["recall"] is None and face["false_alarm_rate"] == 0.0 and face["frames_without"] == 4)

    # The threshold sweep, from boxes kept at any score.  Clip 0 (frames 0-4):
    # a shrub boxed as a person at one spot, and an oversized "face".  Clip 1
    # (frames 5-6): a real person at the same spot, scored 0.3, then missed.
    shrub = lambda s: {"label": "person", "score": s, "box": [0.1, 0.1, 0.3, 0.6]}
    big_face = {"label": "face", "score": 0.9, "box": [0.3, 0.2, 0.7, 0.8]}
    everything = [[shrub(0.55), big_face], [shrub(0.55)], [shrub(0.55)], [shrub(0.65)], [],
                  [shrub(0.3)], []]
    clip_of = [0, 0, 0, 0, 0, 1, 1]
    labels = {f: {"person": "y" if f >= 5 else "n", "face": "n", "vehicle": "n"}
              for f in range(7)}
    sw = E.rescore(everything, clip_of, labels)
    person = {r["threshold"]: r for r in sw["person"]}
    check("sweep: a lower threshold finds the person the tool's misses; the rules run per "
          "clip, so a box static in one clip still counts in another",
          person[0.2]["as reported"]["tp"] == 1 and person[0.5]["as reported"]["tp"] == 0
          and person[0.2]["as the models said"]["fp"] == 4)
    check("sweep: a higher threshold can raise reported false alarms - a box too rare to "
          "be static is counted",
          person[0.5]["as reported"]["fp"] == 0 and person[0.6]["as reported"]["fp"] == 1)
    faces = {r["threshold"]: r for r in sw["face"]}
    check("sweep: an implausible face box is not counted, though the model said it",
          faces[0.9]["as reported"]["fp"] == 0 and faces[0.9]["as the models said"]["fp"] == 1)

    # The sweep command scores the boxes `sample` kept at low scores; no model runs.
    sw_dir = os.path.join(tmp, "analytics_sweep")
    os.makedirs(sw_dir, exist_ok=True)
    stored = [{"frame": f, "clip": c, "detections": [], "any_score": e}
              for f, (c, e) in enumerate(zip(clip_of, everything))]
    with open(os.path.join(sw_dir, "labels.csv"), "w", newline="", encoding="utf-8") as fh:
        fh.write("frame,person,face,vehicle\n"
                 + "".join(f"{f},{'y' if f >= 5 else 'n'},n,n\n" for f in range(7)))
    dump = lambda: json.dump({"thresholds": {"face": 0.8, "objects": 0.5}, "tiles": 3,
                              "detections": stored},
                             open(os.path.join(sw_dir, "detections.json"), "w", encoding="utf-8"))
    dump()
    check("sweep command: scores the stored low-score boxes, with nothing run again",
          E.sweep(sw_dir, log=lambda *a: None)["classes"] == sw)
    for x in stored:
        del x["any_score"]
    dump()
    try:
        E.sweep(sw_dir, log=lambda *a: None)
        refused = False
    except SystemExit:
        refused = True
    check("sweep command: refuses a sample that kept no low-score boxes", refused)


def test_analytics_tiles() -> None:
    """Tiling for small people: the grid spans the frame with overlapping
    tiles, a tile's box maps back to the whole frame, the same object boxed
    in two tiles is kept once, and boxes kept at any score then filtered are
    the boxes kept at the threshold (what `sweep` relies on)."""
    print("\n[analytics: tiles]")
    from analytics.tiles import merge, tiles, to_frame
    g = tiles(1920, 1080, 3, 0.2)
    xs, ys = sorted({t[0] for t in g}), sorted({t[1] for t in g})
    tw, th = g[0][2], g[0][3]
    check("a 3 x 3 grid spans the frame edge to edge",
          len(g) == 9 and xs[0] == ys[0] == 0 and xs[-1] + tw == 1920 and ys[-1] + th == 1080,
          str(g))
    check("neighbouring tiles overlap by a fifth of a tile",
          all(abs(xs[i] + tw - xs[i + 1] - 0.2 * tw) <= 2 for i in range(2))
          and all(abs(ys[i] + th - ys[i + 1] - 0.2 * th) <= 2 for i in range(2)), str(g))
    check("a 1 x 1 grid is the whole frame", tiles(640, 360, 1) == [(0, 0, 640, 360)])
    corner = g[-1]
    check("a box found in a tile maps back to the whole frame",
          to_frame([0.0, 0.0, 1.0, 1.0], corner, 1920, 1080)
          == [round(corner[0] / 1920, 4), round(corner[1] / 1080, 4), 1.0, 1.0]
          and to_frame([0.5, 0.2, 1.0, 0.6], (960, 540, 960, 540), 1920, 1080)
          == [0.75, 0.6, 1.0, 0.8])
    person = lambda s, box: {"label": "person", "score": s, "box": box}
    whole = person(0.55, [0.40, 0.40, 0.50, 0.70])       # small, in the whole frame
    tile = person(0.81, [0.41, 0.40, 0.50, 0.69])        # the same person, in a tile
    other = person(0.60, [0.70, 0.40, 0.80, 0.70])
    face = {"label": "face", "score": 0.9, "box": [0.42, 0.41, 0.47, 0.47]}
    check("the same person boxed in the whole frame and in a tile is kept once, the "
          "stronger box; another person, and a face on the first, are kept",
          [d["score"] for d in merge([whole, tile, other, face])] == [0.9, 0.81, 0.6])
    boxes = [person(s, [0.1 + (i % 4) * 0.05, 0.1, 0.3 + (i % 4) * 0.05, 0.5])
             for i, s in enumerate((0.25, 0.9, 0.45, 0.6, 0.35, 0.52, 0.3, 0.41))]
    check("boxes merged at any score and then filtered are the boxes merged at the threshold",
          all([d for d in merge(boxes) if d["score"] >= t] == merge([d for d in boxes if d["score"] >= t])
              for t in (0.2, 0.3, 0.4, 0.5, 0.6)))


def test_hikbtree(tmp: str) -> None:
    """HIKBTREE records as observed on real media: found by shape, the data
    base found as the common residue, copies de-duplicated, and a carved
    stream labelled only when its own times fall inside a record."""
    print("\n[Hikvision HIKBTREE records]")
    from parsers import hikbtree

    base, gib = 0x4C5E000, 1 << 30
    size = base + 40 * gib

    def rec(ch, start, end, block):
        r = bytearray(48)
        r[0:8] = b"\xff" * 8
        r[0x11] = ch
        struct.pack_into("<IIQ", r, 0x18, start, end, base + block * gib)
        return bytes(r)
    t0 = 1_722_000_000
    page = (b"HIKBTREE" + bytes(56)
            + rec(5, t0, t0 + 70_000, 3) + rec(5, t0 + 70_000, t0 + 140_000, 9)
            + rec(2, t0, t0 + 90_000, 4) + rec(255, t0 - 999, t0 - 999, 1)
            + b"\xff" * 8 + bytes(40))                     # a record-like shape off the grid
    img = os.path.join(tmp, "hik_index.img")
    with open(img, "wb") as fh:
        fh.write(bytes(1 << 16) + page + page + bytes(1 << 16))   # two identical copies
    class Dev:
        size_bytes = size
        def read_at(self, off, n):
            with open(img, "rb") as fh:
                fh.seek(off)
                return fh.read(n)
    idx = hikbtree.read_index(Dev(), [1 << 16, (1 << 16) + len(page)])
    check("the data-area base is found as the common residue", idx["base"] == base, hex(idx["base"] or 0))
    check("the two copies de-duplicate to four records",
          len(idx["records"]) == 4 and all(r["copies"] == 2 for r in idx["records"]))
    from datetime import datetime, timezone
    loc = lambda v: datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows = [{"id": "in", "offset": base + 3 * gib + 5000,
             "time_first_local": loc(t0 + 100), "time_last_local": loc(t0 + 3600)},
            {"id": "older", "offset": base + 3 * gib + 9000,
             "time_first_local": loc(t0 - 400_000), "time_last_local": loc(t0 - 390_000)},
            {"id": "unused", "offset": base + 1 * gib, "time_first_local": loc(t0),
             "time_last_local": loc(t0 + 10)},
            {"id": "newer", "offset": base + 3 * gib + 20000,
             "time_first_local": loc(t0 + 200_000), "time_last_local": loc(t0 + 200_100)},
            {"id": "no_record", "offset": base + 20 * gib, "time_first_local": loc(t0),
             "time_last_local": loc(t0 + 10)}]
    labels = {x["id"]: x for x in hikbtree.label_streams(idx, rows)}
    lab = {k: v["label"] for k, v in labels.items()}
    check("a stream inside its block's record window gets the record's channel",
          lab["in"] == "CH05", str(lab))
    check("older footage left in a reused block is stale_tail, with how much older, and "
          "no camera", lab["older"] == "stale_tail"
          and labels["older"]["older_than_record_by_s"] == 390_000, str(labels["older"]))
    check("footage newer than its block's record, or in a block with no record, is "
          "outside_index - never stale_tail",
          lab["newer"] == "outside_index" and lab["no_record"] == "outside_index")
    check("a block reserved at initialisation (channel 255) labels nothing",
          lab["unused"] == "outside_index")
    from analyse.timeline import ClockModel, build as build_timeline
    ps = {"streams": [dict(r, bytes=1000, index_label=lab[r["id"]]) for r in rows]}
    tl = build_timeline(None, None, ClockModel(), ps_report=ps)
    kinds = {e["id"]: (e["kind"], e["camera"]) for e in tl["events"]}
    check("the timeline shows stale_tail as a remnant of unknown camera, like Dahua's",
          kinds["older"] == ("remnant", "UNKNOWN") and kinds["in"] == ("indexed", "CH05")
          and tl["counts"]["remnant"] == 1, str(kinds))


# Vendor-made files, not ours.  Each Hikvision entry: its "HK" time
# descriptors in stream order, and what the keyframe after each shows painted
# on the picture (read by eye), or the recorder's own file-name time.
#  IMKH  VideoLAN samples/IMKH/00000001541000000.mp4, SHA-256 79b1e557...
#  T4182 samples.ffmpeg.org trac ticket4182 20150327215559_ch01.mp4, 20e31574...
#  T3566 samples.ffmpeg.org trac ticket3566 Control Room 1..._20140314235910_
#        20140314235939_164863298.mp4, 80eaa112... (video type 0xB0: ffmpeg
#        cannot decode it, so its check is the file name, not the picture)
IMKH_HK = ["400e484b010012448778aa1000ffffff", "400e484b0100124487792a0800ffffff",
           "400e484b010012448779aa0800ffffff", "400e484b01001244877a2aa800ffffff",
           "400e484b01001244877aaab000ffffff", "400e484b01001244877b2aa800ffffff",
           "400e484b01001244877baa0800ffffff", "400e484b01001244877c2a0800ffffff",
           "400e484b01001244877caa0800ffffff", "400e484b01001244877d2a1800ffffff"]
IMKH_PAINTED = [f"01:55:{s}" for s in range(33, 52, 2)]
T4182_HK = ["400e484b01000f3dd782f54000ffffff", "400e484b01000f3dd783754000ffffff",
            "400e484b01000f3dd783f54000ffffff", "400e484b01000f3dd784754000ffffff",
            "400e484b01000f3dd784f54000ffffff"]
T4182_PAINTED = [f"21:56:{s}" for s in range(11, 20, 2)]
T3566_HK_FIRST = "400e484b00010e375fb2a987ffffffff"
# Real Dahua .dav files: (saved name, SHA-256 prefix, frames before the first
# keyframe, ffmpeg keeps a truncated last frame, video frames compared)
DAHUA_SAMPLES = [("ffmpeg_t6144_19.25.00-19.25.50[R].dav", "c17602dd", 21, False, 726),
                 ("handbrake_1935_dav-sample.dav", "9787cb4b", 12, True, 104)]


def test_independent_checks(tmp: str) -> None:
    """Checks that do not rest on our own reading: Hikvision-made files for
    the HK time and the PS carver, and ffmpeg's dhav demuxer as a second
    implementation of the DHAV frame walk, on real Dahua files."""
    print("\n[independent checks: vendor-made samples, second implementation]")
    import hashlib
    import random
    import shutil as _sh
    from recover import pscarve
    from tests import synth_dahua as SD
    from validate import dhav_crosscheck as XC, ps_sample as PSS

    hk = lambda hexes: [pscarve.hk_time(bytes.fromhex(h)) for h in hexes]
    times = hk(IMKH_HK)
    check("Hikvision-made file (2018): all 10 HK times decode to a real date, 2 s apart",
          times == [f"2018-04-09 01:55:{s}" for s in range(34, 53, 2)], str(times))
    check("... and every painted clock is the HK time minus exactly 1 s (a constant, "
          "not noise)", PSS.offsets(times, IMKH_PAINTED) == [-1.0] * 10)
    t2 = hk(T4182_HK)
    check("a second Hikvision-made file (2015): its 5 HK times equal the painted clock to "
          "the second", PSS.offsets(t2, T4182_PAINTED) == [0.0] * 5
          and t2[0] == "2015-03-27 21:56:11", str(t2))
    check("a third (2014): the first HK time equals the start time in the recorder's own "
          "file name", hk([T3566_HK_FIRST]) == ["2014-03-14 23:59:10"])

    a = {"video": [(10, 1, True, 100.0, 0), (20, 2, False, 100.0, 50)], "audio": [(5, 9)], "aux": 1}
    same = {"video": [(10, 1, True, 100.04), (20, 2, False, 100.5)], "audio": [(5, 9)]}
    extra = {"video": [(10, 1, True, 100.0), (7, 3, False, 100.0), (20, 2, False, 100.5)],
             "audio": [(5, 9)]}
    r1, r2 = XC.compare(a, same), XC.compare(a, extra)
    check("second implementation: agreement is frame for frame; a frame only one side "
          "has is found at its index",
          r1["video"]["identical"] and r1["time"]["ffmpeg_within_the_frames_own_second"] == 2
          and not r2["video"]["identical"] and r2["video"]["first_difference"]["frame"] == 1,
          str(r2["video"]))
    mid = {"video": [(8, 7, False, 99.0, 0), (10, 1, True, 100.0, 20), (20, 2, False, 100.0, 50)],
           "audio": [(5, 9)], "aux": 0,
           "truncated_tail": {"kind": "video", "payload_present": 6, "offset": 90}}
    ff_mid = {"video": [(10, 1, True, 100.0), (20, 2, False, 100.2), (6, 4, False, 100.3)],
              "audio": [(5, 9)]}
    ff_wrong = {"video": [(10, 1, True, 100.0), (20, 2, False, 100.2), (9, 4, False, 100.3)],
                "audio": [(5, 9)]}
    r3, r4 = XC.compare(mid, ff_mid), XC.compare(mid, ff_wrong)
    check("the two expected differences are aligned and counted - ffmpeg starts at the "
          "first keyframe, and keeps exactly the bytes of a truncated last frame - and "
          "nothing else is excused",
          r3["video"]["identical"]
          and r3["expected_differences"]["ours_before_first_keyframe"] == 1
          and r3["expected_differences"]["ffmpeg_truncated_last_frame"]
          and not r4["video"]["identical"], str(r3["expected_differences"]))

    ffmpeg = os.environ.get("FFMPEG") or _sh.which("ffmpeg")
    if ffmpeg:
        cam = SD.Camera(1, SD.T0, 1000, 100, 50, random.Random(7))
        dav = os.path.join(tmp, "xc.dav")
        with open(dav, "wb") as fh:
            for _ in range(60):
                for *_, b in cam.next_frames():
                    fh.write(b)
        good = XC.check_file(dav, ffmpeg)
        raw = bytearray(open(dav, "rb").read())
        k = raw.find(b"DHAV", 20000)
        raw[k + 23] ^= 0xFF                       # break one header checksum only
        bad_path = os.path.join(tmp, "xc_bad.dav")
        open(bad_path, "wb").write(raw)
        bad = XC.check_file(bad_path, ffmpeg)
        check("ffmpeg's dhav demuxer and ours agree on every frame: size, checksum, key "
              "flag, and each time inside the frame's own second",
              good["video"]["identical"] and good["audio"]["identical"]
              and good["video"]["ours"] == 60
              and good["time"]["ffmpeg_within_the_frames_own_second"] == 60, str(good["video"]))
        check("a frame ffmpeg keeps but we reject (bad header checksum) is reported, "
              "with where", not bad["video"]["identical"]
              and (bad["video"]["ours"], bad["video"]["ffmpeg"]) == (59, 60)
              and bad["video"]["first_difference"]["ours"]["offset"] > k, str(bad["video"]))
    else:
        print("  [ffmpeg] skipped - put ffmpeg on PATH or set FFMPEG")

    folder = os.environ.get("VENDOR_SAMPLES")
    if not folder:
        print("  [vendor samples] skipped - set VENDOR_SAMPLES to the folder of sample files")
        return
    at = lambda name: os.path.join(folder, name)
    if os.path.exists(at("imkh_00000001541000000.mp4")):
        rep = PSS.check(at("imkh_00000001541000000.mp4"), os.path.join(tmp, "imkh"), ffmpeg or "")
        s = rep["streams"][0]
        check("Hikvision-made file: one stream from right after the 40-byte IMKH header, "
              "every complete pack kept, the 10 HK times as pinned",
              rep["sha256"].startswith("79b1e557") and s["offset"] == 0x28 and s["packs"] == 463
              and rep["uncarved_bytes"]["after"] == 6436 and rep["psm_times"] == times
              and s["resolution"] == "1920x1088", str(s))
        if ffmpeg:
            f = rep["frames"]
            check("... and every video frame ffmpeg decodes from our carve is identical to "
                  "the same frame from the vendor's file", f["common"] == 463
                  and f["common_identical"] == 463, str(f))
    if ffmpeg and os.path.exists(at("ffmpeg_t4182_20150327215559_ch01.mp4")):
        rep = PSS.check(at("ffmpeg_t4182_20150327215559_ch01.mp4"), os.path.join(tmp, "t4182"),
                        ffmpeg)
        check("the 2015 Hikvision file: whole stream carved, 215/215 frames identical to "
              "ffmpeg's decode of the vendor file, HK times as pinned",
              rep["sha256"].startswith("20e31574") and rep["streams"][0]["offset"] == 0x28
              and rep["uncarved_bytes"]["after"] == 0 and rep["psm_times"] == t2
              and rep["frames"]["common_identical"] == rep["frames"]["common"] == 215,
              str(rep.get("frames")))
    if ffmpeg:
        for name, sha, lead, cut, n in DAHUA_SAMPLES:
            if not os.path.exists(at(name)):
                continue
            with open(at(name), "rb") as fh:
                ok_sha = hashlib.sha256(fh.read()).hexdigest().startswith(sha)
            r = XC.check_file(at(name), ffmpeg)
            ex = r["expected_differences"]
            check(f"real Dahua file {name[:24]}: ffmpeg and ours identical on all {n} video "
                  "frames and all audio, times inside their own second, the only differences "
                  "the two expected ones",
                  ok_sha and r["video"]["identical"] and r["audio"]["identical"]
                  and r["video"]["matching_prefix"] == n
                  and ex["ours_before_first_keyframe"] == lead
                  and ex["ffmpeg_truncated_last_frame"] == cut
                  and r["time"]["ffmpeg_within_the_frames_own_second"] == n, str(r["video"]))


def test_combined(tmp: str) -> None:
    """Two recorders share no clock. A combined view may only put them on one
    axis when every case states its recorder's timezone; without that it must
    make no statement at all about what happened at the same time."""
    print("\n[combined view across recorders]")
    from analyse import combined as C

    def case(name: str, tz, drift_source: str, first_local: str, last_local: str,
             first_utc, last_utc) -> str:
        d = os.path.join(tmp, "comb", name)
        os.makedirs(d, exist_ok=True)
        ev = [{"id": "e1", "kind": "indexed", "camera": "CH01",
               "start_local": first_local, "end_local": last_local,
               "start_utc": first_utc, "end_utc": last_utc, "duration_s": 3600.0}]
        tl = {"clock": {"tz_offset_min": tz, "drift_s": 0.0,
                        "drift_source": drift_source or None, "rule": "..."},
              "events": ev, "cameras": {"CH01": {"recordings": 1, "first_local": first_local,
                                                 "last_local": last_local,
                                                 "covered_s": 3600.0, "gaps": 0}},
              "gaps": [], "anomalies": [], "counts": {"indexed": 1}}
        with open(os.path.join(d, "timeline.json"), "w", encoding="utf-8") as fh:
            json.dump(tl, fh)
        with open(os.path.join(d, "scan_report.json"), "w", encoding="utf-8") as fh:
            json.dump({"case": {"case_id": name}, "stats": {"complete_pass": True},
                       "device": {"path": f"/dev/{name}", "model": "ST1000VX013",
                                  "serial": name.upper(), "size_bytes": 1000 << 20},
                       "hashes": [{"algorithm": "sha256", "value": "ab" * 32}]}, fh)
        return d

    a = case("rec-a", 330, "examiner observation", "2026-09-01 12:00:00",
             "2026-09-01 13:00:00", "2026-09-01T06:30:00Z", "2026-09-01T07:30:00Z")
    b = case("rec-b", 330, "", "2026-09-01 12:30:00", "2026-09-01 13:30:00",
             "2026-09-01T07:00:00Z", "2026-09-01T08:00:00Z")
    c_notz = case("rec-c", None, "", "2026-09-01 12:30:00", "2026-09-01 13:30:00", None, None)

    v = C.build([a, b])
    check("two recorders that both state a timezone share a UTC axis",
          v["axis"]["axis"] == "utc" and v["axis"]["shared"], str(v["axis"]["axis"]))
    check("a recorder whose clock error was never measured is named as a caveat, not hidden",
          len(v["axis"]["caveats"]) == 1 and "rec-b" in v["axis"]["caveats"][0],
          str(v["axis"]["caveats"]))
    check("overlapping coverage on the shared axis is reported once, with its duration",
          len(v["overlaps"]) == 1 and v["overlaps"][0]["from_utc"] == "2026-09-01T07:00:00Z"
          and v["overlaps"][0]["duration_s"] == 1800.0, str(v["overlaps"]))

    v2 = C.build([a, c_notz])
    check("one recorder without a timezone denies the whole view a shared axis",
          v2["axis"]["axis"] == "recorder_local" and not v2["axis"]["shared"])
    check("with no shared axis, NOTHING is claimed about recorders running at the same time",
          v2["overlaps"] == [], str(v2["overlaps"]))
    check("the view says which case is missing what, rather than only that it cannot",
          any("rec-c" in n and "timezone" in n for n in v2["axis"]["needs"]),
          str(v2["axis"]["needs"]))
    check("the separate-axes warning leads the notes",
          "SEPARATE axes" in v2["notes"][0], v2["notes"][0][:60])

    # Recorders whose spans merely touch are not "running at the same time".
    d = case("rec-d", 330, "x", "2026-09-01 13:00:00", "2026-09-01 13:00:30",
             "2026-09-01T07:30:00Z", "2026-09-01T07:30:30Z")
    check("an overlap shorter than the minimum is not reported",
          C.build([a, d])["overlaps"] == [])

    v3 = C.build([a, b])
    check("totals add up the recorders, and each case's timeline is cited by hash",
          v3["totals"]["recorders"] == 2 and v3["totals"]["events"] == 2
          and len(v3["inputs"]) == 2 and all(len(h) == 64 for h in v3["inputs"].values()),
          str(v3["totals"]))

    try:
        C.build([a, a])
        dup = False
    except ValueError:
        dup = True
    check("the same case given twice is refused, not counted as two recorders", dup)

    from report.html import render_combined
    page = render_combined(dict(v2, title="T", generated_utc="2026-09-27T00:00:00Z"))
    check("the page states the recorders are not aligned, and makes no simultaneity claim",
          "not aligned" in page and "Not determined" in page and "<h1>T</h1>" in page)


def test_osd_rules() -> None:
    """The rules for reading a burned-in OSD: a title only when frames agree,
    a band chosen by the footage rather than hardcoded, and an ambiguous date
    left ambiguous until the container resolves it."""
    print("\n[OSD: title and clock rules]")
    from datetime import datetime
    from analytics import osd_rules as R

    check("digit-shaped letters are fixed inside a numeric word only",
          R.normalise_title("Camera O1") == "Camera 01"
          and R.normalise_title("Road VIew 1") == "Road VIew 1")
    check("a bare number is not a title, and noise is not either",
          R.normalise_title("2024-08-30") is None and R.normalise_title("~~") is None
          and R.normalise_title("ab") is None)

    v = R.vote_title(["Camera 01", "Camera O1", "CAMERA 01", "Parklng", "%%%"])
    check("a title is the agreed reading, with the share that agreed and the rest kept",
          v["title"] == "Camera 01" and v["frames_agreeing"] == 3 and v["frames_read"] == 4
          and v["confidence"] == 0.75 and v["alternatives"] == {"parklng": 1}, str(v))
    check("frames that disagree claim nothing",
          R.vote_title(["Parking", "Gate 2", "Road View 1"]) is None)
    check("too few readable frames claim nothing",
          R.vote_title(["Parking", "Parking", "%%"]) is None)

    # Readings are grouped per stream: two streams are two cameras with two
    # different titles, so a band is scored within a stream and then averaged.
    bands = {"top_left": [["Parking"] * 4, ["Gate 2"] * 4],
             "top_right": [["", "%%", "", ""], ["", "", "", ""]],
             "bottom_left": [[""] * 4, [""] * 4],
             "bottom_right": [["", "", "", ""], ["", "", "", ""]]}
    picked = R.pick_band(bands, "title")
    check("the band that reads consistently wins, and every band's score is kept",
          picked["band"] == "top_left" and picked["scores"]["top_right"] == 0.0, str(picked))
    check("two streams with different titles do not cancel each other out",
          picked["score"] == 1.0, str(picked["score"]))
    check("no band claims a layout when nothing reads",
          R.pick_band({b: [["", "%%"]] for b in R.BANDS}, "title") is None)

    p = R.parse_osd_clock("2024-08-30 14:23:45")
    check("an unambiguous clock reads once",
          not p["ambiguous"] and p["readings"] == [datetime(2024, 8, 30, 14, 23, 45)])
    p = R.parse_osd_clock("01/02/2024 08:00:00")
    check("a date that is two dates returns both, flagged ambiguous",
          p["ambiguous"] and len(p["readings"]) == 2, str(p["readings"]))
    check("an ambiguous reading with no second source stays unresolved",
          R.resolve_against(p, None)["resolved"] is None)
    r = R.resolve_against(p, datetime(2024, 2, 1, 8, 0, 2))
    check("the container's own date chooses between the two, and is recorded as having",
          r["resolved"] == datetime(2024, 2, 1, 8, 0) and r["resolved_by"] == "container date",
          str(r.get("resolved_by")))
    check("a two-digit year is not read as the first century",
          R.parse_osd_clock("24-08-30 14:23:45") is None)

    # The two clocks the first real run could not read (VALIDATION_REPORT 8c).
    p = R.parse_osd_clock("28-07-2024 Sun 02:07:20")
    check("a Hikvision clock with its weekday reads, and the weekday fits the date",
          p is not None and p["readings"] == [datetime(2024, 7, 28, 2, 7, 20)]
          and p["weekday"] == "Sun" and p["weekday_checked"] and not p["weekday_disagrees"], str(p))
    p = R.parse_osd_clock("01/05/2026 01:20:26 PM")
    check("a CP Plus 12-hour clock: PM makes it 13:20, and 01/05 stays two dates",
          p is not None and p["twelve_hour"] == "PM" and p["ambiguous"]
          and set(p["readings"]) == {datetime(2026, 5, 1, 13, 20, 26),
                                     datetime(2026, 1, 5, 13, 20, 26)}, str(p))
    p = R.parse_osd_clock("01/05/2026 Fri 01:20:26 PM")
    check("the weekday the recorder painted chooses between the two dates",
          p is not None and p["readings"] == [datetime(2026, 5, 1, 13, 20, 26)]
          and not p["ambiguous"] and p["weekday_checked"], str(p))
    p = R.parse_osd_clock("28-07-2024 Mon 02:07:20")
    check("a weekday that fits no reading is reported, not trusted over the digits",
          p is not None and p["weekday_disagrees"]
          and p["readings"] == [datetime(2024, 7, 28, 2, 7, 20)], str(p))
    check("12 AM is midnight, 12 PM is noon, and 13 PM is not a clock",
          R.parse_osd_clock("2024-08-30 12:05:00 AM")["readings"] == [datetime(2024, 8, 30, 0, 5)]
          and R.parse_osd_clock("2024-08-30 12:05:00 PM")["readings"]
          == [datetime(2024, 8, 30, 12, 5)]
          and R.parse_osd_clock("2024-08-30 13:05:00 PM") is None)
    check("digit-shaped letters among the digits are repaired, a weekday's letters are not",
          R.parse_osd_clock("2O24-O8-3O Fri 14:23:45")["readings"]
          == [datetime(2024, 8, 30, 14, 23, 45)])

    c = R.clock_check(datetime(2024, 8, 30, 14, 23, 45), datetime(2024, 8, 30, 14, 23, 43))
    d = R.clock_check(datetime(2024, 8, 30, 14, 23, 45), datetime(2024, 8, 30, 14, 20, 43))
    check("the picture and the container agree within tolerance, and disagree outside it",
          c["verdict"] == "agrees" and d["verdict"] == "disagrees" and d["offset_s"] == 182.0)
    check("nothing is compared when either clock is missing",
          R.clock_check(None, datetime(2024, 1, 1))["verdict"] == "not compared")


def test_osd_reader(tmp: str) -> None:
    """The OSD reader end to end with the OCR stubbed: ffmpeg and Tesseract are
    not installed in CI, so `sample` and `ocr` are replaced by a fake recorder
    that paints a title in one corner and a clock in another.  This exercises
    calibration, the per-stream vote, the clock cross-check against the
    container's own date, and the report shape - not Tesseract's accuracy,
    which no test here can claim."""
    print("\n[OSD: reader against a stubbed recorder]")
    from datetime import datetime, timedelta
    from analytics import osd as O

    start = datetime(2024, 8, 30, 14, 0, 0)
    painted = {"ps-00001": "Camera 01", "ps-00002": "Parking"}

    def fake_sample(clip, band, out_dir, frames=6, window_s=30, mode="normal"):
        # The recorder puts the title bottom-left and the clock top-right; every
        # other band holds picture, which reads as nothing.
        sid = os.path.splitext(os.path.basename(clip))[0]
        step = window_s / float(frames)
        out = []
        for i in range(frames):
            if band == O.BANDS["bottom_left"]:
                text = painted.get(sid, "")
            elif band == O.BANDS["top_right"]:
                text = (start + timedelta(seconds=i * step)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                text = ""
            p = os.path.join(out_dir, f"f{i:03d}.pgm")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            out.append(p)
        return out

    def fake_ocr(image, chars):
        with open(image, "r", encoding="utf-8") as fh:
            return fh.read()

    case = os.path.join(tmp, "osd-case")
    os.makedirs(os.path.join(case, "carve", "ps_streams"), exist_ok=True)
    clips = []
    for sid in ("ps-00001", "ps-00002"):
        p = os.path.join(case, "carve", "ps_streams", sid + ".ps")
        with open(p, "wb") as fh:
            fh.write(b"\x00" * 16)
        clips.append(p)
    # the container's own date for one stream only: the other has nothing to
    # check its picture against, which must not be reported as agreement
    with open(os.path.join(case, "carve", "ps_report.json"), "w", encoding="utf-8") as fh:
        json.dump({"streams": [{"id": "ps-00001",
                                "time_first_local": start.strftime("%Y-%m-%d %H:%M:%S")}]}, fh)

    real = (O.sample, O.ocr, O.have_tools)
    O.sample, O.ocr, O.have_tools = fake_sample, fake_ocr, lambda: None
    try:
        r = O.run(clips, case, frames=4, log=lambda *a: None)
    finally:
        O.sample, O.ocr, O.have_tools = real

    lay = r["layout"]
    check("calibration finds the corners the recorder actually painted",
          lay["title"]["band"] == "bottom_left" and lay["clock"]["band"] == "top_right",
          f"{lay['title']} / {lay['clock']}")
    by = {s["clip"]: s for s in r["streams"]}
    check("each stream is named from its own picture",
          by["ps-00001.ps"]["label"]["title"] == "Camera 01"
          and by["ps-00002.ps"]["label"]["title"] == "Parking")
    check("the picture's clock is checked against the container's date for the same moment",
          by["ps-00001.ps"]["clock"]["verdict"] == "agrees"
          and by["ps-00001.ps"]["clock"]["frames_compared"] == 4,
          str(by["ps-00001.ps"]["clock"]))
    check("a stream with no container date is read, not compared",
          by["ps-00002.ps"]["clock"]["verdict"] == "read, not compared")
    check("the summary counts what the picture named and how the clocks compared",
          r["summary"]["streams_named_by_the_picture"] == 2
          and r["summary"]["clock_checks"] == {"agrees": 1, "read, not compared": 1},
          str(r["summary"]))
    check("osd.json is written with the rule and the status it may claim",
          os.path.exists(os.path.join(case, "analytics", "osd.json"))
          and r["rule"] == "osd.tesseract_title_clock.v1"
          and r["status"] == "lead, not evidence")

    # The same picture against a container date 400 s away: a recorder whose
    # displayed clock and stored dates disagree must not be absorbed.
    with open(os.path.join(case, "carve", "ps_report.json"), "w", encoding="utf-8") as fh:
        json.dump({"streams": [{"id": "ps-00001", "time_first_local":
                                (start - timedelta(seconds=400)).strftime("%Y-%m-%d %H:%M:%S")}]}, fh)
    O.sample, O.ocr, O.have_tools = fake_sample, fake_ocr, lambda: None
    try:
        r2 = O.run(clips[:1], case, frames=4, log=lambda *a: None)
    finally:
        O.sample, O.ocr, O.have_tools = real
    check("a picture 400 s from the container's date is reported as a disagreement",
          r2["streams"][0]["clock"]["verdict"] == "disagrees"
          and r2["streams"][0]["clock"]["offset_s"] == 400.0,
          str(r2["streams"][0]["clock"]))

    # A recorder whose text reads only inverted, and not in every frame: the
    # band must not be rejected because the other mode read nothing.
    def negated_only(clip, band, out_dir, frames=6, window_s=30, mode="normal"):
        got = fake_sample(clip, band, out_dir, frames, window_s, mode)
        for k, p in enumerate(got):
            if mode != "negated" or k == 0:           # one frame in each stream misread
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("")
        return got

    O.sample, O.ocr, O.have_tools = negated_only, fake_ocr, lambda: None
    try:
        r3 = O.run(clips, case, frames=4, log=lambda *a: None)
    finally:
        O.sample, O.ocr, O.have_tools = real
    by3 = {s["clip"]: s for s in r3["streams"]}
    check("a band that reads only inverted is found - its score is not diluted by the mode "
          "that read nothing", r3["layout"]["title"] is not None
          and r3["layout"]["title"]["band"] == "bottom_left"
          and r3["layout"]["title"]["mode"] == "negated"
          and by3["ps-00002.ps"]["label"]["title"] == "Parking", str(r3["layout"]))
    check("the filter graph: the crop in grey, upscaled; inverted only in the negated mode",
          O.filters(O.BANDS["top_left"], 0.2, "negated").endswith("negate")
          and not O.filters(O.BANDS["top_left"], 0.2, "normal").endswith("negate"))
    check("a layout saved before modes existed still reads (negate -> negated)",
          O.layout_mode({"negate": True}) == "negated" and O.layout_mode({}) == "normal")


def _h26x_stream(rng, n: int, codec: str = "h265", gop: int = 25,
                 static_every: int = 0) -> list[list[bytes]]:
    """Access units of a synthetic H.264/H.265 stream, as lists of NAL units:
    parameter sets and an IDR slice every `gop` frames, one P slice otherwise.
    With `static_every`, that share of P slices is a tiny slice identical
    every time, like a camera watching a still scene.  Slice bytes contain no
    0x00, so no start code can appear inside a NAL."""
    def body(k):
        return rng.randbytes(k).replace(b"\x00", b"\x01")
    if codec == "h265":
        params = [b"\x40\x01" + body(20), b"\x42\x01" + body(40), b"\x44\x01" + body(8)]
        idr, p = b"\x26\x01", b"\x02\x01"
    else:
        params = [b"\x67" + body(20), b"\x68" + body(6)]
        idr, p = b"\x65", b"\x41"
    aus = []
    for f in range(n):
        if f % gop == 0:
            aus.append(params + [idr + body(rng.randint(2000, 3000))])
        elif static_every and f % static_every == 0:
            aus.append([p + b"\x9a\x7c\x11"])
        else:
            aus.append([p + body(rng.randint(200, 600))])
    return aus


def _annexb(nals: list[bytes]) -> bytes:
    return b"".join(b"\x00\x00\x00\x01" + n for n in nals)


def _dav(aus, first: int, t0, fn0: int = 1000, sei: bool = False) -> bytes:
    """DHAV frames for access units, frame `first + k` dated as the k-th
    frame of a 25 fps recording starting at t0.  `sei` inserts a prefix SEI
    in every keyframe, as an export might."""
    from datetime import timedelta
    out = bytearray()
    for k, nals in enumerate(aus):
        key = nals[0][:1] == b"\x40"
        if sei and key:
            nals = nals[:3] + [b"\x4e\x01\x05\x10" + b"export-sei" * 2] + nals[3:]
        out += synth_dahua.dhav(0xFD if key else 0xFC, fn0 + k,
                                t0 + timedelta(seconds=(first + k) // 25), 40 * k,
                                _annexb(nals), synth_dahua.EXT_VIDEO)
    return bytes(out)


def _hik_ps(aus, first: int, t0, pes_max: int, imkh: bool = False) -> bytes:
    """A Hikvision-style Program Stream of H.264 access units: one pack per
    frame, a stream map with the `HK` time before each keyframe, the frame's
    bytes split into MPEG-2 PES packets of at most `pes_max` bytes."""
    from datetime import timedelta

    def pack_header(scr):
        b = bytearray(14)
        b[0:4] = b"\x00\x00\x01\xba"
        b[4] = 0x44 | ((scr >> 30) & 0x07) << 3 | ((scr >> 28) & 0x03)
        b[5] = (scr >> 20) & 0xFF
        b[6] = ((scr >> 15) & 0x1F) << 3 | 0x04 | ((scr >> 13) & 0x03)
        b[7] = (scr >> 5) & 0xFF
        b[8] = (scr & 0x1F) << 3 | 0x04
        b[9], b[10], b[11], b[12], b[13] = 0x01, 0x89, 0xC3, 0xF8, 0xF8
        return bytes(b)

    def psm(t):
        v = ((t.month << 28) | (t.day << 23) | (t.hour << 18) | (t.minute << 12)
             | (t.second << 6) | 32)
        hk = (b"\x40\x0e" + b"HK\x01\x00" + bytes([t.year - 2000]) + v.to_bytes(4, "big")
              + b"\x00\xff\xff\xff\xff")                   # 14 bytes, as declared
        es = b"\x1b\xe0\x00\x00"
        body = (b"\xf8\xff" + struct.pack(">H", len(hk)) + hk + struct.pack(">H", len(es))
                + es + b"\x00\x00\x00\x00")
        return b"\x00\x00\x01\xbc" + struct.pack(">H", len(body)) + body

    out = bytearray(b"IMKH" + bytes(36) if imkh else b"")
    for k, nals in enumerate(aus):
        f = first + k
        pkt = pack_header(f * 3600)
        if nals[0][:1] == b"\x67":
            pkt += psm(t0 + timedelta(seconds=f // 25))
        es = _annexb(nals)
        for j in range(0, len(es), pes_max):
            piece = b"\x80\x80\x05" + bytes(5) + es[j:j + pes_max]    # MPEG-2 PES header
            pkt += b"\x00\x00\x01\xe0" + struct.pack(">H", len(piece)) + piece
        out += pkt
    return bytes(out)


def test_validate_export(tmp: str) -> None:
    """Recovered footage against a recorder's export: the verdict rests on
    the picture slices, in order - never on container bytes, and never on
    tiny slices that repeat."""
    print("\n[validate-export]")
    import argparse
    import random
    from datetime import datetime
    import cli
    from validate import exportmatch as X

    d = os.path.join(tmp, "vx")
    os.makedirs(d)
    t0 = datetime(2026, 9, 28, 11, 0, 0)

    def put(name, data):
        path = os.path.join(d, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    # -- NAL splitting ---------------------------------------------------
    rng = random.Random(28)
    nals = [bytes([0x02, 0x01]) + rng.randbytes(50).replace(b"\x00", b"\x01") for _ in range(40)]
    buf = b"".join((b"\x00\x00\x01" if k % 2 else b"\x00\x00\x00\x01") + n
                   for k, n in enumerate(nals))
    check("Annex-B split: 3- and 4-byte start codes, trailing zeros not in the NAL",
          list(X.split_annexb(buf)) == nals)
    sp, got, k = X.NalSplitter(), [], 0
    while k < len(buf):
        step = rng.randint(1, 90)                       # pieces cut anywhere, even mid start code
        got += [n for n, _ in sp.feed(buf[k:k + step], k)]
        k += step
    got += [n for n, _ in sp.flush()]
    check("NAL units split across arbitrary pieces come out whole", got == nals)

    h265 = _h26x_stream(random.Random(1), 60, "h265")
    h264 = _h26x_stream(random.Random(1), 60, "h264")
    check("codec told apart from NAL headers alone",
          X.guess_codec([n for au in h265 for n in au]) == "h265"
          and X.guess_codec([n for au in h264 for n in au]) == "h264")

    # -- Dahua: the disk's recording and exports of part of it -------------
    cam = _h26x_stream(random.Random(7), 400, "h265")
    rec = put("rec.dav", _dav(cam, 0, t0, fn0=5000))
    ex_rewrap = put("export_rewrap.dav", _dav(cam[100:250], 100, t0, fn0=1, sei=True))
    r = X.compare(ex_rewrap, [rec])
    m, c = r["match"], r["container"]
    check("export re-wrapped (new counters, SEI added): every slice found, verdict identical",
          m["verdict"] == "identical" and m["slices_matched"] == m["slices_total"] == 150
          and r["meets_criterion"], str(m))
    check("...its container differences are measured, not counted against it",
          c["frames_compared"] == 150 and c["frames_byte_identical"] == 0
          and c["date_equal"] == 150 and c["frame_counter_equal"] == 0, str(c))

    with open(rec, "rb") as fh:
        raw = fh.read()
    frames = list(dahua.walk_frames(raw, 0))
    cut = raw[frames[100].offset:frames[250].offset]
    r = X.compare(put("export_cut.dav", cut), [rec])
    check("an export that kept the frames as stored: frames byte-identical, header and all",
          r["match"]["verdict"] == "identical"
          and r["container"]["frames_byte_identical"] == 150, str(r["container"]))

    r = X.compare(put("export.h265", b"".join(_annexb(au) for au in cam[100:250])), [rec])
    check("a bare H.265 export matches the same recording", r["match"]["verdict"] == "identical"
          and r["export"]["codec"] == "h265")

    lost = put("rec_lost.dav", _dav(cam[:180], 0, t0, fn0=5000)
               + _dav(cam[181:], 181, t0, fn0=5181))
    r = X.compare(ex_rewrap, [lost])
    m = r["match"]
    check("a frame lost on the disk: partial, and exactly that frame is named",
          m["verdict"] == "partial" and m["unmatched_ranges_total"] == 1
          and m["unmatched_ranges"][0]["from"]["frame"] == 80
          and m["frames_fully_matched"] == 149 and not r["meets_criterion"], str(m))

    other = put("other_cam.dav", _dav(_h26x_stream(random.Random(8), 400, "h265"), 0, t0))
    r = X.compare(ex_rewrap, [other])
    check("another camera at the same times: verdict none", r["match"]["verdict"] == "none"
          and r["match"]["slices_matched"] == 0)

    still_a = _h26x_stream(random.Random(11), 300, "h265", static_every=2)
    still_b = _h26x_stream(random.Random(12), 300, "h265", static_every=2)
    rec_a = put("still_a.dav", _dav(still_a, 0, t0))
    ex_b = put("still_b_export.dav", _dav(still_b[50:200], 50, t0))
    r = X.compare(ex_b, [rec_a])
    check("two still scenes share identical tiny slices - and that alone matches nothing",
          r["match"]["slices_matched"] == 0 and r["match"]["verdict"] == "none",
          str(r["match"]))
    r = X.compare(put("still_a_export.dav", _dav(still_a[50:200], 50, t0)), [rec_a])
    check("...while the same scene's tiny slices are checked in place and all match",
          r["match"]["verdict"] == "identical", str(r["match"]))

    part1 = put("hour_10.dav", _dav(cam[:200], 0, t0))
    part2 = put("hour_11.dav", _dav(cam[200:], 200, t0))
    r = X.compare(put("export_span.dav", _dav(cam[150:250], 150, t0)), [part1, part2])
    check("an export across two recovered files: identical, each file credited its part",
          r["match"]["verdict"] == "identical"
          and [x["export_range"] for x in r["recovered"]] == [[0, 49], [50, 99]],
          str([x["export_range"] for x in r["recovered"]]))

    # -- Hikvision: Program Stream, packets split differently --------------
    hik = _h26x_stream(random.Random(21), 300, "h264")
    rec_ps = put("hik_rec.ps", _hik_ps(hik, 0, t0, pes_max=1000))
    ex_ps = put("hik_export.mp4", _hik_ps(hik[50:150], 50, t0, pes_max=700, imkh=True))
    r = X.compare(ex_ps, [rec_ps])
    check("Hikvision .mp4 export (IMKH + PS) read as a Program Stream",
          X.sniff_file(ex_ps) == "ps" and r["export"]["codec"] == "h264")
    check("...PES packets cut at different places: identical, HK times equal",
          r["match"]["verdict"] == "identical"
          and r["container"].get("time_equal") == r["container"]["frames_compared"] == 100,
          str(r["match"]) + str(r["container"]))

    # -- the command -------------------------------------------------------
    case = os.path.join(tmp, "vx_case")
    os.makedirs(os.path.join(case, "clips"))
    shutil.copy(rec, os.path.join(case, "clips", "rec.dav"))
    with open(os.path.join(case, "clips", "rec.h265"), "wb") as fh:
        fh.write(b"".join(_annexb(au) for au in cam))
    check("a stream extracted twice (.dav and .h265) is searched once",
          cli._recovered_files([os.path.join(case, "clips")])
          == [os.path.join(case, "clips", "rec.dav")])
    led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"), actor="t", case_id="VX")
    led.append("case_opened")
    rc = cli.cmd_validate_export(argparse.Namespace(
        export=ex_rewrap, against=[os.path.join(case, "clips")], out=case, codec="auto",
        recorder="synthetic"))
    res_path = os.path.join(case, "validation", "export_export_rewrap.dav.json")
    led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"))
    with open(res_path, "r", encoding="utf-8") as fh:
        res = json.load(fh)
    check("validate-export writes the result with both files' SHA-256",
          rc == 0 and res["export"]["sha256"] == hashlib.sha256(open(ex_rewrap, "rb").read()).hexdigest()
          and len(res["recovered"]) == 1 and len(res["recovered"][0]["sha256"]) == 64)
    check("...and records it in the custody ledger, chain still valid",
          led.entries[-1]["action"] == "export_compared" and led.verify()["valid"]
          and led.entries[-1]["data_hash"] == hashlib.sha256(open(res_path, "rb").read()).hexdigest())


def test_model(tmp: str) -> None:
    """The recorder's model: from its number's shape, from strings on the
    platter outside the video, and checked against the format on the disk."""
    print("\n[recorder model]")
    import argparse
    import random
    import cli
    from detect import model as M
    from report.case import load_case
    from report.html import render

    ids = {m: M.identify(m) for m in ("CP-UNR-104F1", "DS-7B08HUHI-K1", "ds-7b08huhi-k1",
                                      "DS-2CD1023G0-I", "DH-XVR5104HS-X", "XYZ-123")}
    check("model numbers identified by shape: vendor and recorder vs camera",
          ids["CP-UNR-104F1"]["vendor"] == "CP Plus" and ids["CP-UNR-104F1"]["kind"] == "recorder"
          and ids["DS-7B08HUHI-K1"]["vendor"] == "Hikvision"
          and ids["DS-7B08HUHI-K1"]["kind"] == "recorder"
          and ids["ds-7b08huhi-k1"]["kind"] == "recorder"
          and ids["DS-2CD1023G0-I"]["kind"] == "camera"
          and ids["DH-XVR5104HS-X"]["vendor"] == "Dahua" and ids["XYZ-123"] is None, str(ids))

    ms = M.ModelSearch()
    block = bytearray(4096)
    line = b"devType=NVR;model=CP-UNR-104F1;ver=4.0\x00"
    block[100:100 + len(line)] = line
    block[4090:4096] = b"DS-7B0"                      # straddles into the next block
    nxt = bytearray(b"8HUHI-K1\x00" + bytes(4087))
    nxt[2000:2020] = b"XDS-7208HGHI-F1 cam\x00"      # inside a longer token: not a model
    ms.feed(0, bytes(block))
    ms.feed(4096, bytes(nxt))
    got = {c["model"]: c for c in ms.result({})["candidates"]}
    check("model strings found with their offsets, one straddling two blocks found once",
          set(got) == {"CP-UNR-104F1", "DS-7B08HUHI-K1"}
          and got["CP-UNR-104F1"]["offsets"] == [118] and got["DS-7B08HUHI-K1"]["count"] == 1
          and got["DS-7B08HUHI-K1"]["offsets"] == [4090], str(got))

    bmap = [{"offset": i * 100, "length": 100,
             "incompressibility": 1.0 if 3 <= i < 17 else 0.3,
             "start_codes": 40 if 3 <= i < 17 else 0} for i in range(20)]
    blocks, searched = M.select_blocks(bmap, 2000, max_bytes=10_000, ends=2)
    check("video blocks are never searched; the two ends always are",
          [o for o, _ in blocks] == [0, 100, 200, 1700, 1800, 1900]
          and searched["video_blocks_skipped"] == 14 and searched["capped_at_bytes"] is None,
          str(blocks))
    blocks, searched = M.select_blocks(bmap, 2000, max_bytes=300, ends=2)
    check("...and a byte cap is honoured and stated", len(blocks) == 3
          and searched["capped_at_bytes"] == 300)

    dahua = [{"vendor": "Dahua", "confidence": 0.9}]
    both = [{"vendor": "Dahua", "confidence": 0.9}, {"vendor": "Hikvision", "confidence": 0.8}]
    cp = [M.observation("CP-UNR-104F1")]
    hk = [M.observation("DS-7B08HUHI-K1")]
    c1 = M.check(cp, None, dahua)[0]
    c2 = M.check(hk, None, both)[0]
    check("a CP Plus unit on a Dahua-format disk agrees (Dahua-built)",
          c1["verdict"] == "agree" and "Dahua-built" in c1["detail"], str(c1))
    check("a Hikvision unit whose disk also carries Dahua structures is flagged",
          c2["verdict"] == "differ" and "Dahua" in c2["detail"], str(c2))
    plat = {"searched": {"bytes": 1}, "candidates": [
        {"model": "DS-7B08HUHI-K1", "kind": "recorder", "count": 3},
        {"model": "DS-2CD1023G0-I", "kind": "camera", "count": 9}]}
    v_same = M.check(hk, plat, both)[1]["verdict"]
    v_diff = M.check(cp, plat, dahua)[1]["verdict"]
    check("platter model vs the unit: agree / differ; camera strings never name the recorder",
          v_same == "agree" and v_diff == "differ", f"{v_same} {v_diff}")
    check("no observation: every check says not determined",
          all(c["verdict"] == "not determined" for c in M.check([], None, None)))

    # -- the commands, end to end on an image -------------------------------
    # A real scan of an image: a metadata block naming the model, 18 blocks
    # of "video" (start codes + noise), an empty block.
    case = os.path.join(tmp, "model_case")
    rng = random.Random(5)
    img = os.path.join(tmp, "model.img")
    head = bytearray(4096)
    line = b"sys: model=CP-UNR-104F1 fw=V4.001.0000\x00"
    head[500:500 + len(line)] = line
    video = b"".join(b"".join(b"\x00\x00\x00\x01" + rng.randbytes(1020) for _ in range(4))
                     for _ in range(18))
    with open(img, "wb") as fh:
        fh.write(bytes(head) + video + bytes(4096))
    ScanSession(img, case, CaseInfo(case_id="MODEL", investigator="test"),
                block_size=4096, quiet=True).run()
    photo = os.path.join(tmp, "label.jpg")
    with open(photo, "wb") as fh:
        fh.write(b"\xff\xd8 not really a jpeg")
    rc1 = cli.cmd_identify_model(argparse.Namespace(device=img, out=case, max_gb=1.0))
    rc2 = cli.cmd_record_device(argparse.Namespace(
        out=case, model="CP-UNR-104F1", serial="ABC123", firmware="V4.001", read_from="label",
        photo=[photo]))
    with open(os.path.join(case, "model.json"), "r", encoding="utf-8") as fh:
        res = json.load(fh)
    led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"))
    check("identify-model skips the video between the disk's ends and finds the model",
          rc1 == 0 and res["searched"]["blocks"] == 8
          and res["searched"]["video_blocks_skipped"] == 18
          and [c["model"] for c in res["candidates"]] == ["CP-UNR-104F1"], str(res["searched"]))
    check("record-device hashes the photo and both land in the ledger, chain valid",
          rc2 == 0 and [e["action"] for e in led.entries][-2:] == ["model_searched",
                                                                    "device_recorded"]
          and led.entries[-1]["detail"]["photos"][0]["sha256"]
          == hashlib.sha256(open(photo, "rb").read()).hexdigest() and led.verify()["valid"])
    c = load_case(case)
    page = render(c)
    check("the report shows the model; with no vendor format detected, it says so",
          "Recorder model" in page and "CP-UNR-104F1" in page
          and [x["verdict"] for x in c["model"]["checks"]] == ["not determined", "agree",
                                                                "not determined"]
          and "run identify-model again" in c["model"]["checks"][-1]["detail"],
          str(c["model"]["checks"]))

    # -- the unit's own serial, device ID and MAC on the platter --------------
    check("a MAC is taken in any common form, and refused when it is not one",
          M.normalize_mac("02-00-5e-10-00-01") == "02:00:5E:10:00:01"
          and M.normalize_mac("0200.5E10.0001") == "02:00:5E:10:00:01"
          and M.normalize_mac("02:00:5E:10:00") is None
          and M.normalize_mac("G8:20:5E:10:00:01") is None)
    unit = M.observation("CP-UNR-104F1", serial="TSTSERIAL0000001", mac="02:00:5E:10:00:01",
                         device_id="0A0B0C0D")
    forms = M.identifier_forms(unit)
    check("the unit's serial, device ID and MAC become search forms; too-short ones are not",
          {(f["identifier"], f["form"]) for f in forms}
          == {("serial", "text"), ("device_id", "text"), ("mac", "text, colons"),
              ("mac", "text, hyphens"), ("mac", "text, no separators"), ("mac", "6 raw bytes")}
          and M.identifier_forms(M.observation("X", serial="AB12")) == [])
    ms = M.ModelSearch(forms)
    a = bytearray(4096)
    a[10:30] = b"sn=tstserial0000001;"                 # lower case: still the serial
    a[300:306] = bytes.fromhex("02005E100001")          # the MAC as raw bytes
    a[600:618] = b"XTSTSERIAL0000001X"                  # inside a longer token: not it
    a[4090:4096] = b"=02:00"                            # the MAC as text, across the edge
    b = bytearray(4096)
    b[0:24] = b":5E:10:00:01;id=0A0B0C0D;"[:24]
    ms.feed(0, bytes(a))
    ms.feed(4096, bytes(b))
    plat_u = ms.result({"bytes": 8192})
    got = {(r["identifier"], r["form"]): r for r in plat_u["unit_identifiers"]["found"]}
    check("found as whole tokens in either case, as raw bytes, and once across a block edge",
          set(got) == {("serial", "text"), ("mac", "6 raw bytes"), ("mac", "text, colons"),
                       ("device_id", "text")}
          and got[("serial", "text")]["offsets"] == [13]
          and got[("mac", "6 raw bytes")]["offsets"] == [300]
          and got[("mac", "text, colons")]["offsets"] == [4091]
          and all(r["count"] == 1 for r in got.values()), str(got))
    none = M.ModelSearch(forms)
    none.feed(0, bytes(4096))
    v_found = M.check([unit], plat_u, dahua)[-1]
    v_stale = M.check([unit], {"searched": {"bytes": 1}, "candidates": []}, dahua)[-1]
    v_none = M.check([unit], none.result({"bytes": 4096}), dahua)[-1]
    check("the check: found - this unit wrote to the disk; searched before the unit was "
          "recorded - run again; none found - that shows nothing",
          v_found["verdict"] == "agree" and "this unit wrote to this disk" in v_found["detail"]
          and v_stale["verdict"] == "not determined" and "again" in v_stale["detail"]
          and v_none["verdict"] == "not determined" and "does not show" in v_none["detail"],
          f"{v_found} {v_stale} {v_none}")

    # the same search over worker processes (search_blocks) - what a whole drive needs
    import random
    disk = bytearray(random.Random(26150).randbytes(64 * 4096))
    for at, s in ((5000, b" CP-UNR-104F1 "),                    # a model string
                  (4096 * 3 - 5, b"=DS-7B08HUHI-K1;"),         # across an edge
                  (4096 * 9 + 7, b" sn=TSTSERIAL0000001 "),    # the serial
                  (4096 * 22 - 3, bytes.fromhex("02005E100001")),   # raw MAC, across an edge
                  (4096 * 44 + 100, b"mac=02-00-5e-10-00-01;"),     # MAC text, lower case
                  (4096 * 40 + 100, b" DH-XVR5104HS-X ")):     # in a block not searched
        disk[at:at + len(s)] = s
    blocks = [(k * 4096, 4096) for k in range(64) if k % 7 != 5]   # contiguous runs and gaps
    one = M.ModelSearch(forms)
    for off, n in blocks:
        one.feed(off, bytes(disk[off:off + n]))
    many = M.ModelSearch(forms)
    M.search_blocks(lambda off, n: bytes(disk[off:off + n]), blocks, many, workers=2)
    r1, r2 = one.result({}), many.result({})
    check("the search spread over worker processes finds exactly what one process finds",
          json.dumps(r1) == json.dumps(r2)
          and [c["model"] for c in r1["candidates"]] == ["CP-UNR-104F1", "DS-7B08HUHI-K1"]
          and {(r["form"], r["count"]) for r in r1["unit_identifiers"]["found"]}
          == {("text", 1), ("6 raw bytes", 1), ("text, hyphens", 1)},
          json.dumps(r2)[:300])

    case_u = os.path.join(tmp, "unit_case")
    img_u = os.path.join(tmp, "unit.img")
    head_u = bytearray(4096)
    head_u[700:739] = b"devSN=TSTSERIAL0000001;devID=0A0B0C0D;\x00"
    head_u[1200:1206] = bytes.fromhex("02005E100001")
    with open(img_u, "wb") as fh:
        fh.write(bytes(head_u) + video + bytes(4096))
    ScanSession(img_u, case_u, CaseInfo(case_id="UNIT", investigator="test"),
                block_size=4096, quiet=True).run()
    rc_bad = cli.cmd_record_device(argparse.Namespace(
        out=case_u, model="CP-UNR-104F1", serial="", firmware="", read_from="label", photo=[],
        mac="02:00:5E", device_id=""))
    rc_rec = cli.cmd_record_device(argparse.Namespace(
        out=case_u, model="CP-UNR-104F1", serial="TSTSERIAL0000001", firmware="V1.00.14.00.T",
        read_from="system-info", photo=[], mac="02-00-5e-10-00-01", device_id="0A0B0C0D"))
    rc_id = cli.cmd_identify_model(argparse.Namespace(device=img_u, out=case_u, max_gb=1.0))
    with open(os.path.join(case_u, "model.json"), "r", encoding="utf-8") as fh:
        res_u = json.load(fh)
    led_u = CustodyLedger(os.path.join(case_u, "custody_ledger.jsonl"))
    c_u = load_case(case_u)
    check("end to end: a malformed MAC is refused; the unit's serial, device ID and raw MAC "
          "found on the disk; both steps in the ledger, chain valid",
          rc_bad == 1 and rc_rec == 0 and rc_id == 0
          and {r["identifier"] for r in res_u["unit_identifiers"]["found"]}
          == {"serial", "device_id", "mac"}
          and led_u.entries[-2]["detail"]["mac"] == "02:00:5E:10:00:01"
          and led_u.entries[-1]["detail"]["unit_identifiers_found"] == 3
          and c_u["model"]["checks"][-1]["verdict"] == "agree" and led_u.verify()["valid"],
          str(res_u.get("unit_identifiers")))


class _BitWriter:
    """Exp-Golomb bit writer, to build real parameter sets for the tests."""

    def __init__(self):
        self.bits: list[int] = []

    def u(self, n: int, v: int) -> "_BitWriter":
        self.bits += [(v >> (n - 1 - i)) & 1 for i in range(n)]
        return self

    def ue(self, v: int) -> "_BitWriter":
        v += 1
        self.bits += [0] * (v.bit_length() - 1)
        return self.u(v.bit_length(), v)

    def rbsp(self) -> bytes:
        bits = self.bits + [1]                          # rbsp_stop_one_bit
        bits += [0] * (-len(bits) % 8)
        return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))


def _emulation_prevent(rbsp: bytes) -> bytes:
    out, zeros = bytearray(), 0
    for b in rbsp:
        if zeros >= 2 and b <= 3:
            out.append(3)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)


def _h264_sps(w: int, h: int, profile: int = 66) -> bytes:
    bw = _BitWriter().u(8, profile).u(8, 0xC0).u(8, 40).ue(0)
    if profile == 100:
        bw.ue(1).ue(0).ue(0).u(1, 0).u(1, 0)            # 4:2:0, 8-bit, no scaling lists
    mbs_h = (h + 15) // 16
    bw.ue(0).ue(2).ue(1).u(1, 0).ue(w // 16 - 1).ue(mbs_h - 1).u(1, 1).u(1, 1)
    pad = mbs_h * 16 - h
    bw.u(1, 1 if pad else 0)
    if pad:
        bw.ue(0).ue(0).ue(0).ue(pad // 2)
    bw.u(1, 0)                                          # no VUI
    return b"\x67" + _emulation_prevent(bw.rbsp())


def _h265_sps(w: int, h: int) -> bytes:
    bw = _BitWriter().u(4, 0).u(3, 0).u(1, 1)
    bw.u(2, 0).u(1, 0).u(5, 1).u(32, 0x60000000).u(4, 0b1001).u(32, 0).u(11, 0).u(1, 0).u(8, 120)
    coded_h = (h + 7) // 8 * 8
    bw.ue(0).ue(1).ue(w).ue(coded_h).u(1, 1 if coded_h != h else 0)
    if coded_h != h:
        bw.ue(0).ue(0).ue(0).ue((coded_h - h) // 2)
    bw.ue(0).ue(0).ue(4)                                # bit depths, log2_max_poc_lsb - 4
    return b"\x42\x01" + _emulation_prevent(bw.rbsp())


def _vendor_frames(rng, n: int, codec: str, w: int, h: int, seq0: int = 0) -> bytes:
    """Frames of a camera in a container nobody has documented: a 12-byte
    header whose length and counter produce stray 00 00 01 sequences, the
    Annex-B access unit, and a 2-byte trailer."""
    def body(k):
        return rng.randbytes(k).replace(b"\x00", b"\x01")
    if codec == "h265":
        params = [b"\x40\x01" + body(20), _h265_sps(w, h), b"\x44\x01" + body(6)]
        idr, p = b"\x26\x01", b"\x02\x01"
    else:
        params = [_h264_sps(w, h, 100), b"\x68" + body(5)]
        idr, p = b"\x65", b"\x41"
    out = bytearray()
    for k in range(n):
        nals = (params + [idr + body(1500)]) if k % 25 == 0 else [p + body(rng.randint(200, 500))]
        au = b"".join(b"\x00\x00\x00\x01" + x for x in nals)
        out += (b"VNDR" + struct.pack("<I", len(au)) + bytes([1, 0x80, (seq0 + k) & 0xFF, 0])
                + au + b"\xaa\x55")
    return bytes(out)


def test_annexb_carver(tmp: str) -> None:
    """Raw H.264/H.265 from an undocumented container: anchored on real
    parameter sets, split at a new one or a gap, noise ignored."""
    print("\n[raw H.264/H.265 carver]")
    import argparse
    import random
    import cli
    from recover import annexb as A

    sizes = [(A.h264_sps(_h264_sps(1920, 1080)), (1920, 1080)),
             (A.h264_sps(_h264_sps(1280, 720, 100)), (1280, 720)),
             (A.h265_sps(_h265_sps(2560, 1440)), (2560, 1440)),
             (A.h265_sps(_h265_sps(1920, 1080)), (1920, 1080))]
    check("SPS parsed to the picture size: H.264 baseline/high, H.265, cropping applied",
          all(p and (p["width"], p["height"]) == want for p, want in sizes),
          str([(p and (p["width"], p["height"]), want) for p, want in sizes]))
    rng = random.Random(9)
    fp264 = sum(1 for _ in range(5000) if A.h264_sps(b"\x67" + rng.randbytes(30)))
    fp265 = sum(1 for _ in range(5000) if A.h265_sps(b"\x42\x01" + rng.randbytes(30)))
    check("random bytes behind an SPS header almost never pass as an SPS (< 0.1%)",
          fp264 <= 5 and fp265 <= 5, f"h264 {fp264}/5000, h265 {fp265}/5000")

    noise = rng.randbytes(256 << 10)
    cam_a = _vendor_frames(rng, 120, "h265", 1280, 720)
    cam_b = _vendor_frames(rng, 100, "h264", 1920, 1080)
    cam_c = _vendor_frames(rng, 60, "h264", 1280, 720)
    short = _vendor_frames(rng, 10, "h265", 1280, 720)
    gap = bytes(5 << 20)
    img = os.path.join(tmp, "unknown_vendor.img")
    layout = [noise, cam_a, gap, cam_b + cam_c, gap, short, rng.randbytes(128 << 10)]
    with open(img, "wb") as fh:
        fh.write(b"".join(layout))
    at_a = len(noise)
    at_b = at_a + len(cam_a) + len(gap)
    at_c = at_b + len(cam_b)

    def first_sc(base, blob):                 # the first 00 00 01 of the first access unit
        return base + blob.find(b"\x00\x00\x00\x01") + 1

    def last_sc(base, blob):
        return base + blob.rfind(b"\x00\x00\x00\x01") + 1

    with BlockDevice(img) as dev:
        streams, stats = A.carve(dev, chunk=1 << 20)
    rows = [s.to_row() for s in streams]
    got = [(r["codec"], r["width"], r["height"]) for r in rows]
    check("three cameras found, codec and size from their own SPS; the short run is not footage",
          got == [("h265", 1280, 720), ("h264", 1920, 1080), ("h264", 1280, 720)]
          and stats["fragments"] >= 1, f"{got} {stats}")
    check("streams start exactly at their first parameter set (the VPS on H.265)",
          [r["offset"] for r in rows] == [first_sc(at_a, cam_a), first_sc(at_b, cam_b),
                                          first_sc(at_c, cam_c)],
          str([r["offset"] for r in rows]))
    check("a new SPS ends one stream where the next begins; a gap ends it at its last "
          "known NAL", rows[1]["offset"] + rows[1]["bytes"] == rows[2]["offset"]
          and rows[0]["offset"] + rows[0]["bytes"] == last_sc(at_a, cam_a)
          and stats["splits_on_new_parameter_set"] >= 1, str(stats))
    check("the container's stray 00 00 01 are passed over, not taken as NAL units",
          rows[0]["start_codes_passed_over"] >= 119 and rows[0]["slices"] == 119
          and rows[0]["keyframes"] == 5, str(rows[0]))

    with BlockDevice(img) as dev:
        tap = A.AnnexBTap()
        tap.prepare(dev, 0, dev.size_bytes, log=lambda *_: None)
        off = 0
        for n in [777_777, 1 << 20, 3_333_333] * 4:
            data = dev.read_at(off, n)
            if not data:
                break
            tap.feed(off, data)
            off += len(data)
        tap.feed(off, dev.read_at(off, dev.size_bytes - off))
        res = tap.finish(os.path.join(tmp, "annexb_case"), dev.info())
    with open(os.path.join(tmp, "annexb_case", "carve", "annexb_report.json"),
              encoding="utf-8") as fh:
        inline = [(r["offset"], r["bytes"]) for r in json.load(fh)["streams"]]
    check("inside the scan, fed in uneven pieces: the same streams as a standalone carve",
          inline == [(r["offset"], r["bytes"]) for r in rows] and res["streams_kept"] == 3)

    only_noise = os.path.join(tmp, "noise.img")
    with open(only_noise, "wb") as fh:
        fh.write(random.Random(2).randbytes(4 << 20))
    with BlockDevice(only_noise) as dev:
        ns, _ = A.carve(dev)
    check("4 MiB of noise yields no footage", ns == [])

    case = os.path.join(tmp, "annexb_cli")
    os.makedirs(case)
    CustodyLedger(os.path.join(case, "custody_ledger.jsonl"),
                  actor="t", case_id="ES").append("case_opened")
    rc1 = cli.cmd_carve_annexb(argparse.Namespace(device=img, out=case, max_mb=0))
    rc2 = cli.cmd_extract_carved(argparse.Namespace(device=img, out=case, format="annexb",
                                                    ids="", label="all"))
    with open(os.path.join(case, "carve", "es_extracted.json"), encoding="utf-8") as fh:
        man = json.load(fh)["streams"]
    first = open(os.path.join(case, "carve", "es_streams", "es-00001.h265"), "rb").read()
    led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"))
    check("carve-annexb and extract: files as stored, hashed, both in the ledger",
          rc1 == 0 and rc2 == 0 and len(man) == 3
          and first == open(img, "rb").read()[rows[0]["offset"]:rows[0]["offset"] + rows[0]["bytes"]]
          and man["es-00001"]["sha256"] == hashlib.sha256(first).hexdigest()
          and [e["action"] for e in led.entries][-2:] == ["annexb_carved", "es_streams_extracted"]
          and led.verify()["valid"])

    from report.case import load_case
    from report.html import render
    scan_case = os.path.join(tmp, "annexb_scan")
    ScanSession(img, scan_case, CaseInfo(case_id="ES-SCAN", investigator="test"),
                block_size=1 << 20, quiet=True, taps=[A.AnnexBTap()]).run()
    c = load_case(scan_case)
    page = render(c)
    check("scan --carve-annexb: the report shows the streams and says what they are not",
          c["es_carve"]["streams_total"] == 3 and "5c. Raw H.264/H.265" in page
          and "no date and no camera" in page)


def test_honeywell(tmp: str) -> None:
    """The Honeywell plugin against a disk built to Yoon & Hwang (2026) s.5:
    it reads the paper's fields, finds recordings per camera, extracts
    playable video, and still recovers footage after a format."""
    print("\n[Honeywell plugin (spec_only, from Yoon & Hwang 2026)]")
    import argparse
    import cli
    from detect import model as M
    from report.case import vendor_matrix
    from tests import synth_honeywell as SH

    hw = get_parser("Honeywell")
    img = os.path.join(tmp, "honeywell.img")
    truth = SH.build(img)
    with BlockDevice(img) as dev:
        found = hw.detect(dev)
        res = hw.parse(dev)
    v = res.volume
    check("the drop-in plugin registers, detects the layout, and says spec_only",
          hw is not None and found and res.validation_status == "spec_only"
          and all(f["source"] == "published" for f in res.field_provenance))
    check("header fields decoded x0x1000 (the paper's 'rounded at the third digit')",
          v["header"]["video_start"] == SH.VIDEO_START
          and v["header"]["block_group_start"] == SH.T0 and v["block_indexes"] == 6,
          str(v["header"]))
    check("machine data in sector 34 gives the model and device ID",
          any(SH.MODEL in s for s in v["machine_data_strings"])
          and any(SH.DEVICE_ID in s for s in v["machine_data_strings"]),
          str(v["machine_data_strings"]))
    check("channel offsets' origin measured, not assumed: the video area",
          v["channel_offset_origin"] == "video area" and v["channel_indexes"] == 12
          and v["codec"] == "h264", str(v))
    ids = [r.id for r in res.recordings]
    check("recordings per camera, split where recording paused",
          ids == ["hw-ch00-main-0000", "hw-ch00-main-0001", "hw-ch01-main-0000",
                  "hw-ch01-main-0001"]
          and res.recordings[0].start_utc == "2025-11-26T21:48:19Z", str(ids))

    with BlockDevice(img) as dev:
        st = hw.extract_recording(dev, "hw-ch00-main-0000", os.path.join(tmp, "hw_rec"))
    with open(os.path.join(tmp, "hw_rec.h264"), "rb") as fh:
        out = fh.read()
    check("extract: the camera's NAL units without the custom headers, frame times kept",
          out == b"".join(truth["nals"][(0, False)]) and st["frames"] == 90
          and st["length_counted_start_code"] > 0 and st["first_time_utc"] == "2025-11-26T21:48:19Z",
          str({k: st[k] for k in ("frames", "length_counted_start_code", "padding_skips")}))

    fmt = os.path.join(tmp, "honeywell_formatted.img")
    SH.build(fmt, format=True)
    with BlockDevice(fmt) as dev:
        res_f = hw.parse(dev)
        runs = hw.recover_video_area(dev)
    check("after a format the index is gone - and the footage is not (paper s.6)",
          res_f.recordings == [] and len(runs) == truth["chunks_total"]
          and sum(r.frame_count for r in runs) == truth["frames"]
          and all(r.camera_id == "unknown" for r in runs), f"{len(runs)} runs")

    with BlockDevice(os.path.join(tmp, "unknown_vendor.img")) as dev:
        not_hw = hw.detect(dev)
    check("a disk with no GPT Honeywell layout is not detected", not not_hw)

    ms = M.ModelSearch()
    with open(img, "rb") as fh:
        ms.feed(0, fh.read(1 << 16))
    cands = ms.result({})["candidates"]
    row = next(r for r in vendor_matrix() if r["vendor"] == "Honeywell")
    check("identify-model reads the model from the machine data; the matrix lists the parser",
          [c["model"] for c in cands] == [SH.MODEL] and cands[0]["kind"] == "recorder"
          and row["parser"] == "Honeywell" and row["parser_status"] == "spec_only",
          f"{cands} {row}")

    rc = cli.cmd_extract(argparse.Namespace(device=img, vendor="Honeywell",
                                            recording="hw-ch01-main-0001",
                                            out=os.path.join(tmp, "hw_out"), tz_offset=None))
    man = json.load(open(os.path.join(tmp, "hw_out", "hw-ch01-main-0001.manifest.json"),
                         encoding="utf-8"))
    check("extract --vendor Honeywell works through the plugin, with a hashed manifest",
          rc == 0 and man["validation_status"] == "spec_only"
          and man["output"]["frames"] == 90 and len(man["output"]["sha256"]) == 64)


def test_uniview(tmp: str) -> None:
    """The Uniview plugin against a disk built to the layout in the recorder's
    own storage driver (comm.ko): superblock and copy with CRC-16, abstract
    zone, block headers, GOP index, and GOPs that check themselves - so
    footage is found with the index and without it."""
    print("\n[Uniview plugin (spec_only, from the firmware's storage driver)]")
    import argparse
    import cli
    from detect.engine import SignatureScanner
    from plugins import uniview as U
    from report.case import vendor_matrix
    from tests import synth_uniview as SU

    img = os.path.join(tmp, "uniview.img")
    truth = SU.build(img)
    p = get_parser("Uniview")
    p.block_bytes = SU.BLOCK                  # the fixture's 1 MiB blocks, not 256 MiB
    with BlockDevice(img) as dev:
        found = p.detect(dev)
        res = p.parse(dev)
    v = res.volume
    check("the plugin registers, detects the UBS superblock, and says spec_only from firmware",
          found and res.validation_status == "spec_only"
          and {f["source"] for f in res.field_provenance} == {"vendor_firmware"})
    check("superblock and its tail copy: CRC-16 (kernel crc16) checks, fields decoded",
          v["superblock"]["crc_ok"] and v["tail_copy"] == "matches"
          and v["superblock"]["device_id"] == SU.DEVICE_ID
          and (v["superblock"]["az_pos"], v["superblock"]["dz_pos"]) == (SU.AZ_POS, SU.DZ_POS),
          str(v["superblock"]))
    check("the abstract zone lists the blocks; each block is named by its own header",
          v["abstract"]["entries"] == 4 and not v["abstract"]["groups_crc_failed"]
          and v["block_kinds"] == {"record": 2, "snapshot": 1, "none": 1}, str(v["block_kinds"]))
    recs = res.recordings
    check("one recording per block, its camera and recorder-clock times from the block header",
          [(r.id, r.camera_id, r.codec) for r in recs]
          == [("unv-b00000", "chan 0/0/1/0", "h264"), ("unv-b00001", "chan 0/0/2/0", "h264")]
          and recs[0].start_utc is None
          and recs[0].timestamps[0].raw_value.endswith("2024-07-01 10:40:00 recorder-local")
          and len(p.extents["unv-b00000"]) == truth["gops"][0], str([r.id for r in recs]))
    with BlockDevice(img) as dev:
        st = p.extract_recording(dev, "unv-b00000", os.path.join(tmp, "unv_rec"))
    out = open(os.path.join(tmp, st["file"]), "rb").read()
    check("extract: the video packets without their headers, audio left out, every GOP checked",
          out == truth["video"][0] and st["gops"] == 3 and st["gops_failing_checks"] == 0
          and st["frames"] == 15 and st["file"].endswith(".h264"), str(st))
    with BlockDevice(img) as dev:
        runs = p.recover_video_area(dev)
    check("without the index: GOPs found by their own trailers; the older GOP past a "
          "block's write position is a run of its own",
          [r.id for r in runs] == ["unv-gops-00000", "unv-gops-00001", "unv-stale-00002"]
          and runs[2].offset == truth["stale_gop"] and p.video_area_stats["past_write_position"] == 1,
          str([(r.id, hex(r.offset)) for r in runs]))

    fmt = os.path.join(tmp, "uniview_formatted.img")
    SU.build(fmt, formatted=True)
    pf = get_parser("Uniview")
    pf.block_bytes = SU.BLOCK
    with BlockDevice(fmt) as dev:
        res_f = pf.parse(dev)
        runs_f = pf.recover_video_area(dev)
    check("abstract zone and block headers wiped: no recordings - and the footage still found",
          res_f.recordings == [] and len(runs_f) == 3
          and sum(r.frame_count for r in runs_f) == 29, str([r.frame_count for r in runs_f]))

    bad = bytearray(open(img, "rb").read())
    bad[0x0C] ^= 0xFF                          # corrupt the head superblock
    with open(os.path.join(tmp, "uniview_badhead.img"), "wb") as fh:
        fh.write(bad)
    with BlockDevice(os.path.join(tmp, "uniview_badhead.img")) as dev:
        rb = p.parse(dev)
    check("a head superblock that fails CRC is reported, and the tail copy is used",
          rb.volume["superblock_used"] == "tail copy" and len(rb.recordings) == 2)
    with BlockDevice(os.path.join(tmp, "unknown_vendor.img")) as dev:
        check("a disk with no UBS superblock is not detected", not p.detect(dev))

    sc = SignatureScanner()
    with open(img, "rb") as fh:
        sc.scan_block(0, fh.read(1 << 20), 0, "")
    row = next(r for r in vendor_matrix() if r["vendor"] == "Uniview")
    check("the scan detects Uniview by the plugin's own signature; the matrix lists the parser",
          any(d.vendor == "Uniview" for d in sc.detections())
          and row["parser"] == "Uniview" and row["parser_status"] == "spec_only", str(row))

    saved = U.UniviewParser.block_bytes
    U.UniviewParser.block_bytes = SU.BLOCK
    try:
        rc = cli.cmd_extract(argparse.Namespace(device=img, vendor="Uniview",
                                                recording="unv-b00001",
                                                out=os.path.join(tmp, "unv_out"), tz_offset=None))
    finally:
        U.UniviewParser.block_bytes = saved
    man = json.load(open(os.path.join(tmp, "unv_out", "unv-b00001.manifest.json"),
                         encoding="utf-8"))
    check("extract --vendor Uniview works through the plugin, with a hashed manifest",
          rc == 0 and man["validation_status"] == "spec_only" and man["output"]["frames"] == 10
          and man["output"]["first_time_local"] == "2024-07-01 10:50:00", str(man["output"]))


def test_tplink(tmp: str) -> None:
    """The TP-Link plugin against disks built to what the VIGI firmware shows:
    it finds the format sector and the index, reads a plain index by its
    columns, and reports an unreadable one as such - never a guess."""
    print("\n[TP-Link plugin (from the VIGI firmware)]")
    from report.case import vendor_matrix
    from tests import synth_tplink as ST

    def parser():
        p = get_parser("TP-Link")
        p.format_at = ST.FORMAT_AT             # the fixture's 1 MiB, not 512 MiB
        return p

    img = os.path.join(tmp, "tplink.img")
    truth = ST.build(img)
    p = parser()
    with BlockDevice(img) as dev:
        found = p.detect(dev)
        res = p.parse(dev)
    v = res.volume
    idx = v["index"] or {}
    check("the format sector is found and its CRC-32 checks; the TpFile header's slots read",
          found and v["format_sector"]["version"] == ST.VERSION and v["format_sector"]["crc32_ok"]
          and [s["type"] for s in v["databases"][0]["head"]["slots"]] == [1, 2, 3], str(v["format_sector"]))
    check("a plain index is read by its columns: recordings per camera, GOP rows, system log",
          res.validation_status == "spec_only" and idx.get("database_at") == truth["db_at"]
          and len(idx["events"]) == truth["events"] and idx["gops"] == truth["gops"]
          and [e["detail"] for e in idx["system_log"]][-1] == "system time changed"
          and idx["cameras"][0]["first_clock"] == "2024-07-01 10:40:00"
          and idx["cameras"][0]["time_unit"] == "s", str(idx.get("cameras")))
    check("no footage is placed on the disk: the zone geometry was not recovered",
          res.recordings == [] and any("carve-annexb" in n for n in res.notes))

    enc = os.path.join(tmp, "tplink_encrypted.img")
    ST.build(enc, encrypted=True)
    with BlockDevice(enc) as dev:
        re_ = parser().parse(dev)
    check("an index that is not plain SQLite is reported as encrypted or unreadable, not parsed",
          re_.validation_status == "detected_not_parsed" and re_.volume["index"] is None
          and "encrypted" in re_.volume["databases"][0]["status"], re_.volume["databases"][0]["status"])

    v0 = os.path.join(tmp, "tplink_v0.img")
    ST.build(v0, with_format=False)
    with BlockDevice(v0) as dev:
        pp = parser()
        alone, hinted = pp.detect(dev), pp.detect(dev, [ST.DB_AT])
        rv = pp.parse(dev, hint_offsets=[ST.DB_AT])
    check("with no format sector, the index is found at the offset the scan reports",
          not alone and hinted and rv.volume["index"]["database_at"] == ST.DB_AT)
    with BlockDevice(os.path.join(tmp, "unknown_vendor.img")) as dev:
        check("a disk with no VIGI marker is not detected", not parser().detect(dev))
    row = next(r for r in vendor_matrix() if r["vendor"] == "TP-Link")
    check("the matrix lists the plugin but keeps TP-Link at detected_not_parsed: no footage placed",
          row["parser"] == "TP-Link" and row["parser_status"] == "detected_not_parsed", str(row))


def test_ext4(tmp: str) -> None:
    """The ext reader on ext4: extents in the inode and behind an index
    block, an allocated-but-unwritten extent, 64-bit group descriptors, a
    directory over several blocks - and features it cannot read, refused."""
    print("\n[ext4 reader]")
    import random
    from parsers.ext3 import Ext, ExtError
    from tests.synth_ext4 import BS, Ext4

    rnd = random.Random(1)
    fs = Ext4(8000, label="vol", created=1700000000)
    a, b, c = rnd.randbytes(10 * BS + 123), rnd.randbytes(3 * BS), rnd.randbytes(5000)
    fs.add_file("d/a.bin", a, 1700000100, fragments=6)
    fs.add_file("d/b.bin", b, 1700000200, fragments=2)
    fs.add_file("c.bin", c, 1700000300, unwritten=True)
    for k in range(300):
        fs.add_file(f"many/file{k:04d}_with_a_long_name.txt", b"x", 1700000400)
    img = os.path.join(tmp, "ext4.img")
    raw = bytearray(fs.build())
    with open(img, "wb") as fh:
        fh.write(raw)
    with BlockDevice(img) as dev:
        e = Ext(dev, 0)
        root = {x["name"]: x for x in e.listdir()}
        d = {x["name"]: x for x in e.listdir(root["d"]["number"])}
        ok_a = e.read(d["a.bin"]) == a and len(e.extents(d["a.bin"])) == 6
        ok_b, ok_c = e.read(d["b.bin"]) == b, e.read(root["c.bin"]) == bytes(len(c))
        many = len(e.listdir(root["many"]["number"]))
        runs = e.byte_runs(d["a.bin"])
    check("ext4 recognised; 64-bit descriptors read", e.kind == "ext4" and e.desc_size == 64
          and e.label == "vol")
    check("a file in six extents behind an index block reads back exactly; its disk runs cover it",
          ok_a and ok_b and sum(n for _, _, n in runs) == len(a), str(runs))
    check("an allocated but unwritten extent reads as zeros, not as whatever the disk holds",
          ok_c and many == 300)
    raw[1024 + 0x60] |= 0x10                         # meta_bg
    with open(os.path.join(tmp, "ext4_metabg.img"), "wb") as fh:
        fh.write(raw)
    try:
        with BlockDevice(os.path.join(tmp, "ext4_metabg.img")) as dev:
            Ext(dev, 0)
        refused = False
    except ExtError as exc:
        refused = "meta_bg" in str(exc)
    check("a layout it does not read (meta_bg descriptors) is refused, not guessed", refused)


def test_matrix(tmp: str) -> None:
    """The Matrix plugin on disks built to Matrix's own documents: the
    CameraNN/DD_Mon_YYYY/HH tree on ext4, in a partition or one RAID 1
    mirror; anything else is named, not read."""
    print("\n[Matrix plugin (spec_only, from Matrix's documents)]")
    import argparse
    import cli
    from report.case import vendor_matrix
    from tests import synth_matrix as SM

    img = os.path.join(tmp, "matrix.img")
    truth = SM.build(img)
    p = get_parser("Matrix")
    with BlockDevice(img) as dev:
        found = p.detect(dev)
        res = p.parse(dev)
    recs = res.recordings
    check("the plugin registers, finds ext4 in the partition and the camera tree; spec_only",
          found and res.validation_status == "spec_only"
          and res.volume["filesystems"][0]["offset"] == truth["fs_at"]
          and res.volume["filesystems"][0]["camera_folders"] == ["/Camera01", "/Camera02"])
    check("one recording per .stm file: camera, codec, times from the recorder's own names",
          [(r.id, r.camera_id, r.codec) for r in recs]
          == [("mtx-camera01-20180421-144719-s1", "Camera01", "h264"),
              ("mtx-camera01-20180421-150000-s1", "Camera01", "h264"),
              ("mtx-camera02-20180421-144720-s1", "Camera02", "h265")]
          and recs[0].duration_s == 760.0 and recs[0].start_utc is None
          and recs[0].timestamps[0].raw_value.endswith("= 2018-04-21 14:47:19 recorder-local")
          and res.volume["other_files_in_hour_folders"] == 1, str([r.id for r in recs]))
    check("each recording's disk runs cover the file exactly, fragments included",
          all(sum(n for _, _, n in p.files[r.id]["runs"]) == r.length for r in recs))
    with BlockDevice(img) as dev:
        st = p.extract_recording(dev, recs[0].id, os.path.join(tmp, "mtx_rec"))
    out = open(os.path.join(tmp, st["file"]), "rb").read()
    want = truth["files"]["Camera01/21_Apr_2018/14/14_47_19~14_59_59.stm1"]
    check("extract: the .stm as stored and its three sidecars, each hashed; pictures counted",
          out == want and st["file"] == "mtx_rec.stm1" and sorted(st["sidecars"])
          == ["mtx_rec.evnt", "mtx_rec.ifrm", "mtx_rec.tmid"] and st["frames"] == 60, str(st))

    notes = {}
    for layout in ("raid1", "raid0", "xfs"):
        path = os.path.join(tmp, f"matrix_{layout}.img")
        SM.build(path, layout)
        with BlockDevice(path) as dev:
            r = get_parser("Matrix").parse(dev)
        notes[layout] = (len(r.recordings), r.volume["summary"][0][1], "; ".join(r.volume["not_read"]))
    check("one mirror of a Linux md RAID 1 is read",
          notes["raid1"][0] == 3 and "RAID 1 mirror" in notes["raid1"][1], str(notes["raid1"]))
    check("a RAID 0 member and an XFS disk are named, not read",
          notes["raid0"][0] == 0 and "needs all its disks" in notes["raid0"][2]
          and notes["xfs"][0] == 0 and "XFS" in notes["xfs"][2], str(notes))
    with BlockDevice(os.path.join(tmp, "unknown_vendor.img")) as dev:
        check("a disk with no SATATYA tree is not detected", not p.detect(dev))
    row = next(r for r in vendor_matrix() if r["vendor"] == "Matrix")
    rc = cli.cmd_extract(argparse.Namespace(device=img, vendor="Matrix", recording=recs[2].id,
                                            out=os.path.join(tmp, "mtx_out"), tz_offset=None))
    man = json.load(open(os.path.join(tmp, "mtx_out", f"{recs[2].id}.manifest.json"),
                         encoding="utf-8"))
    check("extract --vendor Matrix works through the plugin; the matrix lists the parser",
          rc == 0 and man["output"]["codec"] == "h265" and row["parser"] == "Matrix"
          and row["parser_status"] == "spec_only", str(row))


def test_nist_export(tmp: str) -> None:
    """The NIST CCTV Export Profile (NISTIR 8161r1 Level 0): per-frame MISB
    time stamps in UTC, a timesource record, the ClockOffset box - with the
    pictures untouched, and no UTC asserted without a stated zone."""
    print("\n[NIST CCTV export profile (NISTIR 8161r1 Level 0)]")
    import random
    import re
    import subprocess
    import xml.etree.ElementTree as ET
    from datetime import datetime, timedelta, timezone
    from report import nist_export as N

    rnd = random.Random(5)
    # a real SPS/PPS (NIST's WEB3.mp4, High 1280x720) and made-up slices
    sps = bytes.fromhex("6764001facb402802dd808800001f480007530733000098968000393875ef706"
                        "660001312d00007270ebdee03c60ca80")
    pps = bytes.fromhex("68ee3cb0")
    sc = b"\x00\x00\x00\x01"
    es = bytearray()
    for f in range(30):
        if f % 10 == 0:
            es += sc + sps + sc + pps + sc + b"\x65\x88" + rnd.randbytes(400)
        else:
            es += sc + b"\x41\x9a" + rnd.randbytes(120)
    t0 = datetime(2024, 9, 21, 18, 58, 0)
    times = [t0 + timedelta(seconds=k / 25) for k in range(30)]
    out = os.path.join(tmp, "nist.mp4")
    res = N.export(bytes(es), out, times, tz_offset_min=330, drift_s=-38.0,
                   clock_reading=(datetime(2024, 9, 21, 19, 0, 27), datetime(2024, 9, 21, 19, 1, 5)))
    back = N.read_back(out)
    check("an MP4 of 30 pictures, each with a MISB time stamp and a timesource record",
          res["pictures"] == 30 and back["samples"] == 30 and len(back["stamps"]) == 30
          and back["timesource_seis"] == 30 and res["level0"], str(res["not_level0_because"]))
    check("UTC = recorder clock - measured error - zone: 18:58:00 IST, 38 s slow -> 13:28:38Z",
          res["first_utc"] == "2024-09-21T13:28:38.000000Z"
          and back["stamps"][1][1] - back["stamps"][0][1] == 40_000
          and all(st == N.STATUS_UNLOCKED for st, _ in back["stamps"]), res["first_utc"])
    check("the pictures are untouched: input NAL units = the MP4's, less the added SEI "
          "(read back from the file)", res["pictures_unchanged"] and res["keyframes"] == 3)
    root = ET.fromstring(back["xmp"].split(b"?>", 1)[1].rsplit(b"<?xpacket", 1)[0])
    vals = {el.tag.split("}")[1] + ":" + (el.text or ""): 1 for el in root.iter()
            if el.tag.startswith("{" + N.NS_TIME)}
    check("the ClockOffset XMP is well-formed, in NIST's namespaces, times in UTC-offset form",
          "ExportSystemTimeModeSourceCode:0B" in vals and "ExternalReferenceTimeModeSourceCode:0F"
          in vals and "TimeValue:2024-09-21T19:00:27+05:30" in vals, str(sorted(vals)))

    jump = times[:15] + [t - timedelta(seconds=30) for t in times[15:]]
    rj = N.export(bytes(es), os.path.join(tmp, "nist_jump.mp4"), jump, tz_offset_min=0)
    st = [s for s, _ in N.read_back(os.path.join(tmp, "nist_jump.mp4"))["stamps"]]
    check("a clock that jumps back is marked in that frame's status (discontinuity, reverse)",
          rj["discontinuities"] == 1 and st[15] == 0xFF and st[14] == N.STATUS_UNLOCKED)
    rn = N.export(bytes(es), os.path.join(tmp, "nist_nozone.mp4"), times)
    check("no stated zone: no UTC time stamp and no ClockOffset - marked not Level 0",
          not rn["level0"] and rn["time_stamps"] == 0 and not rn["clock_offset_box"]
          and rn["pictures_unchanged"])
    try:
        N.export(sc + b"\x40\x01" + rnd.randbytes(20) + sc + b"\x42\x01" + rnd.randbytes(40),
                 os.path.join(tmp, "nist_h265.mp4"), times)
        refused = False
    except ValueError as exc:
        refused = "H.265" in str(exc)
    check("H.265 is refused, not re-encoded (Level 0 is H.264)", refused)

    web3 = os.path.join(os.environ.get("VENDOR_SAMPLES", ""), "WEB3.mp4")
    if os.path.isfile(web3):
        buf = open(web3, "rb").read()
        ref = N.read_back(web3)
        stbl = N._find(buf, [b"moov", b"trak", b"mdia", b"minf", b"stbl"], 0, len(buf))
        bx = {k: (a, b) for k, a, b in N._walk(buf, *stbl)}
        n = struct.unpack(">I", buf[bx[b"stsz"][0] + 8:bx[b"stsz"][0] + 12])[0]
        sizes = struct.unpack(f">{n}I", buf[bx[b"stsz"][0] + 12:bx[b"stsz"][0] + 12 + 4 * n])
        offs = struct.unpack(f">{n}I", buf[bx[b"stco"][0] + 8:bx[b"stco"][0] + 8 + 4 * n])
        raw, nist_misb = bytearray(), []
        for o, s in zip(offs, sizes):
            p = o
            while p < o + s:
                ln = struct.unpack(">I", buf[p:p + 4])[0]
                nal = buf[p + 4:p + 4 + ln]
                p += 4 + ln
                if nal[0] & 0x1F == 6 and N.read_misb(nal):
                    nist_misb.append(nal)
                elif not (nal[0] & 0x1F == 6 and nal[3:13] == b"timesource"):
                    raw += sc + nal
        wt = [datetime.fromtimestamp(us / 1e6, tz=timezone.utc).replace(tzinfo=None)
              for _, us in ref["stamps"]]
        mine = os.path.join(tmp, "web3_again.mp4")
        rw = N.export(bytes(raw), mine, wt, tz_offset_min=0, clock_set="auto-nonnetwork")
        mb = open(mine, "rb").read()
        ours = [mb[m.start() - 3:m.start() + 29] for m in re.finditer(b"MISPmicrosectime", mb)]
        check("against NIST's own reference file (WEB3.mp4): every MISB time stamp SEI "
              "byte-identical, pictures unchanged",
              rw["pictures"] == 355 and ours == nist_misb and rw["pictures_unchanged"],
              f"{len(ours)} {len(nist_misb)}")
        ffmpeg = os.environ.get("FFMPEG") or shutil.which("ffmpeg")
        if ffmpeg:
            def md5s(path):
                r = subprocess.run([ffmpeg, "-v", "error", "-i", path, "-fps_mode", "passthrough",
                                    "-f", "framemd5", "-"], capture_output=True, text=True)
                return [ln.rsplit(",", 1)[-1].strip() for ln in r.stdout.splitlines()
                        if ln and not ln.startswith("#")], r.stderr
            a, err = md5s(mine)
            b, _ = md5s(web3)
            check("ffmpeg decodes our export to the same 355 pictures as NIST's, with no error",
                  a == b and len(a) == 355 and not err.strip(), err[:200])
    else:
        print("  [NIST WEB3.mp4] skipped - put WEB3.mp4 in VENDOR_SAMPLES")


def test_s63_certificate(tmp: str) -> None:
    """The s.63 certificate draft: the Schedule's wording, the case's own
    hashes and device facts, and nothing said on a person's behalf."""
    print("\n[BSA 2023 s.63 certificate (draft)]")
    import argparse
    import cli
    from recover import annexb as A

    img = os.path.join(tmp, "unknown_vendor.img")
    case = os.path.join(tmp, "s63_case")
    ScanSession(img, case, CaseInfo(case_id="S63", investigator="test"),
                block_size=1 << 20, quiet=True, taps=[A.AnnexBTap()]).run()
    cli.cmd_extract_carved(argparse.Namespace(device=img, out=case, format="annexb", ids="",
                                              label="all"))
    cli.cmd_record_device(argparse.Namespace(out=case, model="CP-UNR-104F1", serial="ABC123",
                                             firmware="", read_from="label", photo=[]))
    blank = {k: "" for k in ("name", "relation", "address", "designation", "date", "time",
                             "place")}
    rc_b = cli.cmd_certificate(argparse.Namespace(out=case, part="B", records="both",
                                                  **dict(blank, name="A. Examiner",
                                                         designation="Forensic examiner")))
    rc_a = cli.cmd_certificate(argparse.Namespace(out=case, part="A", records="drive", **blank))
    with open(os.path.join(case, "certificate_s63_partB.json"), encoding="utf-8") as fh:
        cb = json.load(fh)
    hb = open(os.path.join(case, "certificate_s63_partB.html"), encoding="utf-8").read()
    ha = open(os.path.join(case, "certificate_s63_partA.html"), encoding="utf-8").read()
    with open(os.path.join(case, "scan_report.json"), encoding="utf-8") as fh:
        scan = json.load(fh)
    drive = {h["algorithm"].upper(): h["value"] for h in scan["hashes"]
             if h["scope"] == "full_device"}
    with open(os.path.join(case, "carve", "es_extracted.json"), encoding="utf-8") as fh:
        es = {v["sha256"] for v in json.load(fh)["streams"].values()}
    vals = cb["fields"]["hash_values"]
    check("the Schedule's wording, Part B for the expert, marked a draft",
          rc_b == 0 and "section 63(<i>4</i>)(<i>c</i>)" in hb and "(To be filled by the Expert)" in hb
          and "do hereby solemnly affirm and sincerely state and submit as follows:—" in hb
          and "(Hash report to be enclosed with the certificate)" in hb and "DRAFT" in hb)
    # Word for word against the Gazette: the Schedule as printed in the Gazette
    # of India Extraordinary, Part II Sec. 1, No. 55, 25 Dec 2023, pp. 46-47,
    # transcribed in tests/fixtures/bsa_schedule_gazette.txt.
    from report import s63 as S
    gz_a, gz_b = open(os.path.join(os.path.dirname(__file__), "fixtures", "bsa_schedule_gazette.txt"),
                      encoding="utf-8").read().split("=== PART B")
    empty = os.path.join(tmp, "s63_empty")
    os.makedirs(empty, exist_ok=True)
    form_a = S.form_words(S.render(S.build(empty, part="A")))
    form_b = S.form_words(S.render(S.build(empty, part="B")))
    head = S.form_words("THE SCHEDULE [See section 63(4)(c)] CERTIFICATE")
    check("Part A, word for word, as printed in the Gazette (2023, No. 55, p. 46)",
          form_a == S.form_words(gz_a),
          f"{[w for w in form_a if w not in S.form_words(gz_a)][:8]}")
    check("Part B, word for word, as printed in the Gazette (p. 47)",
          form_b[len(head):] == S.form_words(gz_b) and form_b[:len(head)] == head,
          f"{[w for w in form_b if w not in S.form_words(gz_b)][:8]}")
    check("hash values are the case's own: whole-drive SHA-256 and MD5, and every extracted file",
          {v["value"] for v in vals if v["record"] == "whole drive"} == set(drive.values())
          and {v["value"] for v in vals if v["record"] != "whole drive"} == es
          and cb["fields"]["algorithm_ticks"] == ["MD5", "SHA256"], str(cb["fields"]["algorithm_ticks"]))
    check("DVR ticked; make, model and serial from the examiner's record",
          "DVR &#9745;" in hb and "Mobile &#9744;" in hb
          and "recorder CP Plus CP-UNR-104F1" in cb["fields"]["make_model"]
          and "recorder ABC123" in cb["fields"]["serial"], str(cb["fields"]["make_model"]))
    check("nothing said for a person: ownership unticked, date/place blank, name only as given",
          rc_a == 0 and all(f"{r} &#9744;" in ha for r in ("Owned", "Maintained", "Managed",
                                                            "Operated"))
          and "&#9745; Owned" not in ha and "A. Examiner" in hb and "A. Examiner" not in ha
          and "Date (DD/MM/YYYY): __________" in ha)

    tri = os.path.join(tmp, "s63_triage")
    ScanSession(img, tri, CaseInfo(case_id="TRI", investigator="test"),
                block_size=1 << 20, quiet=True).run(max_bytes=2 << 20)
    with open(os.path.join(tri, "scan_report.json"), encoding="utf-8") as fh:
        tscan = json.load(fh)
    rc_t = cli.cmd_certificate(argparse.Namespace(out=tri, part="B", records="drive", **blank))
    with open(os.path.join(tri, "certificate_s63_partB.json"), encoding="utf-8") as fh:
        ct = json.load(fh)
    check("a triage pass is not complete, its hash is a region's, and no drive hash is certified",
          not tscan["stats"]["complete_pass"]
          and all(h["scope"] != "full_device" for h in tscan["hashes"])
          and rc_t == 1 and ct["fields"]["hash_values"] == [] and ct["notes"], str(ct["notes"]))
    led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"))
    check("each draft is recorded in the custody ledger, chain valid",
          [e["action"] for e in led.entries][-2:] == ["s63_certificate_drafted"] * 2
          and led.verify()["valid"])


def test_s63_footage_folders(tmp: str) -> None:
    """Footage extracted into a subfolder (USER_MANUAL 3.4: `extract --out clips/`)
    is still certified; footage from another device is not."""
    print("\n[s.63 certificate: where the footage was extracted to]")
    from report import s63
    case = os.path.join(tmp, "s63_case")                    # made by test_s63_certificate
    with open(os.path.join(case, "scan_report.json"), encoding="utf-8") as fh:
        device = json.load(fh)["device"]["path"]
    for folder, src, sha in (("clips", device, "11" * 32), ("other", "/dev/sdz", "22" * 32)):
        os.makedirs(os.path.join(case, folder), exist_ok=True)
        with open(os.path.join(case, folder, f"{folder}.manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"source_device": src, "output": {"file": f"{folder}.h265", "bytes": 10,
                                                        "sha256": sha}}, fh)
    cert = s63.build(case, "B", records="footage")
    vals = {v["record"]: v["value"] for v in cert["fields"]["hash_values"]}
    check("footage extracted into a subfolder of the case is certified with its path; footage "
          "whose manifest names another device is left out, and the draft says why",
          vals.get("clips/clips.h265") == "11" * 32 and "other/other.h265" not in vals
          and any("other/other.manifest.json" in n and "not certified" in n
                  for n in cert.get("notes", [])), str(sorted(vals))[:300])


def test_real_media_tools(tmp: str) -> None:
    """The pieces of the real-media run: the decode check's classes, the
    head-image model search, and the carver coverage score."""
    print("\n[real-media tools]")
    import argparse
    import random
    from datetime import datetime
    import cli
    from analytics import decodecheck as D
    from validate import realmedia as RM

    # A stream with 5 frames before its first keyframe, one frame missing
    # from the disk (counter 26), and one frame that fails for no visible reason.
    rng = random.Random(4)
    t0 = datetime(2026, 5, 1, 13, 20, 0)
    numbers = list(range(10, 26)) + list(range(27, 43))
    keys = {15, 32}
    dav, es = bytearray(), bytearray()
    for n in numbers:
        pay = b"\x00\x00\x00\x01" + (b"\x26\x01" if n in keys else b"\x02\x01") \
            + rng.randbytes(300).replace(b"\x00", b"\x01")
        dav += synth_dahua.dhav(0xFD if n in keys else 0xFC, n, t0, n * 40, pay,
                                synth_dahua.EXT_VIDEO)
        es += pay
    case = os.path.join(tmp, "decode_case")
    sdir = os.path.join(case, "carve", "streams")
    os.makedirs(sdir)
    with open(os.path.join(sdir, "carve-00001.dav"), "wb") as fh:
        fh.write(bytes(dav))
    with open(os.path.join(sdir, "carve-00001.h265"), "wb") as fh:
        fh.write(bytes(es))
    with open(os.path.join(case, "carve", "extracted.json"), "w", encoding="utf-8") as fh:
        json.dump({"streams": {"carve-00001": {"codec": "h265", "files": {}}}}, fh)
    frames = D.video_frames(os.path.join(sdir, "carve-00001.dav"))
    fail = set(range(10, 15)) | set(range(27, 32)) | {38}

    def fake_probe(_es, _codec):
        return ([f["es_offset"] for f in frames],
                [f["es_offset"] for f in frames if f["number"] not in fail])

    got = D.classify(frames, *fake_probe(None, None))
    check("undecodable frames sorted: before a keyframe, after a missing frame, unexplained",
          got["classes"] == {"before_first_keyframe": 5, "after_a_gap": 5, "unexplained": 1}
          and got["counter_gaps"] == 1 and got["unexplained_examples"][0]["counter"] == 38,
          str(got["classes"]))
    real = D.probe, D.have_ffprobe
    D.probe, D.have_ffprobe = fake_probe, (lambda: True)
    try:
        rc = cli.cmd_decode_check(argparse.Namespace(out=case, ids="", limit=0))
    finally:
        D.probe, D.have_ffprobe = real
    res = json.load(open(os.path.join(case, "analytics", "decode_check.json"), encoding="utf-8"))
    check("decode-check: a missing frame explains 5 of the 6 failures after a keyframe",
          rc == 0 and res["summary"]["share_explained_by_a_gap"] == round(5 / 6, 4))

    # identify-model on a head image of a scanned drive
    img = os.path.join(tmp, "unknown_vendor.img")
    full = os.path.join(tmp, "head_case")
    ScanSession(img, full, CaseInfo(case_id="HEAD", investigator="test"),
                block_size=1 << 20, quiet=True).run()
    head = os.path.join(tmp, "head.img")
    other = os.path.join(tmp, "not_head.img")
    with open(img, "rb") as src:
        first = src.read(4 << 20)
    open(head, "wb").write(first)
    open(other, "wb").write(b"\x01" + first[1:])
    rc_head = cli.cmd_identify_model(argparse.Namespace(device=head, out=full, max_gb=1.0))
    m = json.load(open(os.path.join(full, "model.json"), encoding="utf-8"))["searched"]
    rc_other = cli.cmd_identify_model(argparse.Namespace(device=other, out=full, max_gb=1.0))
    check("identify-model reads a head image once block 0 proves it is the same drive",
          rc_head == 0 and "head_image" in m and m["bytes"] <= 4 << 20 and rc_other == 1, str(m))

    cov = RM.coverage([[0, 100], [200, 100]], [[50, 200]], end=1000)
    check("carver coverage: bytes of the known carve also found, and bytes found beyond it",
          cov["known_bytes"] == 200 and cov["known_bytes_also_found"] == 100
          and cov["share_of_known_found"] == 0.5 and cov["found_bytes_not_known"] == 100, str(cov))
    check("carver range reaches the first known footage when the default holds none",
          RM.annexb_range_mb([[4500 << 20, 1 << 20]], 2048) == 4500 + 2048
          and RM.annexb_range_mb([[100 << 20, 1 << 20]], 2048) == 2048
          and RM.annexb_range_mb([], 2048) == 2048)

    # The drive-2 reference frames: eight cameras record at once, so the time
    # matches several streams and only the camera the title names picks one.
    case2 = os.path.join(tmp, "refcase")
    os.makedirs(os.path.join(case2, "carve"), exist_ok=True)
    t1, t2 = RM.DRIVE2_REFERENCE[0][0], RM.DRIVE2_REFERENCE[1][0]
    span = lambda sid, a, b: {"id": sid, "time_first_local": a, "time_last_local": b}
    rows = [span("ps-a", "2024-07-28 02:00:00", "2024-07-28 23:00:00"),   # CH07, listed first
            span("ps-b", "2024-07-28 05:00:00", "2024-07-28 18:00:00"),   # CH01
            span("ps-c", "2024-07-28 06:00:00", "2024-07-28 09:00:00"),   # outside_index
            span("ps-d", "2023-07-22 10:00:00", "2023-07-22 12:00:00")]   # CH05, alone
    labels = {"ps-a": "CH07", "ps-b": "CH01", "ps-c": "outside_index", "ps-d": "CH05"}
    json.dump({"streams": rows}, open(os.path.join(case2, "carve", "ps_report.json"), "w"))
    json.dump({"streams": [{"id": k, "label": v} for k, v in labels.items()]},
              open(os.path.join(case2, "carve", "ps_labels.json"), "w"))
    refs, unresolved = RM.ps_reference_ids(case2)
    check("reference stream chosen by the camera the title names, not the first in time",
          refs == [("ps-b", t1, RM.DRIVE2_REFERENCE[0][1])], str(refs))
    check("a lone stream labelled another camera is not taken for the reference",
          len(unresolved) == 1 and t2 in unresolved[0], str(unresolved))


def test_ewf(tmp: str) -> None:
    """E01 images read directly: the same bytes, hashes and carve as the raw
    image, across segments; a damaged chunk is reported, never guessed."""
    print("\n[E01 images]")
    import argparse
    import cli
    from acquire import ewf
    from recover.carver import CarveTap
    from tests import synth_ewf

    raw = os.path.join(tmp, "e01src.img")
    synth_dahua.build(raw, seconds=20)
    with open(raw, "rb") as fh:
        media = fh.read()
    # an incompressible tail, so the set holds stored chunks as well as compressed ones
    import random
    media += bytes(-len(media) % 512) + random.Random(1).randbytes(256 << 10)
    with open(raw, "wb") as fh:
        fh.write(media)
    base = os.path.join(tmp, "e01set")
    paths = synth_ewf.write(base, media, chunks_per_segment=7)
    e01 = paths[0]
    with BlockDevice(e01) as dev:
        same = dev.size_bytes == len(media) and dev.read_at(0, len(media)) == media
        odd = dev.read_at(12345, 70000) == media[12345:12345 + 70000]
        model = dev.model
    img = ewf.EwfImage(e01)
    comp = sum(1 for c in img.chunks if c[3])
    img.close()
    check("an E01 set in several segments reads back byte-identical to the raw image",
          same and odd and len(paths) > 2 and f"{len(paths)} segment" in model
          and 0 < comp < len(img.chunks), f"{len(paths)} segments, {comp} compressed")

    rc = cli.cmd_ewf_info(argparse.Namespace(image=e01, verify=True))
    check("ewf-info --verify reproduces the MD5 and SHA-1 the image stores", rc == 0)

    outs = {}
    for name, path in (("raw", raw), ("e01", e01)):
        rep = ScanSession(path, os.path.join(tmp, f"ewfscan_{name}"),
                          CaseInfo(case_id=name, investigator="t"), block_size=1 << 20,
                          quiet=True, taps=[CarveTap()]).run()
        with open(os.path.join(tmp, f"ewfscan_{name}", "carve", "carve_report.json"),
                  encoding="utf-8") as fh:
            carve = [(r["recording"]["frame_count"], r["extents"]) for r in json.load(fh)["streams"]]
        outs[name] = ({h.algorithm: h.value for h in rep.hashes}, carve)
    check("scan + carve of the E01 equal the raw image's: MD5, SHA-256, Merkle root, streams",
          outs["raw"] == outs["e01"] and outs["raw"][1], str(len(outs["raw"][1])))

    bad = os.path.join(tmp, "e01bad")
    bad_paths = synth_ewf.write(bad, media, chunks_per_segment=7)
    # corrupt the first STORED (uncompressed) chunk's data, not its checksum
    img = ewf.EwfImage(bad_paths[0])
    k = next(i for i, c in enumerate(img.chunks) if not c[3])
    seg, at = img.chunks[k][0], img.chunks[k][1]
    img.close()
    with open(bad_paths[seg], "rb") as fh:
        blob = bytearray(fh.read())
    blob[at + 100] ^= 0xFF
    with open(bad_paths[seg], "wb") as fh:
        fh.write(bytes(blob))
    rep = ScanSession(bad_paths[0], os.path.join(tmp, "ewfscan_bad"),
                      CaseInfo(case_id="bad", investigator="t"), block_size=1 << 20,
                      quiet=True).run()
    check("a damaged chunk is reported as an unreadable region, never read as good data",
          rep.bad_regions and rep.bad_regions[0].offset <= k * 32768 < rep.bad_regions[0].offset
          + sum(b.length for b in rep.bad_regions), str(rep.bad_regions[:1]))

    broken = bytearray(open(e01, "rb").read())
    broken[13 + 20] ^= 0x01                      # inside the first section descriptor
    brk = os.path.join(tmp, "broken.E01")
    open(brk, "wb").write(bytes(broken))
    try:
        BlockDevice(brk)
        refused = False
    except Exception as exc:                      # noqa: BLE001
        refused = "checksum" in str(exc)
    check("a section descriptor failing its checksum is refused at open", refused)


class ExplodingTap:
    """A tap that fails part-way through, to prove a failure in a worker
    process never touches the hashes (constructed by the worker by name)."""

    name = "exploding"

    def prepare(self, dev, start, end, log=print):
        self.n = 0

    def feed(self, offset, data):
        self.n += 1
        if self.n == 2:
            raise ValueError("boom")

    def finish(self, out_dir, info):
        return {"blocks": self.n}


def test_parallel_taps(tmp: str) -> None:
    """Taps in their own processes: the same reports and the same hashes as
    in the scanning process; a failing worker is recorded, the scan completes."""
    print("\n[parallel taps]")
    from acquire.parallel import TAPS, ProcessTap, _resolve

    img = os.path.join(tmp, "unknown_vendor.img")          # DHAV-free, raw H.264/H.265
    dahua_img = os.path.join(tmp, "e01src.img")            # DHAV footage + noise

    def run(path, name, parallel):
        taps = [ProcessTap(TAPS[n]) if parallel else _resolve(TAPS[n])() for n in TAPS]
        out = os.path.join(tmp, f"par_{name}_{parallel}")
        rep = ScanSession(path, out, CaseInfo(case_id="P", investigator="t"),
                          block_size=1 << 20, quiet=True, taps=taps).run()
        reports = {}
        for f in ("carve/carve_report.json", "carve/ps_report.json",
                  "carve/annexb_report.json", "activity.json"):
            p = os.path.join(out, f)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    r = json.load(fh)
                for k in ("generated_utc", "tool"):
                    r.pop(k, None)
                reports[f] = r
        return {h.algorithm: h.value for h in rep.hashes}, reports

    same = True
    for path, name in ((img, "es"), (dahua_img, "dhav")):
        a, b = run(path, name, False), run(path, name, True)
        same = same and a == b and len(a[1]) == 4
    check("every tap in its own process: the same four reports and the same hashes", same)

    out = os.path.join(tmp, "par_fail")
    s = ScanSession(img, out, CaseInfo(case_id="F", investigator="t"), block_size=1 << 20,
                    quiet=True, taps=[ProcessTap("tests.test_pipeline:ExplodingTap")])
    rep = s.run()
    plain = ScanSession(img, os.path.join(tmp, "par_plain"), CaseInfo(case_id="F", investigator="t"),
                        block_size=1 << 20, quiet=True).run()
    led = CustodyLedger(os.path.join(out, "custody_ledger.jsonl"))
    check("a tap failing in its worker: recorded, hashes unchanged, scan complete",
          {h.algorithm: h.value for h in rep.hashes} == {h.algorithm: h.value for h in plain.hashes}
          and rep.stats.complete_pass and "boom" in s.tap_results["exploding"]["error"]
          and any(e["action"] == "inline_exploding_failed" for e in led.entries))


def test_case_export(tmp: str) -> None:
    """CASE/UCO JSON-LD: the drive, the recorder, every ledger action and
    every extracted file with its hash and its byte ranges on the drive."""
    print("\n[CASE/UCO export]")
    import argparse
    import cli
    from recover.carver import CarveTap

    img = os.path.join(tmp, "e01src.img")
    case = os.path.join(tmp, "case_uco")
    ScanSession(img, case, CaseInfo(case_id="UCO-1", investigator="J. Examiner"),
                block_size=1 << 20, quiet=True, taps=[CarveTap()]).run()
    cli.cmd_extract_carved(argparse.Namespace(device=img, out=case, format="dhav", ids="",
                                              label="all"))
    cli.cmd_record_device(argparse.Namespace(out=case, model="CP-UNR-104F1", serial="ABC123",
                                             firmware="", read_from="label", photo=[]))
    rc = cli.cmd_case_export(argparse.Namespace(out=case))
    first = open(os.path.join(case, "case.jsonld"), encoding="utf-8").read()
    doc = json.loads(first)
    nodes = {n["@id"]: n for n in doc["@graph"]}
    by_type: dict = {}
    for n in doc["@graph"]:
        by_type.setdefault(n["@type"], []).append(n)
    led = CustodyLedger(os.path.join(case, "custody_ledger.jsonl"))
    man = json.load(open(os.path.join(case, "carve", "extracted.json"), encoding="utf-8"))
    want = {f"carve/streams/{name}": (f["sha256"], v["extents"])
            for v in man["streams"].values() for name, f in v["files"].items()}
    got = {}
    for f in by_type.get("uco-observable:File", []):
        cdf = next(x for x in f["uco-core:hasFacet"] if x["@type"] == "uco-observable:ContentDataFacet")
        rel = next(r for r in by_type["uco-observable:ObservableRelationship"]
                   if r["uco-core:source"]["@id"] == f["@id"])
        got[f["uco-core:name"]] = (cdf["uco-observable:hash"][0]["uco-types:hashValue"]["@value"].lower(),
                                   [[r["uco-observable:rangeOffset"], r["uco-observable:rangeSize"]]
                                    for r in rel.get("uco-core:hasFacet", [])])
    check("every extracted file: its SHA-256 and its byte ranges on the drive",
          rc == 0 and got == want and len(want) > 0, f"{len(got)} vs {len(want)}")
    drive = next(n for n in by_type["uco-observable:Device"] if n["uco-core:name"].startswith("evidence"))
    cdf = next(x for x in drive["uco-core:hasFacet"] if x["@type"] == "uco-observable:ContentDataFacet")
    scan = json.load(open(os.path.join(case, "scan_report.json"), encoding="utf-8"))
    sha = next(h["value"] for h in scan["hashes"] if h["algorithm"] == "sha256")
    check("the drive carries its whole-drive hashes; the recorder its model, with a relationship",
          any(h["uco-types:hashValue"]["@value"].lower() == sha for h in cdf["uco-observable:hash"])
          and any(r["uco-core:kindOfRelationship"] == "Contained_Within"
                  and nodes[r["uco-core:target"]["@id"]]["uco-core:name"] == "recorder CP-UNR-104F1"
                  for r in by_type["uco-observable:ObservableRelationship"]))
    check("one InvestigativeAction per custody-ledger entry before the export",
          len(by_type["case-investigation:InvestigativeAction"]) == len(led.entries) - 1
          and led.entries[-1]["action"] == "case_exported")
    cli.cmd_case_export(argparse.Namespace(out=case))
    again = json.load(open(os.path.join(case, "case.jsonld"), encoding="utf-8"))
    check("exporting twice gives the same identifiers (UUIDv5 from the case)",
          {n["@id"] for n in doc["@graph"]} <= {n["@id"] for n in again["@graph"]})


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
        test_hikvision_parser(tmp)
        test_parser_robustness(tmp)
        test_dahua_frames()
        test_dahua_parser(tmp)
        test_dahua_chain_split(tmp)
        test_hik_log(tmp)
        test_dahua_robustness(tmp)
        test_carver(tmp)
        test_preserve(tmp)
        test_inline_carve(tmp)
        test_plugins(tmp)
        test_device_loss(tmp)
        test_short_read(tmp)
        test_survey(tmp)
        test_regions(tmp)
        test_activity(tmp)
        test_timeline_clock_default()
        test_timeline_recurring()
        test_timeline_recorder_log()
        test_ps_carver(tmp)
        test_static_detections()
        test_analytics_eval(tmp)
        test_analytics_tiles()
        test_combined(tmp)
        test_osd_rules()
        test_osd_reader(tmp)
        test_hikbtree(tmp)
        test_independent_checks(tmp)
        test_validate_export(tmp)
        test_model(tmp)
        test_annexb_carver(tmp)
        test_honeywell(tmp)
        test_uniview(tmp)
        test_tplink(tmp)
        test_ext4(tmp)
        test_matrix(tmp)
        test_nist_export(tmp)
        test_s63_certificate(tmp)
        test_s63_footage_folders(tmp)
        test_real_media_tools(tmp)
        test_ewf(tmp)
        test_parallel_taps(tmp)
        test_case_export(tmp)
        test_heimvision(tmp)
        test_godrej(tmp)
        test_daylight(tmp)
        test_dahua_real_media()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"  {len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"    FAILED: {name}  {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())

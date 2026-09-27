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
from tests import synth_dahua, synth_dvr

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
        check("master sector found at 0x200",
              parser.find_master(dev) == 0x200,
              hex(parser.find_master(dev)))
        result = parser.parse(dev)

    # --- the honesty invariants. These matter more than the parse itself.
    check("parse is NEVER claimed as validated",
          result.validation_status != "validated", result.validation_status)
    check("fixture-sourced fields force synthetic_only",
          result.validation_status == "synthetic_only",
          result.validation_status)
    check("field provenance is recorded for every decoded field",
          len(result.field_provenance) >= len(synth_hik_fields()))
    check("every fixture-sourced field says so",
          all(f["implies_status"] == "synthetic_only"
              for f in result.field_provenance if f["source"] == "fixture"))

    # --- the parse
    check("every indexed clip is recovered",
          len(result.recordings) == meta["active_clips"],
          f"{len(result.recordings)} vs {meta['active_clips']}")
    check("volume metadata decoded",
          result.volume["master"]["model"].startswith("DS-"),
          result.volume["master"]["model"])
    check("channel count decoded", result.volume["master"]["channel_count"] == 4)

    by_offset = {r.offset: r for r in result.recordings}
    for start, length, cam, ts in meta["index_entries"]:
        rec = by_offset.get(start)
        if rec is None:
            check(f"index entry at 0x{start:X} recovered", False)
            continue
        check(f"extent matches index at 0x{start:X}", rec.length == length)
        check(f"camera id decoded at 0x{start:X}",
              rec.camera_id == f"CH{cam + 1:02d}", rec.camera_id)

    r0 = result.recordings[0]
    check("provenance is attached to every recording",
          all(r.provenance is not None for r in result.recordings))
    check("provenance sha256 matches the bytes on the platter",
          r0.provenance.sha256 == hashlib.sha256(
              open(img, "rb").read()[r0.offset:r0.offset + r0.length]
          ).hexdigest())
    check("sector range brackets the byte extent",
          r0.provenance.sector_start * 512 <= r0.offset
          and r0.provenance.sector_end * 512 >= r0.offset + r0.length)
    check("frames are counted", r0.frame_count > 0, str(r0.frame_count))
    check("codec identified per recording", r0.codec == "h264")

    # --- timestamps are claims, never conclusions
    check("every recording carries a timestamp claim",
          all(r.timestamps for r in result.recordings))
    tc = r0.timestamps[0]
    check("timestamp claim names its source", tc.source == "index")
    check("timestamp claim carries a decode rule", bool(tc.decode_rule))
    check("a single-source timestamp is not asserted as certain",
          tc.confidence < 1.0, str(tc.confidence))
    check("timestamp decodes to the fixture's value",
          tc.decoded_utc == "2025-09-22T00:00:00.000Z", str(tc.decoded_utc))

    # --- confidence is never certainty
    check("no recording claims certainty",
          all(r.confidence < 1.0 for r in result.recordings))

    # --- the deleted clip is NOT in the index: that is the carver's job, and
    # the parser must not silently invent it.
    deleted_off = meta["deleted_clip"]["offset"]
    check("the unindexed deleted clip is absent from the parse",
          deleted_off not in by_offset)


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

    # Master sector present, index absent - the damaged-index case.
    noidx = os.path.join(tmp, "noindex.img")
    buf = bytearray(1 << 20)
    buf[0x200:0x200 + 18] = b"HIKVISION@HANGZHOU"
    with open(noidx, "wb") as fh:
        fh.write(bytes(buf))
    with BlockDevice(noidx) as dev:
        res = parser.parse(dev)
    check("a missing index is reported, not fatal",
          any("HIKBTREE" in n for n in res.notes))
    check("a missing index still reports the volume", bool(res.volume))

    # Index claiming absurd extents - garbage read off a damaged platter.
    bad = os.path.join(tmp, "badindex.img")
    buf = bytearray(1 << 20)
    buf[0x200:0x200 + 18] = b"HIKVISION@HANGZHOU"
    buf[0x1000:0x1008] = b"HIKBTREE"
    buf[0x1010:0x1014] = (3).to_bytes(4, "little")
    buf[0x1020:0x1026] = b"OFFSET"
    # entry 0: extent past the end of the device.  entry 1: absurd length.
    # entry 2: valid but empty (length 0).
    struct_pack = __import__("struct").pack_into
    struct_pack("<QQII", buf, 0x1040, 1 << 40, 4096, 0, 1758499200)
    struct_pack("<QQII", buf, 0x1058, 0x2000, 1 << 40, 1, 1758499200)
    struct_pack("<QQII", buf, 0x1070, 0x3000, 0, 2, 1758499200)
    with open(bad, "wb") as fh:
        fh.write(bytes(buf))
    with BlockDevice(bad) as dev:
        res = parser.parse(dev)
    check("out-of-range extents are skipped and reported",
          any("past the end" in n for n in res.notes))
    check("absurd lengths are skipped and reported",
          any("sanity bound" in n for n in res.notes))
    check("no garbage recording is emitted", not res.recordings)

    # A timestamp of 0 must not become 1970 presented as fact.
    check("an unusable timestamp decodes to None",
          hik._decode_utc(0) is None)


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
    finally:
        P.PLUGIN_DIR = saved_dir
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
        hk = b"\x40\x0e" + b"HK\x01\x00" + bytes([t.year - 2000]) + v.to_bytes(4, "big") + b"\x00\xff\xff\xff"
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
             "time_last_local": loc(t0 + 10)}]
    lab = {x["id"]: x["label"] for x in hikbtree.label_streams(idx, rows)}
    check("a stream inside its block's record window gets the record's channel",
          lab["in"] == "CH05", str(lab))
    check("older footage left in a reused block is outside_index",
          lab["older"] == "outside_index")
    check("an initialised, never-used block (channel 255) labels nothing",
          lab["unused"] == "outside_index")


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

    def fake_sample(clip, band, out_dir, frames=6, window_s=30, negate=False):
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
        test_dahua_robustness(tmp)
        test_carver(tmp)
        test_preserve(tmp)
        test_inline_carve(tmp)
        test_plugins(tmp)
        test_device_loss(tmp)
        test_short_read(tmp)
        test_survey(tmp)
        test_activity(tmp)
        test_timeline_clock_default()
        test_timeline_recurring()
        test_ps_carver(tmp)
        test_static_detections()
        test_osd_rules()
        test_osd_reader(tmp)
        test_hikbtree(tmp)
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

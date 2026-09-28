"""Generate a synthetic DVR disk image for testing.

This exists so the acquisition, detection and (later) carving engines can be
developed and regression-tested before the physical Hikvision drive is
imaged, and so CI has something deterministic to run against.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Passing here proves the
code reads this layout, not that the layout is the vendor's.  The Hikvision
structures follow the layout OBSERVED on the team's drive 2 (ST1000VX005
s/n Z9C2632A; parsers/hiklog.py, parsers/hikbtree.py): the magic 0x10 into
the master sector, the master's fields at their observed offsets, two
HIKBTREE copies where the master points, 48-byte leaf records on a block
grid.  The values are ours, and the blocks are 256 KiB where the real drive
uses 1 GiB.  The video itself is raw H.264, not Hikvision's MPEG-PS.

Layout (64 MiB default):

    0x000000  MBR with one primary partition
    0x000200  Hikvision master sector - HIKVISION@HANGZHOU at 0x210
    0x001000  HIKBTREE index, copy 1 (magic at +0x10, records from +0x100)
    0x010000  HIKBTREE index, copy 2
    0x020000  system-log area (empty)
    0x100000  data area, 256 KiB blocks; video region A - "active"
              recordings, 4 cameras, each indexed by its block
    0x800000  video region B - "deleted" recording (no index record)
    0xE00000  high-entropy region (stands in for encrypted/compressed data)
    ......    zero fill
"""

from __future__ import annotations

import argparse
import os
import random
import struct

SECTOR = 512
DEFAULT_SIZE = 64 * 1024 * 1024

OFF_MASTER = 0x000200
OFF_BTREE = 0x001000
OFF_BTREE2 = 0x010000
OFF_LOG, LOG_SIZE = 0x020000, 0x010000
HIK_BLOCK = 0x40000                    # 256 KiB data blocks (1 GiB on the real drive)
HIK_RECORDS_AT = 0x100                 # leaf records start this far into a HIKBTREE page
OFF_VIDEO_A = 0x100000
OFF_VIDEO_B = 0x800000
OFF_ENTROPY = 0xE00000

# H.264 Annex-B NAL headers. Start code + a header byte whose low 5 bits are
# the NAL type: 7=SPS, 8=PPS, 5=IDR slice, 1=non-IDR slice.
SC = b"\x00\x00\x00\x01"
NAL_SPS = b"\x67"
NAL_PPS = b"\x68"
NAL_IDR = b"\x65"
NAL_P = b"\x41"

# A plausible minimal SPS/PPS payload. Structurally realistic enough for the
# detector and the future carver's SPS/PPS rebuild step to key on.
SPS_PAYLOAD = bytes.fromhex("42001e ab40 5001 ed80 8080 a000 0007 d000 01d4 c0".replace(" ", ""))
PPS_PAYLOAD = bytes.fromhex("ce3c8000")


def _mbr(total_size: int) -> bytes:
    mbr = bytearray(512)
    mbr[0:3] = b"\xeb\x3c\x90"
    mbr[3:11] = b"DVRIMAGE"
    part = bytearray(16)
    part[0] = 0x00                       # not bootable
    part[4] = 0x83                       # Linux - typical of DVR firmware areas
    struct.pack_into("<I", part, 8, 2048)            # first LBA
    struct.pack_into("<I", part, 12, max(total_size // SECTOR - 2048, 1))
    mbr[446:462] = part
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def _hik_master(capacity: int, block: int = HIK_BLOCK, data_offset: int = OFF_VIDEO_A,
                btrees: tuple[int, int] = (OFF_BTREE, OFF_BTREE2),
                init_time: int = 1_758_412_800) -> bytes:
    """A master sector with the observed layout (parsers/hiklog.py
    MASTER_FIELDS): magic at +0x10, and fields that agree with each other."""
    b = bytearray(SECTOR)
    b[0x10:0x22] = b"HIKVISION@HANGZHOU"
    b[0x30:0x3E] = b"HIK.2011.03.08"
    count = (capacity - data_offset) // block
    for off, value in ((0x48, capacity), (0x50, OFF_LOG), (0x58, LOG_SIZE),
                       (0x60, OFF_LOG + LOG_SIZE), (0x68, 0), (0x78, data_offset),
                       (0x80, count * block), (0x88, block), (0x90, count),
                       (0x98, btrees[0]), (0xA0, 0x1000), (0xA8, btrees[1]), (0xB0, 0x1000)):
        struct.pack_into("<Q", b, off, value)
    struct.pack_into("<I", b, 0xF0, init_time)
    return bytes(b)


def hik_record(channel: int, start: int, end: int, block_offset: int) -> bytes:
    """One 48-byte HIKBTREE leaf record, as observed (parsers/hikbtree.py)."""
    r = bytearray(48)
    r[0:8] = b"\xff" * 8
    r[0x11] = channel
    struct.pack_into("<IIQ", r, 0x18, start, end, block_offset)
    return bytes(r)


def _hik_btree(records: list[bytes]) -> bytes:
    """A HIKBTREE page: the magic at +0x10, the version string, an OFFSET
    marker (published), then the leaf records."""
    b = bytearray(0x1000)
    b[0x10:0x18] = b"HIKBTREE"
    b[0x18:0x26] = b"HIK.2010.11.09"
    b[0x40:0x46] = b"OFFSET"
    for k, rec in enumerate(records):
        b[HIK_RECORDS_AT + 48 * k:HIK_RECORDS_AT + 48 * (k + 1)] = rec
    return bytes(b)


def _clip(rng: random.Random, frames: int, payload: int = 2048) -> bytes:
    """One synthetic recording: SPS, PPS, IDR, then P-frames."""
    out = bytearray()
    out += SC + NAL_SPS + SPS_PAYLOAD
    out += SC + NAL_PPS + PPS_PAYLOAD
    out += SC + NAL_IDR + rng.randbytes(payload * 2)
    for _ in range(frames):
        out += SC + NAL_P + rng.randbytes(payload)
    return bytes(out)


def build(path: str, size: int = DEFAULT_SIZE, seed: int = 26150,
          vendor: str = "hikvision") -> dict:
    rng = random.Random(seed)
    img = bytearray(size)
    img[0:512] = _mbr(size)

    index_entries: list[tuple[int, int, int, int]] = []
    hik_records: list[tuple[int, int, int, int]] = []

    # --- active recordings, 4 cameras, 1 hour apart -----------------------
    pos = OFF_VIDEO_A
    base_ts = 1_758_499_200            # 2025-09-22 00:00:00 on the recorder's clock
    for i in range(8):
        clip = _clip(rng, frames=rng.randint(20, 40))
        img[pos:pos + len(clip)] = clip
        index_entries.append((pos, len(clip), i % 4, base_ts + i * 3600))
        block_off = OFF_VIDEO_A + (pos - OFF_VIDEO_A) // HIK_BLOCK * HIK_BLOCK
        hik_records.append((i % 4 + 1, base_ts + i * 3600, base_ts + i * 3600 + 60 + i,
                            block_off))
        pos += len(clip) + rng.randint(1024, 4096)

    # --- "deleted" recording: present on the platter, absent from the index
    deleted = _clip(rng, frames=60)
    img[OFF_VIDEO_B:OFF_VIDEO_B + len(deleted)] = deleted

    if vendor in ("hikvision", "mixed"):
        m = _hik_master(size)
        img[OFF_MASTER:OFF_MASTER + len(m)] = m
        # a block reserved when the disk was initialised: channel 255, not a camera
        last = OFF_VIDEO_A + ((size - OFF_VIDEO_A) // HIK_BLOCK - 1) * HIK_BLOCK
        recs = [hik_record(*r) for r in hik_records] + [
            hik_record(255, 1_758_412_800, 1_758_412_800, last)]
        t = _hik_btree(recs)
        for at in (OFF_BTREE, OFF_BTREE2):
            img[at:at + len(t)] = t

    if vendor in ("dahua", "mixed"):
        # DHFS superblock and a few DHAV-wrapped frames
        off = 0x002000 if vendor == "dahua" else 0x003000
        sb = bytearray(SECTOR)
        sb[0:4] = b"DHFS"
        sb[4:12] = b"4.1\x00\x00\x00\x00\x00"
        img[off:off + len(sb)] = sb
        dp = OFF_VIDEO_A + 0x40000
        for i in range(6):
            body = rng.randbytes(1024)
            frame = b"DHAV" + struct.pack("<I", len(body) + 24) + body + b"dhav"
            img[dp:dp + len(frame)] = frame
            dp += len(frame) + 512

    # --- high-entropy region ---------------------------------------------
    ent = rng.randbytes(2 * 1024 * 1024)
    img[OFF_ENTROPY:OFF_ENTROPY + len(ent)] = ent

    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(img)

    return {
        "path": path, "size": size, "seed": seed, "vendor": vendor,
        "synthetic": True,
        "active_clips": len(index_entries),
        "deleted_clip": {"offset": OFF_VIDEO_B, "length": len(deleted)},
        "index_entries": index_entries,
        "hik_records": hik_records, "hik_block_size": HIK_BLOCK,
        "hik_btree_offsets": [OFF_BTREE, OFF_BTREE2],
        "entropy_region": {"offset": OFF_ENTROPY, "length": len(ent)},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a synthetic DVR disk image")
    ap.add_argument("path")
    ap.add_argument("--size-mb", type=int, default=64)
    ap.add_argument("--seed", type=int, default=26150)
    ap.add_argument("--vendor", default="hikvision",
                    choices=["hikvision", "dahua", "mixed"])
    args = ap.parse_args()
    meta = build(args.path, args.size_mb * 1024 * 1024, args.seed, args.vendor)
    print(f"[+] wrote {meta['path']}  ({meta['size'] // 1024 // 1024} MiB, "
          f"vendor={meta['vendor']}, seed={meta['seed']})")
    print(f"    {meta['active_clips']} indexed clips, "
          f"1 deleted clip at 0x{meta['deleted_clip']['offset']:X} "
          f"({meta['deleted_clip']['length']} B)")
    print("    SYNTHETIC - not evidence, not a vendor sample")


if __name__ == "__main__":
    main()

"""Generate a synthetic DVR disk image for testing.

This exists so the acquisition, detection and (later) carving engines can be
developed and regression-tested before the physical Hikvision drive is
imaged, and so CI has something deterministic to run against.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Anything validated only
against this file is marked `synthetic_only` in the report - a parser that
passes here has proven it can read a layout we invented, which is a test of
the code, not of our understanding of the vendor's format.  Only the real
DS-80xx drive can move Hikvision to `validated`.

Layout (64 MiB default):

    0x000000  MBR with one primary partition
    0x000200  Hikvision master sector - HIKVISION@HANGZHOU magic
    0x001000  HIKBTREE index header
    0x100000  video region A - "active" recordings, 4 cameras
    0x800000  video region B - "deleted" recording (no index entry)
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


def _hik_master() -> bytes:
    """Hikvision-shaped master sector. Field layout is our own invention
    beyond the magic string - see module docstring."""
    b = bytearray(SECTOR * 2)
    b[0:18] = b"HIKVISION@HANGZHOU"
    struct.pack_into("<Q", b, 0x20, 500_107_862_016)   # nominal capacity
    struct.pack_into("<Q", b, 0x28, 256 * 1024 * 1024)  # data block size
    struct.pack_into("<I", b, 0x30, 4)                  # channel count
    b[0x40:0x50] = b"DS-8008HGHI-SH\x00\x00"
    b[0x60:0x68] = b"V3.4.92\x00"
    return bytes(b)


def _hik_btree(entries: list[tuple[int, int, int, int]]) -> bytes:
    """HIKBTREE header plus simple index entries:
    (start_offset, length, camera_id, unix_start)."""
    b = bytearray(SECTOR * 8)
    b[0:8] = b"HIKBTREE"
    struct.pack_into("<I", b, 0x10, len(entries))
    b[0x20:0x26] = b"OFFSET"
    pos = 0x40
    for start, length, cam, ts in entries:
        struct.pack_into("<QQII", b, pos, start, length, cam, ts)
        pos += 24
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

    # --- active recordings, 4 cameras, 1 hour apart -----------------------
    pos = OFF_VIDEO_A
    base_ts = 1_758_499_200            # 2025-09-22T00:00:00Z
    for i in range(8):
        clip = _clip(rng, frames=rng.randint(20, 40))
        img[pos:pos + len(clip)] = clip
        index_entries.append((pos, len(clip), i % 4, base_ts + i * 3600))
        pos += len(clip) + rng.randint(1024, 4096)

    # --- "deleted" recording: present on the platter, absent from the index
    deleted = _clip(rng, frames=60)
    img[OFF_VIDEO_B:OFF_VIDEO_B + len(deleted)] = deleted

    if vendor in ("hikvision", "mixed"):
        m = _hik_master()
        img[OFF_MASTER:OFF_MASTER + len(m)] = m
        t = _hik_btree(index_entries)
        img[OFF_BTREE:OFF_BTREE + len(t)] = t

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

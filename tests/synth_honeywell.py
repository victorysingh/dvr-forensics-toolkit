"""Generate a synthetic Honeywell NVR disk, built to Yoon & Hwang (DFRWS USA
2026, arXiv:2605.07430) section 5.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Field positions and
encodings follow the paper; every value is ours.  Passing against it proves
`plugins/honeywell.py` does what the paper says - nothing about real units.

Two deliberate choices, both stated so nobody mistakes them for findings:

  * the video area starts at 16 MiB of Partition 1, not the paper's 2 GiB,
    so the image stays small.  The header field that the paper says holds
    this offset is set accordingly, and the parser reads that field;
  * the paper does not give the byte layout of the Machine Data sector, only
    that it holds the device ID and model name, so this writes them as text.

What it builds: a protective MBR and GPT; Machine Data in sector 34;
Partition 1 with its header, block index list, channel index list and video
area, where each H.264 NAL unit is preceded by the 20-byte Custom Header;
chunks padded to 0x1000 with a dummy byte, each channel's data ended by 20
zero bytes.  `format=True` then does what the paper found formatting does:
resets the header and removes the lists, leaving the video in place.
"""

from __future__ import annotations

import random
import struct

SECTOR = 512
P1_LBA = 2048
UNIT = 0x1000
BLOCK_LIST = 0x40000
CHANNEL_LIST = 0x400000
VIDEO_START = 0x1000000
MODEL = "HN35080200"
DEVICE_ID = "HWNVR-0001"
T0 = 1764193699              # 2025-11-26 21:48:19 UTC, the paper's example time


def _gpt(total_sectors: int, p1_sectors: int) -> bytes:
    head = bytearray(34 * SECTOR)
    mbr = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1,
                      min(total_sectors - 1, 0xFFFFFFFF))
    head[446:446 + 16] = mbr
    head[510:512] = b"\x55\xaa"
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    hdr[8:12] = struct.pack("<I", 0x00010000)
    hdr[12:16] = struct.pack("<I", 92)
    hdr[24:32] = struct.pack("<Q", 1)
    hdr[40:48] = struct.pack("<Q", 34)
    hdr[48:56] = struct.pack("<Q", total_sectors - 34)
    hdr[72:80] = struct.pack("<Q", 2)
    hdr[80:84] = struct.pack("<I", 128)
    hdr[84:88] = struct.pack("<I", 128)
    head[SECTOR:SECTOR + 92] = hdr
    entry = bytearray(128)
    entry[0:16] = bytes(range(1, 17))            # a type GUID; the paper names none
    entry[16:32] = bytes(range(17, 33))
    entry[32:40] = struct.pack("<Q", P1_LBA)
    entry[40:48] = struct.pack("<Q", P1_LBA + p1_sectors - 1)
    head[2 * SECTOR:2 * SECTOR + 128] = entry
    return bytes(head)


def frame(ftype: int, w: int, h: int, nal: bytes, us: int) -> bytes:
    """Custom Header (5.4.6) + start code + NAL unit.  The length field here
    covers the start code and the NAL unit."""
    body = b"\x00\x00\x00\x01" + nal
    return (bytes([ftype]) + b"\x80\x01\x00" + struct.pack("<HHIQ", w, h, len(body), us)
            + body)


def build(path: str, channels: int = 2, chunks_per_channel: int = 6, frames_per_chunk: int = 30,
          seed: int = 2026, format: bool = False, gap_after: int = 3) -> dict:
    """Write the image; return ground truth for the tests."""
    rng = random.Random(seed)

    def body(k):
        return rng.randbytes(k).replace(b"\x00", b"\x01")

    video = bytearray()
    chan_entries, block_times, truth = [], [], {"chunks": [], "nals": {}}
    for k in range(chunks_per_channel):
        for ch in range(channels):
            # A pause in recording after chunk `gap_after`, to split recordings.
            t = T0 + k * 2 + (600 if k >= gap_after else 0)
            start = len(video)
            nals = []
            for f in range(frames_per_chunk):
                key = f == 0
                n =(b"\x65" if key else b"\x41") + body(1200 if key else rng.randint(100, 300))
                us = t * 1_000_000 + f * 40_000
                video += frame(0x82 if key else 0x02, 1920, 1080, n, us)
                nals.append(b"\x00\x00\x00\x01" + n)
            video += bytes(20)                    # End of Channel Data (5.4.6)
            pad = -len(video) % UNIT
            video += b"\xee" * pad                # dummy value up to the rounded length
            length = len(video) - start
            chan_entries.append(struct.pack("<BBHII4x", ch, 0x00, length // UNIT, t,
                                            start // UNIT))
            truth["chunks"].append({"channel": ch, "time": t, "offset": start,
                                    "length": length})
            truth["nals"].setdefault((ch, k >= gap_after), []).extend(nals)
        block_times.append(T0 + k * 2)

    p1_size = VIDEO_START + len(video) + (1 << 20)
    total = P1_LBA * SECTOR + p1_size + (1 << 20)
    head = bytearray(_gpt(total // SECTOR, p1_size // SECTOR))
    machine = f"DEVICE ID {DEVICE_ID}\x00MODEL {MODEL}\x00".encode("ascii")
    head[34 * SECTOR:34 * SECTOR + len(machine)] = machine

    p1 = bytearray(VIDEO_START)
    next_write = VIDEO_START + len(video)
    avail = p1_size - next_write
    total_alloc = p1_size - VIDEO_START
    if format:                                   # paper 6: header reset, lists removed
        next_write, avail = VIDEO_START, total_alloc
    struct.pack_into("<IIIIIIII", p1, 0, VIDEO_START // UNIT, 0, next_write // UNIT, 0,
                     avail // UNIT, 0, total_alloc // UNIT, 0)
    struct.pack_into("<I", p1, 0x44, T0)
    if not format:
        for i, t in enumerate(block_times):
            struct.pack_into("<4xI4xBB2x", p1, BLOCK_LIST + i * 16, t, i % 256, i // 256)
        for i, e in enumerate(chan_entries):
            p1[CHANNEL_LIST + i * 16:CHANNEL_LIST + i * 16 + 16] = e

    with open(path, "wb") as fh:
        fh.write(bytes(head))
        fh.write(bytes(P1_LBA * SECTOR - len(head)))
        fh.write(bytes(p1))
        fh.write(bytes(video))
        fh.write(bytes(total - P1_LBA * SECTOR - VIDEO_START - len(video)))
    truth.update({"p1": P1_LBA * SECTOR, "video_start": VIDEO_START,
                  "frames": channels * chunks_per_channel * frames_per_chunk,
                  "chunks_total": channels * chunks_per_channel})
    return truth

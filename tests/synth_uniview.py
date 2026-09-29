"""Generate a synthetic Uniview NVR disk, built to the layout read from the
recorder's own storage driver (plugins/uniview.py, comm.ko B3612.1.21.220408).

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Field positions follow
the firmware; every value is ours.  Passing against it proves the plugin
follows the firmware - nothing about real units.

Choices of ours, stated so nobody mistakes them for findings:

  * data blocks are 1 MiB, not the firmware's 256 MiB, so the image stays
    small; the test sets the plugin's block size to match;
  * the 4 bytes after each packet's payload are written as zero - the
    firmware prints them but the value it writes was not established;
  * the packet stream type of video is written as 0x1B.  The firmware only
    says which codes are NOT video (0x10, 0x11, 0x15);
  * payloads are made-up H.264 NAL units, not real video.

What it builds: the head superblock and its tail copy; an abstract zone
listing four blocks; block 0 and block 1 recordings (two cameras) with
block headers, GOP indexes and GOPs; block 1 also holds one older GOP past
its write position, as a reused block would; block 2 a snapshot block; block
3 listed but with no header left.  `formatted=True` zeroes the abstract zone
and every block header, leaving the GOPs - the case a GOP walk is for.
"""

from __future__ import annotations

import random
import struct

from plugins import uniview as U

BLOCK = 1 << 20
AZ_POS = 0x10000
DZ_POS = 0x100000
UNITS = 5
T0 = 1719830400                # 2024-07-01 10:40:00 on the recorder's clock
DEVICE_ID = "UNV-TEST-0001"
PAGE = 0x1000


def crc_into(buf: bytearray, at: int, width: int) -> None:
    buf[at:at + width] = b"\x00" * width
    struct.pack_into("<I" if width == 4 else "<H", buf, at, U.crc16(bytes(buf)))


def _nal(rnd: random.Random, kind: int, n: int) -> bytes:
    return b"\x00\x00\x00\x01" + bytes([kind]) + rnd.randbytes(n)


def gop(rnd: random.Random, sec: int, ms: int, frames: int, audio: bool = True) -> tuple[bytes, list[bytes]]:
    """One GOP with its trailer, padded to whole pages; and the video payloads."""
    out = bytearray(struct.pack("<IIHBB4xQ", U.GOP_MAGIC, sec, ms, 0, 0, 1))
    video = []
    for f in range(frames):
        payload = (_nal(rnd, 0x67, 12) + _nal(rnd, 0x68, 4) + _nal(rnd, 0x65, 900)) if f == 0 \
            else _nal(rnd, 0x41, 300 + rnd.randrange(200))
        video.append(payload)
        out += struct.pack("<IIIBBHBBHI", U.PKT_MAGIC, f * 3600, f * 3600, 0x82, 25, f,
                           0, 0x1B, len(payload), f) + payload + b"\x00" * 4
        if audio and f == 0:
            a = rnd.randbytes(160)
            out += struct.pack("<IIIBBHBBHI", U.PKT_MAGIC, 0, 0, 0x83, 0, 0, 0, 0x10,
                               len(a), 0) + a + b"\x00" * 4
    out += struct.pack("<I", U.GOP_END)
    length = len(out)
    trailer = (len(out) + PAGE) & ~(PAGE - 1)
    out += b"\x00" * (trailer - len(out))
    struct.pack_into("<II", out, trailer - 8, length, U.GOP_TAIL)
    return bytes(out), video


def block_header(chan, start, end, items, pos_pages, segments=1) -> bytearray:
    h = bytearray(U.REC_HEADER)
    struct.pack_into("<IIHHB", h, 0, U.REC_MAGIC, U.REC_V4, 0, 1, 0)
    struct.pack_into("<4I", h, 0x10, *chan)
    struct.pack_into("<IIHHHHQH", h, 0x20, start, end, 0, 500, items, pos_pages, 1, segments)
    h[0x40:0x40 + 5] = b"IPC-1"
    struct.pack_into("<IIQH", h, U.SEGMENTS_AT, start, end, 1, pos_pages)
    crc_into(h, 8, 2)
    return h


def build(path: str, formatted: bool = False) -> dict:
    rnd = random.Random(7)
    capacity = DZ_POS + UNITS * BLOCK + U.SUPER_BYTES
    img = bytearray(capacity)
    truth = {"video": {}, "gops": {}, "stale_gop": None}

    sup = bytearray(U.SUPER_BYTES)
    struct.pack_into("<II", sup, 0, U.SUPER_MAGIC, U.SUPER_V2)
    sup[0x0C:0x0C + len(DEVICE_ID)] = DEVICE_ID.encode()
    struct.pack_into("<4I", sup, 0x3C, 0x1234, 0x5678, 0x9ABC, 0xDEF0)
    sup[0x4C:0x4F] = b"001"
    struct.pack_into("<QIIQQQII", sup, 0x60, capacity, UNITS, 0x10000, AZ_POS, DZ_POS,
                     DZ_POS - 0x1000, T0 - 86400, T0)
    crc_into(sup, 8, 4)
    img[0:U.SUPER_BYTES] = sup
    img[capacity - U.SUPER_BYTES:capacity] = sup

    abstract = bytearray(U.GROUP)
    cams = {0: (0, 0, 1, 0), 1: (0, 0, 2, 0)}
    for n, chan in cams.items():
        base = DZ_POS + n * BLOCK
        pos, index, t = 0x80000, [], T0 + n * 600
        payloads = []
        for g in range(3 if n == 0 else 2):
            data, video = gop(rnd, t + g * 2, 40 * g, 5)
            img[base + pos:base + pos + len(data)] = data
            index.append(struct.pack("<IHBxQHH12x", t + g * 2, 40 * g, 0, 1, len(data) // PAGE,
                                     pos // PAGE))
            payloads.append(video)
            pos += len(data)
        truth["video"][n] = b"".join(b"".join(v) for v in payloads)
        truth["gops"][n] = len(index)
        img[base + U.INDEX_AT:base + U.INDEX_AT + 32 * len(index)] = b"".join(index)
        end = t + 2 * (len(index) - 1)
        img[base:base + U.REC_HEADER] = block_header(chan, t, end, len(index), pos // PAGE)
        if n == 1:
            # an older GOP past the write position, from the block's last cycle
            old, _ = gop(rnd, T0 - 86400, 0, 4, audio=False)
            img[base + pos:base + pos + len(old)] = old
            truth["stale_gop"] = base + pos
        e = bytearray(U.ENTRY)
        struct.pack_into("<HxxIQ4III", e, 0, 1, 0x80, 1, *chan, t, end)
        abstract[(n + 1) * U.ENTRY:(n + 2) * U.ENTRY] = e
    # block 2: a snapshot block; block 3: listed, header gone
    struct.pack_into("<II", img, DZ_POS + 2 * BLOCK, U.PIC_MAGIC, 0x100)
    for n in (2, 3):
        struct.pack_into("<HxxI", abstract, (n + 1) * U.ENTRY, 2, 0x80)
        struct.pack_into("<II", abstract, (n + 1) * U.ENTRY + 0x20, T0, T0 + 60)
    crc_into(abstract, 0, 2)
    img[AZ_POS:AZ_POS + U.GROUP] = abstract

    if formatted:
        img[AZ_POS:AZ_POS + U.GROUP] = bytes(U.GROUP)
        for n in range(UNITS):
            b = DZ_POS + n * BLOCK
            img[b:b + U.INDEX_AT + 0x1000] = bytes(U.INDEX_AT + 0x1000)
    with open(path, "wb") as fh:
        fh.write(img)
    return truth

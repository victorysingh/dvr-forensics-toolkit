"""Generate a synthetic Qualvision QVFS-style disk for testing plugins/godrej.py.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  It follows what the
Qualvision firmware's code checks (plugins/godrej.py): a disk head "QVEX",
version 0x00010000, the disk's size in sectors at +0x0C and two (start,
size) regions; frames of a 20-byte head - 00 00 01 and a type 0xE0-0xEB, a
u32 length, a DHTIME, u16 milliseconds - then `length` bytes of payload, the
next head straight after.  The values, the region sizes and the meaning of
the frame types are ours.

Two runs of frames sit in the data region, an hour apart, separated by
random bytes that hold one planted fake head (00 00 01 E3, a valid-looking
length and date) which chains to nothing and must not be taken as footage.
"""

from __future__ import annotations

import random
import struct
from datetime import datetime, timedelta

from tests.synth_dahua import pack_date

SECTOR = 512
TOTAL = 32768                      # 16 MiB
A_START, A_SIZE = 64, 1024         # region A (the firmware's first pair)
B_START, B_SIZE = 2048, 30000      # region B, where frames are written here
VIDEO_TYPES, AUDIO_TYPE = (0xE0, 0xE1), 0xE8


def head() -> bytes:
    h = bytearray(SECTOR)
    struct.pack_into("<4sIII", h, 0, b"QVEX", 0x00010000, 0x51560001, TOTAL)
    struct.pack_into("<IIII", h, 0x10, A_START, A_SIZE, B_START, B_SIZE)
    return bytes(h)


def frame(ftype: int, t: datetime, ms: int, payload: bytes) -> bytes:
    return (struct.pack("<BBBBIIH", 0, 0, 1, ftype, len(payload), pack_date(t), ms)
            + bytes(6) + payload)


def run(rng: random.Random, t0: datetime, frames: int) -> tuple[bytes, dict]:
    out, video, n_video = bytearray(), bytearray(), 0
    for k in range(frames):
        t = t0 + timedelta(milliseconds=40 * k)
        if k % 5 == 4:                                   # audio: no start code
            out += frame(AUDIO_TYPE, t.replace(microsecond=0), t.microsecond // 1000,
                         b"\xff" + rng.randbytes(159))
            continue
        pay = (b"\x00\x00\x00\x01" + (b"\x67" if k % 25 == 0 else b"\x41")
               + rng.randbytes(rng.randint(400, 1500)))
        out += frame(VIDEO_TYPES[0] if k % 25 == 0 else VIDEO_TYPES[1],
                     t.replace(microsecond=0), t.microsecond // 1000, pay)
        video += pay
        n_video += 1
    last = t0 + timedelta(milliseconds=40 * (frames - 1))
    return bytes(out), {"frames": frames, "video_frames": n_video, "video": bytes(video),
                        "first": t0, "last": last.replace(microsecond=0),
                        "last_ms": last.microsecond // 1000}


def build(path: str, seed: int = 5) -> dict:
    rng = random.Random(seed)
    disk = bytearray(TOTAL * SECTOR)
    disk[0:SECTOR] = head()
    r1, t1 = run(rng, datetime(2025, 3, 14, 9, 30, 0), 120)
    r2, t2 = run(rng, datetime(2025, 3, 14, 10, 30, 0), 75)
    at = B_START * SECTOR
    disk[at:at + len(r1)] = r1
    gap = bytearray(rng.randbytes(20000))
    fake = at + len(r1) + 5000
    gap[5000:5020] = struct.pack("<BBBBIIH", 0, 0, 1, 0xE3, 300,
                                 pack_date(datetime(2025, 3, 14, 9, 45)), 10) + bytes(6)
    disk[at + len(r1):at + len(r1) + len(gap)] = gap
    at2 = at + len(r1) + len(gap)
    disk[at2:at2 + len(r2)] = r2
    with open(path, "wb") as fh:
        fh.write(disk)
    return {"runs": [dict(t1, offset=at, bytes=len(r1)), dict(t2, offset=at2, bytes=len(r2))],
            "fake_head_at": fake}

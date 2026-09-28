"""Generate a small disk with a Hikvision master sector and system log.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  The layout is what
parsers/hiklog.py documents as observed on the real drive Z9C2632A: the master
sector with `HIKVISION@HANGZHOU` at +0x10, the log area it points to, and
`RATS` records.  Passing here proves the code handles that layout; it proves
nothing new about Hikvision.  `build()` returns the ground truth.
"""

from __future__ import annotations

import struct

SIZE = 4 << 20
LOG_OFFSET, LOG_SIZE = 0x8200, 0x100000
DATA_OFFSET, BLOCK_SIZE, BLOCK_COUNT = 0x110000, 0x100000, 2
HIKBTREE = (0x3F0000, 0x3F8000)
T0 = 1_700_000_000                      # disk initialised (recorder clock)


def master(log_end: int = LOG_OFFSET + LOG_SIZE) -> bytes:
    m = bytearray(0x200)
    m[0x10:0x22] = b"HIKVISION@HANGZHOU"
    m[0x30:0x3E] = b"HIK.2011.03.08"
    for off, val in ((0x48, SIZE), (0x50, LOG_OFFSET), (0x58, LOG_SIZE), (0x60, log_end),
                     (0x68, 0x7E00), (0x78, DATA_OFFSET), (0x80, BLOCK_SIZE * BLOCK_COUNT),
                     (0x88, BLOCK_SIZE), (0x90, BLOCK_COUNT),
                     (0x98, HIKBTREE[0]), (0xA0, 0x1000), (0xA8, HIKBTREE[1]), (0xB0, 0x1000)):
        struct.pack_into("<Q", m, off, val)
    struct.pack_into("<I", m, 0xF0, T0)
    return bytes(m)


def record(t: int, major: int, minor: int, payload: bytes) -> bytes:
    return b"RATS" + struct.pack("<IIHH", 0x14, t, major, minor) + payload


def user_payload(user: str, n: int = 80) -> bytes:
    return user.encode().ljust(32, b"\x00") + bytes(n - 32)


# (seconds after T0, major, minor, payload): the log the generator writes.
EVENTS = [
    (100, 3, 0x43, bytes(80)),                            # abnormal shutdown
    (160, 3, 0x41, bytes(80)),                            # power on
    (200, 4, 0xA3, bytes(64)),                            # start record
    (5000, 3, 0x50, user_payload("admin")),               # login (local)
    (5001, 3, 0x52, user_payload("admin")),               # configuration (local)
    (5010, 3, 0x54, user_payload("admin", 92)),           # playback by time (local)
    (5900, 3, 0x51, user_payload("admin")),               # logout (local)
    (6000, 4, 0xAA, b"\x00" * 8 + b"Main CVBS\x00HDMI\x00Aux VGA" + bytes(40)),  # undefined
    # a record marker inside a payload, with no real major type: not a record
    (6100, 4, 0xA2, bytes(20) + b"RATS" + struct.pack("<IIHH", 0x14, T0 + 6100, 9, 1) + bytes(40)),
    (9000, 3, 0x43, bytes(80)),
    (9070, 3, 0x41, bytes(80)),
]


def build(path: str, primary: bool = True, backup: bool = True,
          bad_log_end: bool = False) -> dict:
    img = bytearray(SIZE)
    m = master(LOG_OFFSET + LOG_SIZE + (0x1000 if bad_log_end else 0))
    if primary:
        img[0x200:0x400] = m
    if backup:                                  # the copy after the log area
        img[0x108000:0x108200] = m
    pos = LOG_OFFSET
    for dt, major, minor, payload in EVENTS:
        rec = record(T0 + dt, major, minor, payload)
        img[pos:pos + len(rec)] = rec
        pos += len(rec)
    # a well-formed record OUTSIDE the log area, in the data area: ignored
    stray = record(T0 + 7000, 3, 0x5C, user_payload("admin"))
    img[DATA_OFFSET + 0x100:DATA_OFFSET + 0x100 + len(stray)] = stray
    for off in HIKBTREE:
        img[off + 0x10:off + 0x18] = b"HIKBTREE"
    with open(path, "wb") as fh:
        fh.write(img)
    return {"path": path, "records": len(EVENTS),
            "power_on": [T0 + dt for dt, ma, mi, _ in EVENTS if (ma, mi) == (3, 0x41)],
            "user_actions": sum(1 for _, ma, _, p in EVENTS if ma == 3 and p[:5] == b"admin"),
            "t0": T0}

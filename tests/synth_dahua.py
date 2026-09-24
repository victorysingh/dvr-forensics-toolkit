"""Generate a synthetic Dahua DHFS 4.1 image for testing.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  The layout reproduces what
parsers/dahua.py documents as observed on the real SkyHawk disk, so passing
here proves the code handles that layout - it proves nothing new about Dahua.

What it simulates, because each of these broke the parser against real media
at least once:

  * several cameras recording at the same time, each a chain of clusters
    handed out in rotation as clusters fill up;
  * a frame that overflows its cluster being finished in the PHYSICALLY next
    cluster, overwriting the start of whatever camera owns it;
  * an older recording (a month earlier) filling the data area underneath, so
    reused clusters keep stale footage past where the new recording stopped;
  * video, audio and aux frame counters that start apart and never meet, and
    a millisecond clock that wraps.

Small clusters (64 KiB) keep the image to a few MiB.  `build()` returns ground
truth - which frames each camera wrote and which survived - for the tests.
"""

from __future__ import annotations

import os
import random
import struct
from datetime import datetime, timedelta

SECTOR = 512
SECTORS_PER_CLUSTER = 0x80            # 64 KiB clusters
CLUSTER = SECTORS_PER_CLUSTER * SECTOR
DATA_BASE = 0x10000                    # cluster N lives at DATA_BASE + N * CLUSTER
FIRST_DATA_CLUSTER = 4
INDEX_SECTOR = 0x60                    # cluster table at 0xC000
CAPACITY = 64                          # cluster slots
IMAGE_SIZE = DATA_BASE + CAPACITY * CLUSTER

T0 = datetime(2026, 9, 3, 10, 0, 0)    # the recording under test
T_OLD = datetime(2026, 8, 1, 6, 0, 0)  # the older recording underneath

EXT_VIDEO = (bytes([0x80, 0x00, 1920 // 8, 1080 // 8, 0x81, 0x32, 0x0C, 25])
             + bytes([0x88, 1, 2, 3, 4, 0, 0, 0]) + bytes([0xB8, 8, 0, 0, 0, 0, 0, 0]))
EXT_AUDIO = bytes([0x83, 0x01, 0x0E, 0x02]) + bytes([0x88, 1, 2, 3, 4, 0, 0, 0]) + bytes(4)
EXT_AUX = bytes([0x88, 0x0B, 0x73, 0xA5, 0x8F, 0, 0, 0])


def pack_date(dt: datetime) -> int:
    return ((dt.year - 2000) << 26 | dt.month << 22 | dt.day << 17
            | dt.hour << 12 | dt.minute << 6 | dt.second)


def dhav(ftype: int, fn: int, dt: datetime, ms: int, payload: bytes, ext: bytes) -> bytes:
    flen = 24 + len(ext) + len(payload) + 8
    hdr = struct.pack("<4sBBBBIIIHB", b"DHAV", ftype, 1 if ftype == 0xFD else 0,
                      0, 0, fn, flen, pack_date(dt), ms & 0xFFFF, len(ext))
    hdr += bytes([sum(hdr) & 0xFF])
    return hdr + ext + payload + b"dhav" + struct.pack("<I", flen)


class Camera:
    """One stream: its own counters and clock, like a real channel."""

    def __init__(self, n: int, start: datetime, ms0: int, vfn0: int, afn0: int,
                 rng: random.Random):
        self.n, self.t, self.ms = n, start, ms0
        self.vfn, self.afn, self.xfn = vfn0, afn0, 2000 + n
        self.rng = rng
        self.k = 0
        self.force_i = True

    def next_frames(self) -> list[tuple[int, int, datetime, bytes]]:
        """Frames for the next 40 ms tick: (type, counter, date, bytes)."""
        # Order as on the real disk: video first (so a new cluster opens on
        # an I-frame at +0), then the once-a-second aux frame, then audio.
        out = []
        dt = self.t
        is_i = self.force_i or self.k % 50 == 0
        self.force_i = False
        nal = b"\x00\x00\x00\x01" + (b"\x40\x01" if is_i else b"\x02\x01")
        pay = nal + self.rng.randbytes(self.rng.randint(3000, 4000) if is_i
                                       else self.rng.randint(300, 900))
        ftype = 0xFD if is_i else 0xFC
        out.append((ftype, self.vfn, dt, dhav(ftype, self.vfn, dt, self.ms, pay, EXT_VIDEO)))
        self.vfn += 1
        if self.k % 25 == 0:
            out.append((0xF1, self.xfn, dt, dhav(0xF1, self.xfn, dt, self.ms, b"", EXT_AUX)))
            self.xfn += 1
        if self.k % 2 == 0:
            pay = self.rng.randbytes(320)
            out.append((0xF0, self.afn, dt, dhav(0xF0, self.afn, dt, self.ms + 20, pay, EXT_AUDIO)))
            self.afn += 1
        self.k += 1
        self.ms = (self.ms + 40) & 0xFFFF
        if self.k % 25 == 0:
            self.t += timedelta(seconds=1)
        return out


def _record(kind: int, ch: int, a: int, start: int, end: int, nxt: int,
            prev: int, head: int) -> bytes:
    return struct.pack("<BBHIIIIIIHH", kind, 0x30 + ch if ch >= 0 else 0xFE, a,
                       start, end, nxt, 0, prev, head, 0x38, 0)


def build(path: str, seconds: int = 12, cameras: int = 3, seed: int = 26150,
          twins: bool = False) -> dict:
    """`twins=True` gives cameras 1 and 2 identical counters and clocks - the
    worst case, where nothing in the frames themselves tells them apart."""
    rng = random.Random(seed)
    img = bytearray(IMAGE_SIZE)

    # -- the older recording underneath: one continuous stream across the
    #    whole data area, a month before the recording under test.
    old = Camera(9, T_OLD, 5000, 700000, 700050, rng)
    pos = DATA_BASE + FIRST_DATA_CLUSTER * CLUSTER
    while True:
        frames = old.next_frames()
        blob = b"".join(f[3] for f in frames)
        if pos + len(blob) > IMAGE_SIZE:
            break
        img[pos:pos + len(blob)] = blob
        pos += len(blob)

    # -- superblock, partition table (+backup), volume header (+backup)
    img[0:8] = b"DHFS4.1\x00"
    img[0x20:0x20 + 43] = b"uuid:{00000000-0000-4000-8000-00000026150a}"
    img[0x1F4:0x1F8] = b"\xAA\x55\xAA\x55"
    pt = bytearray(0x400)
    e = 0x40
    struct.pack_into("<I", pt, e + 0x08, 0x22)
    struct.pack_into("<I", pt, e + 0x24, 0)
    struct.pack_into("<I", pt, e + 0x2C, IMAGE_SIZE // SECTOR)
    img[0x3C00:0x4000] = pt
    img[0x7C00:0x8000] = pt

    # -- cameras record concurrently; clusters are handed out in rotation
    cams = [Camera(n, T0, [1000, 64000, 30000][n % 3] + n,
                   400000 + 37 * n, 400000 + 37 * n + [3, 150, 300][n % 3], rng)
            for n in range(cameras)]
    if twins and cameras >= 3:
        cams[2] = Camera(2, T0, cams[1].ms, cams[1].vfn, cams[1].afn, rng)
        cams[2].xfn = cams[1].xfn
    next_free = FIRST_DATA_CLUSTER
    heads, chains, cur, fill = {}, {}, {}, {}
    written: dict[int, list[tuple[int, int]]] = {n: [] for n in range(cameras)}
    frame_at: dict[int, tuple[int, int, int]] = {}      # abs offset -> (cam, type, fn)
    windows: dict[int, list] = {}
    for n in range(cameras):
        heads[n] = next_free
        next_free += 1
        chains[n] = []
    for n in range(cameras):                             # the first continuation
        chains[n].append(next_free)
        cur[n], fill[n] = next_free, 0
        next_free += 1

    ticks = seconds * 25
    for _ in range(ticks):
        for cam in cams:
            n = cam.n
            if fill[n] >= CLUSTER - 300:                 # full: take the next cluster
                if next_free >= CAPACITY:
                    continue
                chains[n].append(next_free)
                cur[n], fill[n] = next_free, 0
                next_free += 1
                cam.force_i = True
            for ftype, fn, dt, blob in cam.next_frames():
                c = cur[n]
                off = DATA_BASE + c * CLUSTER + fill[n]
                end = off + len(blob)
                if end > IMAGE_SIZE:
                    break
                # Overflow runs on into the physically next cluster,
                # overwriting its first bytes - whoever owns it.
                for k in [k for k in frame_at if off <= k < end]:
                    del frame_at[k]
                img[off:end] = blob
                frame_at[off] = (n, ftype, fn)
                written[n].append((ftype, fn))
                windows.setdefault(c, []).append(pack_date(dt))
                fill[n] += len(blob)

    # A frame is lost when a later overflow overwrote any byte of it.
    survived: dict[int, set[tuple[int, int]]] = {n: set() for n in range(cameras)}
    owner: dict[int, int] = {}                           # abs offset -> camera
    for off, (n, ftype, fn) in frame_at.items():
        flen = struct.unpack_from("<I", img, off + 12)[0]
        if (img[off:off + 4] == b"DHAV" and img[off + flen - 8:off + flen - 4] == b"dhav"
                and sum(img[off:off + 23]) & 0xFF == img[off + 23]):
            survived[n].add((ftype, fn))
            owner[off] = n

    # -- the cluster table
    table = bytearray(CAPACITY * 32)
    for c in range(FIRST_DATA_CLUSTER):
        table[c * 32] = 0xFE
    for n in range(cameras):
        h = heads[n]
        conts = chains[n]
        first = min(windows[conts[0]])
        last = max(windows[conts[-1]])
        table[h * 32:(h + 1) * 32] = _record(0x01, n, len(conts), first, last,
                                             conts[0], 0, h)
        for i, c in enumerate(conts):
            ws = windows.get(c, [first])
            table[c * 32:(c + 1) * 32] = _record(
                0x02, n, i + 1, min(ws), max(ws),
                conts[i + 1] if i + 1 < len(conts) else 0,
                conts[i - 1] if i else h, h)
    img[INDEX_SECTOR * SECTOR:INDEX_SECTOR * SECTOR + len(table)] = table

    vh = bytearray(512)
    all_dates = [d for ws in windows.values() for d in ws]
    struct.pack_into("<I", vh, 0x10, min(all_dates))
    struct.pack_into("<I", vh, 0x14, max(all_dates))
    struct.pack_into("<I", vh, 0x2C, SECTOR)
    struct.pack_into("<I", vh, 0x30, SECTORS_PER_CLUSTER)
    struct.pack_into("<I", vh, 0x38, FIRST_DATA_CLUSTER)
    struct.pack_into("<I", vh, 0x44, INDEX_SECTOR)
    struct.pack_into("<I", vh, 0x4C, CAPACITY)
    img[0x4400:0x4600] = vh
    img[0x8400:0x8600] = vh

    with open(path, "wb") as fh:
        fh.write(img)
    return {
        "path": path, "cameras": cameras, "data_base": DATA_BASE,
        "heads": heads, "chains": chains, "written": written, "survived": survived,
        "owner": owner,   # every other valid frame on the image is the older recording
        "old_date": T_OLD, "t0": T0,
    }


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "synth_dahua.img"
    meta = build(out)
    print(f"wrote {out} ({os.path.getsize(out)} B), chains {meta['chains']}")

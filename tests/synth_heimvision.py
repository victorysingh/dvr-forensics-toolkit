"""Generate a synthetic HeimVision-style disk for testing plugins/heimvision.py.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Field positions follow
what was observed on the NIST CFReDS HeimVision K9604-W image; the values
are ours, and the disk is small: 4 KiB clusters and 64 KiB .dat files where
the real recorder uses 16 KiB clusters and 8 MiB files.

What it builds: a GPT disk; partition 1 a placeholder; partition 2 FAT32
with ident.bin, index.bin and dir00000 holding FILE0000..FILE0003.DAT.
Files 0-2 hold interleaved frames of 4 cameras (video and audio), file 3 is
pre-allocated and never written, and file 1's clusters are FRAGMENTED so the
cluster chain has to be followed.  FAT write times are the files' Unix end
times minus 8 hours, as on the real disk.
"""

from __future__ import annotations

import random
import struct
from datetime import datetime, timedelta, timezone

SECTOR = 512
SPC = 8                              # 4 KiB clusters
CLUSTER = SECTOR * SPC
FILE_SIZE = 64 << 10                 # clusters per file: 16
P1_LBA, P2_LBA = 2048, 4096
RSV, FATSZ = 32, 16                  # reserved sectors, sectors per FAT (2048 entries)
T0 = 1628085591                      # 2021-08-04 13:59:51 UTC, as on the real disk
ZONE_H = -8


def _gpt(total_sectors: int, parts: list[tuple[int, int]]) -> bytes:
    head = bytearray(34 * SECTOR)
    head[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1,
                                total_sectors - 1)
    head[510:512] = b"\x55\xaa"
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<IIQ", hdr, 8, 0x00010000, 92, 0)
    struct.pack_into("<QQQ", hdr, 24, 1, 34, total_sectors - 34)
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    head[SECTOR:SECTOR + 92] = hdr
    for k, (first, last) in enumerate(parts):
        e = bytearray(128)
        e[0:16] = bytes(range(1 + k, 17 + k))
        struct.pack_into("<QQ", e, 32, first, last)
        e[56:70] = "primary".encode("utf-16-le")
        head[2 * SECTOR + 128 * k:2 * SECTOR + 128 * (k + 1)] = e
    return bytes(head)


def _dirent(name: bytes, attr: int, cluster: int, size: int, written: datetime) -> bytes:
    d = ((written.year - 1980) << 9) | (written.month << 5) | written.day
    t = (written.hour << 11) | (written.minute << 5) | (written.second // 2)
    return (name.ljust(11) + bytes([attr]) + bytes(2) + struct.pack("<HH", t, d) + bytes(2)
            + struct.pack("<HHHHI", cluster >> 16, t, d, cluster & 0xFFFF, size))


def frame(kind: int, ch: int, seq: int, t_us: int, payload: bytes) -> bytes:
    h = bytearray(128)
    h[0:4], h[124:128] = b"liu ", b" uil"
    struct.pack_into("<I", h, 0x04, 0x320BD62F + ch)
    if kind:                                   # video
        struct.pack_into("<IIII", h, 0x08, 1920, 1080, 15, 0xFFFFFFFF)
        h[0x18:0x1C] = b"H265"
    else:
        struct.pack_into("<IIII", h, 0x08, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 8000)
    struct.pack_into("<IIII", h, 0x24, kind, ch + 1, ch, 1)
    struct.pack_into("<II", h, 0x34, seq, 0)
    struct.pack_into("<IQII", h, 0x3C, len(payload), t_us, t_us // 1_000_000, 1)
    return bytes(h) + payload


def build(path: str, seed: int = 9) -> dict:
    rng = random.Random(seed)

    def body(n):
        return rng.randbytes(n).replace(b"\x00", b"\x01")

    truth = {"video": {c: [] for c in range(4)}, "files": []}
    seq = [0] * 4
    datas = []
    t = T0
    for fi in range(3):
        start = t
        out = bytearray()
        per_start, per_end = [0] * 4, [0] * 4
        for step in range(12):                  # 12 ticks x 4 cameras per file
            for c in range(4):
                key = step % 6 == 0
                nal = (b"\x00\x00\x00\x01\x40\x01" + body(20) + b"\x00\x00\x00\x01\x26\x01"
                       + body(300)) if key else b"\x00\x00\x00\x01\x02\x01" + body(80)
                t_us = t * 1_000_000 + step * 66_000 + c
                out += frame(1 if key else 2, c, seq[c], t_us, nal)
                truth["video"][c].append(nal)
                seq[c] += 1
                per_start[c] = per_start[c] or t
                per_end[c] = t + 1
                if step % 3 == 0:
                    out += frame(0, c, seq[c], t_us + 10, b"\xd5" * 64)
            t += 1
        hdr = bytearray(0x2080)
        hdr[0:4] = b"luo "
        struct.pack_into("<II", hdr, 4, start, t)
        struct.pack_into("<I", hdr, 12, 0x2080)
        for c in range(4):
            struct.pack_into("<I", hdr, 0x8C + 4 * c, per_start[c])
            struct.pack_into("<I", hdr, 0x18C + 4 * c, per_end[c])
        data = bytes(hdr) + bytes(out)
        assert len(data) <= FILE_SIZE, len(data)
        datas.append(data + bytes(FILE_SIZE - len(data)))
        truth["files"].append((start, t))
    datas.append(bytes(FILE_SIZE))              # FILE0003: pre-allocated, never written

    # clusters: 2 root, 3 dir00000, 4 ident, 5 index, then files; file 1 fragmented
    n = FILE_SIZE // CLUSTER                     # 16 clusters a file
    chains = {"root": [2], "dir": [3], "ident": [4], "index": [5],
              0: list(range(6, 6 + n)),                                  # 6..21
              1: list(range(22, 22 + n // 2)) + list(range(34, 34 + n // 2)),   # gap 30..33
              2: list(range(42, 42 + n)),                                # 42..57
              3: list(range(58, 58 + n))}                                # 58..73
    total_clusters = 74 + 4
    fat = bytearray(FATSZ * SECTOR)
    struct.pack_into("<II", fat, 0, 0x0FFFFFF8, 0x0FFFFFFF)
    for ch in chains.values():
        for a, b in zip(ch, ch[1:] + [None]):
            struct.pack_into("<I", fat, 4 * a, b if b else 0x0FFFFFFF)

    part = bytearray((RSV + FATSZ) * SECTOR + (total_clusters - 2) * CLUSTER)
    vbr = bytearray(512)
    vbr[3:11] = b"mkdosfs\x00"
    struct.pack_into("<HBHB", vbr, 11, SECTOR, SPC, RSV, 1)
    struct.pack_into("<I", vbr, 36, FATSZ)
    struct.pack_into("<I", vbr, 44, 2)
    vbr[0x52:0x5A] = b"FAT32   "
    vbr[510:512] = b"\x55\xaa"
    part[0:512] = vbr
    part[RSV * SECTOR:RSV * SECTOR + len(fat)] = fat
    data_at = (RSV + FATSZ) * SECTOR

    def put(chain, blob):
        for k, c in enumerate(chain):
            piece = blob[k * CLUSTER:(k + 1) * CLUSTER]
            o = data_at + (c - 2) * CLUSTER
            part[o:o + len(piece)] = piece

    local = lambda u: datetime.fromtimestamp(u, tz=timezone.utc).replace(tzinfo=None) + timedelta(hours=ZONE_H)
    epoch = datetime(1980, 1, 1)
    root = (_dirent(b"IDENT   BIN", 0x20, 4, 16, epoch) + _dirent(b"INDEX   BIN", 0x20, 5, 64, local(t))
            + _dirent(b"DIR00000   ", 0x10, 3, 0, local(T0)))
    put(chains["root"], root)
    put(chains["ident"], b"ok1ormated")
    put(chains["index"], b"x" * 64)
    ents = b"".join(_dirent(f"FILE{k:04d}DAT".encode(), 0x20, chains[k][0], FILE_SIZE,
                            local(truth["files"][k][1]) if k < 3 else epoch)
                    for k in range(4))
    put(chains["dir"], ents)
    for k in range(4):
        put(chains[k], datas[k])

    p1_size, p2_size = (P2_LBA - P1_LBA) * SECTOR, len(part)
    total = P2_LBA * SECTOR + p2_size + (1 << 16)
    head = _gpt(total // SECTOR, [(P1_LBA, P2_LBA - 1), (P2_LBA, P2_LBA + p2_size // SECTOR - 1)])
    with open(path, "wb") as fh:
        fh.write(head + bytes(P2_LBA * SECTOR - len(head)) + bytes(part) + bytes(1 << 16))
    truth["span"] = (T0, t)
    return truth

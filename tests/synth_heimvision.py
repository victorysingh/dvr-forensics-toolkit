"""Generate a synthetic HeimVision-style disk for testing plugins/heimvision.py.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Field positions follow
what was observed on the NIST CFReDS HeimVision K9604-W image; the values
are ours, and the disk is small: 4 KiB clusters and 64 KiB .dat files where
the real recorder uses 16 KiB clusters and 8 MiB files.

What it builds: a GPT disk; partition 2 FAT32 with ident.bin, index.bin
and dir00000 holding FILE0000..FILE0003.DAT.  Files 0-2 hold interleaved
frames of 4 cameras (video and audio), file 3 is pre-allocated and never
written, and file 1's clusters are FRAGMENTED so the cluster chain has to be
followed.  FAT write times are the files' Unix end times minus 8 hours, as
on the real disk.

Partition 1 (unless system=False) is a small ext2 holding the recorder's own
files as on the real disk - dvr_log.db and search.db (real SQLite, the real
schemas), pbversion - plus pad.bin, long enough to need an indirect block.
Their inode times are the recorder's local clock (UTC-8).  Three faults are
planted for the checks to find: search.db gives FILE0002 an end 5 s later
than its header does; the log's 'Rec begin' for CH02 is 2 s after its first
frame; index.bin marks FILE0002 (written) as not complete.
"""

from __future__ import annotations

import os
import random
import sqlite3
import struct
import tempfile
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


EXT_BS = 4096
PAD_BYTES = 60 << 10                 # 15 blocks: past the 12 direct pointers


def _sqlite_bytes(statements: list[tuple[str, tuple]]) -> bytes:
    """A real SQLite database file, built in a temporary directory."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.db")
        con = sqlite3.connect(path)
        for sql, args in statements:
            con.execute(sql, args)
        con.commit()
        con.close()
        with open(path, "rb") as fh:
            return fh.read()


def _ext2(size: int, files: list[tuple[str, bytes, int]], created: int) -> bytes:
    """A minimal ext2: one group, 4 KiB blocks, 128-byte inodes, the files in
    the root directory - 12 direct blocks, then one indirect block."""
    part = bytearray(size)
    sb = bytearray(1024)
    struct.pack_into("<II", sb, 0x00, 32, size // EXT_BS)          # inodes, blocks
    struct.pack_into("<II", sb, 0x14, 0, 2)                        # first data block, 4 KiB
    struct.pack_into("<III", sb, 0x20, 32768, 32768, 32)           # per group
    struct.pack_into("<II", sb, 0x2C, created + 8, created + 8)    # mounted, written
    struct.pack_into("<HH", sb, 0x38, 0xEF53, 1)
    struct.pack_into("<I", sb, 0x40, created)
    struct.pack_into("<I", sb, 0x4C, 1)                            # revision 1
    struct.pack_into("<IH", sb, 0x54, 11, 128)                     # first inode, inode size
    sb[0x88:0x88 + 12] = b"/root/rec/a1"
    struct.pack_into("<I", sb, 0x108, created)
    part[1024:2048] = sb
    part[EXT_BS:EXT_BS + 12] = struct.pack("<III", 2, 3, 4)        # bitmaps, inode table at 4
    free = [5]

    def alloc(n):
        out = list(range(free[0], free[0] + n))
        free[0] += n
        return out

    def inode(number, mode, data, t):
        blocks = alloc(-(-len(data) // EXT_BS))
        for k, b in enumerate(blocks):
            piece = data[k * EXT_BS:(k + 1) * EXT_BS]
            part[b * EXT_BS:b * EXT_BS + len(piece)] = piece
        ind = 0
        if len(blocks) > 12:
            ind = alloc(1)[0]
            rest = blocks[12:]
            part[ind * EXT_BS:ind * EXT_BS + 4 * len(rest)] = struct.pack(f"<{len(rest)}I", *rest)
        raw = bytearray(128)
        struct.pack_into("<HHIIIII", raw, 0, mode, 0, len(data), t, t, t, 0)
        struct.pack_into("<H", raw, 26, 1)
        direct = blocks[:12] + [0] * (12 - len(blocks[:12]))
        struct.pack_into("<15I", raw, 40, *direct, ind, 0, 0)
        o = 4 * EXT_BS + (number - 1) * 128
        part[o:o + 128] = raw

    entries = [(".", 2, 2), ("..", 2, 2)]
    for k, (name, data, t) in enumerate(files):
        inode(12 + k, 0x81A4, data, t)
        entries.append((name, 12 + k, 1))
    root = bytearray()
    for k, (name, number, kind) in enumerate(entries):
        n = name.encode()
        rec = 8 + (len(n) + 3) // 4 * 4
        if k == len(entries) - 1:
            rec = EXT_BS - len(root)
        root += struct.pack("<IHBB", number, rec, len(n), kind) + n + bytes(rec - 8 - len(n))
    inode(2, 0x41ED, bytes(root), created)
    return bytes(part)


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


def build(path: str, seed: int = 9, system: bool = True) -> dict:
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
    put(chains["index"], b"xx" + b"u" * 62)     # FILE0002 written but not marked complete
    ents = b"".join(_dirent(f"FILE{k:04d}DAT".encode(), 0x20, chains[k][0], FILE_SIZE,
                            local(truth["files"][k][1]) if k < 3 else epoch)
                    for k in range(4))
    put(chains["dir"], ents)
    for k in range(4):
        put(chains[k], datas[k])

    p1_size, p2_size = (P2_LBA - P1_LBA) * SECTOR, len(part)
    truth["pad"] = rng.randbytes(PAD_BYTES)
    p1 = _system_partition(p1_size, truth, t) if system else bytes(p1_size)
    total = P2_LBA * SECTOR + p2_size + (1 << 16)
    head = _gpt(total // SECTOR, [(P1_LBA, P2_LBA - 1), (P2_LBA, P2_LBA + p2_size // SECTOR - 1)])
    with open(path, "wb") as fh:
        fh.write(head + bytes(P1_LBA * SECTOR - len(head)) + p1 + bytes(part) + bytes(1 << 16))
    truth["span"] = (T0, t)
    return truth


def _system_partition(size: int, truth: dict, t_end: int) -> bytes:
    """The recorder's own files, as on the real disk's ext3 partition."""
    local = lambda u: u + ZONE_H * 3600          # inode times: the recorder's local clock
    log = [(2, T0 - 3565, "reload environment."), (2, T0 - 3558, "reload environment.")]
    log += [(3, T0 + (2 if c == 1 else 0), f"Rec begin {c},type:1") for c in range(4)]
    log += [(3, t_end, f"Rec stop {c}") for c in range(4)]
    dvr_log = _sqlite_bytes(
        [("CREATE TABLE [dvr_log]([id] integer PRIMARY KEY AUTOINCREMENT, [type] int, "
          "[write_time] int, [log_content] varchar)", ())]
        + [("INSERT INTO dvr_log(type, write_time, log_content) VALUES (?, ?, ?)", r) for r in log])
    search = _sqlite_bytes(
        [("CREATE TABLE [SEARCH]([id] integer PRIMARY KEY AUTOINCREMENT, [session_rnd] int, "
          "[frame_count] int,[frame_total_size] bigint, [channel] int,[type] int, "
          "[start_time] int,[start_hour] int,[start_min] int,[start_sec] int, "
          "[start_folder] int,[start_file] int, [end_time] int,[end_hour] int,[end_min] int,"
          "[end_sec] int, [end_folder] int,[end_file] int)", ()),
         ("CREATE TABLE [DETAIL]([id] integer PRIMARY KEY AUTOINCREMENT, [folder] int,[file] int,"
          "[fs_index] int, [start_time] int,[end_time] int)", ())]
        + [("INSERT INTO SEARCH(session_rnd, frame_count, frame_total_size, channel, type, "
            "start_time, start_folder, start_file, end_time, end_folder, end_file) "
            "VALUES (?, 0, 0, ?, 1, ?, 0, 0, ?, 0, 2)", (0x320BD62F + c, c, T0, t_end))
           for c in range(4)]
        + [("INSERT INTO DETAIL(folder, file, fs_index, start_time, end_time) VALUES (?, ?, ?, ?, ?)",
            (0, k, k, s, e + (5 if k == 2 else 0))) for k, (s, e) in enumerate(truth["files"])])
    created = local(T0 - 3600)
    truth["log"] = log
    return _ext2(size, [("search.db", search, local(t_end)), ("dvr_log.db", dvr_log, local(t_end)),
                        ("pbversion", b"1.0.0.1", created), ("pad.bin", truth["pad"], created)],
                 created)

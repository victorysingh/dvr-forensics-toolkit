"""Generate a synthetic Matrix SATATYA-style disk for testing plugins/matrix.py.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  The tree follows Matrix's
own wiki ("How to Backup recording files from HDD in SATATYA Devices?", V1R1,
2018): <volume>/CameraNN/DD_Mon_YYYY/HH/HH_MM_SS~HH_MM_SS.stm1, with .evnt,
.ifrm and .tmid beside each clip.  The .stm bytes and the filesystem type are
ours: Matrix documents neither.  The volume is ext4 - 4 KiB blocks, 64-bit
group descriptors, every file and directory mapped by extents - built to
exercise parsers/ext3.py: a single extent, a file split in two, a depth-1
extent tree with an index block, and an unwritten extent (reads as zeros).

Recorder clock: clip names are local wall-clock time; inode times are the
kernel's Unix seconds, ZONE_MIN behind (an Indian unit set to IST).  One
fault is planted: a clip filed under an hour folder its own name disagrees
with.
"""

from __future__ import annotations

import random
import struct
from datetime import datetime, timedelta, timezone

from tests.synth_heimvision import SECTOR, _gpt

BS = 4096
BLOCKS = 2048                       # 8 MiB volume
INODES = 128
INODE_SIZE = 256
ITABLE = 4                          # inode table at block 4 (8 blocks)
FIRST_DATA = ITABLE + INODES * INODE_SIZE // BS
ZONE_MIN = 330
P_LBA = 2048


def _stamp(local: datetime) -> int:
    """Kernel seconds for a local wall-clock time on a UTC+ZONE_MIN recorder."""
    return int((local - timedelta(minutes=ZONE_MIN)).replace(tzinfo=timezone.utc).timestamp())


class Ext4:
    def __init__(self):
        self.part = bytearray(BLOCKS * BS)
        self.next_block = FIRST_DATA
        self.next_inode = 11
        self.truth: dict[str, bytes] = {}

    def alloc(self, n: int, gap: int = 0) -> list[int]:
        self.next_block += gap
        out = list(range(self.next_block, self.next_block + n))
        self.next_block += n
        return out

    def _write(self, blocks: list[int], data: bytes) -> None:
        for k, b in enumerate(blocks):
            piece = data[k * BS:(k + 1) * BS]
            self.part[b * BS:b * BS + len(piece)] = piece

    @staticmethod
    def _node(entries: list[bytes], depth: int, maximum: int) -> bytes:
        return struct.pack("<HHHHI", 0xF30A, len(entries), maximum, depth, 0) + b"".join(entries)

    @staticmethod
    def _leaf(logical: int, length: int, phys: int, unwritten: bool = False) -> bytes:
        return struct.pack("<IHHI", logical, length + (32768 if unwritten else 0),
                           phys >> 32, phys & 0xFFFFFFFF)

    def put(self, number: int, mode: int, data: bytes, t: int, layout: str = "one") -> bytes:
        """Write the file; returns its bytes as the filesystem stores them."""
        n = max(1, -(-len(data) // BS))
        if layout == "one":
            blocks = self.alloc(n)
            self._write(blocks, data)
            i_block = self._node([self._leaf(0, n, blocks[0])], 0, 4)
        elif layout == "split":                        # two extents, a gap between
            a = self.alloc(n // 2)
            b = self.alloc(n - n // 2, gap=3)
            self._write(a + b, data)
            i_block = self._node([self._leaf(0, len(a), a[0]),
                                  self._leaf(len(a), len(b), b[0])], 0, 4)
        elif layout == "tree":                         # 5 fragments: needs an index block
            per, leaves, blocks, logical = -(-n // 5), [], [], 0
            while logical < n:
                run = self.alloc(min(per, n - logical), gap=1)
                leaves.append(self._leaf(logical, len(run), run[0]))
                blocks += run
                logical += len(run)
            self._write(blocks, data)
            leaf_block = self.alloc(1)[0]
            node = self._node(leaves, 0, (BS - 12) // 12)
            self.part[leaf_block * BS:leaf_block * BS + len(node)] = node
            i_block = self._node([struct.pack("<IIHH", 0, leaf_block, 0, 0)], 1, 4)
        elif layout == "unwritten":                    # second half allocated, never written
            blocks = self.alloc(n)
            half = n // 2
            self._write(blocks[:half], data[:half * BS])
            i_block = self._node([self._leaf(0, half, blocks[0]),
                                  self._leaf(half, n - half, blocks[half], unwritten=True)], 0, 4)
            data = data[:half * BS] + bytes(len(data) - half * BS)
        else:
            raise ValueError(layout)
        raw = bytearray(INODE_SIZE)
        struct.pack_into("<HHIIIII", raw, 0, mode, 0, len(data) & 0xFFFFFFFF, t, t, t, 0)
        struct.pack_into("<H", raw, 26, 1)
        struct.pack_into("<I", raw, 32, 0x80000)                  # EXTENTS
        raw[40:40 + len(i_block)] = i_block
        struct.pack_into("<I", raw, 108, len(data) >> 32)
        o = ITABLE * BS + (number - 1) * INODE_SIZE
        self.part[o:o + INODE_SIZE] = raw
        return data

    def mkdir(self, number: int, parent: int, children: list[tuple[str, int, int]], t: int) -> None:
        entries = [(".", number, 2), ("..", parent, 2)] + children
        body = bytearray()
        for k, (name, ino, kind) in enumerate(entries):
            nb = name.encode()
            rec = 8 + (len(nb) + 3) // 4 * 4
            if k == len(entries) - 1:
                rec = BS - len(body)
            body += struct.pack("<IHBB", ino, rec, len(nb), kind) + nb + bytes(rec - 8 - len(nb))
        self.put(number, 0x41ED, bytes(body), t)

    def finish(self, t: int) -> bytes:
        sb = bytearray(1024)
        struct.pack_into("<II", sb, 0x00, INODES, BLOCKS)
        struct.pack_into("<II", sb, 0x14, 0, 2)                    # first data block 0, 4 KiB
        struct.pack_into("<III", sb, 0x20, 32768, 32768, INODES)
        struct.pack_into("<II", sb, 0x2C, t, t)
        struct.pack_into("<HH", sb, 0x38, 0xEF53, 1)
        struct.pack_into("<I", sb, 0x4C, 1)
        struct.pack_into("<IH", sb, 0x54, 11, INODE_SIZE)
        struct.pack_into("<III", sb, 0x5C, 0, 0x2 | 0x40 | 0x80, 0)  # filetype, extents, 64bit
        struct.pack_into("<H", sb, 0xFE, 64)                       # descriptor size
        sb[0x88:0x88 + 11] = b"/mnt/sata1\x00"
        self.part[1024:2048] = sb
        gd = bytearray(64)
        struct.pack_into("<III", gd, 0, 2, 3, ITABLE)
        self.part[BS:BS + 64] = gd
        return bytes(self.part)


CLIPS = [  # (volume, camera, day, hour folder, name, sidecars, layout)
    ("RAID0", 1, datetime(2018, 4, 21), 14, "14_47_19~14_59_59.stm1", True, "split"),
    ("RAID0", 1, datetime(2018, 4, 21), 15, "15_00_00~15_12_30.stm1", True, "tree"),
    ("RAID0", 2, datetime(2018, 4, 21), 14, "14_50_02~14_59_59.stm1", False, "one"),
    ("RAID0", 2, datetime(2018, 4, 21), 15, "16_00_00~16_05_00.stm1", True, "unwritten"),  # fault
]


def build(path: str, seed: int = 7) -> dict:
    rng = random.Random(seed)
    fs = Ext4()
    ino = iter(range(11, INODES))
    t0 = _stamp(datetime(2018, 4, 21, 14, 0, 0))
    tree: dict = {}
    truth = {"clips": [], "zone_min": ZONE_MIN}
    for vol, cam, day, hour, name, sidecars, layout in CLIPS:
        start = datetime.strptime(f"{day:%Y-%m-%d} {name[:8]}", "%Y-%m-%d %H_%M_%S")
        end = datetime.strptime(f"{day:%Y-%m-%d} {name[9:17]}", "%Y-%m-%d %H_%M_%S")
        body = b"STM1" + struct.pack("<I", cam) + rng.randbytes(9 * BS + 123)
        n = next(ino)
        stored = fs.put(n, 0x81A4, body, _stamp(end), layout)
        files = [(name, n, 1)]
        if sidecars:
            for ext in (".evnt", ".ifrm", ".tmid"):
                m = next(ino)
                fs.put(m, 0x81A4, rng.randbytes(200), _stamp(end))
                files.append((name.rsplit(".", 1)[0] + ext, m, 1))
        key = (vol, f"Camera{cam:02d}", f"{day:%d_%b_%Y}", f"{hour:02d}")
        tree.setdefault(key, []).extend(files)
        truth["clips"].append({"camera": f"Camera{cam:02d}", "start": start, "end": end,
                               "hour_folder": hour, "bytes": stored, "sidecars": sidecars,
                               "layout": layout})
    # directories: inode numbers assigned top-down, so every ".." is right
    vols = sorted({k[0] for k in tree})
    cams = sorted({k[:2] for k in tree})
    days = sorted({k[:3] for k in tree})
    num = {v: next(ino) for v in vols}
    num.update({c: next(ino) for c in cams})
    num.update({d: next(ino) for d in days})
    num.update({h: next(ino) for h in tree})
    for h, files in tree.items():
        fs.mkdir(num[h], num[h[:3]], files, t0)
    for d in days:
        fs.mkdir(num[d], num[d[:2]], [(h[3], num[h], 2) for h in tree if h[:3] == d], t0)
    for c in cams:
        fs.mkdir(num[c], num[c[0]], [(d[2], num[d], 2) for d in days if d[:2] == c], t0)
    for v in vols:
        fs.mkdir(num[v], 2, [(c[1], num[c], 2) for c in cams if c[0] == v], t0)
    fs.mkdir(2, 2, [(v, num[v], 2) for v in vols], t0)
    part = fs.finish(t0)
    total = P_LBA * SECTOR + len(part) + (1 << 16)
    head = _gpt(total // SECTOR, [(P_LBA, P_LBA + len(part) // SECTOR - 1)])
    with open(path, "wb") as fh:
        fh.write(head + bytes(P_LBA * SECTOR - len(head)) + part + bytes(1 << 16))
    return truth

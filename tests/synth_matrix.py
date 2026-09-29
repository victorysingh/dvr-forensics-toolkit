"""Generate a synthetic Matrix SATATYA disk, built to Matrix's own documents
(plugins/matrix.py): `CameraNN/DD_Mon_YYYY/HH/HH_MM_SS~HH_MM_SS.stm1` with
.evnt, .ifrm and .tmid files beside each recording.

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  The tree follows the
documents; everything else is ours:

  * the filesystem is ext4 in an MBR partition at 1 MiB.  Matrix does not
    say which filesystem it uses;
  * the .stm contents are made up: a 64-byte header, then H.264 or H.265 NAL
    units with 16 bytes of our own "container" between them.  The real .stm
    format is not published;
  * the sidecars hold made-up bytes.

`layout` puts the filesystem somewhere else: "raid1" in a Linux md RAID 1
member (superblock v1.2 at 4 KiB, data at 1 MiB), "raid0" in a RAID 0 member
(which cannot be read from one disk), "xfs" replaces it with an XFS
superblock.
"""

from __future__ import annotations

import random
import struct

from tests.synth_ext4 import Ext4

PART_AT = 1 << 20
FS_BLOCKS = 6000
T0 = 1524322039                       # 2018-04-21 14:47:19, the documents' example


def _picture(rnd: random.Random, codec: str, key: bool) -> bytes:
    if codec == "h264":
        nals = ([b"\x67" + rnd.randbytes(10), b"\x68" + rnd.randbytes(4)] if key else []) \
            + [bytes([0x65 if key else 0x41, 0x88]) + rnd.randbytes(700 if key else 200)]
    else:
        nals = ([b"\x40\x01" + rnd.randbytes(20), b"\x42\x01" + rnd.randbytes(30),
                 b"\x44\x01" + rnd.randbytes(6)] if key else []) \
            + [bytes([0x26 if key else 0x02, 0x01, 0xAF]) + rnd.randbytes(700 if key else 200)]
    return b"".join(b"\x00\x00\x00\x01" + n for n in nals)


def stm(rnd: random.Random, codec: str, frames: int) -> bytes:
    out = bytearray(b"STMHDR" + bytes(57) + b"\xff")
    for f in range(frames):
        out += rnd.randbytes(16) + _picture(rnd, codec, f % 10 == 0)
    return bytes(out)


def _mbr(start: int, sectors: int) -> bytes:
    m = bytearray(512)
    struct.pack_into("<B3sB3sII", m, 446, 0, b"\x00\x02\x00", 0x83, b"\xff\xff\xff",
                     start // 512, sectors)
    m[510:512] = b"\x55\xaa"
    return bytes(m)


def _md(level: int, disks: int, data_offset: int) -> bytes:
    sb = bytearray(256)
    struct.pack_into("<II", sb, 0, 0xA92B4EFC, 1)
    sb[32:32 + 9] = b"satatya:0"
    struct.pack_into("<i", sb, 72, level)
    struct.pack_into("<I", sb, 92, disks)
    struct.pack_into("<Q", sb, 128, data_offset // 512)
    return bytes(sb)


def build(path: str, layout: str = "plain") -> dict:
    rnd = random.Random(11)
    fs = Ext4(FS_BLOCKS, label="HDD1", created=T0 - 86400)
    truth = {"files": {}, "sidecars": {}}
    plan = [("Camera01", "h264", "21_Apr_2018", "14", "14_47_19~14_59_59", 60, 4),
            ("Camera01", "h264", "21_Apr_2018", "15", "15_00_00~15_12_30", 40, 1),
            ("Camera02", "h265", "21_Apr_2018", "14", "14_47_20~14_59_59", 50, 3)]
    for cam, codec, day, hour, stem, frames, frags in plan:
        data = stm(rnd, codec, frames)
        p = f"{cam}/{day}/{hour}/{stem}.stm1"
        fs.add_file(p, data, T0 + len(truth["files"]) * 60, fragments=frags)
        truth["files"][p] = data
        for ext in (".evnt", ".ifrm", ".tmid"):
            side = rnd.randbytes(96)
            fs.add_file(f"{cam}/{day}/{hour}/{stem}{ext}", side, T0)
            truth["sidecars"][f"{cam}/{day}/{hour}/{stem}{ext}"] = side
    fs.add_file("Camera01/21_Apr_2018/14/notes.dat", b"unrelated", T0)
    image = fs.build()

    inner = 0 if layout in ("plain", "xfs") else 1 << 20
    part = bytearray(inner + len(image))
    part[inner:] = image
    if layout in ("raid1", "raid0"):
        part[0x1000:0x1100] = _md(1 if layout == "raid1" else 0, 2, inner)
    if layout == "xfs":
        part[:len(part)] = bytes(len(part))
        part[0:4] = b"XFSB"
    img = bytearray(PART_AT + len(part))
    img[0:512] = _mbr(PART_AT, len(part) // 512)
    img[PART_AT:] = part
    with open(path, "wb") as fh:
        fh.write(img)
    truth["fs_at"] = PART_AT + inner
    return truth

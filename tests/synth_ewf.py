"""Write an EnCase-6-style E01 set for testing acquire/ewf.py.

Built to the libyal EWF description, like the reader.  Passing against it
shows the reader handles that layout: segments, compressed and stored
chunks, a short last chunk, the hash and digest sections.  It does not show
the reader matches a real acquisition tool - that is what `ewf-info
--verify` on a real E01 is for, where the image's own stored MD5 decides.
"""

from __future__ import annotations

import hashlib
import struct
import zlib

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


def _adler(b: bytes) -> bytes:
    return struct.pack("<I", zlib.adler32(b) & 0xFFFFFFFF)


def _descriptor(kind: str, nxt: int, size: int) -> bytes:
    d = kind.encode("ascii").ljust(16, b"\x00") + struct.pack("<QQ", nxt, size) + bytes(40)
    return d + _adler(d)


def _ext(n: int, upper: bool = True) -> str:
    e = f"E{n:02d}"
    return e if upper else e.lower()


def write(base: str, media: bytes, sectors_per_chunk: int = 64, bytes_per_sector: int = 512,
          chunks_per_segment: int = 0) -> list[str]:
    """`base` without extension; returns the segment paths written."""
    assert len(media) % bytes_per_sector == 0
    cs = sectors_per_chunk * bytes_per_sector
    chunks = [media[i:i + cs] for i in range(0, len(media), cs)]
    per = chunks_per_segment or len(chunks) or 1
    groups = [chunks[i:i + per] for i in range(0, len(chunks), per)] or [[]]
    paths = []
    for si, group in enumerate(groups, start=1):
        buf = bytearray(SIGNATURE + b"\x01" + struct.pack("<H", si) + b"\x00\x00")
        sections = []                                  # (kind, data) in order
        if si == 1:
            sections.append(("header", zlib.compress(b"1\r\nmain\r\nc\tn\ta\te\tt\r\nTEST\r\n")))
            vol = bytearray(1052)
            vol[0] = 0x01
            struct.pack_into("<IIIQ", vol, 4, len(chunks), sectors_per_chunk,
                             bytes_per_sector, len(media) // bytes_per_sector)
            vol[1048:1052] = _adler(bytes(vol[:1048]))
            sections.append(("volume", bytes(vol)))
        # sectors: each chunk compressed where that helps, else stored + Adler-32
        stored, flags = [], []
        for c in group:
            z = zlib.compress(c, 6)
            if len(z) < len(c):
                stored.append(z)
                flags.append(True)
            else:
                stored.append(c + _adler(c))
                flags.append(False)
        sections.append(("sectors", b"".join(stored)))
        sections.append(("table", None))               # filled once offsets are known
        sections.append(("table2", None))
        last = si == len(groups)
        if last:
            md5 = hashlib.md5(media).digest()
            sections.append(("hash", md5 + bytes(16) + _adler(md5 + bytes(16))))
            dg = md5 + hashlib.sha1(media).digest() + bytes(40)
            sections.append(("digest", dg + _adler(dg)))
        sections.append(("done" if last else "next", b""))

        pos = len(buf)
        layout = []
        sectors_data_at = None
        for kind, data in sections:
            if kind in ("table", "table2"):
                base_off = sectors_data_at
                offs, o = [], 0
                for z, fl in zip(stored, flags):
                    offs.append(o | (0x80000000 if fl else 0))
                    o += len(z)
                head = struct.pack("<IIQI", len(offs), 0, base_off, 0)
                head += _adler(head)
                ent = struct.pack(f"<{len(offs)}I", *offs)
                data = head + ent + _adler(ent)
            if kind == "sectors":
                sectors_data_at = pos + 76
            layout.append((kind, pos, data))
            pos += 76 + len(data)
        for k, (kind, at, data) in enumerate(layout):
            nxt = layout[k + 1][1] if k + 1 < len(layout) else at
            buf += _descriptor(kind, nxt, 76 + len(data)) + data
        path = f"{base}.{_ext(si)}"
        with open(path, "wb") as fh:
            fh.write(bytes(buf))
        paths.append(path)
    return paths

"""EnCase / Expert Witness (.E01) images, read directly - stdlib only.

Forensic labs and public datasets (NIST CFReDS included) ship disk images as
E01 files: the media cut into chunks, most chunks zlib-compressed, spread
over segment files E01, E02, ...  This reads them so that every command
works on an E01 exactly as on a raw image: `BlockDevice` hands reads here
when a file starts with the EWF signature.

FORMAT (libyal, "Expert Witness Compression Format (EWF)"; EnCase 6 layout)
--------------------------------------------------------------------------
  * each segment starts with a 13-byte header: "EVF\\t\\r\\n\\xff\\x00", 0x01,
    the segment number (u16), 0x0000;
  * then a chain of sections, each opened by a 76-byte descriptor: type (16
    bytes), offset of the next section (u64), size (u64), 40 bytes padding,
    Adler-32 of the first 72 bytes;
  * `volume` (or `disk`): number of chunks, sectors per chunk, bytes per
    sector, number of sectors;
  * `sectors`: the chunk data;  `table` (and its copy `table2`): a 24-byte
    header (entry count; base offset at +8) and one u32 per chunk - offset
    from the base, top bit set when the chunk is compressed;
  * compressed chunks are zlib streams; stored chunks carry an Adler-32
    after the data;
  * `hash`: MD5 of the media; `digest`: MD5 and SHA-1; `next` / `done` end
    a segment.

THE IMAGE CHECKS ITSELF
-----------------------
An E01 carries the MD5 of the media it holds.  `verify()` reads every chunk
and compares: a match proves this reader decoded that image correctly, with
no other reference - which is how the reader is validated on real files.

Read-only: segment files are opened "rb" and nothing is ever written.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zlib
from array import array
from collections import OrderedDict
from typing import Optional

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
DESCRIPTOR = 76
CACHE_CHUNKS = 16


class EwfError(IOError):
    pass


def is_ewf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == SIGNATURE
    except OSError:
        return False


def segment_paths(first: str) -> list[str]:
    """E01, E02 ... E99, EAA ... EZZ, FAA ... - the siblings that exist."""
    base, ext = os.path.splitext(first)
    m = re.fullmatch(r"\.([A-Za-z])(\d\d)", ext)
    if not m:
        return [first]
    letter, upper = m.group(1), ext[1].isupper()
    out, n = [], 1
    while True:
        if n <= 99:
            e = f"{letter}{n:02d}"
        else:
            k = n - 100
            first_ch = chr(ord(letter.upper()) + k // 676)
            if first_ch > "Z":
                break
            e = f"{first_ch}{chr(65 + (k // 26) % 26)}{chr(65 + k % 26)}"
        e = e.upper() if upper else e.lower()
        p = f"{base}.{e}"
        if not os.path.exists(p):
            break
        out.append(p)
        n += 1
    return out or [first]


class ChunkTable:
    """Where every chunk lives, in typed arrays: 15 bytes a chunk.  A list
    of tuples held the 4.58 M chunks of a real 150 GB image in ~580 MB
    (this holds them in 69 MB), and would need gigabytes for a 2 TB disk.
    Reads back as (segment, offset, size, compressed) tuples, like the list
    it replaced."""

    def __init__(self):
        self.seg, self.off = array("H"), array("Q")
        self.size, self.comp = array("I"), array("B")

    def extend(self, seg: int, offsets, sizes, compressed) -> None:
        """One table's chunks, all in segment `seg`."""
        self.seg.extend([seg] * len(offsets))
        self.off.extend(offsets)
        self.size.extend(sizes)
        self.comp.extend(compressed)

    def __len__(self) -> int:
        return len(self.off)

    def __getitem__(self, k: int) -> tuple[int, int, int, bool]:
        return self.seg[k], self.off[k], self.size[k], bool(self.comp[k])

    def __iter__(self):
        for k in range(len(self.off)):
            yield self[k]


class EwfImage:
    """The media inside an E01 set, as bytes at offsets."""

    def __init__(self, path: str):
        self.paths = segment_paths(path)
        self.files = [open(p, "rb") for p in self.paths]
        self.chunks = ChunkTable()                  # (segment, offset, size, compressed)
        self.bytes_per_sector = 512
        self.sectors_per_chunk = 64
        self.sectors = 0
        self.stored_md5: Optional[str] = None
        self.stored_sha1: Optional[str] = None
        self.sections: list[tuple[int, str, int, int]] = []
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        try:
            for i, fh in enumerate(self.files):
                self._read_segment(i, fh)
        except Exception:
            self.close()
            raise
        if not self.sectors:
            self.close()
            raise EwfError(f"{path}: no volume section - not a usable E01")

    @property
    def chunk_size(self) -> int:
        return self.sectors_per_chunk * self.bytes_per_sector

    @property
    def size_bytes(self) -> int:
        return self.sectors * self.bytes_per_sector

    def close(self) -> None:
        for fh in self.files:
            fh.close()
        self.files = []

    # -- structure ----------------------------------------------------------
    def _read_segment(self, seg: int, fh) -> None:
        head = fh.read(13)
        if head[:8] != SIGNATURE:
            raise EwfError(f"{self.paths[seg]}: not an EWF segment")
        size = os.fstat(fh.fileno()).st_size
        pos, sectors_range, seen = 13, None, set()
        while pos + DESCRIPTOR <= size and pos not in seen:
            seen.add(pos)
            fh.seek(pos)
            d = fh.read(DESCRIPTOR)
            if zlib.adler32(d[:72]) & 0xFFFFFFFF != struct.unpack_from("<I", d, 72)[0]:
                raise EwfError(f"{self.paths[seg]}: section descriptor at {pos} fails its "
                               f"checksum")
            kind = d[:16].rstrip(b"\x00").decode("ascii", "replace")
            nxt, length = struct.unpack_from("<QQ", d, 16)
            self.sections.append((seg, kind, pos, length))
            body = pos + DESCRIPTOR
            if kind in ("volume", "disk"):
                fh.seek(body)
                self._volume(fh.read(min(1052, max(0, length - DESCRIPTOR))))
            elif kind == "sectors":
                sectors_range = (body, pos + length)
            elif kind == "table":
                fh.seek(body)
                self._table(seg, fh, pos, sectors_range)
            elif kind == "hash":
                fh.seek(body)
                self.stored_md5 = fh.read(16).hex()
            elif kind == "digest":
                fh.seek(body)
                v = fh.read(36)
                self.stored_md5, self.stored_sha1 = v[:16].hex(), v[16:36].hex()
            if kind in ("done", "next") or nxt == pos or nxt == 0:
                break
            pos = nxt

    def _volume(self, v: bytes) -> None:
        if len(v) >= 24:
            self.sectors_per_chunk = struct.unpack_from("<I", v, 8)[0] or 64
            self.bytes_per_sector = struct.unpack_from("<I", v, 12)[0] or 512
            self.sectors = (struct.unpack_from("<Q", v, 16)[0] if len(v) >= 1052
                            else struct.unpack_from("<I", v, 16)[0])

    def _table(self, seg: int, fh, table_pos: int, sectors_range) -> None:
        hdr = fh.read(24)
        count, = struct.unpack_from("<I", hdr, 0)
        base, = struct.unpack_from("<Q", hdr, 8)
        entries = struct.unpack(f"<{count}I", fh.read(4 * count))
        offsets = [(e & 0x7FFFFFFF) + base for e in entries]
        flags = [e >> 31 for e in entries]
        # Each chunk runs to the next; the last to the end of the sectors
        # data (or, in older layouts with no sectors section, to this table).
        end = sectors_range[1] if sectors_range else table_pos
        sizes = [b - a for a, b in zip(offsets, offsets[1:] + [end])]
        self.chunks.extend(seg, offsets, sizes, flags)

    # -- data -------------------------------------------------------------
    def _chunk(self, k: int) -> bytes:
        hit = self._cache.get(k)
        if hit is not None:
            self._cache.move_to_end(k)
            return hit
        seg, off, size, compressed = self.chunks[k]
        fh = self.files[seg]
        fh.seek(off)
        raw = fh.read(size)
        want = min(self.chunk_size, self.size_bytes - k * self.chunk_size)
        if compressed:
            try:
                data = zlib.decompress(raw)
            except zlib.error as exc:
                raise EwfError(f"chunk {k}: {exc}") from exc
        else:
            data = raw[:want]
            stored = raw[want:want + 4]
            if len(stored) == 4 and zlib.adler32(data) & 0xFFFFFFFF != struct.unpack("<I", stored)[0]:
                raise EwfError(f"chunk {k}: stored data fails its Adler-32")
        if len(data) < want:
            raise EwfError(f"chunk {k}: {len(data)} bytes, expected {want}")
        data = data[:want]
        self._cache[k] = data
        if len(self._cache) > CACHE_CHUNKS:
            self._cache.popitem(last=False)
        return data

    def read(self, offset: int, length: int) -> bytes:
        """Up to `length` bytes of the media at `offset`; fewer only at its end."""
        end = min(offset + length, self.size_bytes)
        out = bytearray()
        cs = self.chunk_size
        while offset < end:
            k = offset // cs
            if k >= len(self.chunks):
                raise EwfError(f"offset {offset}: chunk {k} missing from the table")
            c = self._chunk(k)
            rel = offset - k * cs
            piece = c[rel:rel + (end - offset)]
            out += piece
            offset += len(piece)
        return bytes(out)

    def verify(self, progress=None) -> dict:
        """Read every chunk; compare the media's MD5 (and SHA-1) with the
        values the image stores."""
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        step = self.chunk_size * 256
        for off in range(0, self.size_bytes, step):
            b = self.read(off, step)
            md5.update(b)
            sha1.update(b)
            if progress:
                progress(off + len(b), self.size_bytes)
        got = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest()}
        return {"computed": got, "stored": {"md5": self.stored_md5, "sha1": self.stored_sha1},
                "md5_match": (got["md5"] == self.stored_md5) if self.stored_md5 else None,
                "sha1_match": (got["sha1"] == self.stored_sha1) if self.stored_sha1 else None}

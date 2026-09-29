"""ext2 / ext3 / ext4, read-only and minimal: list a directory, read its files.

Linux-based recorders keep files on ext filesystems: their own system files
beside the video (the HeimVision K9604-W: `plugins/heimvision.py`), or the
recordings themselves (Matrix SATATYA: `plugins/matrix.py`).  This reads
enough of the format to list a directory, read a file, and say where on the
disk each of its bytes lies - through `dev.read_at` only.

FORMAT (the kernel's ext2/ext4 layout, as documented in e2fsprogs and the
kernel's Documentation/filesystems/ext4)
-----------------------------------------------------------------------------
  * superblock at byte 1024 of the partition: magic 0xEF53 at +0x38, block
    size 1024 << (+0x18), blocks and inodes per group (+0x20, +0x28), first
    data block (+0x14), inode size (+0x58; 128 on revision 0), incompatible
    features (+0x60), group descriptor size (+0xFE, with the 64bit feature),
    times, the last mount point;
  * group descriptors in the block after the superblock's, 32 bytes each (or
    the descriptor size, with 64bit): the inode table's block at +8, its
    high half at +0x28;
  * an inode: mode, size, atime/ctime/mtime (Unix seconds, as the kernel's
    clock read), flags at +0x20, and 60 bytes at +0x28 that hold either 15
    block pointers - 12 direct, then single, double and triple indirect - or
    (flag 0x80000) an extent tree: a 12-byte header (magic 0xF30A, entries,
    max, depth) and 12-byte entries - leaves (first logical block, length,
    start block) at depth 0, indexes (first logical block, child block)
    above.  An extent longer than 32768 is allocated but not written, and
    reads as zeros;
  * a directory: records of (inode u32, record length u16, name length u8,
    type u8, name).  An indexed (htree) directory keeps the same records, so
    reading it in order is enough.

Refused rather than read wrongly: an extent flag without an extent header,
inline data, encrypted or compressed filesystems, and the meta_bg layout of
group descriptors.  Inode times are whatever the recorder's kernel clock
said - often local time, not UTC - so they are reported raw, never converted.
"""

from __future__ import annotations

import struct
from typing import Optional

MAGIC = 0xEF53
EXTENTS = 0x80000                  # inode flag: extent tree in i_block
INLINE_DATA = 0x10000000           # inode flag: data inside the inode
EXTENT_MAGIC = 0xF30A
UNWRITTEN = 32768                  # an extent length over this is allocated, not written
ROOT = 2

INCOMPAT_COMPRESSION = 0x1
INCOMPAT_META_BG = 0x10
INCOMPAT_EXTENTS = 0x40
INCOMPAT_64BIT = 0x80
INCOMPAT_ENCRYPT = 0x10000
COMPAT_JOURNAL = 0x4
REFUSED = {INCOMPAT_COMPRESSION: "compression", INCOMPAT_META_BG: "meta_bg descriptors",
           INCOMPAT_ENCRYPT: "encryption"}


class ExtError(ValueError):
    pass


class Ext:
    def __init__(self, dev, start: int):
        self.dev, self.start = dev, start
        sb = dev.read_at(start + 1024, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != MAGIC:
            raise ExtError(f"no ext2/3/4 superblock at 0x{start + 1024:X}")
        log_bs = struct.unpack_from("<I", sb, 0x18)[0]
        if log_bs > 6:
            raise ExtError(f"implausible block size 1024 << {log_bs}")
        self.block_size = 1024 << log_bs
        self.first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, 0x20)[0] or 1
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0] or 1
        revision = struct.unpack_from("<I", sb, 0x4C)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0] if revision else 128
        compat, incompat = struct.unpack_from("<I", sb, 0x5C)[0], struct.unpack_from("<I", sb, 0x60)[0]
        refused = [name for bit, name in REFUSED.items() if incompat & bit]
        if refused:
            raise ExtError(f"ext filesystem with {', '.join(refused)} - not read")
        self.desc_size = 32
        if incompat & INCOMPAT_64BIT:
            self.desc_size = max(32, struct.unpack_from("<H", sb, 0xFE)[0])
        self.kind = ("ext4" if incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT)
                     else "ext3" if compat & COMPAT_JOURNAL else "ext2")
        self.blocks_count = struct.unpack_from("<I", sb, 0x04)[0]
        if incompat & INCOMPAT_64BIT:
            self.blocks_count |= struct.unpack_from("<I", sb, 0x150)[0] << 32
        self.label = sb[0x78:0x88].rstrip(b"\x00").decode("utf-8", "replace")
        self.last_mounted_on = sb[0x88:0xC8].rstrip(b"\x00").decode("utf-8", "replace")
        self.times = {name: struct.unpack_from("<I", sb, off)[0] for name, off in
                      (("mounted", 0x2C), ("written", 0x30), ("checked", 0x40),
                       ("created", 0x108))}

    def _block(self, n: int) -> bytes:
        return self.dev.read_at(self.start + n * self.block_size, self.block_size)

    def inode(self, number: int) -> dict:
        group, index = divmod(number - 1, self.inodes_per_group)
        gd_at = self.start + (self.first_data_block + 1) * self.block_size + group * self.desc_size
        gd = self.dev.read_at(gd_at, self.desc_size)
        table = struct.unpack_from("<I", gd, 8)[0]
        if self.desc_size >= 64:
            table |= struct.unpack_from("<I", gd, 0x28)[0] << 32
        raw = self.dev.read_at(self.start + table * self.block_size + index * self.inode_size, 128)
        mode, _, size, atime, ctime, mtime, dtime = struct.unpack_from("<HHIIIII", raw, 0)
        if mode & 0xF000 == 0x8000:
            size |= struct.unpack_from("<I", raw, 108)[0] << 32
        return {"number": number, "mode": mode, "size": size, "atime": atime, "ctime": ctime,
                "mtime": mtime, "dtime": dtime, "flags": struct.unpack_from("<I", raw, 32)[0],
                "blocks": struct.unpack_from("<15I", raw, 40), "i_block": bytes(raw[40:100])}

    # -- where the data is ------------------------------------------------------
    def _pointers(self, block: int, depth: int, want: int) -> list[int]:
        """Up to `want` data block numbers under an indirect block."""
        per = self.block_size // 4
        if not block:
            return [0] * min(want, per ** depth)
        ptrs = struct.unpack(f"<{per}I", self._block(block))
        if depth == 1:
            return list(ptrs[:want])
        out: list[int] = []
        for p in ptrs:
            if len(out) >= want:
                break
            out += self._pointers(p, depth - 1, want - len(out))
        return out

    def _extent_node(self, node: bytes, depth_left: int, out: list) -> None:
        magic, entries, _max, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != EXTENT_MAGIC:
            raise ExtError("extent flag set but no extent header - not read")
        if depth > depth_left or 12 + 12 * entries > len(node):
            raise ExtError("implausible extent tree - not read")
        for i in range(entries):
            e = 12 + 12 * i
            if depth == 0:
                lblk, length, hi, lo = struct.unpack_from("<IHHI", node, e)
                written = length <= UNWRITTEN
                out.append((lblk, (hi << 32) | lo, length if written else length - UNWRITTEN,
                            written))
            else:
                lblk, leaf_lo, leaf_hi = struct.unpack_from("<IIH", node, e)
                self._extent_node(self._block((leaf_hi << 32) | leaf_lo), depth - 1, out)

    def extents(self, ino: dict) -> Optional[list[tuple[int, int, int, bool]]]:
        """(first logical block, first disk block, blocks, written) per
        extent, in logical order; None for a block-map (ext2/3) inode."""
        if ino["flags"] & INLINE_DATA:
            raise ExtError(f"inode {ino['number']} keeps its data inline - not read")
        if not ino["flags"] & EXTENTS:
            return None
        out: list = []
        self._extent_node(ino["i_block"], 5, out)
        return sorted(out)

    def data_blocks(self, ino: dict) -> list[int]:
        """The disk block of every logical block of the file; 0 = a hole, or
        an allocated but unwritten block (both read as zeros)."""
        want = -(-ino["size"] // self.block_size)
        ext = self.extents(ino)
        if ext is not None:
            out = [0] * want
            for lblk, pblk, n, written in ext:
                if written:
                    for k in range(max(0, min(n, want - lblk))):
                        out[lblk + k] = pblk + k
            return out
        b = ino["blocks"]
        out = list(b[:12])[:want]
        for depth, ptr in ((1, b[12]), (2, b[13]), (3, b[14])):
            if len(out) >= want:
                break
            out += self._pointers(ptr, depth, want - len(out))
        return out

    def byte_runs(self, ino: dict) -> list[tuple[int, int, int]]:
        """(offset in the file, absolute offset on the device, bytes) for
        every written stretch of the file, in file order, adjacent blocks
        joined; holes and unwritten extents are left out."""
        runs: list[list[int]] = []
        for k, blk in enumerate(self.data_blocks(ino)):
            if not blk:
                continue
            f, d = k * self.block_size, self.start + blk * self.block_size
            if runs and runs[-1][0] + runs[-1][2] == f and runs[-1][1] + runs[-1][2] == d:
                runs[-1][2] += self.block_size
            else:
                runs.append([f, d, self.block_size])
        out = []
        for f, d, n in runs:
            n = min(n, ino["size"] - f)
            if n > 0:
                out.append((f, d, n))
        return out

    def read(self, ino: dict, limit: Optional[int] = None) -> bytes:
        """The file's bytes (the first `limit` of them); a hole reads as zeros."""
        size = ino["size"] if limit is None else min(ino["size"], limit)
        out = bytearray(size)
        for f, d, n in self.byte_runs(ino):
            if f >= size:
                break
            n = min(n, size - f)
            out[f:f + n] = self.dev.read_at(d, n)
        return bytes(out)

    def listdir(self, number: int = ROOT) -> list[dict]:
        """Every entry of a directory but '.' and '..', with its inode."""
        data, pos, out = self.read(self.inode(number)), 0, []
        while pos + 8 <= len(data):
            ino, rec_len, name_len, _ = struct.unpack_from("<IHBB", data, pos)
            if rec_len < 8:
                break
            name = data[pos + 8:pos + 8 + name_len].decode("utf-8", "replace")
            if ino and name not in (".", ".."):
                entry = self.inode(ino)
                entry["name"] = name
                entry["kind"] = {0x4000: "dir", 0x8000: "file", 0xA000: "link"}.get(
                    entry["mode"] & 0xF000, "other")
                out.append(entry)
            pos += rec_len
        return out

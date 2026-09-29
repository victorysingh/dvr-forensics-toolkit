"""ext2 / ext3 / ext4, read-only and minimal: list a directory, read its files.

Linux-based recorders keep their own system files - the event log, the
recording index, settings - on a small ext partition beside the video (the
HeimVision K9604-W does: `plugins/heimvision.py`).  This reads enough of
ext2/ext3 to list a directory and copy its files out, with their inode
times, through `dev.read_at` only.

FORMAT (the kernel's ext2 layout, as documented in e2fsprogs)
-------------------------------------------------------------
  * superblock at byte 1024 of the partition: magic 0xEF53 at +0x38, block
    size 1024 << (+0x18), inodes per group (+0x28), first data block (+0x14),
    inode size (+0x58; 128 on revision 0), times, the last mount point;
  * group descriptors in the block after the superblock's, 32 bytes each:
    the inode table's block at +8;
  * an inode: mode, size, atime/ctime/mtime (Unix seconds, as the kernel's
    clock read), and 15 block pointers - 12 direct, then single, double and
    triple indirect blocks of pointers;
  * a directory: records of (inode u32, record length u16, name length u8,
    type u8, name).

ext4, read-only (added for recorders that keep footage as files, e.g.
plugins/matrix.py):
  * 64-bit group descriptors when INCOMPAT_64BIT (0x80) is set: their size
    at superblock +0xFE, the inode table's high 32 bits at descriptor +0x28;
  * extents (inode flag 0x80000): the 60-byte block area holds an extent
    tree - a 12-byte header (magic 0xF30A, entries, max, depth) and 12-byte
    entries; a leaf maps (logical block, length, physical block), an index
    points at the next level's block.  A length above 32768 marks an
    unwritten extent, which reads as zeros, as the kernel does.  Every node's
    magic, depth and entry count is checked; a tree that fails is refused.
  * inline data (inode flag 0x10000000) is refused, not guessed.

Inode times are whatever the recorder's kernel clock said - often local
time, not UTC - so they are reported raw, never converted.
"""

from __future__ import annotations

import struct

MAGIC = 0xEF53
EXTENTS = 0x80000
INLINE_DATA = 0x10000000
EXTENT_MAGIC = 0xF30A
INCOMPAT_64BIT = 0x80
ROOT = 2


class ExtError(ValueError):
    pass


class Ext:
    def __init__(self, dev, start: int):
        self.dev, self.start = dev, start
        sb = dev.read_at(start + 1024, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != MAGIC:
            raise ExtError(f"no ext2/3 superblock at 0x{start + 1024:X}")
        log_bs = struct.unpack_from("<I", sb, 0x18)[0]
        if log_bs > 6:
            raise ExtError(f"implausible block size 1024 << {log_bs}")
        self.block_size = 1024 << log_bs
        self.first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0] or 1
        revision = struct.unpack_from("<I", sb, 0x4C)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0] if revision else 128
        incompat = struct.unpack_from("<I", sb, 0x60)[0]
        self.desc_size = (max(32, struct.unpack_from("<H", sb, 0xFE)[0])
                          if incompat & INCOMPAT_64BIT else 32)
        self.blocks_count = struct.unpack_from("<I", sb, 0x04)[0] | (
            struct.unpack_from("<I", sb, 0x150)[0] << 32 if incompat & INCOMPAT_64BIT else 0)
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

    def _extent_node(self, node: bytes, depth_left: int, want: int, out: dict) -> None:
        """Map logical -> physical blocks under one extent-tree node."""
        if len(node) < 12:
            raise ExtError("extent node too short")
        magic, entries, maximum, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != EXTENT_MAGIC or entries > maximum or depth > depth_left \
                or 12 + 12 * entries > len(node):
            raise ExtError(f"invalid extent node (magic 0x{magic:04X}, {entries}/{maximum} "
                           f"entries, depth {depth})")
        for k in range(entries):
            e = 12 + 12 * k
            if depth == 0:
                logical, length, hi, lo = struct.unpack_from("<IHHI", node, e)
                unwritten = length > 32768
                length -= 32768 if unwritten else 0
                phys = (hi << 32) | lo
                for i in range(length):
                    if logical + i >= want:
                        break
                    if not unwritten and phys + i >= self.blocks_count > 0:
                        raise ExtError(f"extent points past the filesystem (block {phys + i})")
                    out[logical + i] = 0 if unwritten else phys + i
            else:
                _logical, lo, hi = struct.unpack_from("<IIH", node, e)
                self._extent_node(self._block((hi << 32) | lo), depth - 1, want, out)

    def _extent_blocks(self, ino: dict, want: int) -> list[int]:
        found: dict[int, int] = {}
        self._extent_node(ino["i_block"], 5, want, found)
        return [found.get(i, 0) for i in range(want)]         # holes read as zeros

    def runs(self, ino: dict) -> list[tuple[int, int]]:
        """The file's data as (byte offset in the partition's device, length)
        runs, holes left out - where the footage physically sits."""
        out: list[list[int]] = []
        left = ino["size"]
        for n in self.data_blocks(ino):
            take = min(self.block_size, left)
            left -= take
            if not n:
                continue
            off = self.start + n * self.block_size
            if out and out[-1][0] + out[-1][1] == off:
                out[-1][1] += take
            else:
                out.append([off, take])
        return [(o, n) for o, n in out]

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

    def data_blocks(self, ino: dict) -> list[int]:
        want = -(-ino["size"] // self.block_size)
        if ino["flags"] & INLINE_DATA:
            raise ExtError(f"inode {ino['number']} keeps its data inline - not read")
        if ino["flags"] & EXTENTS:
            try:
                return self._extent_blocks(ino, want)
            except ExtError as exc:
                raise ExtError(f"inode {ino['number']}: {exc}") from None
        b = ino["blocks"]
        out = list(b[:12])[:want]
        for depth, ptr in ((1, b[12]), (2, b[13]), (3, b[14])):
            if len(out) >= want:
                break
            out += self._pointers(ptr, depth, want - len(out))
        return out

    def read(self, ino: dict) -> bytes:
        """The file's bytes; a hole (block 0) reads as zeros."""
        out = bytearray()
        for n in self.data_blocks(ino):
            out += self._block(n) if n else bytes(self.block_size)
        return bytes(out[:ino["size"]])

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

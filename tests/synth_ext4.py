"""A minimal ext4 image, to test `parsers/ext3.py` and the plugins that read
recorders' ext4 disks (plugins/matrix.py).

One block group, 4 KiB blocks, 256-byte inodes, 64-bit group descriptors;
every file and directory keeps its data in extents.  A file asked to be
`fragments` pieces is laid out in that many extents with gaps between them,
and more than four extents need an index level - so both a leaf in the
inode and a two-level tree are exercised.  `unwritten` marks a file's last
extent as allocated but not written (it must read as zeros).

It follows the kernel's documented layout (Documentation/filesystems/ext4);
it is not made by mkfs, and has no journal, bitmaps in use, or checksums -
nothing here reads those.
"""

from __future__ import annotations

import struct

BS = 4096
INODE_SIZE = 256
INODES = 1024
INCOMPAT = 0x2 | 0x40 | 0x80          # filetype, extents, 64bit
TABLE_AT = 4                          # inode table's first block


class Ext4:
    def __init__(self, blocks: int, label: str = "", created: int = 0):
        if blocks > 32768:
            raise ValueError("one block group holds at most 32768 blocks")
        self.blocks, self.label, self.created = blocks, label, created
        self.img = bytearray(blocks * BS)
        self.next_block = TABLE_AT + INODES * INODE_SIZE // BS
        self.next_inode = 12
        self.dirs: dict[str, tuple[int, list]] = {"": (2, [])}
        self.files: dict[str, int] = {}

    # -- allocation -------------------------------------------------------------
    def _alloc(self, n: int, gap: int = 0) -> int:
        self.next_block += gap
        first = self.next_block
        self.next_block += n
        if self.next_block > self.blocks:
            raise ValueError("image full")
        return first

    def _inode(self, number: int, mode: int, size: int, t: int, extents: list) -> None:
        if number > INODES:
            raise ValueError("out of inodes")
        raw = bytearray(INODE_SIZE)
        struct.pack_into("<HHIIIII", raw, 0, mode, 0, size & 0xFFFFFFFF, t, t, t, 0)
        struct.pack_into("<H", raw, 26, 1)
        struct.pack_into("<I", raw, 32, 0x80000)                     # extents
        struct.pack_into("<I", raw, 108, size >> 32)
        struct.pack_into("<H", raw, 128, 32)                         # i_extra_isize
        if len(extents) <= 4:
            node = struct.pack("<HHHHI", 0xF30A, len(extents), 4, 0, 0)
            for lblk, pblk, n, written in extents:
                node += struct.pack("<IHHI", lblk, n if written else n + 32768, pblk >> 32,
                                    pblk & 0xFFFFFFFF)
        else:
            leaf_blk = self._alloc(1)
            leaf = struct.pack("<HHHHI", 0xF30A, len(extents), (BS - 12) // 12, 0, 0)
            for lblk, pblk, n, written in extents:
                leaf += struct.pack("<IHHI", lblk, n if written else n + 32768, pblk >> 32,
                                    pblk & 0xFFFFFFFF)
            self.img[leaf_blk * BS:leaf_blk * BS + len(leaf)] = leaf
            node = struct.pack("<HHHHI", 0xF30A, 1, 4, 1, 0)
            node += struct.pack("<IIHH", 0, leaf_blk & 0xFFFFFFFF, leaf_blk >> 32, 0)
        raw[40:40 + len(node)] = node
        o = TABLE_AT * BS + (number - 1) * INODE_SIZE
        self.img[o:o + INODE_SIZE] = raw

    def _write(self, data: bytes, fragments: int = 1, unwritten: bool = False) -> list:
        """Lay `data` out in `fragments` extents; the (lblk, pblk, n, written) list."""
        nblk = max(1, -(-len(data) // BS))
        pieces = max(1, min(fragments, nblk))
        per = -(-nblk // pieces)
        out, lblk = [], 0
        while lblk < nblk:
            n = min(per, nblk - lblk)
            p = self._alloc(n, gap=2 if out else 0)
            chunk = data[lblk * BS:(lblk + n) * BS]
            written = not (unwritten and lblk + n == nblk)
            if written:
                self.img[p * BS:p * BS + len(chunk)] = chunk
            out.append((lblk, p, n, written))
            lblk += n
        return out

    # -- the tree ----------------------------------------------------------------
    def mkdir(self, path: str, t: int = 0) -> None:
        parts = [p for p in path.strip("/").split("/") if p]
        for k in range(1, len(parts) + 1):
            sub = "/".join(parts[:k])
            if sub not in self.dirs:
                number = self.next_inode
                self.next_inode += 1
                self.dirs[sub] = (number, [])
                self.dirs["/".join(parts[:k - 1])][1].append((parts[k - 1], number, 2, t))

    def add_file(self, path: str, data: bytes, t: int = 0, fragments: int = 1,
                 unwritten: bool = False) -> int:
        parent, _, name = path.strip("/").rpartition("/")
        self.mkdir(parent, t)
        number = self.next_inode
        self.next_inode += 1
        self._inode(number, 0x81A4, len(data), t, self._write(data, fragments, unwritten))
        self.dirs[parent][1].append((name, number, 1, t))
        self.files[path.strip("/")] = number
        return number

    def build(self) -> bytes:
        for path, (number, entries) in self.dirs.items():
            parent = self.dirs["/".join(path.split("/")[:-1])][0] if path else 2
            recs = [(".", number, 2), ("..", parent, 2)] + [(n, i, k) for n, i, k, _ in entries]
            blocks, cur = [], bytearray()
            for k, (name, ino, kind) in enumerate(recs):
                nb = name.encode()
                rec = 8 + (len(nb) + 3) // 4 * 4
                if len(cur) + rec > BS:
                    blocks.append(cur)
                    cur = bytearray()
                cur += struct.pack("<IHBB", ino, rec, len(nb), kind) + nb + bytes(rec - 8 - len(nb))
            blocks.append(cur)
            data = bytearray()
            for blk in blocks:
                # the last record in each block runs to the block's end
                pos, lastpos = 0, 0
                while pos < len(blk):
                    lastpos = pos
                    pos += struct.unpack_from("<H", blk, pos + 4)[0]
                struct.pack_into("<H", blk, lastpos + 4, BS - lastpos)
                data += blk + bytes(BS - len(blk))
            t = entries[0][3] if entries else self.created
            self._inode(number, 0x41ED, len(data), t, self._write(bytes(data)))
        sb = bytearray(1024)
        struct.pack_into("<II", sb, 0x00, INODES, self.blocks)
        struct.pack_into("<II", sb, 0x14, 0, 2)                        # first data block, 4 KiB
        struct.pack_into("<III", sb, 0x20, 32768, 32768, INODES)
        struct.pack_into("<II", sb, 0x2C, self.created, self.created)
        struct.pack_into("<HH", sb, 0x38, 0xEF53, 1)
        struct.pack_into("<I", sb, 0x40, self.created)
        struct.pack_into("<I", sb, 0x4C, 1)
        struct.pack_into("<IH", sb, 0x54, 11, INODE_SIZE)
        struct.pack_into("<III", sb, 0x5C, 0, INCOMPAT, 0)
        sb[0x78:0x78 + len(self.label)] = self.label.encode()
        struct.pack_into("<H", sb, 0xFE, 64)
        struct.pack_into("<I", sb, 0x108, self.created)
        self.img[1024:2048] = sb
        gd = bytearray(64)
        struct.pack_into("<III", gd, 0, 2, 3, TABLE_AT)
        self.img[BS:BS + 64] = gd
        return bytes(self.img)

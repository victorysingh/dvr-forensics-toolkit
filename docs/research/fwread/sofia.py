"""Read Qualvision's `Sofia` (ARM32, statically linked) - disassembly only, nothing run.

Used for plugins/godrej.py.  `Sofia` is the recorder application in the
Qualvision/Homaxi NVR401L-4P4 firmware (20240531): an ARM ELF at file offset
0x200, loaded at 0x10000.  This labels each literal-pool load with the value
and the string it points at, which is how the QVFS functions were found by
their own debug strings.

    python sofia.py Sofia str "openfile frame head time"   # where a string is used
    python sofia.py Sofia dis 0x309610 0x150                # disassemble (ARM)
    python sofia.py Sofia dis 0x954e64 0x110

Needs `pip install capstone pyelftools` (not needed by the tool itself).
"""

from __future__ import annotations

import io
import struct
import sys

import capstone as cs
from elftools.elf.elffile import ELFFile

BASE = 0x200


class Sofia:
    def __init__(self, path: str):
        self.raw = open(path, "rb").read()
        elf = ELFFile(io.BytesIO(self.raw[BASE:]))
        self.segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"])
                     for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        self.md.skipdata = True

    def off(self, va: int):
        for v, o, n in self.segs:
            if v <= va < v + n:
                return BASE + o + va - v
        return None

    def va(self, off: int):
        e = off - BASE
        for v, o, n in self.segs:
            if o <= e < o + n:
                return v + e - o
        return None

    def string_refs(self, text: str) -> list[tuple[int, int]]:
        """(string VA, literal-pool VA) for every copy of `text`."""
        out, i = [], self.raw.find(text.encode())
        while i >= 0:
            sva = self.va(self.raw.rfind(bytes(1), 0, i) + 1)     # the C string's first byte
            pat = struct.pack("<I", sva)
            j = self.raw.find(pat)
            while j >= 0:
                if j % 4 == 0:
                    out.append((sva, self.va(j)))
                j = self.raw.find(pat, j + 1)
            i = self.raw.find(text.encode(), i + 1)
        return out

    def dis(self, va: int, length: int):
        o = self.off(va)
        for ins in self.md.disasm(self.raw[o:o + length], va):
            note = ""
            if ins.mnemonic.startswith("ldr") and "[pc, #" in ins.op_str:
                lit = ins.address + 8 + int(ins.op_str.split("#")[1].rstrip("]"), 0)
                lo = self.off(lit)
                if lo is not None:
                    val = struct.unpack_from("<I", self.raw, lo)[0]
                    so = self.off(val)
                    s = self.raw[so:so + 70].split(b"\0")[0].decode("latin1") if so else ""
                    note = f"   ; =0x{val:x}" + (f" {s!r}" if s.isprintable() and len(s) > 3 else "")
            yield f"{ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}{note}"


if __name__ == "__main__":
    f = Sofia(sys.argv[1])
    if sys.argv[2] == "str":
        for sva, lit in f.string_refs(sys.argv[3]):
            print(f"string 0x{sva:x}  literal 0x{lit:x}  (the loading code is within 4 KiB before it)")
    elif sys.argv[2] == "dis":
        for line in f.dis(int(sys.argv[3], 0), int(sys.argv[4], 0)):
            print(line)

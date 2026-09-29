"""Static reader for an ARM32 relocatable ELF (a Linux .ko): disassemble a
named function, annotating literal-pool words with the string or symbol
their relocation points at, and calls with their target name.  Read-only;
nothing is executed.

    python ko.py FILE func NAME [NAME ...]
    python ko.py FILE find TEXT          # functions whose code references a string containing TEXT
    python ko.py FILE syms PATTERN       # function symbols matching a regex
"""
import re
import struct
import sys

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


class KO:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.secs = {i: s for i, s in enumerate(self.elf.iter_sections())}
        self.symtab = self.elf.get_section_by_name(".symtab")
        self.syms = list(self.symtab.iter_symbols())
        # functions per section index
        self.funcs = {}
        for s in self.syms:
            if s["st_info"]["type"] == "STT_FUNC" and isinstance(s["st_shndx"], int):
                self.funcs.setdefault(s.name, (s["st_shndx"], s["st_value"] & ~1, s["st_size"],
                                               s["st_value"] & 1))
        # relocations per target section index: offset -> (type, symbol)
        self.rel = {}
        for sec in self.elf.iter_sections():
            if isinstance(sec, RelocationSection):
                tgt = sec["sh_info"]
                d = self.rel.setdefault(tgt, {})
                for r in sec.iter_relocations():
                    d[r["r_offset"]] = (r["r_info_type"], self.syms[r["r_info_sym"]])

    def data(self, shndx):
        return self.secs[shndx].data()

    def describe(self, sym, addend=0):
        """Name of a relocation target: a string if it lands in a string section."""
        if sym["st_info"]["type"] == "STT_SECTION" or sym.name == "":
            sh = sym["st_shndx"]
            if isinstance(sh, int):
                sec = self.secs[sh]
                off = sym["st_value"] + addend
                d = sec.data()
                if sec.name.startswith(".rodata") or sec.name.startswith(".data"):
                    end = d.find(b"\x00", off)
                    s = d[off:end if end >= 0 else off + 80]
                    if s and all(32 <= c < 127 or c in (9, 10) for c in s[:80]):
                        return f'"{s[:120].decode()}"'
                return f"{sec.name}+0x{off:x}"
        return sym.name + (f"+0x{addend:x}" if addend else "")

    def func(self, name):
        shndx, start, size, thumb = self.funcs[name]
        code = self.data(shndx)[start:start + size]
        rel = self.rel.get(shndx, {})
        mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
        md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
        out = []
        pool = set()
        for ins in md.disasm(code, start):
            note = ""
            if ins.address in rel:
                t, sym = rel[ins.address]
                note = f"  ; -> {self.describe(sym)}"
            m = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", ins.op_str)
            if ins.mnemonic.startswith("ldr") and m:
                tgt = (ins.address + (4 if thumb else 8)) & ~3
                tgt += int(m.group(1), 0)
                pool.add(tgt)
                if tgt in rel:
                    t, sym = rel[tgt]
                    add = struct.unpack_from("<I", self.data(shndx), tgt)[0]
                    note = f"  ; =[{self.describe(sym, add)}]"
                else:
                    v = struct.unpack_from("<I", self.data(shndx), tgt)[0]
                    note = f"  ; =0x{v:x}"
            if ins.address in pool:
                continue
            out.append(f"{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{note}")
        return out

    def find(self, text):
        """Functions whose literal pool points at a string containing `text`."""
        hits = set()
        for name, (shndx, start, size, thumb) in self.funcs.items():
            rel = self.rel.get(shndx, {})
            for off in range(start, start + size, 4):
                if off in rel:
                    t, sym = rel[off]
                    add = struct.unpack_from("<I", self.data(shndx), off)[0]
                    d = self.describe(sym, add)
                    if text in d:
                        hits.add((name, d[:100]))
        return sorted(hits)


if __name__ == "__main__":
    ko = KO(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "func":
        for n in sys.argv[3:]:
            print(f"==== {n} {ko.funcs[n][1:]}")
            print("\n".join(ko.func(n)))
    elif cmd == "find":
        for n, d in ko.find(sys.argv[3]):
            print(f"{n:40s} {d}")
    elif cmd == "syms":
        for n in sorted(ko.funcs):
            if re.search(sys.argv[3], n):
                print(n, hex(ko.funcs[n][1]), ko.funcs[n][2])

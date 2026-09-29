"""Static reader for an ARM (Thumb-2) shared object: disassemble exported
functions, resolving PIC string loads (ldr rX,[pc]; add rX,pc) and PLT calls.
Read-only; nothing is executed.

    python so.py FILE syms REGEX
    python so.py FILE func NAME [NAME ...]
    python so.py FILE xref TEXT        # functions that load a string containing TEXT
"""
import re
import struct
import sys

import capstone
from elftools.elf.elffile import ELFFile


class SO:
    def __init__(self, path):
        self.raw = open(path, "rb").read()
        self.elf = ELFFile(open(path, "rb"))
        self.segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"]) for s in self.elf.iter_segments()
                     if s["p_type"] == "PT_LOAD"]
        self.funcs = {}
        for sec in (self.elf.get_section_by_name(".dynsym"), self.elf.get_section_by_name(".symtab")):
            if sec is None:
                continue
            for s in sec.iter_symbols():
                if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
                    self.funcs.setdefault(s.name, (s["st_value"] & ~1, s["st_size"], s["st_value"] & 1))
        self.byaddr = {v[0]: n for n, v in self.funcs.items()}
        self.plt = self._plt()

    def off(self, va):
        for v, o, n in self.segs:
            if v <= va < v + n:
                return o + va - v
        return None

    def u32(self, va):
        o = self.off(va)
        return struct.unpack_from("<I", self.raw, o)[0] if o is not None else None

    def cstr(self, va):
        o = self.off(va)
        if o is None:
            return None
        e = self.raw.find(b"\0", o, o + 300)
        s = self.raw[o:e if e >= 0 else o + 120]
        if len(s) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
            return s.decode()
        return None

    def _plt(self):
        out = {}
        relplt = self.elf.get_section_by_name(".rel.plt")
        plt = self.elf.get_section_by_name(".plt")
        if not relplt or not plt:
            return out
        dsym = self.elf.get_section_by_name(".dynsym")
        got2name = {r["r_offset"]: dsym.get_symbol(r["r_info_sym"]).name
                    for r in relplt.iter_relocations()}
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        base, data = plt["sh_addr"], plt.data()
        # ARM PLT stubs: add ip, pc, #a ; add ip, ip, #b ; ldr pc, [ip, #c]!
        ins = list(md.disasm(data, base))
        for i in range(len(ins) - 2):
            a, b, c = ins[i], ins[i + 1], ins[i + 2]
            if a.mnemonic == "add" and a.op_str.startswith("ip, pc") and b.mnemonic == "add" \
                    and c.mnemonic == "ldr" and "ip" in c.op_str:
                imm = lambda x: int(re.search(r"#(-?0x[0-9a-f]+|-?\d+)", x.op_str).group(1), 0)
                got = a.address + 8 + imm(a) + imm(b) + imm(c)
                if got in got2name:
                    out[a.address] = got2name[got]
        return out

    def func(self, name):
        start, size, thumb = self.funcs[name]
        code = self.raw[self.off(start):self.off(start) + size]
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM)
        lit = {}          # reg -> literal value loaded from the pool
        pool = set()
        out = []
        for ins in md.disasm(code, start):
            if ins.address in pool:
                continue
            note = ""
            m = re.match(r"(\w+), \[pc, #(-?0x[0-9a-f]+|-?\d+)\]", ins.op_str)
            if ins.mnemonic.startswith("ldr") and m:
                tgt = ((ins.address + (4 if thumb else 8)) & ~3) + int(m.group(2), 0)
                pool.update((tgt, tgt + 2))
                v = self.u32(tgt)
                lit[m.group(1)] = v
                note = f"  ; =0x{v:x}" if v is not None else ""
            m2 = re.match(r"(\w+), pc$", ins.op_str)
            if ins.mnemonic.startswith("add") and m2 and m2.group(1) in lit and lit[m2.group(1)] is not None:
                va = (lit[m2.group(1)] + ins.address + (4 if thumb else 8)) & 0xffffffff
                s = self.cstr(va)
                note = f'  ; -> "{s[:110]}"' if s else f"  ; -> 0x{va:x}"
            if ins.mnemonic in ("bl", "blx", "b.w", "b") and ins.op_str.startswith("#"):
                t = int(ins.op_str[1:], 0)
                if t in self.plt:
                    note = f"  ; -> {self.plt[t]}"
                elif t in self.byaddr:
                    note = f"  ; -> {self.byaddr[t]}"
            out.append(f"{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{note}")
        return out


if __name__ == "__main__":
    so = SO(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "syms":
        for n in sorted(so.funcs):
            if re.search(sys.argv[3], n):
                print(n, hex(so.funcs[n][0]), so.funcs[n][1])
    elif cmd == "func":
        for n in sys.argv[3:]:
            print(f"==== {n}")
            print("\n".join(so.func(n)))
    elif cmd == "xref":
        for n in sorted(so.funcs):
            try:
                body = so.func(n)
            except Exception:
                continue
            hits = [l for l in body if sys.argv[3] in l]
            if hits:
                print(n, "|", hits[0].split(";", 1)[-1][:120])

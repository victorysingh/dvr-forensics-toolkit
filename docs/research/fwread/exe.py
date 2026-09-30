"""so.py for a fixed-address ARM executable: a literal-pool word that points at a
string is shown as that string.  python exe.py FILE func NAME [NAME ...]"""
import re
import sys

sys.path.insert(0, ".")
from so import SO


class EXE(SO):
    def func(self, name):
        out = []
        for line in super().func(name):
            m = re.search(r"; =0x([0-9a-f]+)$", line)
            if m:
                s = self.cstr(int(m.group(1), 16))
                if s:
                    line += f'  "{s[:100]}"'
            out.append(line)
        return out


if __name__ == "__main__":
    e = EXE(sys.argv[1])
    if sys.argv[2] == "func":
        for n in sys.argv[3:]:
            print(f"==== {n}")
            print("\n".join(e.func(n)))
    elif sys.argv[2] == "syms":
        for n in sorted(e.funcs):
            if re.search(sys.argv[3], n):
                print(n, hex(e.funcs[n][0]), e.funcs[n][1])

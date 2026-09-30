"""Disassemble an address range of a Thumb shared object with so.py's annotations."""
import sys
sys.path.insert(0, ".")
from so import SO
s = SO(sys.argv[1])
a = int(sys.argv[2], 0)
nxt = min([v[0] for v in s.funcs.values() if v[0] > a] or [a + 0x400])
end = int(sys.argv[3], 0) if len(sys.argv) > 3 else nxt
s.funcs["_range"] = (a, end - a, 1)
print("\n".join(s.func("_range")))

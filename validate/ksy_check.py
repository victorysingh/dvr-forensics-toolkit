"""The Kaitai format definitions, compiled and checked against our own readers.

    python -m validate.ksy_check                          # synthetic disks, built here
    python -m validate.ksy_check --dahua skyhawk_WWD4A3NX_first20GiB.dd \\
        --ps /dev/sdX --ps-region 0x4C5E000 0x40000000    # real media

`formats/*.ksy` describe each observed layout for others to reuse
(docs/TECH_STACK.md); the hand-written parsers are what the tool runs.  This
checks that the two agree.  The .ksy files are compiled by the official
kaitai-struct-compiler into `formats/generated/` (formats/generated/README.md
says how to rebuild them), and every field both sides read is compared:

  Dahua DHFS 4.1   the partition table's volumes against parsers/dahua.py's;
                   each volume's cluster size; every cluster record (kind,
                   channel, count, start, end, next, prev, head); and the
                   DHAV frames the parser accepts in the first recordings'
                   clusters (type, number, length, date, ms, extension
                   length, trailer)
  Hikvision PS     each stream recover/pscarve.py carves in the region: the
                   .ksy must parse its whole extent (every length landing on
                   the next start code), with the same number of packs,
                   stream maps, video and audio packets, and the same HK
                   times at the first and last stream map

Needs the `kaitaistruct` runtime (`pip install kaitaistruct`); nothing else
in the tool does.  Read-only: images are read through BlockDevice.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import sys
import tempfile
from collections import Counter
from typing import Optional

from acquire.device import BlockDevice

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATED = os.path.join(HERE, "formats", "generated")
MAX_FRAMES = 3000


def _generated(name: str):
    spec = importlib.util.spec_from_file_location(f"ksy_{name}", os.path.join(GENERATED, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _DevIO(io.RawIOBase):
    """A BlockDevice as a read-only file, for KaitaiStream (raw or E01 alike)."""

    def __init__(self, dev: BlockDevice):
        self.dev, self.pos = dev, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, off: int, whence: int = 0) -> int:
        self.pos = {0: off, 1: self.pos + off, 2: self.dev.size_bytes + off}[whence]
        return self.pos

    def tell(self) -> int:
        return self.pos

    def readinto(self, b) -> int:
        data = self.dev.read_at(self.pos, len(b)) if self.pos < self.dev.size_bytes else b""
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def _val(x):
    return x.value if hasattr(x, "value") else x


def _stream(dev: BlockDevice):
    from kaitaistruct import KaitaiStream
    return KaitaiStream(io.BufferedReader(_DevIO(dev), buffer_size=1 << 16))


# ---------------------------------------------------------------------------
def check_dahua(path: str) -> dict:
    from kaitaistruct import KaitaiStream
    from parsers.base import get_parser
    from parsers.dahua import walk_frames
    import parsers.dahua  # noqa: F401  (registers the plugin)
    ksy = _generated("dahua_dhfs41").DahuaDhfs41
    out: dict = {"image": path, "mismatches": []}
    bad = out["mismatches"]
    p = get_parser("Dahua")
    with BlockDevice(path) as dev:
        p.parse(dev)
        ks = _stream(dev)
        root = ksy(ks)
        out["superblock_version"] = root.superblock.version
        entries = [e for e in root.partition_table.entries if e.sector_count]
        out["volumes"] = {"ksy": len(entries), "parser": len(p.volumes)}
        if len(entries) != len(p.volumes):
            bad.append(f"volume count: ksy {len(entries)}, parser {len(p.volumes)}")
        records = frames = 0
        for e, v in zip(entries, p.volumes):
            where = f"volume {v.number}"
            if (e.start_sector * 512, e.sector_count * 512) != (v.start, v.length):
                bad.append(f"{where}: extent ksy {e.start_sector * 512}+{e.sector_count * 512}, "
                           f"parser {v.start}+{v.length}")
            if e.start_sector * 512 + 0x4400 + 512 > dev.size_bytes:
                out.setdefault("volumes_beyond_image", []).append(v.number)
                continue
            vh = e.volume
            if vh.cluster_size != v.cluster_size:
                bad.append(f"{where}: cluster size ksy {vh.cluster_size}, parser {v.cluster_size}")
            table = v.start + vh.index_start_sector * 512
            n = min(vh.cluster_capacity, len(v.records))
            ks.seek(table)
            for r in v.records[:n]:
                k = ksy.ClusterRecord(ks, None, root)
                got = (_val(k.kind), k.channel, k.count_or_seq, k.start.raw, k.end.raw,
                       k.next, k.prev, k.head)
                # channel as stored: the .ksy keeps the ASCII digit the parser decodes
                want = (r.kind, r.raw[1], r.count_or_seq, r.start, r.end, r.next, r.prev, r.head)
                if got != want:
                    bad.append(f"{where} record {r.index}: ksy {got}, parser {want}")
                records += 1
            # DHAV frames, in the clusters the parser's first recordings start in
            if v.data_base is None:
                continue
            for f in v.files[:8]:
                if frames >= MAX_FRAMES:
                    break
                base = v.cluster_offset(f.head.index)
                buf = dev.read_at(base, v.cluster_size)
                fs = KaitaiStream(io.BytesIO(buf))
                for fr in walk_frames(buf, base):
                    fs.seek(fr.offset - base)
                    k = ksy.DhavFrame(fs, None, root)
                    got = (_val(k.type), k.frame_number, k.frame_length, k.date.raw, k.ms_clock,
                           k.ext_length, k.trailer_length)
                    want = (fr.ftype, fr.frame_number, fr.length, fr.date, fr.ms, fr.ext_length,
                            fr.length)
                    if got != want:
                        bad.append(f"{where} frame at {fr.offset}: ksy {got}, parser {want}")
                    frames += 1
                    if frames >= MAX_FRAMES:
                        break
        out.update(records_compared=records, frames_compared=frames)
    out["agree"] = not bad
    return out


# ---------------------------------------------------------------------------
def check_ps(path: str, start: int = 0, length: Optional[int] = None, max_streams: int = 50) -> dict:
    from kaitaistruct import KaitaiStream
    from recover import pscarve
    ksy = _generated("hikvision_ps").HikvisionPs
    out: dict = {"image": path, "region": [start, length], "mismatches": []}
    bad = out["mismatches"]

    def hk(u) -> Optional[str]:
        for d in u.body.body.descriptors.items:
            if d.tag == 0x40:
                b = d.body
                return (f"{2000 + b.year}-{b.month:02d}-{b.day:02d} "
                        f"{b.hour:02d}:{b.minute:02d}:{b.second:02d}")
        return None

    with BlockDevice(path) as dev:
        end = dev.size_bytes if length is None else min(dev.size_bytes, start + length)
        streams, _ = pscarve.carve(dev, start, end)
        checked = packs = 0
        for s in streams[:max_streams]:
            if len(s.extents) != 1:
                continue
            off, n = s.extents[0]
            where = f"stream at {off}"
            try:
                units = ksy(KaitaiStream(io.BytesIO(dev.read_at(off, n)))).units
            except Exception as exc:                        # the .ksy could not read it
                bad.append(f"{where}: ksy failed - {type(exc).__name__}: {exc}")
                continue
            ids = Counter(u.stream_id for u in units)
            got = {"packs": ids[0xBA], "stream_maps": ids[0xBC],
                   "video": sum(v for k, v in ids.items() if 0xE0 <= k <= 0xEF),
                   "audio": sum(v for k, v in ids.items() if 0xC0 <= k <= 0xDF)}
            want = {"packs": s.packs, "stream_maps": s.psms, "video": s.video, "audio": s.audio}
            maps = [u for u in units if u.stream_id == 0xBC]
            if maps:
                got["hk_first"], got["hk_last"] = hk(maps[0]), hk(maps[-1])
                want["hk_first"], want["hk_last"] = pscarve.hk_time(s.first_psm), pscarve.hk_time(s.last_psm)
            if got != want:
                bad.append(f"{where}: ksy {got}, carver {want}")
            checked += 1
            packs += ids[0xBA]
        out.update(streams_carved=len(streams), streams_compared=checked, packs_compared=packs)
    out["agree"] = not bad and checked > 0
    return out


# ---------------------------------------------------------------------------
def synthetic(work: str) -> dict:
    """Both checks on disks built here: tests/synth_dahua.py, and the
    Hikvision-style stream the MPEG-PS tests use, between noise."""
    import random
    from datetime import datetime
    from tests import synth_dahua
    from tests.test_pipeline import _ps_recording
    dhfs = os.path.join(work, "dhfs.img")
    synth_dahua.build(dhfs)
    rng = random.Random(7)
    ps = os.path.join(work, "ps.img")
    with open(ps, "wb") as fh:
        fh.write(bytes(rng.getrandbits(8) for _ in range(100_000)))
        fh.write(_ps_recording(rng, datetime(2025, 9, 20, 10, 0, 0), 3, 0))
        fh.write(bytes(rng.getrandbits(8) for _ in range(50_000)))
        fh.write(_ps_recording(rng, datetime(2025, 9, 21, 7, 30, 0), 2, 900_000))
        fh.write(bytes(1 << 12))
    return {"dahua": check_dahua(dhfs), "hikvision_ps": check_ps(ps)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dahua", help="a Dahua/CP Plus disk or image (raw or E01)")
    ap.add_argument("--ps", help="a disk or image holding Hikvision MPEG-PS footage")
    ap.add_argument("--ps-region", nargs=2, metavar=("OFFSET", "LENGTH"),
                    help="carve only this byte range (hex or decimal), e.g. one 1 GiB data block")
    ap.add_argument("--out", help="write the result here as JSON")
    a = ap.parse_args()
    try:
        import kaitaistruct  # noqa: F401
    except ImportError:
        print("needs the Kaitai runtime: pip install kaitaistruct", file=sys.stderr)
        return 2
    if not a.dahua and not a.ps:
        with tempfile.TemporaryDirectory() as work:
            res = synthetic(work)
    else:
        res = {}
        if a.dahua:
            res["dahua"] = check_dahua(a.dahua)
        if a.ps:
            start, length = (int(a.ps_region[0], 0), int(a.ps_region[1], 0)) if a.ps_region else (0, None)
            res["hikvision_ps"] = check_ps(a.ps, start, length)
    text = json.dumps(res, indent=1, default=str)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")
    print(text)
    return 0 if all(r["agree"] for r in res.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

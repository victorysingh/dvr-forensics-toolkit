"""Fuzz every vendor parser with corrupted disks: none may crash or hang.

    python -m validate.fuzz_parsers [--cases 300] [--seed 1] [--timeout 30] [--vendors Dahua,...]
    python -m validate.fuzz_parsers --repro Matrix:295 [--seed 1] [--cases 400]
    python -m validate.fuzz_parsers --vendors carve-dhav,carve-ps,carve-annexb,e01 [--cases 300]

The carvers and the E01 reader are fuzzed the same way (--vendors with the
names above). A carver reads every byte, so its damage is aimed at what it
recognises - DHAV frame headers, MPEG-PS pack and stream-map headers,
Annex B start codes - and the carve is followed by what the tool does with
its result (report rows, recordings, a stream written out). The E01 reader
gets damaged segment files: opening may refuse (a device error) and a
damaged chunk may be refused on read (EwfError, which the scan records as
unreadable); anything else is a crash.

A parser is handed evidence that may be damaged, half-overwritten or
tampered with.  The contract (parsers/base.py, and how cli.py calls it):
`detect()` returns True or False, and `parse()` returns a ParseResult with
any problem written into its `errors`.  cli.py catches only device errors,
so any other exception is a traceback in front of the examiner - a crash.
A parse that runs far longer than the clean disk's is a hang.

For each registered vendor this builds the synthetic disk the tests use
(tests/synth_*.py), parses it once cleanly while recording every byte range
the parser reads - its structures, not the video - and then makes corrupted
copies, most of the damage aimed at those ranges:
  * bit flips (1-64 bits);
  * a 1/2/4/8-byte field set to a poison value (0, 1, all ones, the sign
    bit, just past the disk's end, huge);
  * a run of bytes zeroed, set to 0xFF, or random;
  * one structure copied over another (self-references, loops);
  * the disk truncated inside a structure.
Each case runs `detect()` then `parse()` in a worker process, killed if it
runs past --timeout.  Cases are reproducible: (vendor, seed, case number).
Standard library only.  Writes nothing but its report (--out).
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import random
import sys
import tempfile
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

POISON = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000,
          0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]


class MemDevice:
    """A read-only disk in memory: the clean image plus sparse damage.  Reads
    past the end come back short, as from BlockDevice."""

    def __init__(self, data: bytes, patches: dict | None = None, size: int | None = None,
                 log: list | None = None):
        self._data = data
        self._patches = patches or {}        # offset -> bytes
        self.size_bytes = len(data) if size is None else size
        self.sector_size = 512
        self.path = "fuzz-image"
        self.is_raw = False
        self.model = "fuzz"
        self.serial = ""
        self.write_block_method = "n/a:fuzz"
        self._log = log

    def read_at(self, offset: int, length: int) -> bytes:
        if self._log is not None:
            self._log.append((offset, length))
        if offset < 0 or length <= 0 or offset >= self.size_bytes:
            return b""
        end = min(offset + length, self.size_bytes)
        buf = bytearray(self._data[offset:end])
        for at, blob in self._patches.items():
            lo, hi = max(at, offset), min(at + len(blob), end)
            if lo < hi:
                buf[lo - offset:hi - offset] = blob[lo - at:hi - at]
        return bytes(buf)

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _seed_builders() -> dict:
    """vendor -> function(path) building the synthetic disk the tests use."""
    from tests import (synth_dahua, synth_dvr, synth_heimvision, synth_honeywell, synth_matrix,
                       synth_qvfs, synth_tplink, synth_uniview)
    return {
        "Dahua": lambda p: synth_dahua.build(p),
        "Hikvision": lambda p: synth_dvr.build(p),
        "HeimVision": lambda p: synth_heimvision.build(p),
        "Honeywell": lambda p: synth_honeywell.build(p),
        "Matrix": lambda p: synth_matrix.build(p),
        "Godrej": lambda p: synth_qvfs.build(p),
        "TP-Link": lambda p: synth_tplink.build(p),
        "Uniview": lambda p: synth_uniview.build(p),
    }


CARVERS = ("carve-dhav", "carve-ps", "carve-annexb", "e01")
# what each carver recognises - where its damage is aimed
MARKERS = {"carve-dhav": [b"DHAV", b"dhav"],
           "carve-ps": [b"\x00\x00\x01\xba", b"\x00\x00\x01\xbc", b"\x00\x00\x01\xe0"],
           "carve-annexb": [b"\x00\x00\x00\x01", b"\x00\x00\x01", b"VNDR"],
           "e01": [b"EVF", b"header", b"volume", b"table", b"sectors", b"done", b"next", b"hash"]}


def _pack(parts: list) -> tuple[bytes, list]:
    return b"".join(parts), [len(x) for x in parts]


def _carver_seed(name: str, workdir: str) -> tuple[bytes, list]:
    """(the bytes a carver target reads, segment lengths for the E01 set)."""
    import random as _r
    from datetime import datetime
    from tests import synth_dahua
    if name == "carve-dhav":
        path = os.path.join(workdir, "dhav.img")
        synth_dahua.build(path)
        with open(path, "rb") as fh:
            return fh.read(), []
    if name == "carve-ps":
        from tests.test_pipeline import _ps_recording
        rng = _r.Random(3)
        noise = rng.randbytes(100_000)
        return (noise + _ps_recording(rng, datetime(2021, 4, 23, 7, 40, 7), 6, 1_000_000)
                + noise[:50_000] + _ps_recording(rng, datetime(2021, 4, 25, 18, 2, 0), 4, 90_000_000)
                + noise), []
    if name == "carve-annexb":
        from tests.test_pipeline import _vendor_frames
        rng = _r.Random(9)
        return (rng.randbytes(64 << 10) + _vendor_frames(rng, 60, "h265", 1280, 720)
                + bytes(1 << 20) + _vendor_frames(rng, 50, "h264", 1920, 1080)
                + rng.randbytes(32 << 10)), []
    if name == "e01":
        from tests import synth_ewf
        path = os.path.join(workdir, "e01src.img")
        synth_dahua.build(path, seconds=8)
        with open(path, "rb") as fh:
            media = fh.read()
        media += bytes(-len(media) % 512) + _r.Random(1).randbytes(64 << 10)
        segs = []
        for sp in synth_ewf.write(os.path.join(workdir, "e01set"), media, chunks_per_segment=7):
            with open(sp, "rb") as fh:
                segs.append(fh.read())
        return _pack(segs)
    raise KeyError(name)


def _hotspots(name: str, data: bytes, cap: int = 4000) -> list:
    """(offset, 64) at each marker the carver recognises, as mutation targets."""
    out = []
    for m in MARKERS[name]:
        i = data.find(m)
        while i >= 0 and len(out) < cap * 4:
            out.append((i, 64))
            i = data.find(m, i + 1)
    random.Random(0).shuffle(out)
    return out[:cap]


def run_carver(name: str, data: bytes, patches: dict, size: int, meta: list) -> dict:
    """One carve (or E01 read) of damaged bytes, then what the tool does with
    the result; anything raised other than a device error (or, for E01, the
    reader's own EwfError) is a crash."""
    import io
    from acquire.device import DeviceError
    dev = MemDevice(data, patches, size)
    try:
        if name == "carve-dhav":
            from recover import carver
            streams, stats = carver.carve(dev)
            for st in streams:
                carver.to_recording(st)
            info = type("Info", (), {"path": "fuzz", "size_bytes": size, "write_block_method": "n/a"})()
            carver.build_report(streams, stats, {}, info, False)
            for st in streams[:3]:
                carver.write_stream(dev, st, io.BytesIO(), io.BytesIO())
            return {"outcome": "ok", "streams": len(streams)}
        if name == "carve-ps":
            from recover import pscarve
            streams, stats = pscarve.carve(dev)
            [x.to_row() for x in streams]
            info = type("Info", (), {"path": "fuzz", "size_bytes": size, "write_block_method": "n/a"})()
            pscarve.build_report(streams, stats, info)
            return {"outcome": "ok", "streams": len(streams)}
        if name == "carve-annexb":
            from recover import annexb
            streams, stats = annexb.carve(dev)
            [x.to_row() for x in streams]
            info = type("Info", (), {"path": "fuzz", "size_bytes": size, "write_block_method": "n/a"})()
            annexb.build_report(streams, stats, info, "carve-annexb")
            return {"outcome": "ok", "streams": len(streams)}
        if name == "e01":
            from acquire import ewf
            from acquire.device import BlockDevice
            blob = dev.read_at(0, size)
            with tempfile.TemporaryDirectory() as d:
                pos, paths = 0, []
                for k, n in enumerate(meta):
                    part = blob[pos:pos + n]
                    pos += n
                    if not part:
                        break                              # the set was cut short here
                    paths.append(os.path.join(d, f"e01set.E{k + 1:02d}"))
                    with open(paths[-1], "wb") as fh:
                        fh.write(part)
                if not paths:
                    return {"outcome": "ok", "detail": "nothing left"}
                refused = 0
                with BlockDevice(paths[0]) as img:
                    total = min(img.size_bytes, 256 << 20)   # a claimed size is not trusted
                    off = 0
                    while off < total:
                        try:
                            img.read_at(off, 1 << 20)
                        except ewf.EwfError:
                            refused += 1
                        off += 1 << 20
                    claimed = img.size_bytes
                return {"outcome": "ok", "refused_chunks": refused, "claimed": claimed}
        raise KeyError(name)
    except DeviceError as exc:
        return {"outcome": "device-error", "detail": str(exc)[:200]}
    except BaseException as exc:                   # noqa: BLE001
        tb = traceback.extract_tb(exc.__traceback__)
        where = next((f"{os.path.relpath(f.filename, ROOT)}:{f.lineno}" for f in reversed(tb)
                      if ROOT in os.path.abspath(f.filename)
                      and "fuzz_parsers" not in f.filename), "?")
        return {"outcome": "crash", "error": f"{type(exc).__name__}: {str(exc)[:160]}",
                "where": where}


def configure(vendor: str, parser):
    """What the tests set before parsing a synthetic disk: TP-Link's fixture
    puts the format sector at 1 MiB, not the real disk's 512 MiB."""
    if vendor == "TP-Link":
        from tests import synth_tplink
        synth_tplink.configure(parser)
    return parser


def seed(vendor: str, workdir: str) -> tuple[bytes, list, float]:
    """The clean disk, the ranges its parser reads (for a carver: where the
    headers it recognises are), and how long a clean run takes."""
    if vendor in CARVERS:
        data, meta = _carver_seed(vendor, workdir)
        SEGMENTS[vendor] = meta
        t = time.perf_counter()
        run_carver(vendor, data, {}, len(data), meta)
        return data, _hotspots(vendor, data), time.perf_counter() - t
    import parsers  # noqa: F401  (registers the plugins)
    from parsers.base import get_parser
    path = os.path.join(workdir, f"{vendor}.img")
    _seed_builders()[vendor](path)
    with open(path, "rb") as fh:
        data = fh.read()
    log: list = []
    dev = MemDevice(data, log=log)
    p = configure(vendor, get_parser(vendor))
    t = time.perf_counter()
    p.detect(dev)
    res = p.parse(dev)
    # what run_case does next, so its damage is aimed at the footage too
    if res.recordings and hasattr(p, "extract_recording"):
        with tempfile.TemporaryDirectory() as d:
            p.extract_recording(dev, res.recordings[0].id, os.path.join(d, "rec"))
    if hasattr(p, "recover_video_area"):
        p.recover_video_area(dev)
    took = time.perf_counter() - t
    return data, log, took


def mutate(data: bytes, reads: list, rnd: random.Random) -> tuple[dict, int, list]:
    """Sparse damage aimed mostly at what the parser reads.  Returns
    (patches, size, description)."""
    size = len(data)
    patches: dict = {}
    what = []

    def spot() -> int:
        if reads and rnd.random() < 0.85:
            off, ln = rnd.choice(reads)
            return max(0, min(size - 1, off + rnd.randrange(max(1, min(ln, 4096)))))
        return rnd.randrange(size)

    for _ in range(rnd.choice([1, 1, 1, 2, 3, 5])):
        kind = rnd.choice(["bits", "field", "field", "run", "copy", "truncate"])
        at = spot()
        if kind == "bits":
            n = rnd.choice([1, 2, 4, 8, 16, 64])
            for _ in range(n):
                b = rnd.randrange(max(1, min(size - at, 64))) + at
                cur = patches.get(b, data[b:b + 1]) or b"\x00"
                patches[b] = bytes([cur[0] ^ (1 << rnd.randrange(8))])
            what.append(f"flip {n} bits near {at}")
        elif kind == "field":
            w = rnd.choice([1, 2, 4, 8])
            v = rnd.choice(POISON + [size, size + 1, size - 1, rnd.getrandbits(32)]) % (1 << (8 * w))
            order = rnd.choice(["little", "big"])
            patches[at] = v.to_bytes(w, order)
            what.append(f"field {w}B={v:#x} {order} at {at}")
        elif kind == "run":
            n = rnd.choice([4, 16, 64, 512, 4096])
            fill = rnd.choice(["zero", "ff", "random"])
            blob = (bytes(n) if fill == "zero" else b"\xff" * n if fill == "ff"
                    else bytes(rnd.getrandbits(8) for _ in range(n)))
            patches[at] = blob[:max(0, size - at)]
            what.append(f"{fill} run {n}B at {at}")
        elif kind == "copy":
            src = spot()
            n = rnd.choice([16, 64, 512, 4096])
            patches[at] = data[src:src + n][:max(0, size - at)]
            what.append(f"copy {n}B from {src} to {at}")
        else:
            size = max(0, min(size, at + rnd.randrange(64)))
            what.append(f"truncate to {size}")
    return patches, size, what


def run_case(vendor: str, data: bytes, patches: dict, size: int) -> dict:
    """detect() then parse() on one damaged disk, then what the tool does next
    where the plugin can: extract the first recording, and walk the video
    area for footage no index lists.  Anything raised other than a device
    error is a crash."""
    import parsers  # noqa: F401
    from acquire.device import DeviceError
    from parsers.base import ParseResult, get_parser
    p = configure(vendor, get_parser(vendor))
    dev = MemDevice(data, patches, size)
    try:
        found = p.detect(dev)
        if not isinstance(found, bool):
            return {"outcome": "bad-return", "detail": f"detect returned {type(found).__name__}"}
        if getattr(p, "detect_stopped", ""):
            # the framework's safety net caught it (parsers/base.py _guard): no
            # traceback, but a place to fix, so it is counted apart
            return {"outcome": "stopped", "error": p.detect_stopped, "where": "detect"}
        res = p.parse(dev)
        if not isinstance(res, ParseResult):
            return {"outcome": "bad-return", "detail": f"parse returned {type(res).__name__}"}
        if res.stopped:
            return {"outcome": "stopped", "error": res.stopped, "where": "parse"}
        extracted = remnants = None
        if res.recordings and hasattr(p, "extract_recording"):
            with tempfile.TemporaryDirectory() as d:
                extracted = p.extract_recording(dev, res.recordings[0].id,
                                                os.path.join(d, "rec"))["bytes"]
        if hasattr(p, "recover_video_area"):
            remnants = len(p.recover_video_area(dev))
        return {"outcome": "ok", "recordings": len(res.recordings), "errors": len(res.errors),
                "extracted_bytes": extracted, "remnants": remnants}
    except DeviceError as exc:
        return {"outcome": "device-error", "detail": str(exc)[:200]}
    except BaseException as exc:                   # noqa: BLE001 - that is the point
        tb = traceback.extract_tb(exc.__traceback__)
        where = next((f"{os.path.relpath(f.filename, ROOT)}:{f.lineno}" for f in reversed(tb)
                      if ROOT in os.path.abspath(f.filename)), "?")
        return {"outcome": "crash", "error": f"{type(exc).__name__}: {str(exc)[:160]}",
                "where": where}


SEGMENTS: dict = {}          # E01: the segment lengths of the seed set


def _worker(vendor: str, data: bytes, jobs, results, meta=None) -> None:
    while True:
        job = jobs.get()
        if job is None:
            return
        n, patches, size = job
        results.put((n, "start", None))
        res = (run_carver(vendor, data, patches, size, meta or []) if vendor in CARVERS
               else run_case(vendor, data, patches, size))
        results.put((n, "done", res))


def fuzz(vendor: str, cases: int, rng_seed: int, timeout: float, workdir: str, log=print) -> dict:
    data, reads, took = seed(vendor, workdir)
    rnd = random.Random(f"{vendor}:{rng_seed}")
    plan = [(n, *mutate(data, reads, rnd)) for n in range(cases)]
    jobs, results = mp.Queue(), mp.Queue()
    worker = mp.Process(target=_worker, args=(vendor, data, jobs, results, SEGMENTS.get(vendor)),
                        daemon=True)
    worker.start()
    out: dict = {"vendor": vendor, "cases": cases, "seed": rng_seed, "image_bytes": len(data),
                 "clean_parse_s": round(took, 3), "reads_recorded": len(reads),
                 "outcomes": {}, "failures": []}
    for n, patches, size, what in plan:
        jobs.put((n, patches, size))
        started = time.time()
        res = None
        while res is None:
            try:
                k, stage, payload = results.get(timeout=1)
            except Exception:                          # noqa: BLE001  (queue.Empty)
                k = stage = None
            if stage == "done" and k == n:
                res = payload
            elif time.time() - started > timeout:
                worker.kill()
                worker.join()
                res = {"outcome": "hang", "detail": f"over {timeout:g} s"}
                jobs, results = mp.Queue(), mp.Queue()
                worker = mp.Process(target=_worker, args=(vendor, data, jobs, results, SEGMENTS.get(vendor)),
                        daemon=True)
                worker.start()
        out["outcomes"][res["outcome"]] = out["outcomes"].get(res["outcome"], 0) + 1
        if res["outcome"] in ("crash", "hang", "bad-return", "stopped"):
            out["failures"].append(dict(res, case=n, damage=what))
    jobs.put(None)
    worker.join(timeout=5)
    log(f"{vendor:<11} {cases} cases, clean parse {took:.2f} s: "
        + ", ".join(f"{k} {v}" for k, v in sorted(out["outcomes"].items())))
    return out


def repro(vendor: str, case: int, cases: int, rng_seed: int, timeout: float) -> dict:
    """One case again, in this process: its damage, its result, and - if it
    runs past `timeout` - where every thread is at that moment."""
    import faulthandler
    with tempfile.TemporaryDirectory() as workdir:
        data, reads, _ = seed(vendor, workdir)
    rnd = random.Random(f"{vendor}:{rng_seed}")
    plan = [mutate(data, reads, rnd) for _ in range(max(cases, case + 1))]
    patches, size, what = plan[case]
    print(f"{vendor} case {case}: " + "; ".join(what), flush=True)
    faulthandler.dump_traceback_later(timeout, exit=True)
    res = run_case(vendor, data, patches, size)
    faulthandler.cancel_dump_traceback_later()
    print(res)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds before a case is a hang")
    ap.add_argument("--vendors", default="", help="comma-separated (default: every parser)")
    ap.add_argument("--out", default=None, help="write the report here (JSON)")
    ap.add_argument("--repro", default="", help="VENDOR:CASE - run one case again, in this process")
    a = ap.parse_args()
    if a.repro:
        v, n = a.repro.rsplit(":", 1)
        repro(v, int(n), a.cases, a.seed, a.timeout)
        return 0
    vendors = [v for v in a.vendors.split(",") if v] or list(_seed_builders())
    report = []
    with tempfile.TemporaryDirectory() as workdir:
        for v in vendors:
            report.append(fuzz(v, a.cases, a.seed, a.timeout, workdir))
    bad = [dict(f, vendor=r["vendor"]) for r in report for f in r["failures"]]
    by_place: dict = {}
    for f in bad:
        key = (f["vendor"], f["outcome"], f.get("where", ""), f.get("error", f.get("detail", ""))[:60])
        by_place.setdefault(key, []).append(f["case"])
    print(f"\n{sum(r['cases'] for r in report)} cases, {len(bad)} failures in "
          f"{len(by_place)} distinct places")
    for (v, o, where, err), ns in sorted(by_place.items()):
        print(f"  {v:<11} {o:<10} {where:<28} x{len(ns):<4} {err}   (e.g. case {ns[0]})")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
    return 1 if bad else 0


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())

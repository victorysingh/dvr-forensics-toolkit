"""Godrej SeeThru NVR/UVR = Qualvision QVFS, read from Qualvision's own firmware.

A drop-in plugin: nothing in the core was edited to add it.

WHO MAKES IT
------------
Godrej's SeeThru cloud portal drives Qualvision's `/tdkcgi` API and its
`qveye.net` plugin, and Qualvision's firmware implements the same ~100
`tdkcgi_handle_*` handlers: a Godrej SeeThru recorder runs Qualvision's
software (docs/research/vendor_formats.md, HIGH).  Whether every Godrej model
does is not established: a Godrej unit whose disk carries no QVEX head is
left as detected_not_parsed.

SOURCE
------
Qualvision (Homaxi brand) NVR401L-4P4 firmware 20240531, a public download
(homaxi.com; SHA-256 fe10f5381258146817c1663d10207ec2971eefb890e2485d437804d99172a80a).
Its application `Sofia` (SHA-256 eb9e9e1d5ff48f519eb5c9fef1f8f140006976f0a4462799273524625ec2944b;
ARM ELF at file offset 0x200, loaded at 0x10000) holds the QVFS code, with
build paths .../modules/QVFS/*.cpp and C++ names.  Every layout below was
read from a named function by static disassembly - nothing was run - with
docs/research/fwread/sofia.py.  Addresses are virtual addresses.

LAYOUT
------
Disk head (IDiskExt::CheckHead, 0x954e64):
  +0x00 "QVEX"   +0x04 version 0x00010000
  +0x08 must equal the disk object's field 0x44 (an identity); +0x0C its
        field 0x48 - the size every region is bounded by
  +0x10/+0x14 and +0x18/+0x1C two regions, read as (start, size): the
        checks are start+size <= size-field for each, and the two sizes plus
        one fit in it.  The unit is not in the code; it is inferred here from
        the device (sectors when +0x0C x 512 is the disk's size) and said so.
Frame (FSFileR.cpp: CheckFrameHead 0x989858, LoadFrameHead 0x98a164,
ReadPacket 0x98a320; CHOTUpload::OpenFile 0x309610):
  +0x00 00 00 01 and a type byte 0xE0-0xEB   (CheckFrameHead)
  +0x04 u32 payload length                   (CheckFrameHead; ReadPacket
        allocates length + 0x14 and reads the payload from head + 0x14)
  +0x08 DHTIME: sec 0-5, min 6-11, hour 12-16, day 17-21, month 22-25,
        year-2000 26-31 - Dahua's packed date bit for bit (OpenFile's debug
        print decodes it with exactly these shifts)
  +0x0C u16 milliseconds                     (OpenFile)
  +0x0E six bytes not decoded
  the head is 0x14 bytes (LoadFrameHead reads 0x14); the next frame starts
  at head + 0x14 + length (ReadPacket).

STATUS: spec_only
-----------------
The firmware says what the recorder is programmed to write; no Qualvision or
Godrej disk has been read by the team, and the tests run on a disk built to
this reading.  Not decoded, so not claimed: the index blocks (VIDEO and PIC
index, the per-channel HM time index), the camera of a frame (so footage is
attributed to no camera), what each frame type 0xE0-0xEB means, and the six
bytes at +0x0E.  Footage is found by the frame chain: a head is believed only
when the next head follows exactly where its length says, several in a row.
Times are the recorder's wall clock (DHTIME carries no zone).
"""

from __future__ import annotations

import hashlib
import re
import struct
from collections import Counter
from datetime import timedelta
from typing import Iterator, Optional

from core.contract import STATE_ACTIVE, Provenance, Recording, TimestampClaim
from detect.engine import parse_partitions
from detect.signatures import SPEC_ONLY, Signature
from parsers.base import (SOURCE_FIRMWARE, FieldSpec, ParseResult, VendorParser,
                          register, weakest_source)
from parsers.dahua import decode_date

FW = ("Qualvision NVR401L-4P4 20240531, Sofia SHA-256 eb9e9e1d5ff48f519eb5c9fef1f8f140006976f0"
      "a4462799273524625ec2944b")
HEAD_MAGIC, HEAD_VERSION = b"QVEX", 0x00010000
FRAME_HEAD = 0x14
TYPES = range(0xE0, 0xEC)
MAX_LEN = 8 << 20
MIN_RUN = 3                  # frames chained in a row before a run is believed
WINDOW = 8 << 20
_FRAME_RE = re.compile(rb"\x00\x00\x01[\xe0-\xeb]")


def _fw(fn: str) -> str:
    return f"{FW}; {fn}"


FIELDS = [
    FieldSpec("head.magic", 0x00, "magic", "'QVEX'", SOURCE_FIRMWARE, _fw("IDiskExt::CheckHead 0x954ee0")),
    FieldSpec("head.version", 0x04, "<I", "0x00010000", SOURCE_FIRMWARE, _fw("IDiskExt::CheckHead 0x954ef0")),
    FieldSpec("head.id", 0x08, "<I", "equals the disk object's +0x44", SOURCE_FIRMWARE,
              _fw("IDiskExt::CheckHead 0x954efc")),
    FieldSpec("head.size", 0x0C, "<I", "bounds every region", SOURCE_FIRMWARE,
              _fw("IDiskExt::CheckHead 0x954f0c")),
    FieldSpec("head.region_a", 0x10, "<II", "(start, size), read from the bounds checks",
              SOURCE_FIRMWARE, _fw("IDiskExt::CheckHead 0x954f1c-0x954f40")),
    FieldSpec("head.region_b", 0x18, "<II", "(start, size), read from the bounds checks",
              SOURCE_FIRMWARE, _fw("IDiskExt::CheckHead 0x954f44-0x954f50")),
    FieldSpec("frame.prefix", 0x00, "bytes", "00 00 01 then type 0xE0-0xEB", SOURCE_FIRMWARE,
              _fw("CheckFrameHead 0x989858-0x98987c")),
    FieldSpec("frame.length", 0x04, "<I", "payload bytes after the 0x14-byte head",
              SOURCE_FIRMWARE, _fw("CheckFrameHead 0x9898b0; ReadPacket 0x98a3ac-0x98a41c")),
    FieldSpec("frame.time", 0x08, "<I", "DHTIME, Dahua's packed local date", SOURCE_FIRMWARE,
              _fw("CHOTUpload::OpenFile 0x3096ec-0x30973c")),
    FieldSpec("frame.ms", 0x0C, "<H", "milliseconds", SOURCE_FIRMWARE,
              _fw("CHOTUpload::OpenFile 0x3096ec")),
    FieldSpec("frame.head_size", 0x14, "const", "20 bytes; next frame at +0x14+length",
              SOURCE_FIRMWARE, _fw("LoadFrameHead 0x98a204; ReadPacket 0x98a728")),
]

SIGNATURES = [
    Signature(id="godrej.qvfs_head", vendor="Godrej",
              pattern=HEAD_MAGIC + struct.pack("<I", HEAD_VERSION),
              description="Qualvision QVFS disk head ('QVEX', version 0x00010000)",
              source=_fw("IDiskExt::CheckHead"), validation_status=SPEC_ONLY,
              weight=10.0, expected_offsets=(0,), offset_tolerance=0),
]


def read_head(dev, off: int) -> Optional[dict]:
    raw = dev.read_at(off, 0x20)
    if len(raw) < 0x20 or raw[:4] != HEAD_MAGIC:
        return None
    version, ident, size, a0, a1, b0, b1 = struct.unpack_from("<7I", raw, 4)
    if version != HEAD_VERSION:
        return None
    ok = a0 + a1 <= size and b0 + b1 <= size and a1 + b1 + 1 <= size
    return {"offset": off, "version": version, "id": ident, "size": size,
            "region_a": (a0, a1), "region_b": (b0, b1), "bounds_ok": ok}


def frame_head(b: bytes) -> Optional[dict]:
    """A 20-byte QVFS frame head, or None - the firmware's own checks, plus a
    date that decodes and milliseconds under 1000."""
    if len(b) < FRAME_HEAD or b[:3] != b"\x00\x00\x01" or b[3] not in TYPES:
        return None
    length, when, ms = struct.unpack_from("<IIH", b, 4)
    if not 0 < length <= MAX_LEN or ms >= 1000:
        return None
    dt = decode_date(when)
    if dt is None or dt.year < 2005:
        return None
    return {"type": b[3], "length": length, "time": dt, "ms": ms}


class _Window:
    """Reads a device through one cached window, so walking a frame chain is
    not one read per frame."""

    def __init__(self, dev):
        self.dev, self.base, self.buf = dev, -1, b""

    def get(self, off: int, n: int) -> bytes:
        if not (self.base <= off and off + n <= self.base + len(self.buf)):
            self.base, self.buf = off, self.dev.read_at(off, max(WINDOW, n))
        return self.buf[off - self.base:off - self.base + n]


def walk(dev, start: int, end: int) -> Iterator[dict]:
    """Runs of chained frames in [start, end): each head is followed, where
    its length says, by the next.  A lone head that chains to nothing is
    passed over."""
    win = _Window(dev)
    pos = start
    while pos < end:
        chunk = dev.read_at(pos, min(WINDOW, end - pos))
        if not chunk:
            return
        m = _FRAME_RE.search(chunk)
        if not m:
            pos += max(1, len(chunk) - 3)
            continue
        at = pos + m.start()
        frames, cur = [], at
        while cur + FRAME_HEAD <= end:
            h = frame_head(win.get(cur, FRAME_HEAD))
            if h is None or cur + FRAME_HEAD + h["length"] > end:
                break
            h["offset"] = cur
            frames.append(h)
            cur += FRAME_HEAD + h["length"]
        if len(frames) >= MIN_RUN:
            yield {"offset": at, "end": cur, "frames": frames}
            pos = cur
        else:
            pos = at + 1


def _local(dt, ms: int = 0) -> str:
    return (dt + timedelta(milliseconds=ms)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


@register
class GodrejParser(VendorParser):
    vendor = "Godrej"
    parser_rule = "godrej.qvfs.sofia-nt98631-20240531.v1"

    def __init__(self, tz_offset_min: Optional[int] = None):
        self.tz_offset_min = tz_offset_min
        self.runs: dict[str, dict] = {}

    def _head(self, dev) -> Optional[dict]:
        starts = [0] + [p.start_offset for p in parse_partitions(
            dev.read_at(0, 64 << 10), getattr(dev, "sector_size", 512) or 512)]
        for off in starts:
            h = read_head(dev, off)
            if h:
                return h
        return None

    def detect(self, dev, hint_offsets=None) -> bool:
        h = self._head(dev)
        return bool(h and h["bounds_ok"])

    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=weakest_source([f.source for f in FIELDS]))
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        head = self._head(dev)
        if not head:
            result.errors.append("no QVFS head ('QVEX', version 0x00010000) at LBA 0 or a "
                                 "partition start")
            return result
        size = getattr(dev, "size_bytes", 0)
        span = size - head["offset"]
        unit = 512 if span and abs(head["size"] * 512 - span) <= max(span // 100, 1 << 20) else None
        if unit:
            regions = [(head["offset"] + s * unit, head["offset"] + (s + n) * unit)
                       for s, n in (head["region_a"], head["region_b"]) if n]
        else:
            regions = [(head["offset"] + 512, size)]
        tz = self.tz_offset_min
        types: Counter = Counter()
        n_frames = 0
        for lo, hi in regions:
            for r in walk(dev, lo, min(hi, size)):
                fr = r["frames"]
                n_frames += len(fr)
                types.update(f["type"] for f in fr)
                rid = f"qv-{len(self.runs):05d}"
                self.runs[rid] = r
                a, z = fr[0], fr[-1]

                def claim(f, which):
                    return TimestampClaim(
                        source="container",
                        raw_value=f"0x{f['offset']:X} = {_local(f['time'], f['ms'])[:19]} "
                                  f"recorder-local",
                        decoded_utc=((f["time"] - timedelta(minutes=tz)).strftime(
                            "%Y-%m-%dT%H:%M:%SZ") if tz is not None else None),
                        tz_offset_min=tz, confidence=0.5,
                        decode_rule=f"QVFS frame head +0x08 DHTIME, +0x0C ms, {which} frame "
                                    "of the run (Sofia CHOTUpload::OpenFile); the recorder's "
                                    "wall clock" + ("" if tz is not None else
                                                    "; zone not stated, not converted"))
                dur = (z["time"] - a["time"]).total_seconds() + (z["ms"] - a["ms"]) / 1000
                result.recordings.append(Recording(
                    id=rid, camera_id="UNKNOWN", state=STATE_ACTIVE, codec="",
                    offset=r["offset"], length=r["end"] - r["offset"],
                    start_utc=claim(a, "first").decoded_utc,
                    end_utc=claim(z, "last").decoded_utc, duration_s=round(dur, 3),
                    confidence=0.5, frame_count=len(fr),
                    timestamps=[claim(a, "first"), claim(z, "last")],
                    provenance=Provenance(disk_offset=r["offset"], length=r["end"] - r["offset"],
                                          sector_start=r["offset"] // 512,
                                          sector_end=r["end"] // 512,
                                          parser_rule=self.parser_rule + ".frame-chain")))
        clean = lambda c: c.raw_value.split(" = ")[1].replace(" recorder-local", "")
        firsts = [clean(r.timestamps[0]) for r in result.recordings]
        lasts = [clean(r.timestamps[1]) for r in result.recordings]
        result.volume = {
            "vendor": "Godrej (Qualvision QVFS)", "head": head,
            "region_unit_bytes": unit, "regions_bytes": regions,
            "runs": len(result.recordings), "frames": n_frames,
            "frame_types": {f"0x{t:02X}": n for t, n in sorted(types.items())},
            "tz_offset_min": tz,
            "summary": [
                ("head", f"QVEX v1.0 at 0x{head['offset']:X}; id 0x{head['id']:08X}; size field "
                         f"{head['size']:,}; regions A {head['region_a']}, B {head['region_b']}; "
                         f"bounds {'hold' if head['bounds_ok'] else 'FAIL'}"),
                ("unit", "sectors: size field x 512 = the disk" if unit else
                         "not established - the whole disk after the head is walked"),
                ("footage", f"{len(result.recordings)} run(s), {n_frames:,} frames, by the "
                            f"frame chain; types {', '.join(f'0x{t:02X}' for t in sorted(types))}"),
                ("span", f"{min(firsts) if firsts else '-'} -> {max(lasts) if lasts else '-'} "
                         "recorder-local"),
                ("camera", "not attributed: the index that names it is not decoded"),
            ]}
        result.notes = [
            f"Layout read from Qualvision's own firmware by static disassembly: {FW}. "
            "spec_only: no Qualvision or Godrej disk read.",
            "Footage is found by the frame chain alone; the VIDEO/PIC and HM index blocks "
            "are not decoded, so no run is attributed to a camera and deleted-vs-live is "
            "not told apart.",
            "Frame types 0xE0-0xEB are counted, not named. Extraction keeps the payloads "
            "that open with an H.264/H.265 start code.",
        ]
        if not head["bounds_ok"]:
            result.notes.append("The head's region bounds fail the firmware's own check.")
        return result

    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """A run's video: payloads that open with an Annex-B start code, in order."""
        if recording_id not in self.runs:
            self.parse(dev)
        r = self.runs.get(recording_id)
        if not r:
            raise KeyError(recording_id)
        path = base_path + ".es"
        h = hashlib.sha256()
        kept = skipped = 0
        win = _Window(dev)
        with open(path, "wb") as fh:
            for f in r["frames"]:
                pay = win.get(f["offset"] + FRAME_HEAD, f["length"])
                if pay[:4] == b"\x00\x00\x00\x01" or pay[:3] == b"\x00\x00\x01":
                    fh.write(pay)
                    h.update(pay)
                    kept += 1
                else:
                    skipped += 1
        return {"file": path.replace("\\", "/").rsplit("/", 1)[-1], "sha256": h.hexdigest(),
                "bytes": sum(f["length"] for f in r["frames"]), "frames": kept,
                "frames_without_start_code": skipped,
                "first_time_local": _local(r["frames"][0]["time"], r["frames"][0]["ms"]),
                "last_time_local": _local(r["frames"][-1]["time"], r["frames"][-1]["ms"])}

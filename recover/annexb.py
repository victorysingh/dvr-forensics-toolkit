"""Last-resort carver: raw H.264 / H.265 from a recorder whose format we do
not know.

The PS names eight OEMs; we hold media for three.  For the others -
Honeywell, TP-Link, Godrej, Uniview, Matrix - there is no parser, but almost
every recorder stores standard H.264 or H.265, and those streams can be
found without knowing anything else about the disk.  This is the "carve"
step of the add-a-vendor pipeline (detect -> carve -> survey -> plugin ->
validate): footage first, understanding later.

HOW A STREAM IS FOUND
---------------------
  * It starts only at a sequence parameter set (H.264 SPS; H.265 VPS+SPS)
    that parses to a plausible picture size.  Random bytes contain start
    codes; they do not contain a well-formed SPS.
  * It continues while start codes keep coming - no more than MAX_GAP apart -
    with NAL headers valid for its codec.  A start code whose header is not
    valid is counted and passed over: in an unknown container, the
    container's own bytes (a length, a counter) produce 00 00 01 by chance.
  * It ends at a gap, or at a parameter set with different content - a
    different camera, or the same camera with a new setting.  Split, never
    merged by guesswork.  What cannot be seen is two cameras with identical
    settings interleaved on the disk: their parameter sets are the same, and
    a stream may hold both.  The report says so; where the container is known,
    the DHAV and MPEG-PS carvers separate them.

WHAT A CARVED STREAM IS, AND IS NOT
-----------------------------------
Its bytes are copied from the disk as they are.  Between two frames an
unknown container leaves its own bytes, which a bare-stream reader takes as
the tail of the previous NAL unit.  Decoders conceal that damage and the
footage plays, but it is NOT the recorder's bitstream byte for byte - so it
is never offered to `validate-export` as a candidate for `validated`.  It
has no date and no camera: nothing in an elementary stream carries either.
One carved stream may also span several consecutive recordings of the same
camera; a bare stream marks no boundary between them.

Status: `synthetic_only` until it has recovered footage from a real disk of
a vendor we have no parser for.  On our two drives it can be checked
against the DHAV and MPEG-PS carvers, which know the container.

Read-only: bytes are handed in by the scan, or read from a BlockDevice.
Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Iterator, Optional

RULE = "carve.annexb.sps-anchored.v1"
SC3 = b"\x00\x00\x01"
# Largest distance between consecutive start codes inside one stream: an
# I-frame of a 4K camera plus container overhead stays well under this.
MAX_GAP = 4 << 20
# Bytes kept past a start code before it is judged, so a parameter set
# crossing a block edge is read whole.
LOOKAHEAD = 64 << 10
MAX_PS = 4096               # a parameter set larger than this is not one
MIN_VCL = 25                # shorter runs are counted, not reported as footage
VPS_BEFORE_SPS = 4096       # an H.265 stream starts at its VPS if one is this close


# ---------------------------------------------------------------------------
# Parameter sets
# ---------------------------------------------------------------------------
def rbsp(nal: bytes) -> bytes:
    """NAL payload with emulation-prevention bytes (00 00 03) removed."""
    out, zeros = bytearray(), 0
    for b in nal:
        if zeros >= 2 and b == 3:
            zeros = 0
            continue
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)


class Bits:
    def __init__(self, data: bytes):
        self.d, self.i = data, 0

    def u(self, n: int) -> int:
        v = 0
        for _ in range(n):
            if self.i >= len(self.d) * 8:
                raise ValueError("past the end")
            v = (v << 1) | (self.d[self.i >> 3] >> (7 - (self.i & 7)) & 1)
            self.i += 1
        return v

    def ue(self) -> int:
        z = 0
        while self.u(1) == 0:
            z += 1
            if z > 31:
                raise ValueError("bad exp-Golomb code")
        return (1 << z) - 1 + self.u(z)

    def se(self) -> int:
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)


def _plausible(w: int, h: int) -> bool:
    return 64 <= w <= 8192 and 64 <= h <= 8192


def _result(codec: str, w: int, h: int, profile: int, level: int, head: bytes,
            r: "Bits") -> Optional[dict]:
    """The parse result, keyed on exactly the bytes parsed: an unknown
    container may put bytes of its own after the SPS, and those must not make
    one camera's repeated SPS look like a new one."""
    if not _plausible(w, h):
        return None
    key = hashlib.sha256(head + r.d[:(r.i + 7) // 8]).hexdigest()
    return {"codec": codec, "width": w, "height": h, "profile": profile, "level": level,
            "key": key}


_H264_HIGH = {100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135}
# Values the standards allow.  An SPS is the anchor of a carved stream, so
# every field that has a legal range is held to it: random bytes that merely
# look like an SPS header fail these long before a picture size comes out.
_H264_PROFILES = {66, 77, 88} | _H264_HIGH
_H264_LEVELS = {9, 10, 11, 12, 13, 20, 21, 22, 30, 31, 32, 40, 41, 42, 50, 51, 52, 60, 61, 62}
_H265_LEVELS = {30, 60, 63, 90, 93, 120, 123, 150, 153, 156, 180, 183, 186}


def _need(ok: bool) -> None:
    if not ok:
        raise ValueError("outside the standard's range")


def h264_sps(nal: bytes) -> Optional[dict]:
    """Picture size and profile from an H.264 SPS NAL (header byte included),
    per ITU-T H.264 7.3.2.1.1.  None if it does not parse or is implausible."""
    try:
        r = Bits(rbsp(nal[1:]))
        profile, _constraints, level = r.u(8), r.u(8), r.u(8)
        _need(profile in _H264_PROFILES and level in _H264_LEVELS)
        _need(r.ue() <= 31)                             # seq_parameter_set_id
        chroma = 1
        if profile in _H264_HIGH:
            chroma = r.ue()
            _need(chroma <= 3)
            if chroma == 3:
                r.u(1)
            _need(r.ue() <= 6 and r.ue() <= 6)          # bit depths - 8
            r.u(1)                                      # qpprime bypass
            if r.u(1):                                  # scaling matrices
                for k in range(12 if chroma == 3 else 8):
                    if r.u(1):
                        last = nxt = 8
                        for _ in range(16 if k < 6 else 64):
                            if nxt:
                                nxt = (last + r.se()) % 256
                            last = nxt or last
        _need(r.ue() <= 12)                             # log2_max_frame_num_minus4
        poc = r.ue()
        _need(poc <= 2)
        if poc == 0:
            _need(r.ue() <= 12)
        elif poc == 1:
            r.u(1), r.se(), r.se()
            n = r.ue()
            _need(n <= 255)
            for _ in range(n):
                r.se()
        _need(r.ue() <= 16)                             # max_num_ref_frames
        r.u(1)                                          # gaps allowed
        w_mbs, h_units = r.ue() + 1, r.ue() + 1
        frame_only = r.u(1)
        if not frame_only:
            r.u(1)
        r.u(1)                                          # direct_8x8_inference
        w, h = w_mbs * 16, (2 - frame_only) * h_units * 16
        if r.u(1):                                      # frame cropping
            cl, cr, ct, cb = r.ue(), r.ue(), r.ue(), r.ue()
            cx = 2 if chroma in (1, 2) else 1
            cy = (2 if chroma == 1 else 1) * (2 - frame_only)
            w -= cx * (cl + cr)
            h -= cy * (ct + cb)
    except (ValueError, IndexError):
        return None
    return _result("h264", w, h, profile, level, nal[:1], r)


def h265_sps(nal: bytes) -> Optional[dict]:
    """Picture size and profile from an H.265 SPS NAL (2-byte header
    included), per ITU-T H.265 7.3.2.2.1 and 7.3.3."""
    try:
        r = Bits(rbsp(nal[2:]))
        r.u(4)                                          # sps_video_parameter_set_id
        sub = r.u(3)                                    # sps_max_sub_layers_minus1
        _need(sub <= 6)
        r.u(1)
        _need(r.u(2) == 0)                              # profile space
        r.u(1)                                          # tier
        profile = r.u(5)
        _need(1 <= profile <= 11)
        r.u(32), r.u(4), r.u(32), r.u(11)               # compat flags, 4 flags, 43 reserved bits
        r.u(1)
        level = r.u(8)
        _need(level in _H265_LEVELS)
        present = [(r.u(1), r.u(1)) for _ in range(sub)]
        if sub:
            for _ in range(sub, 8):
                r.u(2)
        for prof, lev in present:
            if prof:
                r.u(32), r.u(32), r.u(24)               # 88 bits of sub-layer profile
            if lev:
                r.u(8)
        _need(r.ue() <= 15)                             # sps_seq_parameter_set_id
        chroma = r.ue()
        _need(chroma <= 3)
        if chroma == 3:
            r.u(1)
        w, h = r.ue(), r.ue()
        _need(w % 8 == 0 and h % 8 == 0)                # whole minimum coding blocks
        if r.u(1):                                      # conformance window
            cl, cr, ct, cb = r.ue(), r.ue(), r.ue(), r.ue()
            sx = 2 if chroma in (1, 2) else 1
            sy = 2 if chroma == 1 else 1
            w -= sx * (cl + cr)
            h -= sy * (ct + cb)
    except (ValueError, IndexError):
        return None
    return _result("h265", w, h, profile, level, nal[:2], r)


# ---------------------------------------------------------------------------
# NAL headers
# ---------------------------------------------------------------------------
def classify(h0: int, h1: int) -> tuple[Optional[int], Optional[int]]:
    """(H.264 type, H.265 type) this header could be - None where it cannot."""
    t264 = h0 & 0x1F if not h0 & 0x80 and 1 <= (h0 & 0x1F) <= 23 else None
    t265 = ((h0 >> 1) & 0x3F if not h0 & 0x81 and 1 <= h1 <= 7
            and ((h0 >> 1) & 0x3F) <= 40 else None)
    return t264, t265


def is_vcl(codec: str, t: int) -> bool:
    return t <= 31 if codec == "h265" else 1 <= t <= 5


def is_key(codec: str, t: int) -> bool:
    return 16 <= t <= 21 if codec == "h265" else t == 5


def is_sps(codec: str, t: int) -> bool:
    return t == (33 if codec == "h265" else 7)


def parse_sps(codec: str, nal: bytes) -> Optional[dict]:
    return h265_sps(nal) if codec == "h265" else h264_sps(nal)


# ---------------------------------------------------------------------------
# The carver
# ---------------------------------------------------------------------------
@dataclass
class EsStream:
    sid: int
    codec: str
    start: int
    sps: dict
    sps_key: str
    end: int = 0
    nals: int = 0
    vcl: int = 0
    keyframes: int = 0
    spurious: int = 0
    last: int = 0                       # offset of the last start code accepted
    last_vcl: bool = False
    last_key: bool = False
    notes: list[str] = field(default_factory=list)

    def to_row(self) -> dict:
        return {"id": f"es-{self.sid:05d}", "codec": self.codec,
                "width": self.sps["width"], "height": self.sps["height"],
                "profile": self.sps["profile"], "level": self.sps["level"],
                "offset": self.start, "bytes": self.end - self.start,
                "extents": [[self.start, self.end - self.start]],
                "nal_units": self.nals, "slices": self.vcl, "keyframes": self.keyframes,
                "start_codes_passed_over": self.spurious, "sps_key": self.sps_key,
                "date": None, "camera": None}


class AnnexBCarver:
    """Start codes from bytes handed in order, each judged with LOOKAHEAD
    bytes after it in hand, so a parameter set crossing a block is whole."""

    def __init__(self, start: int = 0):
        self.base = start
        self.buf = bytearray()
        self.pos = 0
        self.cur: Optional[EsStream] = None
        self.vps_at: Optional[int] = None
        self.kept: list[EsStream] = []
        self.n = 0
        self.stats = {"streams_kept": 0, "fragments": 0, "fragment_bytes": 0,
                      "splits_on_new_parameter_set": 0, "splits_on_gap": 0,
                      "sps_rejected": 0}

    def push(self, offset: int, data: bytes, final: bool = False) -> None:
        if offset != self.base + len(self.buf):
            raise ValueError(f"AnnexBCarver: bytes at 0x{offset:X} arrived out of order")
        self.buf += data
        b = self.buf
        limit = len(b) if final else len(b) - LOOKAHEAD
        while self.pos < limit:
            i = b.find(SC3, self.pos, limit + 2)
            if i < 0 or i >= limit:
                self.pos = max(self.pos, limit)
                break
            self._start_code(self.base + i, i)
            self.pos = i + 3
        drop = min(self.pos, max(0, len(b) - LOOKAHEAD))
        if drop > 0:
            del b[:drop]
            self.base += drop
            self.pos -= drop

    def close(self) -> None:
        self.push(self.base + len(self.buf), b"", final=True)
        self._close(self.cur.last if self.cur else 0)

    def _nal(self, i: int) -> bytes:
        j = self.buf.find(SC3, i + 3, i + 3 + MAX_PS)
        return bytes(self.buf[i + 3:j if j >= 0 else i + 3 + MAX_PS]).rstrip(b"\x00")

    def _start_code(self, at: int, i: int) -> None:
        b = self.buf
        if i + 5 > len(b):
            return
        cur = self.cur
        if cur and at - cur.last > MAX_GAP:
            self.stats["splits_on_gap"] += 1
            self._close(cur.last)                      # the last NAL's end is unknown: left out
            cur = None
        t264, t265 = classify(b[i + 3], b[i + 4])
        if cur is None:
            if t265 == 32:
                self.vps_at = at
            elif t265 == 33 or t264 == 7:
                codec = "h265" if t265 == 33 else "h264"
                sps = parse_sps(codec, self._nal(i))
                if sps is None:
                    self.stats["sps_rejected"] += 1
                else:
                    self._open(at, codec, sps)
            return
        t = t265 if cur.codec == "h265" else t264
        if t is None:
            cur.spurious += 1                          # container bytes, not a NAL
            return
        if t == 32:
            self.vps_at = at
        if is_sps(cur.codec, t):
            sps = parse_sps(cur.codec, self._nal(i))
            if sps is None:
                cur.spurious += 1                      # SPS-shaped, but not one
                return
            if sps["key"] != cur.sps_key:
                self.stats["splits_on_new_parameter_set"] += 1
                self._close(self._stream_start(at, cur.codec))
                self._open(at, cur.codec, sps)
                return
        cur.last = at
        cur.nals += 1
        cur.last_vcl, cur.last_key = is_vcl(cur.codec, t), is_key(cur.codec, t)
        cur.vcl += cur.last_vcl
        cur.keyframes += cur.last_key

    def _stream_start(self, sps_at: int, codec: str) -> int:
        if codec == "h265" and self.vps_at is not None and 0 <= sps_at - self.vps_at <= VPS_BEFORE_SPS:
            return self.vps_at
        return sps_at

    def _open(self, at: int, codec: str, sps: dict) -> None:
        start = self._stream_start(at, codec)
        self.n += 1
        self.cur = EsStream(self.n, codec, start, sps, sps["key"],
                            last=at, nals=1 + (start != at))

    def _close(self, end: int) -> None:
        s, self.cur = self.cur, None
        if s is None:
            return
        s.end = max(end, s.start)
        if end == s.last and s.nals:                   # the last NAL is left out: its end
            s.nals -= 1                                # is not known, or it opens the next
            s.vcl -= s.last_vcl                        # stream
            s.keyframes -= s.last_key
        if s.vcl >= MIN_VCL:
            self.kept.append(s)
            self.stats["streams_kept"] += 1
        else:
            self.stats["fragments"] += 1
            self.stats["fragment_bytes"] += s.end - s.start

    def finish(self) -> tuple[list[EsStream], dict]:
        return self.kept, dict(self.stats)


def carve(dev, start: int = 0, end: Optional[int] = None, chunk: int = 8 << 20):
    end = dev.size_bytes if end is None else min(end, dev.size_bytes)
    c, off = AnnexBCarver(start), start
    while off < end:
        data = dev.read_at(off, min(chunk, end - off))
        if not data:
            break
        c.push(off, data)
        off += len(data)
    c.close()
    return c.finish()


def build_report(streams: list[EsStream], stats: dict, info, tool: str) -> dict:
    from core.contract import SCHEMA_VERSION, utc_now
    return {
        "schema_version": SCHEMA_VERSION, "generated_utc": utc_now(),
        "tool": f"ps26150-forensics {tool}", "rule": RULE, "format": "annexb",
        "validation_status": "synthetic_only",
        "source_device": info.path, "source_bytes": info.size_bytes,
        "write_block_method": info.write_block_method,
        "stats": stats, "streams": [s.to_row() for s in streams],
        "notes": [
            "Each stream starts at a parameter set that parses to a plausible picture "
            "size, continues while start codes with valid headers keep coming, and is "
            "split at a new parameter set or a gap - never merged by guesswork.",
            "Bytes are copied as stored. An unknown container leaves its own bytes "
            "between frames; decoders conceal them, but the stream is not the recorder's "
            "bitstream byte for byte and is never a candidate for `validated`.",
            "No date and no camera: an elementary stream carries neither.",
            "One stream may span consecutive recordings of the same camera.",
            "Streams are told apart by their parameter sets. Two cameras with identical "
            "settings interleaved on the disk cannot be separated here and may share a "
            "stream; the DHAV and MPEG-PS carvers can, where the container is known.",
        ],
    }


class AnnexBTap:
    """Scan tap: carve raw H.264/H.265 in the acquisition pass."""

    name = "carve_annexb"

    def __init__(self):
        self.carver: Optional[AnnexBCarver] = None

    def prepare(self, dev, start: int, end: int, log=print) -> None:
        self.carver = AnnexBCarver(start)
        log("[*] carve-annexb raw H.264/H.265, anchored on parameter sets")

    def feed(self, offset: int, data: bytes) -> None:
        self.carver.push(offset, data)

    def finish(self, out_dir: str, info) -> dict:
        from core.hashing import sha256_file
        self.carver.close()
        streams, stats = self.carver.finish()
        rep = build_report(streams, stats, info, tool="scan --carve-annexb (inline)")
        return write_report(rep, out_dir, sha256_file)


def write_report(rep: dict, out_dir: str, sha256_file) -> dict:
    os.makedirs(os.path.join(out_dir, "carve"), exist_ok=True)
    path = os.path.join(out_dir, "carve", "annexb_report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    return {"report": "carve/annexb_report.json", "sha256": sha256_file(path),
            "streams_kept": rep["stats"]["streams_kept"],
            "bytes": sum(r["bytes"] for r in rep["streams"])}


def extract(dev, rows: list[dict], out_dir: str, manifest_path: str, log=print) -> dict:
    """Copy each stream out as stored: <id>.h264 / <id>.h265, hashed."""
    from core.hashing import sha256_file
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"streams": {}}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    done = manifest["streams"]
    for k, r in enumerate(rows):
        name = f"{r['id']}.{r['codec']}"
        path = os.path.join(out_dir, name)
        if r["id"] in done and os.path.exists(path):
            continue
        n = 0
        with open(path, "wb") as fh:
            for off, length in r["extents"]:
                data = dev.read_at(off, length)
                if len(data) != length:
                    raise IOError(f"short read at 0x{off:X}: {len(data)} of {length}")
                fh.write(data)
                n += len(data)
        done[r["id"]] = {"file": name, "bytes": n, "sha256": sha256_file(path),
                         "bytes_match": n == r["bytes"], "extents": r["extents"],
                         "label": "unindexed"}
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        log(f"  [{k + 1}/{len(rows)}] {name}  {n / 2**20:,.1f} MiB  "
            f"{r['width']}x{r['height']}")
    return manifest


def iter_rows(report: dict, ids: Optional[set] = None) -> Iterator[dict]:
    for r in report["streams"]:
        if not ids or r["id"] in ids:
            yield r

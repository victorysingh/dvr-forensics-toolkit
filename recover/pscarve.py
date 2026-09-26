"""Indexless MPEG-PS carver: footage in a Program Stream, found by structure.

Hikvision recorders store video as an MPEG-2 Program Stream (ISO/IEC
13818-1): pack headers (00 00 01 BA) followed by PES packets - video (E0),
audio (C0), and a Program Stream Map (BC) before each keyframe, which on
Hikvision carries private descriptors starting "HK". Many other recorders
use the same container. This carver needs no filesystem index, so it
recovers footage after the index is gone - for instance when the drive
was later formatted by a different recorder, as on the team's second drive.

HOW A STREAM IS FOUND
---------------------
A pack header is only accepted when the packets after it, read by their
own length fields, end EXACTLY at the next pack header. A chain of such
packs, contiguous on disk, is one run of footage: random data does not
satisfy that. A run is split - never merged by guesswork - where the
pack's system clock (SCR, 90 kHz) jumps backwards or forwards by more
than SCR_JUMP_S: that is where one recording ends and another begins.

WHAT A CARVED PS STREAM IS, AND IS NOT
--------------------------------------
Its bytes are an unmodified Program Stream: copied out, they play in any
MPEG-PS player. Its SCR is a relative clock, not a date; real time comes
from elsewhere (the "HK" stream-map descriptor or the burned-in clock),
and until that is established a stream is reported without a date. Its
camera is unknown unless something in the stream names it.

Read-only: frames come from bytes handed in (a scan tap) or a BlockDevice.
Status: the container is an ISO standard; the Hikvision descriptors are
observed, not documented - spec_only at best.
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

PS_RULE = "carve.mpegps.structure.v1"
PACK = b"\x00\x00\x01\xba"
SCR_HZ = 90000
SCR_JUMP_S = 5.0             # SCR discontinuity that ends a stream
MIN_PACKS = 25               # shorter runs are counted, not reported as footage
LOOKAHEAD = 1 << 20          # bytes kept beyond a pack before it is judged
HK_TAG = b"HK"

STREAM_TYPES = {0x01: "mpeg1", 0x02: "mpeg2", 0x1B: "h264", 0x24: "h265", 0x0F: "aac",
                0x90: "g711a", 0x91: "g711u", 0x03: "mp1audio", 0x04: "mp2audio"}


@dataclass
class Pack:
    offset: int
    length: int              # pack header + every packet up to the next pack
    scr: int                 # 90 kHz units
    video: int = 0           # PES video packets
    audio: int = 0
    psm: Optional[bytes] = None


def _scr(b: bytes, i: int) -> Optional[int]:
    """SCR base from an MPEG-2 pack header at b[i]; None if not MPEG-2."""
    if i + 14 > len(b) or (b[i + 4] & 0xC0) != 0x40:
        return None
    x = b[i + 4:i + 10]
    return (((x[0] >> 3) & 0x07) << 30 | (x[0] & 0x03) << 28 | x[1] << 20
            | ((x[2] >> 3) & 0x1F) << 15 | (x[2] & 0x03) << 13 | x[3] << 5 | (x[4] >> 3))


def parse_pack(b, i: int, at_end: bool = False) -> Optional[Pack]:
    """The pack at b[i], if its packets end exactly on the next pack header -
    or, when `at_end`, exactly at the end of the data.  None otherwise."""
    scr = _scr(b, i)
    if scr is None:
        return None
    q = i + 14 + (b[i + 13] & 0x07)
    p = Pack(i, 0, scr)
    n_b = len(b)
    while q + 4 <= n_b:
        if b[q] or b[q + 1] or b[q + 2] != 1:
            return None
        sid = b[q + 3]
        if sid == 0xBA:
            p.length = q - i
            return p
        if sid == 0xB9:                     # program end code: no length field
            q += 4
            continue
        if sid < 0xBB or q + 6 > n_b:
            return None
        n = (b[q + 4] << 8) | b[q + 5]
        if 0xE0 <= sid <= 0xEF:
            p.video += 1
        elif 0xC0 <= sid <= 0xDF:
            p.audio += 1
        elif sid == 0xBC and p.psm is None:
            p.psm = bytes(b[q:q + 6 + n])
        q += 6 + n
    if at_end and q == n_b:
        p.length = q - i
        return p
    return None


HK_TIME_SOURCE = ("'HK' descriptor 0x40 in the stream map: year byte, then month 4 bits, "
                  "day 5, hour 5, minute 6, second 6 (big-endian). Observed on the team's "
                  "second drive and checked three ways: it matches the clock burned into a "
                  "decoded frame to the second, advances one second per stream map, and "
                  "spans the same time as the pack clock. Low 6 bits undecoded.")


def hk_time(psm: Optional[bytes]) -> Optional[str]:
    """Recorder-local time from a Hikvision stream map, or None."""
    if not psm:
        return None
    j = psm.find(b"\x40\x0e" + HK_TAG)
    if j < 0 or j + 11 > len(psm):
        return None
    body = psm[j + 2:j + 16]
    v = int.from_bytes(body[5:9], "big")
    try:
        from datetime import datetime
        t = datetime(2000 + body[4], v >> 28, (v >> 23) & 0x1F, (v >> 18) & 0x1F,
                     (v >> 12) & 0x3F, (v >> 6) & 0x3F)
    except ValueError:
        return None
    return t.strftime("%Y-%m-%d %H:%M:%S")


def resolution(row: dict) -> Optional[str]:
    """"WIDTHxHEIGHT" from the video entry's 0x42 descriptor in a report row
    (observed: bytes 4-7 of its body, e.g. 0x03C0 x 0x0240 = 960x576)."""
    for st in row.get("streams", []):
        d = bytes.fromhex(st.get("descriptors_hex", ""))
        i = d.find(b"\x42\x0e")
        if i >= 0 and len(d) >= i + 10:
            w, h = int.from_bytes(d[i + 6:i + 8], "big"), int.from_bytes(d[i + 8:i + 10], "big")
            if w and h:
                return f"{w}x{h}"
    return None


def psm_info(psm: bytes) -> dict:
    """Stream types and the raw "HK" descriptors of a Program Stream Map."""
    out = {"streams": [], "hk_descriptors": []}
    if len(psm) < 12:
        return out
    info_len = struct.unpack_from(">H", psm, 8)[0]
    j, end = 10, 10 + info_len
    while j + 2 <= end and j + 2 <= len(psm):
        tag, n = psm[j], psm[j + 1]
        body = psm[j + 2:j + 2 + n]
        if body[:2] == HK_TAG:
            out["hk_descriptors"].append({"tag": f"0x{tag:02X}", "hex": body.hex()})
        j += 2 + n
    if end + 2 <= len(psm):
        es_len = struct.unpack_from(">H", psm, end)[0]
        k = end + 2
        while k + 4 <= end + 2 + es_len and k + 4 <= len(psm):
            st, sid, n = psm[k], psm[k + 1], struct.unpack_from(">H", psm, k + 2)[0]
            out["streams"].append({"type": STREAM_TYPES.get(st, f"0x{st:02X}"),
                                   "stream_id": f"0x{sid:02X}",
                                   "descriptors_hex": psm[k + 4:k + 4 + n].hex()})
            k += 4 + n
    return out


@dataclass
class PsStream:
    sid: int
    extents: list[list[int]] = field(default_factory=list)   # [offset, length]
    packs: int = 0
    video: int = 0
    audio: int = 0
    psms: int = 0
    first_scr: int = 0
    last_scr: int = 0
    first_psm: Optional[bytes] = None
    last_psm: Optional[bytes] = None

    def add(self, p: Pack) -> None:
        if self.extents and self.extents[-1][0] + self.extents[-1][1] == p.offset:
            self.extents[-1][1] += p.length
        else:
            self.extents.append([p.offset, p.length])
        if not self.packs:
            self.first_scr = p.scr
        self.last_scr = p.scr
        self.packs += 1
        self.video += p.video
        self.audio += p.audio
        if p.psm is not None:
            self.psms += 1
            if self.first_psm is None:
                self.first_psm = p.psm
            self.last_psm = p.psm

    def to_row(self) -> dict:
        info = psm_info(self.first_psm) if self.first_psm else {"streams": [], "hk_descriptors": []}
        span = (self.last_scr - self.first_scr) % (1 << 33)
        return {"id": f"ps-{self.sid:05d}", "offset": self.extents[0][0],
                "bytes": sum(n for _, n in self.extents), "extents": self.extents,
                "packs": self.packs, "video_packets": self.video,
                "audio_packets": self.audio, "stream_maps": self.psms,
                "scr_first": self.first_scr, "scr_last": self.last_scr,
                "duration_s": round(span / SCR_HZ, 2),
                "time_first_local": hk_time(self.first_psm),
                "time_last_local": hk_time(self.last_psm),
                "streams": info["streams"], "hk_descriptors": info["hk_descriptors"],
                "first_psm_hex": self.first_psm.hex() if self.first_psm else ""}


class PsCarver:
    """Consumes packs in disk order; a stream is a contiguous pack chain."""

    def __init__(self):
        self.streams: list[PsStream] = []
        self.cur: Optional[PsStream] = None
        self.next_id = 0
        self.stats = {"packs": 0, "streams_opened": 0, "scr_splits": 0, "gap_splits": 0}

    def add(self, p: Pack) -> None:
        self.stats["packs"] += 1
        c = self.cur
        if c is not None:
            end = c.extents[-1][0] + c.extents[-1][1]
            jump = ((p.scr - c.last_scr + (1 << 32)) % (1 << 33)) - (1 << 32)
            if end != p.offset:
                self.stats["gap_splits"] += 1
                c = None
            elif abs(jump) > SCR_JUMP_S * SCR_HZ:
                self.stats["scr_splits"] += 1
                c = None
        if c is None:
            c = PsStream(self.next_id)
            self.next_id += 1
            self.stats["streams_opened"] += 1
            self.streams.append(c)
            self.cur = c
        c.add(p)

    def finish(self) -> tuple[list[PsStream], dict]:
        kept = [s for s in self.streams if s.packs >= MIN_PACKS]
        self.stats["streams_kept"] = len(kept)
        self.stats["packs_in_short_runs"] = sum(s.packs for s in self.streams
                                                if s.packs < MIN_PACKS)
        return kept, self.stats


class PackFeeder:
    """Pack headers from bytes arriving in order, each judged with the
    following bytes in hand, so a pack crossing a block edge is seen whole."""

    def __init__(self, start: int = 0):
        self.base = start
        self.buf = bytearray()
        self.pos = 0                       # next search position within buf

    def push(self, offset: int, data: bytes, final: bool = False) -> Iterator[Pack]:
        if offset != self.base + len(self.buf):
            raise ValueError(f"PackFeeder: bytes at 0x{offset:X} arrived out of order")
        self.buf += data
        limit = len(self.buf) if final else len(self.buf) - LOOKAHEAD
        b = self.buf
        while self.pos < limit:
            i = b.find(PACK, self.pos, max(self.pos, limit) + 3)
            if i < 0 or i >= limit:
                self.pos = max(self.pos, limit)
                break
            p = parse_pack(b, i, at_end=final)
            if p is None:
                self.pos = i + 1
                continue
            p.offset += self.base
            yield p
            self.pos = i + p.length
        drop = min(self.pos, max(0, len(self.buf) - LOOKAHEAD))
        if drop > 0:
            del self.buf[:drop]
            self.base += drop
            self.pos -= drop

    def close(self) -> Iterator[Pack]:
        yield from self.push(self.base + len(self.buf), b"", final=True)


def carve(dev, start: int = 0, end: Optional[int] = None, chunk: int = 8 << 20):
    end = dev.size_bytes if end is None else min(end, dev.size_bytes)
    feeder, c = PackFeeder(start), PsCarver()
    off = start
    while off < end:
        data = dev.read_at(off, min(chunk, end - off))
        if not data:
            break
        for p in feeder.push(off, data):
            c.add(p)
        off += len(data)
    for p in feeder.close():
        c.add(p)
    return c.finish()


def build_report(streams: list[PsStream], stats: dict, info, tool: str = "carve-ps") -> dict:
    from core.contract import SCHEMA_VERSION, utc_now
    return {
        "schema_version": SCHEMA_VERSION, "generated_utc": utc_now(),
        "tool": f"ps26150-forensics {tool}", "rule": PS_RULE, "format": "mpeg-ps",
        "validation_status": "spec_only",
        "source_device": info.path, "source_bytes": info.size_bytes,
        "write_block_method": info.write_block_method,
        "stats": stats, "streams": [s.to_row() for s in streams],
        "notes": [
            "A carved PS stream is a contiguous chain of MPEG-2 Program Stream packs, "
            "each accepted only because its packets end exactly on the next pack header.",
            "Streams are split where the pack clock (SCR) jumps by more than "
            f"{SCR_JUMP_S:.0f} s, never merged by guesswork.",
            "SCR is a relative 90 kHz clock, not a date. Where a stream map carries a "
            "Hikvision 'HK' descriptor, time_first/last_local are the recorder's own "
            "clock read from it: " + HK_TIME_SOURCE,
            "'HK' descriptors in the stream map are Hikvision's private data; their "
            "meaning is observed, not documented.",
        ],
    }


class PsCarveTap:
    """Scan tap: carve Program Stream footage in the acquisition pass."""

    name = "carve_ps"

    def __init__(self):
        self.feeder: Optional[PackFeeder] = None
        self.carver = PsCarver()

    def prepare(self, dev, start: int, end: int, log=print) -> None:
        self.feeder = PackFeeder(start)
        log("[*] carve-ps MPEG Program Stream packs, chained by structure")

    def feed(self, offset: int, data: bytes) -> None:
        for p in self.feeder.push(offset, data):
            self.carver.add(p)

    def finish(self, out_dir: str, info) -> dict:
        from core.hashing import sha256_file
        for p in self.feeder.close():
            self.carver.add(p)
        streams, stats = self.carver.finish()
        rep = build_report(streams, stats, info, tool="scan --carve-ps (inline)")
        os.makedirs(os.path.join(out_dir, "carve"), exist_ok=True)
        path = os.path.join(out_dir, "carve", "ps_report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1)
        return {"report": "carve/ps_report.json", "sha256": sha256_file(path),
                "packs": stats["packs"], "streams_kept": stats["streams_kept"],
                "bytes": sum(r["bytes"] for r in rep["streams"])}


def extract(dev, rows: list[dict], out_dir: str, manifest_path: str, log=print) -> dict:
    """Copy each stream's extents out unmodified as <id>.ps - a playable
    Program Stream. Resumable like the DHAV extraction."""
    from core.hashing import sha256_file
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"streams": {}}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    done = manifest["streams"]
    for i, r in enumerate(rows):
        name = f"{r['id']}.ps"
        if r["id"] in done and os.path.exists(os.path.join(out_dir, name)):
            continue
        path = os.path.join(out_dir, name)
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
        log(f"  [{i + 1}/{len(rows)}] {name}  {n / 2**20:,.1f} MiB  {r['duration_s']:.0f} s")
    return manifest

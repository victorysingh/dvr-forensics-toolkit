"""Honeywell NVR: the proprietary video partition described by Yoon & Hwang (DFRWS USA 2026).

A drop-in plugin: this one file is the whole of the Honeywell support, and
nothing in the core was edited to add it - the add-a-vendor route the tool
claims, used for real.

SOURCE
------
J. Yoon, S. Hwang, "Forensic analysis of video data deletion and recovery in
Honeywell surveillance file system", DFRWS USA 2026, arXiv:2605.07430,
section 5 (layout) and 6 (deletion).  The paper studied a Honeywell
HN35080200 NVR with eight HN40E-2030I cameras recording H.264, on 160 GB
and 250 GB disks.  Every field below cites the section it comes from.

STATUS: spec_only
-----------------
Written from the paper.  No Honeywell disk has been read by this team; the
tests run on a fixture built to the paper's description, which proves the
code does what the paper says, not that the paper matches every Honeywell
unit.  Where the paper is ambiguous, nothing is guessed:

  * the byte order of the 20-byte frame header's size and length fields is
    not stated (5.4 says the partition is little-endian); a frame header is
    accepted only when its length lands exactly on the next header, and
    whether that length counted the start code is measured, not assumed;
  * "the 12th byte" of a block index may count from 0 or from 1, so block and
    group numbers are not decoded - only the block's start time;
  * whether channel-list offsets count from Partition 1 or from its video
    area is tried both ways; the one that lands on valid frame headers is
    kept and reported;
  * four bytes of each 16-byte channel entry, and the Record State status
    bytes, are unexplained in the paper and left undecoded.

TIME
----
Unix seconds (lists) and Unix microseconds (frame headers), as the recorder
wrote them.  Whether its clock ran on UTC or local time is not stated in the
paper and is not assumed: times are shown as the epoch decodes, with the
zone marked unknown.

DELETION (paper, 6)
-------------------
Formatting resets the header and removes the block, channel and record
indexes but leaves the video in place until new recording overwrites it
from the start of the video area.  `recover_video_area` walks the frame
headers directly, so footage - each NAL unit with its own microsecond
timestamp - comes back from a formatted disk with no index at all.
"""

from __future__ import annotations

import os
import struct
from datetime import datetime, timezone
from typing import Iterator, Optional

from core.contract import (
    STATE_ACTIVE,
    STATE_FRAGMENT,
    Provenance,
    Recording,
    TimestampClaim,
)
from core.hashing import sha256_file
from detect.engine import parse_partitions
from parsers.base import (
    SOURCE_PUBLISHED,
    FieldSpec,
    ParseResult,
    VendorParser,
    register,
    weakest_source,
)

PAPER = "Yoon & Hwang, DFRWS USA 2026, arXiv:2605.07430"

# Offsets inside Partition 1 (paper 5.4.1-5.4.6).
HEADER_END = 0x4000
BLOCK_LIST = 0x40000
CHANNEL_LIST = 0x400000
CHANNEL_LIST_END = 0x40000000
UNIT = 0x1000                      # values "rounded at the third digit" (5.4.1, 5.4.3)
ENTRY = 16                         # block index and channel index entries
MACHINE_SECTOR = 34                # "Machine Data": device ID and model name (5.2)
FRAME_HDR = 20
FRAME_TYPES = {0x82: "IDR", 0x02: "non-IDR"}
FRAME_FIXED = b"\x80\x01\x00"
STREAM_TYPES = {0x00: "main", 0x20: "sub"}

MAX_ENTRIES = 4_000_000            # a list longer than this is not a list
MAX_NAL = 2 << 20                  # a 4K I-frame slice is about 1 MiB
GAP_S = 60                         # a channel's chunks this far apart start a new recording
RESYNC = 64 << 10                  # how far past padding to look for the next frame header

FIELDS = [
    FieldSpec("video_start", 0x00, "<I*0x1000", "start of the video data", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.1"),
    FieldSpec("next_write", 0x08, "<I*0x1000", "offset of the next video write",
              SOURCE_PUBLISHED, f"{PAPER}, 5.4.1"),
    FieldSpec("available", 0x10, "<I*0x1000", "available memory", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.1"),
    FieldSpec("total", 0x18, "<I*0x1000", "total allocatable memory", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.1"),
    FieldSpec("block_group_start", 0x44, "<I", "block group start time (Unix s)",
              SOURCE_PUBLISHED, f"{PAPER}, 5.4.1"),
    FieldSpec("block.start_time", 0x04, "<I", "block start time (Unix s), 16-byte entries "
              "from 0x40000", SOURCE_PUBLISHED, f"{PAPER}, 5.4.2"),
    FieldSpec("channel.id", 0x00, "<B", "channel identifier, 16-byte entries from 0x400000",
              SOURCE_PUBLISHED, f"{PAPER}, 5.4.3"),
    FieldSpec("channel.stream", 0x01, "<B", "stream type: 0x00 main, 0x20 sub",
              SOURCE_PUBLISHED, f"{PAPER}, 5.4.3"),
    FieldSpec("channel.length", 0x02, "<H*0x1000", "chunk length", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.3"),
    FieldSpec("channel.start_time", 0x04, "<I", "chunk start time (Unix s)",
              SOURCE_PUBLISHED, f"{PAPER}, 5.4.3"),
    FieldSpec("channel.offset", 0x08, "<I*0x1000", "chunk start offset", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.3"),
    FieldSpec("frame.type", 0x00, "<B", "0x82 IDR, 0x02 non-IDR", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.6"),
    FieldSpec("frame.fixed", 0x01, "bytes:3", "80 01 00", SOURCE_PUBLISHED, f"{PAPER}, 5.4.6"),
    FieldSpec("frame.size", 0x04, "<HH", "width, height", SOURCE_PUBLISHED, f"{PAPER}, 5.4.6"),
    FieldSpec("frame.nal_length", 0x08, "<I", "NAL unit length", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.6"),
    FieldSpec("frame.time_us", 0x0C, "<Q", "Unix microsecond timestamp", SOURCE_PUBLISHED,
              f"{PAPER}, 5.4.6"),
]


def _utc(seconds: float) -> Optional[str]:
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _strings(b: bytes, least: int = 4) -> list[str]:
    out, cur = [], bytearray()
    for c in b + b"\x00":
        if 32 <= c < 127:
            cur.append(c)
        else:
            if len(cur) >= least:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    return out


def frame_header(b: bytes) -> Optional[dict]:
    """A 20-byte Custom Header (5.4.6), or None.  The size and length are
    read little-endian, as the partition is (5.4); a header is only believed
    when the walker finds the next one where its length says."""
    if len(b) < FRAME_HDR or b[0] not in FRAME_TYPES or b[1:4] != FRAME_FIXED:
        return None
    w, h, n, us = struct.unpack_from("<HHIQ", b, 4)
    if not (64 <= w <= 8192 and 64 <= h <= 8192 and 0 < n <= MAX_NAL):
        return None
    return {"type": FRAME_TYPES[b[0]], "width": w, "height": h, "nal_length": n,
            "time_us": us}


class Walk:
    """Frames of the video area from one offset: each header, where its NAL
    unit sits, and whether the length counted the 4-byte start code."""

    def __init__(self):
        self.frames = 0
        self.length_incl_start_code = 0
        self.length_excl_start_code = 0
        self.resyncs = 0


def walk_frames(dev, start: int, end: int, walk: Optional[Walk] = None,
                chunk: int = 8 << 20) -> Iterator[tuple[int, dict, bytes]]:
    """(header offset, header, NAL unit with its start code) for every frame
    from `start` to `end`.  Padding between chunks (5.4.6: a dummy value up to
    the rounded length, 20 zero bytes between channels) is skipped by looking
    ahead for the next valid header; each such jump is counted."""
    walk = walk or Walk()
    pos = start
    buf, base = b"", start
    while pos + FRAME_HDR <= end:
        if pos + FRAME_HDR + MAX_NAL + RESYNC > base + len(buf) and base + len(buf) < end:
            buf = dev.read_at(pos, min(end - pos, chunk + MAX_NAL + RESYNC))
            base = pos
        rel = pos - base
        hdr = frame_header(buf[rel:rel + FRAME_HDR])
        if hdr is None or buf[rel + FRAME_HDR:rel + FRAME_HDR + 4] != b"\x00\x00\x00\x01":
            nxt = _resync(buf, rel + 1)
            if nxt is None:
                return
            walk.resyncs += 1
            pos = base + nxt
            continue
        body = rel + FRAME_HDR
        n = hdr["nal_length"]
        # Does the length cover the start code?  The reading that lands on the
        # next header (or on the 20 zero bytes that end a channel's data) is
        # used and counted.  Where neither does - the dummy padding before a
        # rounded chunk end (5.4.6) - the convention seen so far is kept.
        incl, excl = body + n, body + 4 + n
        a, b = _lands(buf, incl), _lands(buf, excl)
        if a and not b:
            stop = incl
            walk.length_incl_start_code += 1
        elif b and not a:
            stop = excl
            walk.length_excl_start_code += 1
        else:
            stop = excl if walk.length_excl_start_code > walk.length_incl_start_code else incl
        if base + stop > end:
            return
        walk.frames += 1
        yield pos, hdr, bytes(buf[body:stop])
        pos = base + stop


def _lands(buf: bytes, i: int) -> bool:
    b = buf[i:i + FRAME_HDR]
    return len(b) == FRAME_HDR and (frame_header(b) is not None or not b.strip(b"\x00"))


def _resync(buf: bytes, i: int) -> Optional[int]:
    j = buf.find(FRAME_FIXED, i + 1)
    while 0 <= j < i + RESYNC + 1:
        k = j - 1
        if frame_header(buf[k:k + FRAME_HDR]) and buf[k + FRAME_HDR:k + FRAME_HDR + 4] == b"\x00\x00\x00\x01":
            return k
        j = buf.find(FRAME_FIXED, j + 1)
    return None


@register
class HoneywellParser(VendorParser):
    vendor = "Honeywell"
    parser_rule = "honeywell.nvr.yoon-hwang-2026.v1"

    def __init__(self):
        self.extents: dict[str, list[tuple[int, int]]] = {}
        self.partition: Optional[tuple[int, int]] = None

    # -- layout -----------------------------------------------------------
    def _partition(self, dev) -> Optional[tuple[int, int]]:
        ss = getattr(dev, "sector_size", 512) or 512
        parts = [p for p in parse_partitions(dev.read_at(0, 64 << 10), ss) if p.scheme == "gpt"]
        return (parts[0].start_offset, parts[0].length) if parts else None

    def _header(self, dev, p1: int) -> dict:
        raw = dev.read_at(p1, 0x50)
        u = lambda o: struct.unpack_from("<I", raw, o)[0]
        return {"video_start": u(0x00) * UNIT, "next_write": u(0x08) * UNIT,
                "available": u(0x10) * UNIT, "total": u(0x18) * UNIT,
                "block_group_start": u(0x44), "raw_hex": raw.hex()}

    def detect(self, dev, hint_offsets=None) -> bool:
        part = self._partition(dev)
        if not part:
            return False
        p1, size = part
        h = self._header(dev, p1)
        return (0 < h["video_start"] < size and h["available"] <= h["total"] <= size
                and (h["next_write"] == 0 or h["video_start"] <= h["next_write"] <= size)
                and frame_header(dev.read_at(p1 + h["video_start"], FRAME_HDR)) is not None)

    # -- lists --------------------------------------------------------------
    def _entries(self, dev, start: int, end: int) -> Iterator[bytes]:
        pos, n = start, 0
        while pos < end and n < MAX_ENTRIES:
            data = dev.read_at(pos, min(1 << 20, end - pos))
            for i in range(0, len(data) - ENTRY + 1, ENTRY):
                e = data[i:i + ENTRY]
                if not e.strip(b"\x00"):
                    return
                n += 1
                yield e
            pos += len(data)

    def _base(self, dev, p1: int, video_start: int, entries: list[dict]) -> tuple[Optional[int], str]:
        """Which origin the channel-list offsets count from: the one whose
        offsets land on valid frame headers."""
        tried = {}
        for name, base in (("partition", p1), ("video area", p1 + video_start)):
            ok = sum(1 for e in entries[:32]
                     if frame_header(dev.read_at(base + e["offset"], FRAME_HDR)))
            tried[name] = (ok, base)
        name, (ok, base) = max(tried.items(), key=lambda kv: kv[1][0])
        return (base, name) if ok else (None, "undetermined")

    # -- parse --------------------------------------------------------------
    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=weakest_source([f.source for f in FIELDS]))
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        part = self._partition(dev)
        if not part or not self.detect(dev):
            result.errors.append("no Honeywell NVR layout: needs a GPT disk whose first "
                                 "partition starts with a consistent header (paper 5.4.1)")
            return result
        p1, size = self.partition = part
        h = self._header(dev, p1)
        ss = getattr(dev, "sector_size", 512) or 512
        machine = _strings(dev.read_at(MACHINE_SECTOR * ss, ss))
        blocks = [struct.unpack_from("<I", e, 4)[0]
                  for e in self._entries(dev, p1 + BLOCK_LIST, p1 + CHANNEL_LIST)]
        list_end = p1 + min(CHANNEL_LIST_END, h["video_start"])
        chans = [{"channel": e[0], "stream": STREAM_TYPES.get(e[1], f"0x{e[1]:02X}"),
                  "length": struct.unpack_from("<H", e, 2)[0] * UNIT,
                  "time": struct.unpack_from("<I", e, 4)[0],
                  "offset": struct.unpack_from("<I", e, 8)[0] * UNIT}
                 for e in self._entries(dev, p1 + CHANNEL_LIST, list_end)]
        base, base_name = self._base(dev, p1, h["video_start"], chans)
        codec = self._codec(dev, base, chans)

        result.volume = {
            "vendor": self.vendor, "partition1": {"offset": p1, "bytes": size},
            "header": h, "machine_data_strings": machine,
            "block_indexes": len(blocks),
            "block_times": [_utc(min(blocks)), _utc(max(blocks))] if blocks else None,
            "channel_indexes": len(chans), "channel_offset_origin": base_name,
            "codec": codec,
            "summary": [
                ("partition 1", f"0x{p1:X}, {size:,} bytes"),
                ("video area", f"+0x{h['video_start']:X}; next write +0x{h['next_write']:X}"),
                ("space", f"{h['available']:,} of {h['total']:,} bytes available"),
                ("machine data", "; ".join(machine[:4]) or "(none readable)"),
                ("block index", f"{len(blocks)} entries"),
                ("channel index", f"{len(chans)} entries; offsets count from the "
                                  f"{base_name}"),
                ("codec", codec or "?"),
            ]}
        if base is None and chans:
            result.errors.append("channel-list offsets land on no frame header from either "
                                 "origin - chunks not located")
        result.recordings = self._recordings(chans, base, codec) if base is not None else []
        result.indexed_extents = [(base + c["offset"], c["length"]) for c in chans] if base else []
        result.notes = [
            f"Layout from {PAPER}; no Honeywell disk has been read by the team (spec_only).",
            "Times are Unix epoch as the recorder wrote them; whether its clock ran on UTC "
            "or local time is not stated in the paper and not assumed.",
            "Block and group numbers are not decoded: the paper's '12th byte' may count from "
            "0 or 1. Four bytes of each channel entry and the Record State status bytes are "
            "unexplained in the paper and left undecoded.",
            f"Channel-list offsets count from the {base_name} - measured by where they land "
            f"on valid frame headers, not assumed.",
        ]
        return result

    def _codec(self, dev, base: Optional[int], chans: list[dict]) -> Optional[str]:
        if base is None or not chans:
            return None
        b = dev.read_at(base + chans[0]["offset"], FRAME_HDR + 6)
        if frame_header(b) and b[FRAME_HDR:FRAME_HDR + 4] == b"\x00\x00\x00\x01":
            nh = b[FRAME_HDR + 4]
            return "h265" if not nh & 0x81 and b[FRAME_HDR + 5] in range(1, 8) else "h264"
        return None

    def _recordings(self, chans: list[dict], base: int, codec: Optional[str]) -> list[Recording]:
        runs: dict[tuple, list[list[dict]]] = {}
        for c in sorted(chans, key=lambda c: (c["channel"], c["stream"], c["time"])):
            key = (c["channel"], c["stream"])
            lanes = runs.setdefault(key, [])
            if lanes and c["time"] - lanes[-1][-1]["time"] <= GAP_S:
                lanes[-1].append(c)
            else:
                lanes.append([c])
        recs = []
        for (ch, stream), lanes in sorted(runs.items()):
            for k, run in enumerate(lanes):
                rid = f"hw-ch{ch:02d}-{stream}-{k:04d}"
                ext = [(base + c["offset"], c["length"]) for c in run]
                self.extents[rid] = ext
                first, last = run[0], run[-1]
                claim = TimestampClaim(
                    source="index", raw_value=f"0x{first['time']:08X}",
                    decoded_utc=_utc(first["time"]), tz_offset_min=None, confidence=0.5,
                    decode_rule="Unix seconds from the channel index (paper 5.4.3), as the "
                                "recorder wrote them; its zone is not established")
                recs.append(Recording(
                    id=rid, camera_id=f"CH{ch:02d}" + ("" if stream == "main" else f"-{stream}"),
                    state=STATE_ACTIVE, codec=codec or "", offset=ext[0][0],
                    length=sum(n for _, n in ext), start_utc=_utc(first["time"]),
                    end_utc=_utc(last["time"]), duration_s=float(last["time"] - first["time"]),
                    confidence=0.5, frame_count=0, timestamps=[claim],
                    provenance=Provenance(disk_offset=ext[0][0], length=sum(n for _, n in ext),
                                          sector_start=ext[0][0] // 512,
                                          sector_end=(ext[-1][0] + ext[-1][1]) // 512,
                                          parser_rule=self.parser_rule)))
        return recs

    # -- footage out ----------------------------------------------------------
    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """One recording's NAL units, custom headers removed, as a playable
        Annex-B file; each frame's microsecond time kept in the manifest."""
        if recording_id not in self.extents:
            self.parse(dev)
        ext = self.extents.get(recording_id)
        if not ext:
            raise KeyError(recording_id)
        walk, times = Walk(), []
        path = base_path + ".h264"
        with open(path, "wb") as fh:
            for off, n in ext:
                for _pos, hdr, nal in walk_frames(dev, off, off + n, walk):
                    fh.write(nal)
                    times.append(hdr["time_us"])
        return {"file": os.path.basename(path), "sha256": sha256_file(path),
                "bytes": os.path.getsize(path), "frames": walk.frames,
                "first_time_utc": _utc(times[0] / 1e6) if times else None,
                "last_time_utc": _utc(times[-1] / 1e6) if times else None,
                "length_counted_start_code": walk.length_incl_start_code,
                "length_excluded_start_code": walk.length_excl_start_code,
                "padding_skips": walk.resyncs, "chunks": len(ext)}

    def recover_video_area(self, dev, limit: Optional[int] = None) -> list[Recording]:
        """Footage from the video area by its frame headers alone - what is
        left after a format (paper 6), when every index is gone.

        One run per chunk, never joined: frame headers carry no channel, and
        the chunks of different cameras alternate in the video area, so a run
        that crossed padding could cross cameras.  Camera unknown."""
        part = self._partition(dev)
        if not part:
            return []
        p1, size = part
        start = p1 + self._header(dev, p1)["video_start"]
        end = p1 + size if limit is None else min(p1 + size, start + limit)
        walk, runs, cur = Walk(), [], None
        for pos, hdr, nal in walk_frames(dev, start, end, walk):
            t = hdr["time_us"] / 1e6
            if cur and (pos != cur["end"] or abs(t - cur["t1"]) > GAP_S
                        or (hdr["width"], hdr["height"]) != cur["size"]):
                runs.append(cur)
                cur = None
            if cur is None:
                cur = {"start": pos, "end": pos, "t0": t, "t1": t, "frames": 0,
                       "size": (hdr["width"], hdr["height"])}
            cur["end"] = pos + FRAME_HDR + len(nal)
            cur["t1"], cur["frames"] = t, cur["frames"] + 1
        if cur:
            runs.append(cur)
        recs = []
        for k, r in enumerate(runs):
            claim = TimestampClaim(
                source="container", raw_value=f"{int(r['t0'] * 1e6)} us",
                decoded_utc=_utc(r["t0"]), confidence=0.5,
                decode_rule="Unix microseconds from the frame header (paper 5.4.6); zone "
                            "not established")
            recs.append(Recording(
                id=f"hw-video-{k:05d}", camera_id="unknown", state=STATE_FRAGMENT,
                codec="h264", offset=r["start"], length=r["end"] - r["start"],
                start_utc=_utc(r["t0"]), end_utc=_utc(r["t1"]),
                duration_s=round(r["t1"] - r["t0"], 3), confidence=0.4,
                frame_count=r["frames"], timestamps=[claim],
                provenance=Provenance(disk_offset=r["start"], length=r["end"] - r["start"],
                                      sector_start=r["start"] // 512,
                                      sector_end=r["end"] // 512,
                                      parser_rule=self.parser_rule + ".video-area")))
        self.video_area_stats = {"frames": walk.frames, "padding_skips": walk.resyncs,
                                 "runs": len(runs)}
        return recs

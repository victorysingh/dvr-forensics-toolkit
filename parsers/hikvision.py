"""Hikvision proprietary filesystem parser.

Hikvision DVRs do not put a conventional filesystem on the platter.  The
whole disk is one proprietary volume: a master sector near the start of the
disk describes the volume, and a B-tree index (HIKBTREE) maps recordings to
the data blocks that hold them.  This module locates both and turns the index
into `Recording` objects per the frozen contract.

WHAT IS AND IS NOT ESTABLISHED HERE
-----------------------------------
Two different grades of evidence are mixed in this format, and conflating
them is exactly the overclaim START_HERE Rule 3 warns about, so every field
below carries its source explicitly:

  * The **magic strings** and the **overall shape** of the format - a master
    sector at 0x200 carrying `HIKVISION@HANGZHOU`, a `HIKBTREE` index header,
    `OFFSET` markers inside the index page area - are attested by published
    research and by existing open-source parsers.  Those are SOURCE_PUBLISHED.

  * The **exact struct offsets** of the individual fields we decode inside
    those structures (capacity at 0x20, block size at 0x28, channel count at
    0x30, and the 24-byte index entry layout) are corroborated only by
    `tests/synth_dvr.py`, whose non-magic layout that file's own docstring
    describes as "our own invention".  Those are SOURCE_FIXTURE.

The consequence, applied rather than merely stated: because the weakest field
sets the status, this parser reports **synthetic_only** when it has parsed
fixture-sourced fields, not `spec_only`.  Passing against our own generated
image proves the code reads a layout we invented; it proves nothing about
Hikvision.  START_HERE's "mark it spec_only" is the right label for a parser
written purely from the papers - the magic-string location logic here does
qualify - but it would overstate the struct decoding, so the weakest-evidence
rule wins and the parser says so in its own output.

Moving this to `validated` requires the ground-truth experiment in
docs/LINUX_ACQUISITION.md section 6: byte-match carved output against the
DVR's own native export.  Nothing short of that.

Reverse-engineering note for whoever gets the real drive: the field offsets
are declared as data in MASTER_FIELDS / INDEX_ENTRY below precisely so they
can be corrected against real media without touching the parsing logic.  When
a field is confirmed on the physical DS-80xx disk, change its `source` to
SOURCE_OBSERVED and record the evidence in its `citation`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional

from core.contract import (
    STATE_ACTIVE,
    Frame,
    Provenance,
    Recording,
    TimestampClaim,
)
from core.hashing import sha256_bytes
from parsers.base import (
    SOURCE_FIXTURE,
    SOURCE_PUBLISHED,
    FieldSpec,
    ParseResult,
    VendorParser,
    register,
    weakest_source,
)

VENDOR = "Hikvision"

MASTER_MAGIC = b"HIKVISION@HANGZHOU"
BTREE_MAGIC = b"HIKBTREE"
OFFSET_MARKER = b"OFFSET"

# The master sector sits at 0x200 on every Hikvision volume described in the
# literature.  We still search a window around it rather than trusting the
# constant: a disk imaged with an offset, or a volume that does not start at
# LBA 0, would otherwise silently parse as "not Hikvision".
MASTER_EXPECTED_OFFSET = 0x200
MASTER_SEARCH_BYTES = 1 << 20          # 1 MiB
BTREE_SEARCH_BYTES = 16 << 20          # 16 MiB

# A recording extent larger than this is treated as a corrupt index entry
# rather than read into memory.  A real DVR clip is minutes of video, not
# gigabytes, and an index read from a damaged platter will contain garbage.
MAX_CLIP_BYTES = 512 << 20
# How much of a clip we hash and frame-scan.  Clips can be large and this runs
# on a forensic workstation, so we bound the work and say so in the output.
CLIP_INSPECT_BYTES = 8 << 20

_CITE_PUB = ("Han/Jeong/Lee DVR filesystem analysis; hikextractor; "
             "published Hikvision FS write-ups")
_CITE_FIX = "tests/synth_dvr.py::_hik_master / _hik_btree (our own layout)"

# --- master sector ---------------------------------------------------------
MASTER_FIELDS = [
    FieldSpec("magic", 0x00, "magic", "HIKVISION@HANGZHOU volume magic",
              SOURCE_PUBLISHED, _CITE_PUB),
    FieldSpec("capacity_bytes", 0x20, "<Q", "Nominal volume capacity",
              SOURCE_FIXTURE, _CITE_FIX),
    FieldSpec("data_block_size", 0x28, "<Q", "Size of one video data block",
              SOURCE_FIXTURE, _CITE_FIX),
    FieldSpec("channel_count", 0x30, "<I", "Number of camera channels",
              SOURCE_FIXTURE, _CITE_FIX),
    FieldSpec("model", 0x40, "bytes:16", "DVR model string",
              SOURCE_FIXTURE, _CITE_FIX),
    FieldSpec("firmware", 0x60, "bytes:8", "Firmware version string",
              SOURCE_FIXTURE, _CITE_FIX),
]

# --- HIKBTREE index --------------------------------------------------------
BTREE_FIELDS = [
    FieldSpec("magic", 0x00, "magic", "HIKBTREE index header magic",
              SOURCE_PUBLISHED, _CITE_PUB),
    FieldSpec("entry_count", 0x10, "<I", "Number of index entries",
              SOURCE_FIXTURE, _CITE_FIX),
    FieldSpec("offset_marker", 0x20, "magic", "OFFSET page-area marker",
              SOURCE_PUBLISHED, _CITE_PUB),
]

INDEX_ENTRY_START = 0x40
INDEX_ENTRY_FMT = "<QQII"                     # start, length, camera, unix_ts
INDEX_ENTRY_SIZE = struct.calcsize(INDEX_ENTRY_FMT)
INDEX_ENTRY = FieldSpec(
    "index_entry", INDEX_ENTRY_START, INDEX_ENTRY_FMT,
    "start_offset(u64), length(u64), camera_id(u32), unix_start(u32)",
    SOURCE_FIXTURE, _CITE_FIX,
)
# An index page that claims more entries than this is treated as corrupt.
MAX_INDEX_ENTRIES = 1 << 20

# H.264 Annex-B, used for frame counting inside a located clip.  The scanner
# in detect/ profiles codecs across the whole platter; here we only need the
# per-clip structure a carver and a player will rely on.
SC4 = b"\x00\x00\x00\x01"
SC3 = b"\x00\x00\x01"
H264_SPS, H264_PPS, H264_IDR = 7, 8, 5
H264_KEYFRAME_NALS = {H264_IDR, H264_SPS, H264_PPS}


@dataclass
class MasterSector:
    offset: int
    capacity_bytes: int = 0
    data_block_size: int = 0
    channel_count: int = 0
    model: str = ""
    firmware: str = ""

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "capacity_bytes": self.capacity_bytes,
            "data_block_size": self.data_block_size,
            "channel_count": self.channel_count,
            "model": self.model,
            "firmware": self.firmware,
        }


@dataclass
class IndexEntry:
    start_offset: int
    length: int
    camera_id: int
    unix_start: int


def _decode_utc(unix_ts: int) -> Optional[str]:
    """DVR index timestamps are seconds since the Unix epoch in the recorder's
    own notion of time.  We decode the value and say where it came from; we do
    NOT assert it is correct.  A DVR clock that drifts or was never set is the
    normal case, which is why this becomes a TimestampClaim rather than a fact
    and why the timeline stage cross-checks it against other sources."""
    if not 0 < unix_ts < (1 << 31) - 1:
        return None
    try:
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", "replace").strip()


def iter_nals(data: bytes, base_offset: int = 0) -> Iterator[Frame]:
    """Walk Annex-B NAL units in `data`, yielding contract Frame objects.

    Kept deliberately simple and total: it never raises on malformed input,
    because it will be handed carved fragments and partially overwritten
    clips, where giving up on the first bad byte would lose the rest.
    """
    i = 0
    n = len(data)
    index = 0
    starts: list[tuple[int, int]] = []
    while i < n - 3:
        if data[i:i + 4] == SC4:
            starts.append((i, 4))
            i += 4
        elif data[i:i + 3] == SC3:
            starts.append((i, 3))
            i += 3
        else:
            i += 1
    for k, (pos, sclen) in enumerate(starts):
        hdr = pos + sclen
        if hdr >= n:
            break
        nal_type = data[hdr] & 0x1F
        end = starts[k + 1][0] if k + 1 < len(starts) else n
        yield Frame(
            index=index,
            offset=base_offset + pos,
            length=end - pos,
            nal_type=nal_type,
            codec="h264",
            is_keyframe=nal_type in H264_KEYFRAME_NALS,
        )
        index += 1


def _find(dev, pattern: bytes, limit: int, chunk: int = 1 << 20,
          start: int = 0) -> int:
    """Locate `pattern` within the first `limit` bytes. Returns -1 if absent.

    Reads in overlapping chunks so a magic straddling a chunk boundary is
    still found - the same boundary bug the detection engine handles with a
    carry-over tail.
    """
    overlap = len(pattern) - 1
    size = getattr(dev, "size_bytes", 0) or limit
    end = min(limit, size)
    off = start
    while off < end:
        want = min(chunk, end - off)
        try:
            data = dev.read_at(off, want + overlap)
        except Exception:                                # noqa: BLE001
            return -1
        if not data:
            return -1
        pos = data.find(pattern)
        if pos != -1:
            return off + pos
        off += want
    return -1


@register
class HikvisionParser(VendorParser):
    """Parses the Hikvision master sector and HIKBTREE index."""

    vendor = VENDOR
    parser_rule = "hikvision.hikbtree.v1"

    # -- detection ---------------------------------------------------------
    def detect(self, dev, hint_offsets: Optional[list[int]] = None) -> bool:
        if hint_offsets:
            for off in hint_offsets:
                try:
                    if dev.read_at(off, len(MASTER_MAGIC)) == MASTER_MAGIC:
                        return True
                except Exception:                        # noqa: BLE001
                    continue
        return self.find_master(dev) != -1

    def find_master(self, dev) -> int:
        """Absolute offset of the master sector, or -1.

        Checks the documented offset first so the common case costs one read,
        then falls back to a bounded search.
        """
        try:
            if dev.read_at(MASTER_EXPECTED_OFFSET,
                           len(MASTER_MAGIC)) == MASTER_MAGIC:
                return MASTER_EXPECTED_OFFSET
        except Exception:                                # noqa: BLE001
            pass
        return _find(dev, MASTER_MAGIC, MASTER_SEARCH_BYTES)

    def find_btree(self, dev, after: int = 0) -> int:
        return _find(dev, BTREE_MAGIC, BTREE_SEARCH_BYTES, start=after)

    # -- structure decoding ------------------------------------------------
    def parse_master(self, dev, offset: int) -> tuple[MasterSector, list[str]]:
        raw = dev.read_at(offset, 1024)
        notes: list[str] = []
        ms = MasterSector(offset=offset)
        for f in MASTER_FIELDS:
            if f.fmt == "magic":
                continue
            try:
                if f.fmt.startswith("bytes:"):
                    n = int(f.fmt.split(":", 1)[1])
                    value = _cstr(raw[f.offset:f.offset + n])
                else:
                    size = struct.calcsize(f.fmt)
                    value = struct.unpack_from(f.fmt, raw, f.offset)[0]
            except (struct.error, IndexError, ValueError) as exc:
                notes.append(f"master field {f.name} at 0x{f.offset:X} "
                             f"unreadable: {exc}")
                continue
            setattr(ms, f.name, value)

        # Sanity, reported rather than silently corrected.  A capacity that
        # disagrees with the device is a real finding: it can mean the volume
        # was moved between disks, or that our field offset is simply wrong on
        # this firmware - and on real media that is what we most need to see.
        dev_size = getattr(dev, "size_bytes", 0)
        if ms.capacity_bytes and dev_size and ms.capacity_bytes > dev_size * 2:
            notes.append(
                f"master claims capacity {ms.capacity_bytes} B but the device "
                f"is {dev_size} B - field offset may be wrong for this "
                f"firmware, or the volume came from a larger disk")
        return ms, notes

    def parse_index(self, dev, offset: int) -> tuple[list[IndexEntry], list[str]]:
        notes: list[str] = []
        head = dev.read_at(offset, 64)
        if head[:len(BTREE_MAGIC)] != BTREE_MAGIC:
            return [], [f"no HIKBTREE magic at 0x{offset:X}"]

        try:
            count = struct.unpack_from("<I", head, 0x10)[0]
        except struct.error:
            return [], [f"index entry count unreadable at 0x{offset:X}"]

        if count > MAX_INDEX_ENTRIES:
            notes.append(f"index claims {count} entries, clamping to "
                         f"{MAX_INDEX_ENTRIES} - page is probably corrupt")
            count = MAX_INDEX_ENTRIES

        if head[0x20:0x20 + len(OFFSET_MARKER)] != OFFSET_MARKER:
            notes.append("OFFSET page-area marker absent at 0x20 - index "
                         "layout may differ on this firmware")

        want = INDEX_ENTRY_START + count * INDEX_ENTRY_SIZE
        raw = dev.read_at(offset, want)
        entries: list[IndexEntry] = []
        dev_size = getattr(dev, "size_bytes", 0)
        for i in range(count):
            pos = INDEX_ENTRY_START + i * INDEX_ENTRY_SIZE
            try:
                start, length, cam, ts = struct.unpack_from(
                    INDEX_ENTRY_FMT, raw, pos)
            except struct.error:
                notes.append(f"index entry {i} truncated - stopping")
                break
            if length == 0:
                continue
            if length > MAX_CLIP_BYTES:
                notes.append(f"index entry {i} claims {length} B, beyond the "
                             f"{MAX_CLIP_BYTES} B sanity bound - skipped")
                continue
            if dev_size and start + length > dev_size:
                notes.append(f"index entry {i} extent 0x{start:X}+{length} "
                             f"runs past the end of the device - skipped")
                continue
            entries.append(IndexEntry(start, length, cam, ts))
        return entries, notes

    # -- full parse --------------------------------------------------------
    def parse(self, dev, hint_offsets: Optional[list[int]] = None) -> ParseResult:
        result = ParseResult(vendor=VENDOR, parser_rule=self.parser_rule)
        result.field_provenance = [
            {"struct": "master_sector", "field": f.name,
             "offset": f.offset, "source": f.source,
             "implies_status": f.status, "citation": f.citation}
            for f in MASTER_FIELDS
        ] + [
            {"struct": "hikbtree_header", "field": f.name,
             "offset": f.offset, "source": f.source,
             "implies_status": f.status, "citation": f.citation}
            for f in BTREE_FIELDS
        ] + [
            {"struct": "hikbtree_entry", "field": INDEX_ENTRY.name,
             "offset": INDEX_ENTRY.offset, "source": INDEX_ENTRY.source,
             "implies_status": INDEX_ENTRY.status,
             "citation": INDEX_ENTRY.citation},
        ]

        master_off = -1
        if hint_offsets:
            for off in hint_offsets:
                try:
                    if dev.read_at(off, len(MASTER_MAGIC)) == MASTER_MAGIC:
                        master_off = off
                        break
                except Exception:                        # noqa: BLE001
                    continue
        if master_off == -1:
            master_off = self.find_master(dev)
        if master_off == -1:
            result.errors.append(
                "no HIKVISION@HANGZHOU master sector found - not a Hikvision "
                "volume, or the volume does not start at the image origin")
            return result

        master, mnotes = self.parse_master(dev, master_off)
        result.notes.extend(mnotes)
        used_sources = [f.source for f in MASTER_FIELDS]

        btree_off = self.find_btree(dev, after=master_off)
        entries: list[IndexEntry] = []
        if btree_off == -1:
            result.notes.append(
                "master sector present but no HIKBTREE index found - the index "
                "may be damaged or beyond the search window; active recordings "
                "cannot be enumerated, so the carver is the remaining route")
        else:
            entries, inotes = self.parse_index(dev, btree_off)
            result.notes.extend(inotes)
            used_sources += [f.source for f in BTREE_FIELDS] + [INDEX_ENTRY.source]

        result.volume = {
            "vendor": VENDOR,
            "master": master.to_dict(),
            "btree_offset": btree_off if btree_off != -1 else None,
            "index_entries": len(entries),
        }

        for i, e in enumerate(entries):
            result.recordings.append(self._to_recording(dev, i, e))
            result.indexed_extents.append((e.start_offset, e.length))

        result.validation_status = weakest_source(used_sources)
        result.notes.append(
            f"status {result.validation_status}: set by the weakest field "
            f"provenance, not the strongest. Only a byte-match against the "
            f"DVR's own native export justifies 'validated'.")
        return result

    # -- one recording -----------------------------------------------------
    def _to_recording(self, dev, i: int, e: IndexEntry) -> Recording:
        read_len = min(e.length, CLIP_INSPECT_BYTES)
        truncated = read_len < e.length
        try:
            data = dev.read_at(e.start_offset, read_len)
        except Exception as exc:                         # noqa: BLE001
            data = b""
            truncated = True
        frames = list(iter_nals(data, base_offset=e.start_offset))
        has_sps = any(f.nal_type == H264_SPS for f in frames)
        has_pps = any(f.nal_type == H264_PPS for f in frames)
        has_idr = any(f.nal_type == H264_IDR for f in frames)

        # Confidence is about how well the bytes at the indexed extent support
        # the index's claim, not about how much we like the answer.  An index
        # entry pointing at a region with no video structure is exactly the
        # case an investigator must be able to see.
        confidence = 0.35
        if frames:
            confidence += 0.20
        if has_sps and has_pps:
            confidence += 0.30
        if has_idr:
            confidence += 0.10
        if truncated:
            confidence -= 0.05
        confidence = round(max(0.0, min(confidence, 0.95)), 4)

        decoded = _decode_utc(e.unix_start)
        claims = [TimestampClaim(
            source="index",
            raw_value=str(e.unix_start),
            decoded_utc=decoded,
            tz_offset_min=None,
            # A single source is never a conclusion. The recorder's clock is
            # itself the thing under suspicion, so this stays below certainty
            # until the timeline stage corroborates it against another source.
            confidence=0.5 if decoded else 0.0,
            decode_rule=("HIKBTREE entry +0x14 u32 little-endian, seconds "
                         "since Unix epoch, assumed UTC; recorder timezone "
                         "and clock accuracy unverified"),
        )]

        sector = getattr(dev, "sector_size", 512) or 512
        prov = Provenance(
            disk_offset=e.start_offset,
            length=e.length,
            sector_start=e.start_offset // sector,
            sector_end=(e.start_offset + e.length + sector - 1) // sector,
            parser_rule=self.parser_rule,
            sha256=sha256_bytes(data) if data else "",
        )

        end_utc = None
        return Recording(
            id=f"hik-idx-{i:05d}",
            camera_id=f"CH{e.camera_id + 1:02d}",
            state=STATE_ACTIVE,
            codec="h264" if frames else "",
            offset=e.start_offset,
            length=e.length,
            start_utc=decoded,
            end_utc=end_utc,
            duration_s=None,
            confidence=confidence,
            frame_count=len(frames),
            timestamps=claims,
            provenance=prov,
        )

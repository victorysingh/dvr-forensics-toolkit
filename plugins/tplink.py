"""TP-Link VIGI NVR: detection, the recorder's own index, and its footage.

A drop-in plugin: nothing in the core was edited to add it.

SOURCE
------
VIGI NVR1008H V2 firmware, build 240119 (archive.org "embeddedfirmware"
mirror, TP-Link_VIGINVR1008HV2_240119; docs/research/datasets.md).  Three
libraries and the recorder's main program were read by static disassembly -
nothing was run:

  /usr/lib/liblayouthddb.so    SHA-256 df6c5bd2518b908a879de8908b675337d3fe2a3c2bb1410f04e11dad20c3b169
  /usr/lib/libsqlite3.so.0.8.6 SHA-256 4754d86ab6476fd4b8997de9e3c52b0dc94209bb936a2234934e8de8d8c00ea0
  /usr/lib/libstorage.so       SHA-256 be790e1f72fc13e219714b7b7c43ef38dc4f3fe778b5719b8b21f070c8ae71fb
  /bin/nvrcore                 SHA-256 49a5b249481783ad09d89fbb979c36971bfd4f94994220b2f79b340da1361c32

Where each structure comes from, function by function:
docs/research/fwread/README.md.

WHAT THE FIRMWARE SHOWS
-----------------------
  * Two disk layouts ("tpfs_ver").  V0: TP's own partitioning (tp_fdisk),
    swap, and an ext4 data partition holding `sys.bin` (the index) and
    numbered zone files.  V1: the raw disk, with a 512-byte format sector at
    512 MiB - retried further on, up to 560 MiB, past bad sectors - holding
    the ASCII tag "TP-Link Corporation Limited, NVR FOR VERSION x.y.z" at +0
    and a CRC-32 of the first 0x1FC bytes at +0x1FC
    (rawDiskLayout_diskInfoFormatCheck); then a database area of 64, 128 or
    256 MiB by disk size, with a backup and a journal; then zones.
  * The index is SQLite, through TP's own build of it: a 512-byte "TpFile"
    header comes first - the magic "TP-Link format1", then key slots of
    (type, encrypt, length, data), big-endian (sqliteTpFileInit,
    getTpFileHeadSize = 0x200, getTpFileKey) - and the database follows.
    That build carries an AES codec (CodecAES, sqlite3_key), and the layout
    library calls db_encrypt() with a key it takes from those slots.
  * The tables, from the CREATE TABLE statements in liblayouthddb.so:
    tEventInfo (a recording per camera: times, zone, block, GOP lengths,
    lock), tGopInfo (each GOP's zone, offset, length, frame count),
    tZoneInfo, and tSlogInfo - the recorder's system log, kept on the disk.
  * Where the footage is (V1; read 30 Sep 2026):
      - the format sector also holds "PT" at +0x80, the disk size at +0x84,
        0x40000000 at +0x8C and 0x08000000 at +0x90 (rawDiskLayout_diskInfoFormat);
      - the database area starts at 0x23200000.  The main database is up to
        31 extents listed in a 512-byte record at the format sector + 0x400
        (a journal copy at + 0x600): (start, length) pairs of u64, CRC-32 at
        +0x1FC.  The first extent is 0x23201000, its length the area's size
        less 4 KiB; the backup copy follows each extent
        (rawDiskLayout_resetDBAreaInfo, rawDiskLayout_DBAreaInfoInit);
      - the data zones start at 0x23200000 + 2 x the area's size, which is
        64 MiB below 32 GiB of disk, 128 MiB below 3 TiB, else 256 MiB
        (resetDBAreaInfo, which layout_fs_init_resource_v1 runs at every
        mount; rawDiskLayout_determineDefDBSizeByDiskSize);
      - zone z is the 1 GiB at data-zone start + z x 0x40000000
        (rawDiskLayout_io_read: "zone_id ... rawDiskAddr");
      - on this layout the GOP table is not in SQLite (create_gop_table_v1
        is empty): each zone's first 1 MiB is its own index, one 80-byte
        entry per GOP - zone, event, start and end time, stream (0 main,
        1 sub), offset in the zone, length, frame count
        (write_raw_disk_data_index, insert_gop_index_v1, get_gop_index_v1;
        "start get data len ... goplen" in layout_read_data_by_index);
      - a GOP is its frames back to back: a 32-byte header (+0 u64 time,
        +8 u32 payload length, +0x0D frame type, +0x10 codec: 0 H.264,
        1 H.265) and the payload, which must start 00 00 00 01, padded to
        8 bytes; a table of its key frames closes it (web_parse_gop_data_frm
        in nvrcore; extend_iter_i_frame_in_gop in libstorage.so).

WHAT THIS PLUGIN DOES
---------------------
  * finds the V1 format sector (CRC-32 checked) and TpFile headers - at the
    offsets the scan reports for their signatures, or by looking through the
    first GiB after the format sector;
  * reads each TpFile header's key slots, as stored;
  * where the database behind a header is plain SQLite, reads it: recordings
    per camera, GOP rows, zones, and the system log.  Tables are found by
    their columns, not their names.  Where it is not, the index is reported
    as encrypted or unreadable, with what was seen - nothing is guessed;
  * places the footage (V1): works out where the data zones start, reads
    each zone's own GOP index - an entry counts only if it names its own
    zone, fits in the zone and has its unused bytes zero - and reports a
    recording per event and stream, the camera from tEventInfo when the
    database was read;
  * extracts a recording: walks each GOP's frames, checks every start code,
    and writes the H.264/H.265 payloads without the headers;
  * with --remnants, finds GOPs by their frame headers in every zone,
    indexed or not: footage whose index entry is gone.

WHAT IT DOES NOT DO
-------------------
  * read V0's ext4 as a filesystem (the ext reader refuses extents); V0's
    sys.bin is found by its header, like V1's, and its zone files are not
    placed;
  * decrypt.  An encrypted database is reported as encrypted.  The zones' own
    indexes go straight to the disk (write_raw_disk_data_index), not through
    the database's codec, so footage is still placed, the camera unknown.
    A payload that does not start 00 00 00 01 - which is what the recorder's
    optional media encryption would give - fails the GOP's check;
  * read the write-ahead logs (sys.bin-wal0...), which may hold changes not
    yet in the database;
  * decode the frame header's other bytes, the 32-bit fields at +0x24 and
    +0x28 of an index entry, or audio.

STATUS
------
detected_not_parsed when only markers are found; spec_only when an index is
read or footage is placed - every field from the firmware, none yet seen on
a VIGI disk.

TIME
----
The index's times are integers whose unit (seconds, ms or µs) is decided
from their size and stated per value; whether the recorder's clock ran on
UTC or local time is not in the firmware, so nothing is converted.
"""

from __future__ import annotations

import os
import sqlite3
import struct
import zlib
from datetime import datetime, timezone
from typing import Optional

from core.contract import (
    STATE_ACTIVE,
    STATE_FRAGMENT,
    VALIDATION_DETECTED,
    VALIDATION_SPEC_ONLY,
    Provenance,
    Recording,
    TimestampClaim,
)
from core.hashing import sha256_file
from detect.signatures import SPEC_ONLY, Signature
from parsers.base import SOURCE_FIRMWARE, FieldSpec, ParseResult, VendorParser, register

FIRMWARE = "TP-Link VIGI NVR1008H V2 240119"

FORMAT_AT = 0x20000000             # rawDiskLayout_diskInfoFormatCheck: first try
FORMAT_WINDOW = 0x3200000          # ... retried up to 0x231FFFFF
FORMAT_SECTOR = 0x200
FORMAT_CRC_AT = 0x1FC
TAG = b"TP-Link Corporation Limited, NVR FOR VERSION"
TPFILE_MAGIC = b"TP-Link format1\x00"
TPFILE_HEAD = 0x200                # getTpFileHeadSize
SLOTS_AT, SLOTS_END = 0x20, 0x1F0  # getTpFileKey walks slots while offset < 0x1D0 past +0x20
SQLITE_MAGIC = b"SQLite format 3\x00"
DB_MAX = 0x10000000                # the largest database area (256 MiB)
SCAN_AFTER_FORMAT = 1 << 30

# Where the footage is (V1).  Each from the firmware function named.
FMT_MARKER = 0x5450                # diskInfoFormat: u32 at +0x80 ("PT")
DB_AREA_AT = 0x23200000            # resetDBAreaInfo: the database area's first byte
AREA_INFO_AT = 0x400               # DBAreaInfoInit: format sector + 0x400 ...
AREA_JOURNAL_AT = 0x600            # ... and its journal copy, read if that fails its CRC
AREA_EXTENTS = 31                  # (start u64, length u64) pairs; getMainDBSize stops at 31
AREA_HEAD = 0x1000                 # each extent starts 4 KiB into its space
ZONE_BYTES = 0x40000000            # rawDiskLayout_io_read: zone_id * 0x40000000
ZONE_INDEX_BYTES = 0x100000        # write_raw_disk_data_index: (offset + cnt) * 0x50 <= 1 MiB
ENTRY = 0x50                       # one GOP's index entry
FRAME_HEAD = 0x20                  # web_parse_gop_data_frm: header, then payload
START4 = b"\x00\x00\x00\x01"       # ... the payload's first bytes, checked
STREAMS = {0: "main", 1: "sub"}    # get_gop_index_v1: low half of the entry's +0x18
CODECS = {0: "h264", 1: "h265"}    # extend_get_frame_type: frame header +0x10
GOP_MAX = 64 << 20                 # a GOP longer than this is not believed
MAX_ZONES = 1 << 17                # 128 TiB of 1 GiB zones: more than any recorder takes

TIME_LO, TIME_HI = 946684800, 4102444800

# Tables are recognised by the columns the firmware creates them with.
TABLES = {
    "events": {"eventId", "startTime", "endTime", "channelId", "zoneId", "blkId", "eventType"},
    "gops": {"eventId", "startTime", "endTime", "zoneId", "offset", "len", "frame_cnt"},
    "zones": {"zoneId", "blockId", "channelId", "dataType", "status", "curOffset"},
    "log": {"id", "mainType", "subType", "time", "detail"},
}


def _fw(lib: str, fn: str) -> str:
    return f"{FIRMWARE}: {lib} {fn}"


FIELDS = [
    FieldSpec("format.tag", 0x00, "bytes:64", "TP-Link Corporation Limited, NVR FOR VERSION x.y.z",
              SOURCE_FIRMWARE, _fw("liblayouthddb.so", "rawDiskLayout_diskInfoFormatCheck")),
    FieldSpec("format.crc32", FORMAT_CRC_AT, "<I", "CRC-32 of bytes 0..0x1FB", SOURCE_FIRMWARE,
              _fw("liblayouthddb.so", "rawDiskLayout_diskInfoFormatCheck (calculate_CRC32)")),
    FieldSpec("tpfile.magic", 0x00, "bytes:16", "TP-Link format1", SOURCE_FIRMWARE,
              _fw("libsqlite3.so", "sqliteTpFileInit")),
    FieldSpec("tpfile.head_size", 0x14, "<I", "0x200", SOURCE_FIRMWARE,
              _fw("libsqlite3.so", "sqliteTpFileInit, getTpFileHeadSize")),
    FieldSpec("tpfile.slot", 0x20, ">III", "type, encrypt, length, then the data; next slot "
              "after it", SOURCE_FIRMWARE, _fw("libsqlite3.so", "getTpFileKey, setTpFileKey")),
    FieldSpec("index.tables", 0x200, "sqlite", "tEventInfo, tGopInfo, tZoneInfo, tSlogInfo "
              "(CREATE TABLE statements)", SOURCE_FIRMWARE, _fw("liblayouthddb.so", "strings")),
    FieldSpec("format.disk_bytes", 0x84, "<Q", "the disk's size when formatted", SOURCE_FIRMWARE,
              _fw("liblayouthddb.so", "rawDiskLayout_diskInfoFormat")),
    FieldSpec("format.zone_bytes", 0x8C, "<I", "0x40000000", SOURCE_FIRMWARE,
              _fw("liblayouthddb.so", "rawDiskLayout_diskInfoFormat")),
    FieldSpec("area.extent", AREA_INFO_AT, "<QQ", "start, length of a database extent, up to 31; "
              "CRC-32 at +0x1FC", SOURCE_FIRMWARE,
              _fw("liblayouthddb.so", "rawDiskLayout_resetDBAreaInfo, rawDiskLayout_DBAreaInfoInit")),
    FieldSpec("zone.address", 0, "u64", "0x23200000 + 2 x area size + zone x 0x40000000",
              SOURCE_FIRMWARE, _fw("liblayouthddb.so", "rawDiskLayout_resetDBAreaInfo, "
                                   "rawDiskLayout_io_read, determineDefDBSizeByDiskSize")),
    FieldSpec("zone.entry", 0, "<IIQQIIIIIII", "zone, event, start, end, stream, offset, length, "
              "+0x24, +0x28, frames | vi<<24, i | x<<8; 80 bytes", SOURCE_FIRMWARE,
              _fw("liblayouthddb.so", "insert_gop_index_v1, get_gop_index_v1, "
                  "write_raw_disk_data_index")),
    FieldSpec("gop.frame", 0, "<QI", "time u64, payload length u32; type +0x0D, codec +0x10; "
              "payload at +0x20 starting 00 00 00 01, padded to 8", SOURCE_FIRMWARE,
              "TP-Link VIGI NVR1008H V2 240119: nvrcore web_parse_gop_data_frm; libstorage.so "
              "extend_iter_i_frame_in_gop, extend_get_frame_type"),
]

SIGNATURES = [
    Signature(id="tplink.format_tag", vendor="TP-Link", pattern=TAG,
              description="VIGI raw-layout format sector (tpfs V1) at 512 MiB",
              source=_fw("liblayouthddb.so", "rawDiskLayout_diskInfoFormatCheck"),
              validation_status=SPEC_ONLY, weight=10.0, expected_offsets=(FORMAT_AT,),
              offset_tolerance=FORMAT_WINDOW),
    Signature(id="tplink.tpfile", vendor="TP-Link", pattern=TPFILE_MAGIC,
              description="TpFile header of the VIGI index database (sys.bin)",
              source=_fw("libsqlite3.so", "sqliteTpFileInit"), validation_status=SPEC_ONLY,
              weight=8.0),
]


def _when(v) -> tuple[Optional[str], str]:
    """(recorder-clock text, unit) for an integer time of unknown unit."""
    if not isinstance(v, int) or v <= 0:
        return None, "none"
    for div, unit in ((1, "s"), (1000, "ms"), (1_000_000, "us")):
        if TIME_LO <= v // div <= TIME_HI:
            t = datetime.fromtimestamp(v // div, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            return t, unit
    return None, "unrecognised"


def format_sector(raw: bytes) -> Optional[dict]:
    if len(raw) < FORMAT_SECTOR or not raw.startswith(TAG):
        return None
    tag = raw[:0x80].split(b"\x00", 1)[0].decode("ascii", "replace")
    stored = struct.unpack_from("<I", raw, FORMAT_CRC_AT)[0]
    marker, disk = struct.unpack_from("<IQ", raw, 0x80)
    zone, block = struct.unpack_from("<II", raw, 0x8C)
    return {"tag": tag, "version": tag[len(TAG):].strip(),
            "crc_stored": stored, "crc32_ok": zlib.crc32(raw[:FORMAT_CRC_AT]) == stored,
            "marker_ok": marker == FMT_MARKER, "disk_bytes": disk if marker == FMT_MARKER else 0,
            "zone_bytes": zone, "block_bytes": block}


def db_size_for(disk_bytes: int) -> int:
    """The database area's size for a disk (rawDiskLayout_determineDefDBSizeByDiskSize)."""
    if disk_bytes < 8 << 32:
        return 64 << 20
    if disk_bytes < 0x300 << 32:
        return 128 << 20
    return 256 << 20


def area_record(raw: bytes) -> Optional[dict]:
    """The database area's record: its extents, and whether the CRC holds."""
    if len(raw) < FORMAT_SECTOR:
        return None
    ext = []
    for k in range(AREA_EXTENTS):
        start, n = struct.unpack_from("<QQ", raw, 16 * k)
        if n == 0:
            break
        ext.append((start, n))
    stored = struct.unpack_from("<I", raw, FORMAT_CRC_AT)[0]
    return {"extents": ext, "crc_stored": stored,
            "crc32_ok": zlib.crc32(raw[:FORMAT_CRC_AT]) == stored and bool(ext)}


def gop_entry(raw: bytes) -> dict:
    """One 80-byte entry of a zone's own index (insert_gop_index_v1)."""
    (zone, event, st, et, kind, off, n, f24, f28, frames, iframes) = struct.unpack_from(
        "<IIQQIIIIIII", raw, 0)
    return {"zone": zone, "event": event, "start": st, "end": et, "stream": kind & 0xFFFF,
            "flag": kind >> 16, "offset": off, "length": n, "field_24": f24, "field_28": f28,
            "frames": frames & 0xFFFFFF, "vi_frames": frames >> 24, "i_frames": iframes & 0xFF,
            "field_30": iframes >> 8}


def entry_ok(raw: bytes, zone: int, zone_bytes: int, index_bytes: int) -> Optional[dict]:
    """The entry, if it can be one this zone wrote: it names this zone, has a
    length and times in order, fits in the zone after the index, and the 28
    bytes the firmware never fills are zero."""
    if len(raw) < ENTRY or any(raw[0x34:ENTRY]):
        return None
    e = gop_entry(raw)
    if (e["zone"] != zone or not 0 < e["length"] <= GOP_MAX or e["start"] == 0
            or e["end"] < e["start"] or e["offset"] < index_bytes
            or e["offset"] + e["length"] > zone_bytes):
        return None
    return e


def walk_gop(buf: bytes, expect: Optional[int] = None) -> dict:
    """The frames of one GOP, as the recorder's playback walks them
    (web_parse_gop_data_frm): from the start, a 32-byte header then its
    payload padded to 8 bytes; a payload that does not start 00 00 00 01, or
    runs past the GOP, ends the walk.  With `expect`, fewer frames than the
    index states is an error."""
    frames, pos, err = [], 0, None
    while pos + FRAME_HEAD + 4 <= len(buf) and (expect is None or len(frames) < expect):
        pts, n = struct.unpack_from("<QI", buf, pos)
        if n == 0 or pos + FRAME_HEAD + n > len(buf):
            err = f"frame {len(frames)}: length {n} runs past the GOP"
            break
        if buf[pos + FRAME_HEAD:pos + FRAME_HEAD + 4] != START4:
            err = f"frame {len(frames)}: payload does not start 00 00 00 01"
            break
        frames.append({"at": pos + FRAME_HEAD, "length": n, "time": pts,
                       "type": buf[pos + 0x0D], "codec": CODECS.get(buf[pos + 0x10], "")})
        pos += FRAME_HEAD + ((n + 7) & ~7)
    if expect is not None and err is None and len(frames) < expect:
        err = f"{len(frames)} of the {expect} frames the index states"
    if expect is None and err is not None and frames:
        err = None                         # walking with no index: the GOP ends where frames do
    return {"frames": frames, "end": pos, "error": err}


class _Buffered:
    """read_at() through one cached window, so walking frame headers a few
    bytes at a time is not one disk read each."""

    def __init__(self, dev, window: int = 4 << 20):
        self.dev, self.window = dev, window
        self.base, self.buf = 0, b""

    def read_at(self, off: int, n: int) -> bytes:
        if not (self.base <= off and off + n <= self.base + len(self.buf)):
            self.base, self.buf = off, self.dev.read_at(off, max(n, self.window))
        return self.buf[off - self.base:off - self.base + n]


def tpfile_head(raw: bytes) -> Optional[dict]:
    if len(raw) < TPFILE_HEAD or not raw.startswith(TPFILE_MAGIC):
        return None
    flag, head, arg, used = struct.unpack_from("<IIII", raw, 0x10)
    slots, o = [], SLOTS_AT
    while o + 12 <= SLOTS_END:
        kind, enc, n = struct.unpack_from(">III", raw, o)
        if n == 0 or o + 12 + n > SLOTS_END:
            break
        data = raw[o + 12:o + 12 + n]
        text = data.rstrip(b"\x00")
        slots.append({"type": kind, "encrypt": enc, "length": n,
                      "value": text.decode() if text and all(32 <= c < 127 for c in text)
                      else data.hex()})
        o += 12 + n
    return {"flag": flag, "head_size": head, "arg": arg, "used": used, "slots": slots}


def _sqlite_header(page1: bytes) -> Optional[dict]:
    """SQLite's own header fields, if bytes 16..27 look like one (the
    first 16 bytes may be a vendor magic, or salt, rather than SQLite's)."""
    if len(page1) < 100:
        return None
    ps = struct.unpack_from(">H", page1, 16)[0]
    ps = 65536 if ps == 1 else ps
    ok = (ps >= 512 and ps & (ps - 1) == 0 and page1[18] in (1, 2) and page1[19] in (1, 2)
          and page1[21:24] == b"\x40\x20\x20")
    if not ok:
        return None
    pages, change, valid_for = (struct.unpack_from(">I", page1, 28)[0],
                                struct.unpack_from(">I", page1, 24)[0],
                                struct.unpack_from(">I", page1, 92)[0])
    return {"page_size": ps, "reserved": page1[20], "pages": pages,
            "pages_trusted": pages > 0 and change == valid_for,
            "magic": page1[:16].split(b"\x00", 1)[0].decode("ascii", "replace")}


def _open(blob: bytes) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    # a damaged or tampered index can hold bytes that are not UTF-8: read them
    # with replacement characters rather than stop on them
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    if hasattr(con, "deserialize"):
        con.deserialize(blob)
        return con
    con.close()
    raise RuntimeError("this Python cannot open a database from memory (needs 3.11+)")


def read_index(blob: bytes) -> dict:
    """The index tables, found by their columns.  Raises sqlite3 errors when
    the bytes are not a readable database."""
    try:
        return _read_index(_open(blob))
    except UnicodeDecodeError as exc:
        raise sqlite3.DatabaseError(f"damaged text in the database ({exc.reason})") from exc


def _read_index(con) -> dict:
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        found = {}
        for t in tables:
            cols = {r[1] for r in con.execute(f'PRAGMA table_info("{t}")')}
            for role, need in TABLES.items():
                if need <= cols and role not in found:
                    found[role] = t

        def rows(role: str, cols: str, order: str) -> list[dict]:
            if role not in found:
                return []
            names = [c.strip() for c in cols.split(",")]
            q = f'SELECT {cols} FROM "{found[role]}" ORDER BY {order}'
            return [dict(zip(names, r)) for r in con.execute(q)]

        out = {"tables": tables, "roles": found,
               "events": rows("events", "eventId, channelId, startTime, endTime, zoneId, blkId, "
                                        "eventType, lockFlag", "startTime"),
               "gops": rows("gops", "eventId, startTime, endTime, zoneId, offset, len, frame_cnt",
                            "eventId, startTime"),
               "zones": rows("zones", "zoneId, blockId, channelId, dataType, status, startTime, "
                                      "endTime, curOffset", "zoneId, blockId"),
               "log": rows("log", "id, mainType, subType, time, detail", "time")}
        return out
    finally:
        con.close()


@register
class TPLinkParser(VendorParser):
    vendor = "TP-Link"
    parser_rule = "tplink.vigi.liblayouthddb-240119.v1"
    # Fixed by the firmware; the tests move them so their images stay small.
    format_at = FORMAT_AT
    scan_after_format = SCAN_AFTER_FORMAT
    db_area_at = DB_AREA_AT
    zone_bytes = ZONE_BYTES
    zone_index_bytes = ZONE_INDEX_BYTES

    def __init__(self) -> None:
        # recording id -> its GOPs as (disk offset, length, frames the index states)
        self.extents: dict[str, list[tuple[int, int, int]]] = {}

    def _format(self, dev) -> Optional[dict]:
        raw = dev.read_at(self.format_at, FORMAT_SECTOR)
        fs = format_sector(raw)
        if fs:
            return dict(fs, offset=self.format_at)
        # the firmware jumps past bad sectors, so the tag may sit further on
        end = self.format_at + FORMAT_WINDOW
        pos = self.format_at
        while pos < end:
            buf = dev.read_at(pos, min(4 << 20, end - pos))
            if not buf:
                break
            i = buf.find(TAG)
            while i >= 0:
                if (pos + i) % FORMAT_SECTOR == 0:
                    fs = format_sector(dev.read_at(pos + i, FORMAT_SECTOR))
                    if fs:
                        return dict(fs, offset=pos + i)
                i = buf.find(TAG, i + 1)
            pos += len(buf)
        return None

    def _tpfiles(self, dev, hints: list[int], after: Optional[int]) -> list[int]:
        found = set()
        for off in hints:
            if off % FORMAT_SECTOR == 0 and dev.read_at(off, 16) == TPFILE_MAGIC:
                found.add(off)
        if after is not None:
            pos, end = after, min(after + self.scan_after_format,
                                  getattr(dev, "size_bytes", 0) or after + self.scan_after_format)
            while pos < end:
                buf = dev.read_at(pos, min(8 << 20, end - pos))
                if not buf:
                    break
                i = buf.find(TPFILE_MAGIC)
                while i >= 0:
                    if (pos + i) % FORMAT_SECTOR == 0:
                        found.add(pos + i)
                    i = buf.find(TPFILE_MAGIC, i + 1)
                pos += len(buf) - 15 if len(buf) > 16 else len(buf)
        return sorted(found)

    def detect(self, dev, hint_offsets=None) -> bool:
        if self._format(dev):
            return True
        return any(dev.read_at(o, 16) == TPFILE_MAGIC for o in hint_offsets or []
                   if o % FORMAT_SECTOR == 0)

    def _database(self, dev, off: int) -> dict:
        head = tpfile_head(dev.read_at(off, TPFILE_HEAD))
        page1 = dev.read_at(off + TPFILE_HEAD, 100)
        hdr = _sqlite_header(page1)
        db = {"offset": off, "head": head, "sqlite_header": hdr}
        if hdr is None:
            db["status"] = "encrypted or not SQLite: no SQLite header after the TpFile header"
            return db
        size = hdr["page_size"] * hdr["pages"] if hdr["pages_trusted"] else DB_MAX
        blob = bytearray(dev.read_at(off + TPFILE_HEAD, min(size, DB_MAX)))
        blob[:16] = SQLITE_MAGIC
        try:
            db["index"] = read_index(bytes(blob))
            db["status"] = "read" + ("" if hdr["magic"] == "SQLite format 3"
                                     else f" (magic '{hdr['magic']}' in place of SQLite's)")
        except (sqlite3.DatabaseError, RuntimeError) as exc:
            db["status"] = (f"SQLite header present but the database does not open ({exc}); "
                            "encrypted pages, or a database split across areas")
        return db

    # -- where the footage is --------------------------------------------------
    def _geometry(self, dev, fmt: dict) -> dict:
        """Where the data zones start (rawDiskLayout_resetDBAreaInfo): the
        database area's start plus twice its size.  The size is the area
        record's first extent plus 4 KiB when the record's CRC holds and the
        extent starts where the firmware puts it; otherwise it follows from
        the disk's size, as the firmware sets it at format."""
        rec, src = None, None
        for where, name in ((AREA_INFO_AT, "record"), (AREA_JOURNAL_AT, "journal")):
            r = area_record(dev.read_at(fmt["offset"] + where, FORMAT_SECTOR))
            if r and r["crc32_ok"]:
                rec, src = r, name
                break
        disk = fmt.get("disk_bytes") or getattr(dev, "size_bytes", 0)
        by_size = db_size_for(disk)
        by_record = None
        if rec and rec["extents"][0][0] == self.db_area_at + AREA_HEAD:
            by_record = rec["extents"][0][1] + AREA_HEAD
        area = by_record or by_size
        start = self.db_area_at + 2 * area
        return {"area_record": src, "extents": rec["extents"] if rec else [],
                "disk_bytes": disk,
                "disk_bytes_from": "format sector" if fmt.get("disk_bytes") else "image size",
                "area_bytes": area,
                "area_bytes_from": "area record" if by_record else "disk size",
                "area_bytes_by_disk_size": by_size, "data_zone_at": start,
                "zone_bytes": self.zone_bytes,
                "zone_bytes_in_format_sector": fmt.get("zone_bytes"),
                # a damaged size field cannot send the zone walks on for ever
                "zones": min(MAX_ZONES, max(0, (disk - start) // self.zone_bytes))}

    def _zone_index(self, dev, base: int, z: int) -> tuple[list[dict], int]:
        """A zone's own GOP index: entries until the first empty one, each
        kept only if it can be one this zone wrote (entry_ok)."""
        if entry_ok(dev.read_at(base, ENTRY), z, self.zone_bytes, self.zone_index_bytes) is None:
            return [], 0
        raw = dev.read_at(base, self.zone_index_bytes)
        out, bad = [], 0
        for k in range(len(raw) // ENTRY):
            chunk = raw[k * ENTRY:(k + 1) * ENTRY]
            e = entry_ok(chunk, z, self.zone_bytes, self.zone_index_bytes)
            if e is None:
                if not any(chunk):
                    break                      # the index ends at its first empty entry
                bad += 1
                continue
            e["index"] = k
            out.append(e)
        return out, bad

    def _codec_at(self, dev, off: int) -> str:
        head = dev.read_at(off, FRAME_HEAD + 4)
        return (CODECS.get(head[0x10], "") if len(head) == FRAME_HEAD + 4
                and head[FRAME_HEAD:] == START4 else "")

    def _recording(self, dev, rid: str, camera: str, gops: list[dict], dz: int, state: str,
                   confidence: float, source: str, rule: str) -> Recording:
        ext = [(dz + g["zone"] * self.zone_bytes + g["offset"], g["length"], g.get("frames", 0))
               for g in gops]
        self.extents[rid] = ext
        first, last = gops[0]["start"], max(g["end"] for g in gops)
        (a, unit), (b, _) = _when(first), _when(last)
        div = {"s": 1, "ms": 1000, "us": 1_000_000}.get(unit)

        def claim(v: int, text: Optional[str], label: str) -> TimestampClaim:
            return TimestampClaim(
                source=source, raw_value=f"{v} = {text} recorder clock" if text else str(v),
                decoded_utc=None, tz_offset_min=None, confidence=0.4 if text else 0.0,
                decode_rule=f"{label}, unit ({unit}) decided from the value's size; the "
                            f"recorder's zone is not known, so not converted ({rule})")

        off, length = ext[0][0], sum(n for _, n, _ in ext)
        sector = getattr(dev, "sector_size", 512) or 512
        return Recording(
            id=rid, camera_id=camera, state=state, codec=self._codec_at(dev, off),
            offset=off, length=length, start_utc=None, end_utc=None,
            duration_s=(last - first) / div if div else None, confidence=confidence,
            frame_count=sum(f for _, _, f in ext),
            timestamps=[claim(first, a, "first GOP's start"), claim(last, b, "last GOP's end")],
            provenance=Provenance(disk_offset=off, length=length, sector_start=off // sector,
                                  sector_end=(ext[-1][0] + ext[-1][1]) // sector,
                                  parser_rule=self.parser_rule))

    def _footage(self, dev, fmt: dict, idx: Optional[dict]) -> dict:
        """Every zone's GOP index, and a recording per event and stream."""
        geo = self._geometry(dev, fmt)
        dz, size = geo["data_zone_at"], getattr(dev, "size_bytes", 0) or 0
        entries, zones, bad = [], {}, 0
        for z in range(geo["zones"]):
            base = dz + z * self.zone_bytes
            if size and base >= size:
                break                          # an image that stops short of the disk
            got, b = self._zone_index(dev, base, z)
            bad += b
            if got:
                zones[z] = len(got)
                entries += got
        ev_cam = {e["eventId"]: e["channelId"] for e in (idx or {}).get("events", [])}
        zone_cam = {r["zoneId"]: r["channelId"] for r in (idx or {}).get("zones", [])}
        groups: dict = {}
        other = 0
        for e in entries:
            if e["stream"] in STREAMS:
                groups.setdefault((e["event"], e["stream"]), []).append(e)
            else:
                other += 1
        recs = []
        for (ev, st), gops in sorted(groups.items()):
            gops.sort(key=lambda g: (g["start"], g["zone"], g["offset"]))
            cam = ev_cam.get(ev, zone_cam.get(gops[0]["zone"]))
            recs.append(self._recording(
                dev, f"tpl-e{ev:06d}-{STREAMS[st]}",
                f"ch{cam}" if cam is not None else "unknown (database not read)", gops, dz,
                STATE_ACTIVE, 0.4 if cam is not None else 0.3, "index",
                "zone index entry +0x08 / +0x10"))
        return {"geometry": geo, "zones_with_index": zones, "gops": len(entries),
                "entries_rejected": bad, "entries_other_streams": other, "recordings": recs}

    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=VALIDATION_DETECTED)
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        fmt = self._format(dev)
        offs = self._tpfiles(dev, list(hint_offsets or []),
                             fmt["offset"] + FORMAT_SECTOR if fmt else None)
        if not fmt and not offs:
            result.errors.append("no VIGI format sector near 512 MiB and no TpFile header "
                                 "at the offsets given")
            return result
        dbs = [self._database(dev, o) for o in offs]
        readable = [d for d in dbs if "index" in d]
        idx = readable[0]["index"] if readable else None
        foot = self._footage(dev, fmt, idx) if fmt else None
        if foot:
            result.recordings = foot.pop("recordings")
            result.indexed_extents = [(o, n) for r in result.recordings
                                      for o, n, _ in self.extents[r.id]]
        if readable or result.recordings:
            result.validation_status = VALIDATION_SPEC_ONLY
        cams: dict = {}
        if idx:
            for e in idx["events"]:
                c = cams.setdefault(e["channelId"], {"events": 0, "first": None, "last": None})
                c["events"] += 1
                c["first"] = e["startTime"] if c["first"] is None else min(c["first"], e["startTime"])
                c["last"] = e["endTime"] if c["last"] is None else max(c["last"], e["endTime"])
            for c in cams.values():
                (c["first_clock"], unit), (c["last_clock"], _) = _when(c["first"]), _when(c["last"])
                c["time_unit"] = unit
        result.volume = {
            "vendor": self.vendor,
            "layout": "V1 raw (format sector)" if fmt else "TpFile header only (V0 or V1)",
            "format_sector": fmt,
            "databases": [{k: v for k, v in d.items() if k != "index"} for d in dbs],
            "index": ({"database_at": readable[0]["offset"], "tables": idx["roles"],
                       "cameras": cams, "events": idx["events"], "gops": len(idx["gops"]),
                       "gop_bytes": sum(g["len"] or 0 for g in idx["gops"]),
                       "zones": idx["zones"], "system_log": idx["log"]} if idx else None),
            "footage": foot,
            "summary": [
                ("format", (f"{fmt['tag']} at 0x{fmt['offset']:X}, CRC-32 "
                            f"{'ok' if fmt['crc32_ok'] else 'MISMATCH'}") if fmt else "not found"),
                ("index", "; ".join(f"0x{d['offset']:X}: {d['status']}" for d in dbs)
                          or "no TpFile header found"),
                ("cameras", ", ".join(f"ch{k}: {v['events']} recordings, {v['first_clock']} .. "
                                      f"{v['last_clock']}" for k, v in sorted(cams.items()))
                            or "-"),
                ("system log", f"{len(idx['log'])} entries" if idx else "-"),
                ("footage", (f"{len(result.recordings)} recordings, {foot['gops']} GOPs in "
                             f"{len(foot['zones_with_index'])} zones of "
                             f"{self.zone_bytes >> 20} MiB from 0x"
                             f"{foot['geometry']['data_zone_at']:X} (database area "
                             f"{foot['geometry']['area_bytes'] >> 20} MiB, from the "
                             f"{foot['geometry']['area_bytes_from']})") if foot
                            else "not placed: no format sector, so no zone layout"),
                ("times", "recorder clock, zone unknown - not converted to UTC"),
            ]}
        result.notes += [
            f"Layout from the recorder's own libraries ({FIRMWARE}), read by static "
            "disassembly; no VIGI disk has been read by the team.",
            "Footage is placed from each zone's own GOP index; an entry is used only if it "
            "names its own zone, fits in it after the index and has its unused bytes zero. "
            "Extraction checks every frame's start code; --remnants finds GOPs no index "
            "lists.",
        ]
        if foot and foot["entries_rejected"]:
            result.notes.append(f"{foot['entries_rejected']} zone index entries failed the "
                                "checks and were not used")
        if foot and foot["geometry"]["area_bytes"] != foot["geometry"]["area_bytes_by_disk_size"]:
            result.notes.append("The database area's size in its record differs from the one the "
                                "disk's size gives; the record's is used")
        if dbs and not readable:
            result.notes.append("The index was found but not read - reported as it is, "
                                "not guessed at. The recorder's firmware can AES-encrypt it.")
        return result

    # -- footage out ------------------------------------------------------------
    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """A recording's video: each GOP's frames walked as the recorder's
        playback walks them, headers removed, payloads in order.  A GOP that
        fails the walk is left out and counted."""
        if recording_id not in self.extents:
            self.parse(dev)
            if recording_id not in self.extents:
                self.recover_video_area(dev)
        ext = self.extents.get(recording_id)
        if ext is None:
            raise KeyError(recording_id)
        gops = frames = 0
        failed: list[str] = []
        codec, first, last = "", None, None
        tmp = base_path + ".es.part"
        with open(tmp, "wb") as fh:
            for off, n, expect in ext:
                buf = dev.read_at(off, n)
                g = walk_gop(buf, expect or None)
                if g["error"] or not g["frames"]:
                    failed.append(f"0x{off:X}: {g['error'] or 'no frames'}")
                    continue
                gops += 1
                for f in g["frames"]:
                    codec = codec or f["codec"]
                    fh.write(buf[f["at"]:f["at"] + f["length"]])
                frames += len(g["frames"])
                first = g["frames"][0]["time"] if first is None else first
                last = g["frames"][-1]["time"]
        path = base_path + "." + (codec or "es")
        os.replace(tmp, path)
        return {"file": os.path.basename(path), "sha256": sha256_file(path),
                "bytes": os.path.getsize(path), "frames": frames, "gops": gops,
                "gops_failing_checks": len(failed), "failures": failed[:20],
                "first_time_local": _when(first)[0] if first else None,
                "last_time_local": _when(last)[0] if last else None}

    def recover_video_area(self, dev, limit: Optional[int] = None) -> list[Recording]:
        """GOPs found by their own frame headers in every zone, indexed or
        not - what is left when a zone's index entries are gone.  A GOP starts
        with a key frame (SPS, or VPS for H.265, after the start code); its
        frames are walked as playback walks them.  GOPs within 64 KiB of each
        other form one run; the camera is unknown, since a frame header
        carries none."""
        fmt = self._format(dev)
        if not fmt:
            return []
        geo = self._geometry(dev, fmt)
        size = getattr(dev, "size_bytes", 0) or 0
        dz = geo["data_zone_at"]
        stop = size if limit is None else min(size, dz + limit)
        bdev = _Buffered(dev)
        out: list[Recording] = []
        for z in range(geo["zones"]):
            base = dz + z * self.zone_bytes
            if base >= stop:
                break
            end = min(base + self.zone_bytes, stop)
            runs: list[list[dict]] = []
            cur: Optional[list[dict]] = None
            pos = base + self.zone_index_bytes
            while pos < end:
                chunk = dev.read_at(pos, min(16 << 20, end - pos))
                if len(chunk) < FRAME_HEAD + 5:
                    break
                # the next chunk overlaps this one by a header, so no GOP start is missed
                nxt = pos + max(1, len(chunk) - FRAME_HEAD - 4)
                i = chunk.find(START4, FRAME_HEAD)
                while i >= 0:
                    g = self._gop_at(bdev, pos + i - FRAME_HEAD, end)
                    if not g:
                        i = chunk.find(START4, i + 1)
                        continue
                    if cur and g["offset"] - (cur[-1]["offset"] + cur[-1]["length"]) <= 64 << 10:
                        cur.append(g)
                    else:
                        cur = [g]
                        runs.append(cur)
                    after = g["offset"] + g["length"] - pos       # carry on in this chunk
                    if after + FRAME_HEAD + 4 >= len(chunk):
                        nxt = pos + after
                        break
                    i = chunk.find(START4, after + FRAME_HEAD)
                pos = max(nxt, pos + 1)
            for k, run in enumerate(runs):
                for g in run:
                    g["zone"], g["offset"] = z, g["offset"] - base
                out.append(self._recording(
                    dev, f"tpl-z{z:05d}-{k:04d}", "unknown (found by frame headers)", run, dz,
                    STATE_FRAGMENT, 0.2, "container", "frame header +0x00"))
        return out

    @staticmethod
    def _key(codec: int, nal: int) -> bool:
        """A key frame's first NAL: SPS for H.264, VPS for H.265."""
        return (codec == 0 and nal & 0x1F == 7) or (codec == 1 and (nal >> 1) & 0x3F == 32)

    def _gop_at(self, bdev, h: int, end: int) -> Optional[dict]:
        """A GOP starting at h, if a key frame's header is there: its offset,
        length (to the end of its last frame), frame count and times."""
        head = bdev.read_at(h, FRAME_HEAD + 5)
        if (len(head) < FRAME_HEAD + 5 or head[FRAME_HEAD:FRAME_HEAD + 4] != START4
                or not self._key(head[0x10], head[FRAME_HEAD + 4])):
            return None
        codec, times, pos = head[0x10], [], h
        while pos + FRAME_HEAD + 5 <= end:
            fh = bdev.read_at(pos, FRAME_HEAD + 5)
            pts, n = struct.unpack_from("<QI", fh, 0)
            if (len(fh) < FRAME_HEAD + 5 or fh[FRAME_HEAD:FRAME_HEAD + 4] != START4
                    or fh[0x10] != codec or n == 0 or n > GOP_MAX or pos + FRAME_HEAD + n > end):
                break
            if times and self._key(codec, fh[FRAME_HEAD + 4]):
                break                          # the next GOP's key frame
            times.append(pts)
            pos += FRAME_HEAD + ((n + 7) & ~7)
        if not times:
            return None
        return {"offset": h, "length": pos - h, "frames": len(times),
                "start": times[0], "end": times[-1]}

"""TP-Link VIGI NVR: detection, and the recorder's own index when it can be read.

A drop-in plugin: nothing in the core was edited to add it.

SOURCE
------
VIGI NVR1008H V2 firmware, build 240119 (archive.org "embeddedfirmware"
mirror, TP-Link_VIGINVR1008HV2_240119; docs/research/datasets.md).  Two
libraries from its root filesystem were read by static disassembly - nothing
was run:

  /usr/lib/liblayouthddb.so    SHA-256 df6c5bd2518b908a879de8908b675337d3fe2a3c2bb1410f04e11dad20c3b169
  /usr/lib/libsqlite3.so.0.8.6 SHA-256 4754d86ab6476fd4b8997de9e3c52b0dc94209bb936a2234934e8de8d8c00ea0

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

WHAT THIS PLUGIN DOES
---------------------
  * finds the V1 format sector (CRC-32 checked) and TpFile headers - at the
    offsets the scan reports for their signatures, or by looking through the
    first GiB after the format sector;
  * reads each TpFile header's key slots, as stored;
  * where the database behind a header is plain SQLite, reads it: recordings
    per camera, GOP rows, zones, and the system log.  Tables are found by
    their columns, not their names.  Where it is not, the index is reported
    as encrypted or unreadable, with what was seen - nothing is guessed.

WHAT IT DOES NOT DO
-------------------
  * put footage on the disk.  The zone geometry (where the data zone starts,
    how big a zone is) is loaded at run time from an on-disk record whose
    layout was not recovered, so the index rows are reported as the index
    says them, not as disk extents.  Until then, video is recovered with
    `carve-annexb`, which needs no index;
  * read V0's ext4 as a filesystem (the ext reader refuses extents); V0's
    sys.bin is found by its header, like V1's;
  * decrypt.  An encrypted index is reported as encrypted;
  * read the write-ahead logs (sys.bin-wal0...), which may hold changes not
    yet in the database.

STATUS
------
detected_not_parsed when only markers are found or the index cannot be read;
spec_only when a plain index is read - every field from the firmware, none
yet seen on a VIGI disk.

TIME
----
The index's times are integers whose unit (seconds, ms or µs) is decided
from their size and stated per value; whether the recorder's clock ran on
UTC or local time is not in the firmware, so nothing is converted.
"""

from __future__ import annotations

import sqlite3
import struct
import zlib
from datetime import datetime, timezone
from typing import Optional

from core.contract import VALIDATION_DETECTED, VALIDATION_SPEC_ONLY
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
    tag = raw[:FORMAT_CRC_AT].split(b"\x00", 1)[0].decode("ascii", "replace")
    stored = struct.unpack_from("<I", raw, FORMAT_CRC_AT)[0]
    return {"tag": tag, "version": tag[len(TAG):].strip(),
            "crc_stored": stored, "crc32_ok": zlib.crc32(raw[:FORMAT_CRC_AT]) == stored}


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
    if hasattr(con, "deserialize"):
        con.deserialize(blob)
        return con
    con.close()
    raise RuntimeError("this Python cannot open a database from memory (needs 3.11+)")


def read_index(blob: bytes) -> dict:
    """The index tables, found by their columns.  Raises sqlite3 errors when
    the bytes are not a readable database."""
    con = _open(blob)
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
        if readable:
            result.validation_status = VALIDATION_SPEC_ONLY
        idx = readable[0]["index"] if readable else None
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
            "summary": [
                ("format", (f"{fmt['tag']} at 0x{fmt['offset']:X}, CRC-32 "
                            f"{'ok' if fmt['crc32_ok'] else 'MISMATCH'}") if fmt else "not found"),
                ("index", "; ".join(f"0x{d['offset']:X}: {d['status']}" for d in dbs)
                          or "no TpFile header found"),
                ("cameras", ", ".join(f"ch{k}: {v['events']} recordings, {v['first_clock']} .. "
                                      f"{v['last_clock']}" for k, v in sorted(cams.items()))
                            or "-"),
                ("system log", f"{len(idx['log'])} entries" if idx else "-"),
                ("footage", "not placed on the disk: zone geometry not recovered; use "
                            "carve-annexb"),
                ("times", "recorder clock, zone unknown - not converted to UTC"),
            ]}
        result.notes += [
            f"Layout from the recorder's own libraries ({FIRMWARE}), read by static "
            "disassembly; no VIGI disk has been read by the team.",
            "Index rows are reported as the index states them. Where zones sit on the disk "
            "was not recovered, so no footage is placed; carve-annexb recovers the video.",
        ]
        if dbs and not readable:
            result.notes.append("The index was found but not read - reported as it is, "
                                "not guessed at. The recorder's firmware can AES-encrypt it.")
        return result

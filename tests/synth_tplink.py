"""Generate a synthetic TP-Link VIGI disk, built to what the recorder's own
libraries show (plugins/tplink.py, VIGI NVR1008H V2 240119).

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Structures follow the
firmware; every value is ours.  Passing against it proves the plugin follows
the firmware - nothing about real units.

Choices of ours, stated so nobody mistakes them for findings:

  * the geometry is shrunk so the image stays a few MiB: the format sector at
    1 MiB, not 512 MiB; the database area 1 MiB, not 64-256 MiB; zones of
    256 KiB with an 8 KiB index, not 1 GiB with 1 MiB.  configure() moves
    the plugin's constants to match; the arithmetic between them is the
    firmware's;
  * the TpFile header's key-slot types (1, 2, 3) and values are made up: the
    firmware names the slots (version, sync flag, sync count) but their
    numbers were not established;
  * the tables are created with the firmware's own CREATE TABLE statements,
    under the names the firmware uses; the rows are ours;
  * times are seconds in the index and microseconds in the frame headers;
    the firmware does not fix either unit;
  * each GOP's key-frame table holds (frame header offset, frame number);
  * `encrypted=True` replaces the database after the header with random
    bytes, which is what an AES-keyed index looks like from outside.

The footage: zone 0 was recycled - its index is blank but one old H.265
GOP is still in it (for --remnants).  Zone 1 holds camera 0's three events
in H.264 (event 1 also has a sub-stream GOP), zone 2 camera 1's three in
H.265; the third GOP of event 5 has a frame whose start code is damaged.
"""

from __future__ import annotations

import hashlib
import os
import random
import sqlite3
import struct
import tempfile
import zlib

from plugins import tplink as T

FORMAT_AT = 1 << 20
DB_AT = FORMAT_AT + (1 << 20)                 # the TpFile header: the area's first extent
DB_AREA_AT = DB_AT - T.AREA_HEAD
AREA_BYTES = 1 << 20
DATA_ZONE_AT = DB_AREA_AT + 2 * AREA_BYTES    # as rawDiskLayout_resetDBAreaInfo computes it
ZONE_BYTES = 256 << 10
ZONE_INDEX_BYTES = 8 << 10
ZONES = 3
VERSION = "2.2.3"
T0 = 1719830400                 # 2024-07-01 10:40:00 on the recorder's clock
GOP_FRAMES = 6
DAMAGED = (5, 2)                # (event, GOP) with a damaged frame
ORPHAN_AT = DATA_ZONE_AT + ZONE_INDEX_BYTES   # zone 0's unindexed GOP

SCHEMA = [
    "CREATE TABLE IF NOT EXISTS tEventInfo(eventId INTEGER UNIQUE,startTime INTEGER,"
    "endTime INTEGER,channelId INTEGER,zoneId INTEGER,blkId INTEGER,eventType INTEGER,"
    "mainGopLen INTEGER,subGopLen INTEGER,audioGopLen INTEGER,lockFlag INTEGER);",
    "CREATE TABLE IF NOT EXISTS tGopInfo(eventId INTEGER,startTime INTEGER,endTime INTEGER,"
    "zoneId INTEGER,offset INTEGER,len INTEGER,frame_cnt INTEGER);",
    "CREATE TABLE IF NOT EXISTS tZoneInfo(zoneId INTEGER,blockId INTEGER,channelId INTEGER,"
    "dataType INTEGER,status INTEGER,startTime INTEGER,endTime INTEGER,curOffset INTEGER,"
    "lockFlag INTEGER,writeTimes INTEGER,dataBlob BLOB,dataIndexCount INTEGER);",
    "CREATE TABLE IF NOT EXISTS tSlogInfo(id INTEGER UNIQUE,mainType INTEGER,subType INTEGER,"
    "time INTEGER,detail TEXT);",
    "CREATE TABLE IF NOT EXISTS tLayVerInfo(verId INTEGER PRIMARY KEY);",
]
LOG = [(1, 1, 3, T0 - 3600, "disk formatted"), (2, 2, 1, T0 - 60, "admin login"),
       (3, 3, 7, T0 + 1800, "system time changed")]


def configure(parser) -> None:
    """Move the plugin's firmware constants to this fixture's small geometry."""
    parser.format_at = FORMAT_AT
    parser.db_area_at = DB_AREA_AT
    parser.zone_bytes = ZONE_BYTES
    parser.zone_index_bytes = ZONE_INDEX_BYTES


def events() -> list[tuple]:
    """(event, channel, zone, start, end) - camera 0 in zone 1, camera 1 in zone 2."""
    out, ev = [], 0
    for ch in (0, 1):
        for k in range(3):
            ev += 1
            s = T0 + ch * 5 + k * 600
            out.append((ev, ch, 1 + ch, s, s + 590))
    return out


def database() -> bytes:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        con = sqlite3.connect(path)
        for s in SCHEMA:
            con.execute(s)
        for ev, ch, zone, s, e in events():
            con.execute("INSERT INTO tEventInfo VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (ev, s, e, ch, zone, (ev - 1) % 3, 1, 4096, 1024, 0, 0))
            for g in range(4):
                con.execute("INSERT INTO tGopInfo VALUES(?,?,?,?,?,?,?)",
                            (ev, s + g * 2, s + g * 2 + 2, zone, ((ev - 1) % 3 * 4 + g) * 65536,
                             60000, 50))
        for ch in (0, 1):
            con.execute("INSERT INTO tZoneInfo VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (1 + ch, -1, ch, 0, 1, T0, T0 + 1800, 12 * 65536, 0, 3, b"", 12))
        con.executemany("INSERT INTO tSlogInfo VALUES(?,?,?,?,?)", LOG)
        con.commit()
        con.close()
        return open(path, "rb").read()
    finally:
        os.remove(path)


def tpfile_head() -> bytes:
    h = bytearray(T.TPFILE_HEAD)
    h[:16] = T.TPFILE_MAGIC
    struct.pack_into("<IIII", h, 0x10, 1, T.TPFILE_HEAD, 0, 0)
    o = T.SLOTS_AT
    for kind, enc, data in ((1, 0, struct.pack(">I", 2)), (2, 0, b"0\x00\x00\x00"),
                            (3, 0, b"0\x00\x00\x00")):
        struct.pack_into(">III", h, o, kind, enc, len(data))
        h[o + 12:o + 12 + len(data)] = data
        o += 12 + len(data)
    return bytes(h)


def _sector(data: bytes) -> bytes:
    s = bytearray(T.FORMAT_SECTOR)
    s[:len(data)] = data
    struct.pack_into("<I", s, T.FORMAT_CRC_AT, zlib.crc32(bytes(s[:T.FORMAT_CRC_AT])))
    return bytes(s)


def gop(rng, codec: str, t_us: int, damage_frame: int = -1) -> tuple[bytes, bytes, int]:
    """(the GOP as the recorder stores it, its payloads as extraction should
    give them, frame count): frames of a 32-byte header then an Annex-B
    access unit padded to 8, and a key-frame table at the end."""
    from tests.test_pipeline import _h26x_stream
    aus = _h26x_stream(rng, GOP_FRAMES, codec, gop=GOP_FRAMES)
    out, es = bytearray(), bytearray()
    for k, au in enumerate(aus):
        payload = b"".join(T.START4 + nal for nal in au)
        head = bytearray(T.FRAME_HEAD)
        struct.pack_into("<QI", head, 0, t_us + k * 40_000, len(payload))
        head[0x0D] = 0 if k == 0 else 1
        head[0x10] = 0 if codec == "h264" else 1
        if k == damage_frame:
            payload = b"\xff" + payload[1:]
        out += head + payload + bytes(-len(payload) % 8)
        es += payload
    out += struct.pack("<II", 0, 0)             # one key frame: header offset, frame number
    return bytes(out), bytes(es), len(aus)


def entry(zone: int, event: int, start: int, end: int, stream: int, offset: int, length: int,
          frames: int) -> bytes:
    return struct.pack("<IIQQIIIIIII", zone, event, start, end, stream, offset, length, 0, 0,
                       frames, 1) + bytes(T.ENTRY - 0x34)


def build(path: str, encrypted: bool = False, with_format: bool = True) -> dict:
    db = database()
    if encrypted:
        db = random.Random(3).randbytes(len(db))
    size = DATA_ZONE_AT + ZONES * ZONE_BYTES
    img = bytearray(size)
    truth: dict = {"db_at": DB_AT, "events": 6, "gops": 24, "log": len(LOG), "es": {},
                   "zone_gops": {1: 0, 2: 0}, "damaged": None}
    if with_format:
        tag = T.TAG + b" " + VERSION.encode()
        fmt = bytearray(0x94)
        fmt[:len(tag)] = tag
        struct.pack_into("<IQII", fmt, 0x80, T.FMT_MARKER, size, ZONE_BYTES, 0x08000000)
        img[FORMAT_AT:FORMAT_AT + T.FORMAT_SECTOR] = _sector(bytes(fmt))
        area = _sector(struct.pack("<QQ", DB_AT, AREA_BYTES - T.AREA_HEAD))
        img[FORMAT_AT + T.AREA_INFO_AT:FORMAT_AT + T.AREA_INFO_AT + T.FORMAT_SECTOR] = area
    img[DB_AT:DB_AT + T.TPFILE_HEAD] = tpfile_head()
    img[DB_AT + T.TPFILE_HEAD:DB_AT + T.TPFILE_HEAD + len(db)] = db
    if with_format:
        rng = random.Random(11)
        used = {1: ZONE_INDEX_BYTES, 2: ZONE_INDEX_BYTES}
        index = {1: [], 2: []}

        def put(zone: int, event: int, stream: int, s: int, e: int, codec: str, damage=-1):
            data, es, frames = gop(rng, codec, s * 1_000_000, damage)
            off = used[zone]
            base = DATA_ZONE_AT + zone * ZONE_BYTES
            img[base + off:base + off + len(data)] = data
            used[zone] = off + len(data) + (-len(data) % 512)
            index[zone].append(entry(zone, event, s, e, stream, off, len(data), frames))
            key = f"tpl-e{event:06d}-{T.STREAMS[stream]}"
            if damage < 0:
                truth["es"][key] = truth["es"].get(key, b"") + es
            else:
                truth["damaged"] = (key, base + off)
            truth["zone_gops"][zone] += 1

        for ev, ch, zone, s, _ in events():
            codec = "h264" if ch == 0 else "h265"
            for g in range(4):
                put(zone, ev, 0, s + g * 2, s + g * 2 + 2, codec,
                    damage=3 if (ev, g) == DAMAGED else -1)
            if ev == 1:
                put(zone, ev, 1, s, s + 8, codec)
        for zone, rows in index.items():
            base = DATA_ZONE_AT + zone * ZONE_BYTES
            blob = b"".join(rows)
            img[base:base + len(blob)] = blob
        old, _, _ = gop(rng, "h265", (T0 - 86400) * 1_000_000)
        img[ORPHAN_AT:ORPHAN_AT + len(old)] = old
        truth["orphan"] = (ORPHAN_AT, len(old))
        truth["es"] = {k: hashlib.sha256(v).hexdigest() for k, v in truth["es"].items()}
    with open(path, "wb") as fh:
        fh.write(img)
    return truth

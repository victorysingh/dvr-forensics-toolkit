"""Generate a synthetic TP-Link VIGI disk, built to what the recorder's own
libraries show (plugins/tplink.py, VIGI NVR1008H V2 240119).

IT IS NOT EVIDENCE AND IT IS NOT A VENDOR SAMPLE.  Structures follow the
firmware; every value is ours.  Passing against it proves the plugin follows
the firmware - nothing about real units.

Choices of ours, stated so nobody mistakes them for findings:

  * the format sector is put at 1 MiB, not the firmware's 512 MiB, so the
    image stays small; the test moves the plugin's format offset to match;
  * the TpFile header's key-slot types (1, 2, 3) and values are made up: the
    firmware names the slots (version, sync flag, sync count) but their
    numbers were not established;
  * the tables are created with the firmware's own CREATE TABLE statements,
    under the names the firmware uses; the rows are ours;
  * `encrypted=True` replaces the database after the header with random
    bytes, which is what an AES-keyed index looks like from outside.
"""

from __future__ import annotations

import os
import random
import sqlite3
import struct
import tempfile
import zlib

from plugins import tplink as T

FORMAT_AT = 1 << 20
DB_AT = FORMAT_AT + (1 << 20)
VERSION = "2.2.3"
T0 = 1719830400                 # 2024-07-01 10:40:00 on the recorder's clock

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


def database() -> bytes:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        con = sqlite3.connect(path)
        for s in SCHEMA:
            con.execute(s)
        ev = 0
        for ch in (0, 1):
            for k in range(3):
                ev += 1
                s, e = T0 + ch * 5 + k * 600, T0 + ch * 5 + k * 600 + 590
                con.execute("INSERT INTO tEventInfo VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                            (ev, s, e, ch, 10 + ch, k, 1, 4096, 1024, 0, 0))
                for g in range(4):
                    con.execute("INSERT INTO tGopInfo VALUES(?,?,?,?,?,?,?)",
                                (ev, s + g * 2, s + g * 2 + 2, 10 + ch, (k * 4 + g) * 65536,
                                 60000, 50))
        for ch in (0, 1):
            con.execute("INSERT INTO tZoneInfo VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (10 + ch, -1, ch, 0, 1, T0, T0 + 1800, 12 * 65536, 0, 3, b"", 12))
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


def build(path: str, encrypted: bool = False, with_format: bool = True) -> dict:
    db = database()
    if encrypted:
        db = random.Random(3).randbytes(len(db))
    img = bytearray(DB_AT + T.TPFILE_HEAD + len(db) + (1 << 20))
    if with_format:
        sector = bytearray(T.FORMAT_SECTOR)
        tag = (T.TAG + b" " + VERSION.encode())
        sector[:len(tag)] = tag
        struct.pack_into("<I", sector, T.FORMAT_CRC_AT, zlib.crc32(bytes(sector[:T.FORMAT_CRC_AT])))
        img[FORMAT_AT:FORMAT_AT + T.FORMAT_SECTOR] = sector
    img[DB_AT:DB_AT + T.TPFILE_HEAD] = tpfile_head()
    img[DB_AT + T.TPFILE_HEAD:DB_AT + T.TPFILE_HEAD + len(db)] = db
    with open(path, "wb") as fh:
        fh.write(img)
    return {"db_at": DB_AT, "events": 6, "gops": 24, "log": len(LOG)}

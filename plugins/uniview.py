"""Uniview (UNV) NVR: the UBS block store, read from the recorder's own storage driver.

A drop-in plugin, like plugins/honeywell.py: nothing in the core was edited
to add it.

SOURCE
------
Uniview NVR firmware NVR301-04LS3-W, B3612.1.21.220408, a public download
(download.aras.nl/Video/Uniview/Recorders/Firmware/, a Uniview distributor;
docs/research/datasets.md).  A Uniview NVR does its storage in a kernel
module, /driverfile/comm.ko (SHA-256 56b84ede4893acf0c2f5fffe6e2235f2b0b9a6ac
9dee55166449ec53043ac3fc), which kept its symbol table.  Every layout below
was read from a named function in that module by static disassembly -
nothing was run - and each field cites its function.

STATUS: spec_only
-----------------
The firmware says what the recorder is programmed to write.  No Uniview disk
has been read by this team; the tests run on an image built to the same
reading, which proves the code follows the firmware, not that every Uniview
model and firmware version writes the same.  Structures carry a magic and a
version, and anything else is reported, not guessed at.

LAYOUT (superblock version 0x2000)
----------------------------------
  0                     head superblock, 64 KiB, CRC-16  (UBS_RS_SuperInit)
  capacity - 64 KiB     its copy                         (UBS_RS_OpenSuper)
  AzPos                 abstract zone: one 128-byte entry per data block, 31
                        to a 4 KiB group, each group CRC-16  (UBS_RS_SetupAbstNode2,
                        UBS_RS_CheckUnit2, UBS_RS_CrcCheck2)
  DzPos + n * 256 MiB   data block n                     (UBS_Open: DzPos + (n << 28))

In a recording block (record DB version 0x400, UBS_RecDb_Ver4_Init):
  +0         block header, 8 KiB, CRC-16: camera, times, counts
             (UBS_MT_DispDiskDbSuper, UBS_DB_GetRecDbSb4)
  +0x2000    GOP index, 32 bytes per GOP: time, and where the GOP is, in
             4 KiB pages from the block start  (UBS_DB_SetSubIndx4)
  GOPs       each on a 4 KiB boundary: a 24-byte header (0x2006); packets,
             each a 24-byte header (0x1357), its payload and 4 bytes; the
             end marker 0x6002; then padding to the next 4 KiB boundary, whose
             last 8 bytes are the GOP's length and 0x6003
             (UBS_DB_RecoveryFromDataBlk, UBS_DB_ChkIGrpInfo, UBS_MT_PrintGopPkt)

The trailer makes a GOP self-checking: its stated length must equal the
bytes from its header to its end marker.  The walker below accepts a GOP only
when that holds, which is what lets it find footage with no index at all.

CHECKSUMS
---------
CRC-16 from the kernel's crc16() (lib/crc16.c, CRC-16/ARC).  comm.ko imports
that symbol rather than defining it, so the algorithm is the kernel's unless
a vendor kernel changed it: a mismatch is reported, never fatal.

TIME
----
Unix seconds plus milliseconds from the recorder's kernel clock
(UBS_GetSysTime, UBS_Seconds).  Whether a Uniview keeps its kernel on UTC or
on local time is not in the module, so times are shown on the recorder's
clock, not converted.

NOT DECODED
-----------
  * record DB versions 0x100-0x300 (an older 4 KiB header): named, not parsed;
  * snapshot (0x6060) and edge-storage (0x20170801) blocks: counted, not parsed;
  * the four channel-id numbers are kept as the firmware prints them (a/b/c/d);
  * packet stream-type codes: a packet is video by the firmware's own test
    (UBS_DB_ChkVideoPkt); the codec is read from the payload's NAL headers;
  * RAID arrays (Linux md, magic 0xa92b4efc in UBS_DISK_DiskOnline): not handled.
"""

from __future__ import annotations

import os
import struct
from datetime import datetime, timezone
from typing import Optional

from core.contract import (
    STATE_ACTIVE,
    STATE_FRAGMENT,
    Provenance,
    Recording,
    TimestampClaim,
)
from core.hashing import sha256_file
from detect.signatures import SPEC_ONLY, Signature
from parsers.base import (
    SOURCE_FIRMWARE,
    FieldSpec,
    ParseResult,
    VendorParser,
    register,
    weakest_source,
)

FIRMWARE = "Uniview NVR301-04LS3-W B3612.1.21.220408, comm.ko"

SUPER_MAGIC = 0x20131031
SUPER_BYTES = 0x10000
SUPER_V2 = 0x2000
BLOCK = 1 << 28                    # UBS_Open: DzPos + (block << 28)
DZ_MAX = 0x10000000                # UBS_RS_SuperCheck2: a data zone past 256 MiB is invalid
PAGE = 0x1000

GROUP = 0x1000                     # abstract group; entry k of group g is block g*31 + k
PER_GROUP = 31
ENTRY = 0x80

REC_MAGIC, PIC_MAGIC, EDGE_MAGIC = 0x5050, 0x6060, 0x20170801
REC_V4 = 0x400
REC_HEADER = 0x2000
SEGMENTS_AT, SEGMENT, SEGMENTS_MAX = 0x800, 24, 256
INDEX_AT, INDEX_ENTRY, INDEX_MAX = 0x2000, 32, 0x3F00

GOP_MAGIC, PKT_MAGIC, GOP_END, GOP_TAIL = 0x2006, 0x1357, 0x6002, 0x6003
GOP_HDR = PKT_HDR = 0x18
PKT_STEP = 0x1C                    # UBS_DB_ChkPktHdr: next packet at pktlen + 0x1C
MAX_GOP = 0x8000000                # UBS_DB_RecoveryFromDataBlk gives up past 128 MiB

TIME_LO, TIME_HI = 946684800, 4102444800      # 2000 .. 2100: a plausible recorder clock
GAP_S = 60                         # adjacent GOPs further apart than this start a new run

REC_DB_VERSIONS = {0x100: "record DB v1", 0x200: "record DB v2", 0x300: "record DB v3",
                   0x400: "record DB v4"}


def _fw(fn: str) -> str:
    return f"{FIRMWARE}: {fn}"


FIELDS = [
    FieldSpec("super.magic", 0x00, "<I", "0x20131031", SOURCE_FIRMWARE, _fw("UBS_RS_ChkSb")),
    FieldSpec("super.version", 0x04, "<I", "0x2000 for this layout", SOURCE_FIRMWARE,
              _fw("UBS_RS_SuperInit")),
    FieldSpec("super.crc", 0x08, "<I", "CRC-16 of the 64 KiB with this field zeroed",
              SOURCE_FIRMWARE, _fw("UBS_RS_ChkSb")),
    FieldSpec("super.device_id", 0x0C, "bytes:48", "device ID string", SOURCE_FIRMWARE,
              _fw("UBS_MT_PrintSuper")),
    FieldSpec("super.uuid", 0x3C, "<4I", "disk UUID, random at format", SOURCE_FIRMWARE,
              _fw("UBS_RS_SuperInit")),
    FieldSpec("super.rescode", 0x4C, "bytes:16", "resource code string", SOURCE_FIRMWARE,
              _fw("UBS_MT_PrintSuper")),
    FieldSpec("super.capacity", 0x60, "<Q", "disk bytes", SOURCE_FIRMWARE, _fw("UBS_RS_SuperInit")),
    FieldSpec("super.units", 0x68, "<I", "data blocks", SOURCE_FIRMWARE, _fw("UBS_RS_GetKeyParam")),
    FieldSpec("super.az_size", 0x6C, "<I", "abstract zone bytes", SOURCE_FIRMWARE,
              _fw("UBS_RS_SuperCheck2")),
    FieldSpec("super.az_pos", 0x70, "<Q", "abstract zone byte offset", SOURCE_FIRMWARE,
              _fw("UBS_MT_PrintSuper")),
    FieldSpec("super.dz_pos", 0x78, "<Q", "data zone byte offset", SOURCE_FIRMWARE,
              _fw("UBS_Open")),
    FieldSpec("super.rz_pos", 0x80, "<Q", "RzPos (not used here)", SOURCE_FIRMWARE,
              _fw("UBS_MT_PrintSuper")),
    FieldSpec("super.stamp", 0x88, "<I", "format time", SOURCE_FIRMWARE, _fw("UBS_RS_SuperInit")),
    FieldSpec("super.update_stamp", 0x8C, "<I", "last update time", SOURCE_FIRMWARE,
              _fw("UBS_MT_PrintSuper")),
    FieldSpec("abstract.group_crc", 0x00, "<H", "CRC-16 of the 4 KiB group, field zeroed",
              SOURCE_FIRMWARE, _fw("UBS_RS_CrcCheck2")),
    FieldSpec("abstract.block_type", 0x00, "<H", "per 128-byte entry", SOURCE_FIRMWARE,
              _fw("UBS_RS_DbSbToAbs")),
    FieldSpec("abstract.flags", 0x04, "<I", "0x80 records present, 0x08 events, 0x02 motion",
              SOURCE_FIRMWARE, _fw("UBS_RecDbSbToBrief")),
    FieldSpec("abstract.rectype", 0x08, "<Q", "record-type bits", SOURCE_FIRMWARE,
              _fw("UBS_RS_DbSbToAbs")),
    FieldSpec("abstract.channel", 0x10, "<4I", "channel id a/b/c/d", SOURCE_FIRMWARE,
              _fw("UBS_RS_DbSbToAbs")),
    FieldSpec("abstract.start", 0x20, "<I", "block start, recorder seconds", SOURCE_FIRMWARE,
              _fw("UBS_RS_DbSbToAbs")),
    FieldSpec("abstract.end", 0x24, "<I", "block end, recorder seconds", SOURCE_FIRMWARE,
              _fw("UBS_RS_DbSbToAbs")),
    FieldSpec("block.magic", 0x00, "<I", "0x5050 record, 0x6060 snapshot, 0x20170801 edge",
              SOURCE_FIRMWARE, _fw("UBS_MT_GetDataType")),
    FieldSpec("block.version", 0x04, "<I", "0x400", SOURCE_FIRMWARE, _fw("UBS_DB_ChkSb4")),
    FieldSpec("block.crc", 0x08, "<H", "CRC-16 of the 8 KiB header, field zeroed",
              SOURCE_FIRMWARE, _fw("UBS_DB_ChkSb4")),
    FieldSpec("block.type", 0x0A, "<H", "Blktype", SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.channel", 0x10, "<4I", "channel id a/b/c/d (each a byte in a u32)",
              SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.start", 0x20, "<I", "StartTime", SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.end", 0x24, "<I", "EndTime", SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.start_ms", 0x28, "<H", "Startmsec", SOURCE_FIRMWARE,
              _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.end_ms", 0x2A, "<H", "Endmsec", SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.items", 0x2C, "<H", "GOP index entries", SOURCE_FIRMWARE,
              _fw("UBS_DB_GetRecDbSb4")),
    FieldSpec("block.pos", 0x2E, "<H", "write position, 4 KiB pages", SOURCE_FIRMWARE,
              _fw("UBS_DB_UpdateDbSb4")),
    FieldSpec("block.rectype", 0x30, "<Q", "Rectype", SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.segments", 0x38, "<H", "Recitems: segments at +0x800, 24 bytes each",
              SOURCE_FIRMWARE, _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("block.camera_code", 0x40, "bytes:63", "Camecode string", SOURCE_FIRMWARE,
              _fw("UBS_MT_DispDiskDbSuper")),
    FieldSpec("index.sec", 0x00, "<I", "GOP time, recorder seconds", SOURCE_FIRMWARE,
              _fw("UBS_DB_SetSubIndx4")),
    FieldSpec("index.ms", 0x04, "<H", "milliseconds", SOURCE_FIRMWARE, _fw("UBS_DB_SetSubIndx4")),
    FieldSpec("index.rectype", 0x08, "<Q", "record type", SOURCE_FIRMWARE, _fw("UBS_DB_SetSubIndx4")),
    FieldSpec("index.pages", 0x10, "<H", "GOP length, 4 KiB pages", SOURCE_FIRMWARE,
              _fw("UBS_DB_SetSubIndx4")),
    FieldSpec("index.page", 0x12, "<H", "GOP start, 4 KiB pages from the block start",
              SOURCE_FIRMWARE, _fw("UBS_DB_SetSubIndx4")),
    FieldSpec("gop.magic", 0x00, "<I", "0x2006", SOURCE_FIRMWARE, _fw("UBS_DB_ChkIGrpHdr")),
    FieldSpec("gop.sec", 0x04, "<I", "GOP time, recorder seconds", SOURCE_FIRMWARE,
              _fw("UBS_DB_GetIGrpHdrCb4")),
    FieldSpec("gop.ms", 0x08, "<H", "milliseconds", SOURCE_FIRMWARE, _fw("UBS_DB_GetIGrpHdrCb4")),
    FieldSpec("gop.rectype", 0x10, "<Q", "record type", SOURCE_FIRMWARE, _fw("UBS_DB_GetIGrpHdrCb4")),
    FieldSpec("gop.trailer", -8, "<II", "GOP length, 0x6003, at the end of its last 4 KiB page",
              SOURCE_FIRMWARE, _fw("UBS_DB_ChkIGrpInfo")),
    FieldSpec("packet.magic", 0x00, "<I", "0x1357", SOURCE_FIRMWARE, _fw("UBS_DB_ChkPktHdr")),
    FieldSpec("packet.dts_pts", 0x04, "<II", "DTS, PTS", SOURCE_FIRMWARE, _fw("UBS_MT_PrintGopPkt")),
    FieldSpec("packet.flags", 0x0C, "<B", "bit0 type, bit1 first, bit7 end", SOURCE_FIRMWARE,
              _fw("UBS_MT_PrintGopPkt")),
    FieldSpec("packet.stream_type", 0x11, "<B", "not video: 0x10, 0x11, 0x15 or flag bit0",
              SOURCE_FIRMWARE, _fw("UBS_DB_ChkVideoPkt")),
    FieldSpec("packet.length", 0x12, "<H", "payload bytes, from +0x18", SOURCE_FIRMWARE,
              _fw("UBS_DB_ChkPktHdr")),
]

SIGNATURES = [
    Signature(id="uniview.ubs_super", vendor="Uniview",
              pattern=struct.pack("<I", SUPER_MAGIC) + struct.pack("<I", SUPER_V2),
              description="UBS disk superblock (magic 0x20131031, version 0x2000) at LBA 0",
              source=_fw("UBS_RS_ChkSb, UBS_RS_SuperInit"), validation_status=SPEC_ONLY,
              weight=10.0, expected_offsets=(0,), offset_tolerance=0),
]


# -- CRC-16 (kernel lib/crc16.c: CRC-16/ARC, reflected 0x8005) ----------------
def _crc16_table() -> list[int]:
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
        t.append(c)
    return t


_CRC16 = _crc16_table()


def crc16(data: bytes, crc: int = 0) -> int:
    for b in data:
        crc = (crc >> 8) ^ _CRC16[(crc ^ b) & 0xFF]
    return crc


def _crc_with_zeroed(buf: bytes, at: int, width: int) -> int:
    return crc16(buf[:at] + b"\x00" * width + buf[at + width:])


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", "replace")


def _clock(sec: int, ms: int = 0) -> Optional[str]:
    """A recorder-clock time as text, or None for a value that is no
    plausible time (0 must never become 1970 presented as fact)."""
    if not TIME_LO <= sec <= TIME_HI:
        return None
    t = datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f"{t}.{ms:03d}" if ms else t


# -- structures ---------------------------------------------------------------
def read_super(dev, off: int) -> Optional[dict]:
    raw = dev.read_at(off, SUPER_BYTES)
    if len(raw) < SUPER_BYTES or struct.unpack_from("<I", raw, 0)[0] != SUPER_MAGIC:
        return None
    u32 = lambda o: struct.unpack_from("<I", raw, o)[0]
    u64 = lambda o: struct.unpack_from("<Q", raw, o)[0]
    stored = u32(0x08)
    return {"offset": off, "version": u32(0x04), "crc_stored": stored,
            "crc_ok": _crc_with_zeroed(raw, 0x08, 4) == stored,
            "device_id": _cstr(raw[0x0C:0x3C]),
            "uuid": "-".join(f"{u32(o):08x}" for o in (0x3C, 0x40, 0x44, 0x48)),
            "rescode": _cstr(raw[0x4C:0x5C]), "capacity": u64(0x60), "units": u32(0x68),
            "az_size": u32(0x6C), "az_pos": u64(0x70), "dz_pos": u64(0x78), "rz_pos": u64(0x80),
            "stamp": u32(0x88), "update_stamp": u32(0x8C)}


def block_header(dev, base: int) -> dict:
    raw = dev.read_at(base, REC_HEADER)
    if len(raw) < 0x80:
        return {"kind": "unreadable"}
    magic, version = struct.unpack_from("<II", raw, 0)
    if magic == PIC_MAGIC:
        return {"kind": "snapshot", "magic": magic, "version": version}
    if magic == EDGE_MAGIC:
        return {"kind": "edge", "magic": magic, "version": version}
    if magic != REC_MAGIC:
        return {"kind": "none", "magic": magic}
    if version != REC_V4:
        return {"kind": "record", "version": version, "parsed": False,
                "note": f"{REC_DB_VERSIONS.get(version, hex(version))}: layout not decoded"}
    u16 = lambda o: struct.unpack_from("<H", raw, o)[0]
    u32 = lambda o: struct.unpack_from("<I", raw, o)[0]
    stored = u16(0x08)
    h = {"kind": "record", "version": version, "parsed": True, "crc_stored": stored,
         "crc_ok": len(raw) == REC_HEADER and _crc_with_zeroed(raw, 0x08, 2) == stored,
         "block_type": u16(0x0A), "flag": raw[0x0C],
         "channel": tuple(u32(o) & 0xFF for o in (0x10, 0x14, 0x18, 0x1C)),
         "start": u32(0x20), "end": u32(0x24), "start_ms": u16(0x28), "end_ms": u16(0x2A),
         "items": u16(0x2C), "pos_pages": u16(0x2E),
         "rectype": struct.unpack_from("<Q", raw, 0x30)[0], "segments": u16(0x38),
         "events": u16(0x3C), "motion": u16(0x3E), "camera_code": _cstr(raw[0x40:0x7F])}
    h["segment_list"] = [
        dict(zip(("start", "end", "rectype", "size"), struct.unpack_from("<IIQH", raw, o)))
        for o in range(SEGMENTS_AT, SEGMENTS_AT + SEGMENT * min(h["segments"], SEGMENTS_MAX),
                       SEGMENT)]
    return h


def gop_index(dev, base: int, items: int) -> list[dict]:
    n = min(items, INDEX_MAX)
    raw = dev.read_at(base + INDEX_AT, n * INDEX_ENTRY)
    out = []
    for i in range(len(raw) // INDEX_ENTRY):
        sec, ms, proper = struct.unpack_from("<IHB", raw, i * INDEX_ENTRY)
        rectype, pages, page = struct.unpack_from("<QHH", raw, i * INDEX_ENTRY + 8)
        out.append({"sec": sec, "ms": ms, "proper": proper, "rectype": rectype,
                    "offset": page * PAGE, "length": pages * PAGE})
    return out


def walk_gop(dev, off: int, limit: int) -> Optional[dict]:
    """One GOP at `off`, checked the way the recorder checks it on recovery:
    header magic, a chain of packet headers, the end marker, and a trailer
    whose length matches.  None if any of it fails."""
    head = dev.read_at(off, GOP_HDR)
    if len(head) < GOP_HDR or struct.unpack_from("<I", head, 0)[0] != GOP_MAGIC:
        return None
    sec, ms = struct.unpack_from("<IH", head, 4)
    rectype = struct.unpack_from("<Q", head, 0x10)[0]
    pos, packets = off + GOP_HDR, []
    while True:
        if pos + 4 > limit or pos - off > MAX_GOP:
            return None
        hdr = dev.read_at(pos, PKT_HDR)
        if len(hdr) < 4:
            return None
        magic = struct.unpack_from("<I", hdr, 0)[0]
        if magic == GOP_END:
            end = pos + 4
            break
        if magic != PKT_MAGIC or len(hdr) < PKT_HDR:
            return None
        dts, pts, bits, rate, seq, _pic, stype, n, fseq = struct.unpack_from(
            "<IIBBHBBHI", hdr, 4)
        video = not bits & 1 and stype not in (0x10, 0x11, 0x15)
        packets.append({"offset": pos, "payload": pos + PKT_HDR, "length": n, "dts": dts,
                        "pts": pts, "first": bool(bits & 2), "end": bool(bits & 0x80),
                        "stream_type": stype, "video": video, "frame_seq": fseq})
        pos += n + PKT_STEP
    trailer = (end + PAGE) & ~(PAGE - 1)
    if trailer > limit:
        return None
    raw = dev.read_at(trailer - 8, 8)
    if len(raw) < 8:
        return None
    length, tail = struct.unpack("<II", raw)
    if tail != GOP_TAIL or length != end - off:
        return None
    return {"offset": off, "sec": sec, "ms": ms, "rectype": rectype, "packets": packets,
            "end": end, "next": trailer}


class _Buffered:
    """read_at() over a device through one cached window, so walking packet
    headers a few bytes at a time does not mean one disk read each."""

    def __init__(self, dev, window: int = 4 << 20):
        self.dev, self.window = dev, window
        self.base, self.buf = 0, b""
        self.size_bytes = getattr(dev, "size_bytes", 0)

    def read_at(self, off: int, n: int) -> bytes:
        if not (self.base <= off and off + n <= self.base + len(self.buf)):
            self.base, self.buf = off, self.dev.read_at(off, max(n, self.window))
        return self.buf[off - self.base:off - self.base + n]


H265_TYPES = {0, 1, 19, 20, 21, 32, 33, 34, 35, 39}


def _codec(payload: bytes) -> str:
    """h264 / h265 from the first NAL header after a start code, else ''."""
    i = payload.find(b"\x00\x00\x01")
    if i < 0 or i + 4 >= len(payload):
        return ""
    nh = payload[i + 3]
    if not nh & 0x81 and (nh >> 1) & 0x3F in H265_TYPES and payload[i + 4] in range(1, 8):
        return "h265"
    return "h264" if nh & 0x1F in (1, 5, 6, 7, 8, 9) else ""


@register
class UniviewParser(VendorParser):
    vendor = "Uniview"
    parser_rule = "uniview.ubs.comm-ko-b3612.v1"
    # Fixed by the firmware; the tests shrink it so their images stay small.
    block_bytes = BLOCK

    def __init__(self):
        self.extents: dict[str, list[tuple[int, int]]] = {}
        self.video_area_stats: dict = {}

    def _block(self, sup: dict, n: int) -> int:
        return sup["dz_pos"] + n * self.block_bytes

    def detect(self, dev, hint_offsets=None) -> bool:
        s = read_super(dev, 0)
        return bool(s) and s["version"] == SUPER_V2 and 0 < s["dz_pos"] <= DZ_MAX

    # -- abstract zone --------------------------------------------------------
    def _abstract(self, dev, sup: dict) -> tuple[list[dict], dict]:
        groups = -(-sup["units"] // PER_GROUP)
        entries, bad = [], []
        for g in range(groups):
            raw = dev.read_at(sup["az_pos"] + g * GROUP, GROUP)
            if len(raw) < GROUP:
                break
            if _crc_with_zeroed(raw, 0, 2) != struct.unpack_from("<H", raw, 0)[0]:
                bad.append(g)
            for k in range(PER_GROUP):
                n = g * PER_GROUP + k
                if n >= sup["units"]:
                    break
                e = raw[(k + 1) * ENTRY:(k + 2) * ENTRY]
                btype, flags = struct.unpack_from("<HxxI", e, 0)
                start, end = struct.unpack_from("<II", e, 0x20)
                if not (btype or flags or start or end):
                    continue
                entries.append({"block": n, "block_type": btype, "flags": flags,
                                "rectype": struct.unpack_from("<Q", e, 8)[0],
                                "channel": tuple(struct.unpack_from("<4I", e, 0x10)),
                                "start": start, "end": end,
                                "used": struct.unpack_from("<H", e, 0x28)[0]})
        return entries, {"groups": groups, "groups_crc_failed": bad}

    # -- parse ----------------------------------------------------------------
    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=weakest_source([f.source for f in FIELDS]))
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        head = read_super(dev, 0)
        if head is None:
            result.errors.append("no UBS superblock (magic 0x20131031) at LBA 0")
            return result
        size = getattr(dev, "size_bytes", 0) or head["capacity"]
        tail = read_super(dev, head["capacity"] - SUPER_BYTES) if head["capacity"] else None
        sup = head if head["crc_ok"] or not (tail and tail["crc_ok"]) else tail
        if sup["version"] != SUPER_V2:
            result.errors.append(f"superblock version 0x{sup['version']:X}: only 0x2000 is "
                                 "decoded")
            result.volume = {"vendor": self.vendor, "superblock": sup}
            return result
        if not 0 < sup["dz_pos"] <= DZ_MAX:
            result.errors.append(f"data zone at 0x{sup['dz_pos']:X}: the firmware rejects a "
                                 "data zone past 256 MiB (UBS_RS_SuperCheck2)")
        abstract, astats = self._abstract(dev, sup)

        blocks, kinds = [], {}
        for e in abstract:
            base = self._block(sup, e["block"])
            if base + REC_HEADER > size:
                kinds["beyond this image"] = kinds.get("beyond this image", 0) + 1
                continue
            h = block_header(dev, base)
            label = h["kind"] if h["kind"] != "record" or h.get("parsed") else "record (old version)"
            kinds[label] = kinds.get(label, 0) + 1
            if h["kind"] == "record" and h.get("parsed"):
                blocks.append((e, base, h))

        recs = [self._recording(dev, e, base, h) for e, base, h in blocks]
        result.recordings = [r for r in recs if r is not None]
        result.indexed_extents = [x for r in result.recordings for x in self.extents[r.id]]
        chans = sorted({r.camera_id for r in result.recordings})
        result.volume = {
            "vendor": self.vendor, "superblock": sup,
            "superblock_used": "head" if sup is head else "tail copy",
            "tail_copy": ("absent" if not tail else "matches" if tail and all(
                tail[k] == head[k] for k in ("uuid", "az_pos", "dz_pos", "units"))
                          else "differs"),
            "abstract": dict(astats, entries=len(abstract)), "block_kinds": kinds,
            "summary": [
                ("superblock", f"v0x{sup['version']:X} at 0x{sup['offset']:X}, CRC "
                               f"{'ok' if sup['crc_ok'] else 'MISMATCH'}; device "
                               f"{sup['device_id'] or '(blank)'}"),
                ("disk", f"{sup['capacity']:,} bytes; {sup['units']} blocks of "
                         f"{self.block_bytes >> 20} MiB from 0x{sup['dz_pos']:X}"),
                ("abstract", f"{len(abstract)} blocks in use; {len(astats['groups_crc_failed'])} "
                             f"of {astats['groups']} groups fail CRC"),
                ("blocks", ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())) or "none"),
                ("cameras", ", ".join(chans) or "none"),
                ("times", "recorder clock, zone unknown - not converted to UTC"),
            ]}
        if astats["groups_crc_failed"]:
            result.notes.append(f"{len(astats['groups_crc_failed'])} abstract group(s) failed "
                                "CRC-16; their entries are used but flagged by this note")
        result.notes += [
            f"Layout from the recorder's own storage driver ({FIRMWARE}), read by static "
            "disassembly; no Uniview disk has been read by the team (spec_only).",
            "Times are the recorder's clock; whether its kernel ran on UTC or local time "
            "is not in the firmware, so nothing is converted.",
            "Snapshot and edge-storage blocks are counted, not parsed; record DB versions "
            "before 0x400 are named, not parsed.",
        ]
        return result

    def _recording(self, dev, e: dict, base: int, h: dict) -> Optional[Recording]:
        idx = gop_index(dev, base, h["items"])
        ext = [(base + g["offset"], g["length"]) for g in idx
               if g["length"] and g["offset"] + g["length"] <= self.block_bytes]
        rid = f"unv-b{e['block']:05d}"
        self.extents[rid] = ext
        codec = ""
        if ext:
            gop = walk_gop(_Buffered(dev, 1 << 20), ext[0][0], base + self.block_bytes)
            first = next((p for p in (gop or {}).get("packets", []) if p["video"]), None)
            if first:
                codec = _codec(dev.read_at(first["payload"], min(first["length"], 64)))
        start, end = _clock(h["start"], h["start_ms"]), _clock(h["end"], h["end_ms"])

        def claim(sec: int, ms: int, label: str, text: Optional[str]) -> TimestampClaim:
            return TimestampClaim(
                source="index", raw_value=f"{sec}.{ms:03d} = {text} recorder-local",
                decoded_utc=None, tz_offset_min=None, confidence=0.4 if text else 0.0,
                decode_rule=f"block header {label}: seconds since 1970 plus milliseconds on "
                            "the recorder's kernel clock; zone unknown, not converted")

        a, b, c, d = h["channel"]
        conf = 0.5 if h["crc_ok"] else 0.3
        off = ext[0][0] if ext else base
        length = sum(n for _, n in ext) or REC_HEADER
        sector = getattr(dev, "sector_size", 512) or 512
        return Recording(
            id=rid, camera_id=f"chan {a}/{b}/{c}/{d}", state=STATE_ACTIVE, codec=codec,
            offset=off, length=length, start_utc=None, end_utc=None,
            duration_s=float(max(0, h["end"] - h["start"])) + (h["end_ms"] - h["start_ms"]) / 1000,
            confidence=conf, frame_count=0,
            timestamps=[claim(h["start"], h["start_ms"], "+0x20", start),
                        claim(h["end"], h["end_ms"], "+0x24", end)],
            provenance=Provenance(disk_offset=off, length=length, sector_start=off // sector,
                                  sector_end=(ext[-1][0] + ext[-1][1] if ext else base + REC_HEADER)
                                  // sector, parser_rule=self.parser_rule))

    # -- footage out ----------------------------------------------------------
    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """One block's video packets, container headers removed, in GOP order,
        as the payload the recorder stored.  Each GOP is checked before use."""
        if recording_id not in self.extents:
            self.parse(dev)
        ext = self.extents.get(recording_id)
        if ext is None:
            raise KeyError(recording_id)
        bdev = _Buffered(dev)
        gops = bad = frames = 0
        first = last = None
        codec, tmp = "", base_path + ".es.part"
        with open(tmp, "wb") as fh:
            for off, n in ext:
                g = walk_gop(bdev, off, off + n)
                if g is None:
                    bad += 1
                    continue
                gops += 1
                first = first or (g["sec"], g["ms"])
                last = (g["sec"], g["ms"])
                for p in g["packets"]:
                    if not p["video"]:
                        continue
                    data = bdev.read_at(p["payload"], p["length"])
                    codec = codec or _codec(data[:64])
                    frames += p["first"]
                    fh.write(data)
        path = base_path + "." + (codec or "es")
        os.replace(tmp, path)
        return {"file": os.path.basename(path), "sha256": sha256_file(path),
                "bytes": os.path.getsize(path), "frames": frames, "gops": gops,
                "gops_failing_checks": bad,
                "first_time_local": _clock(*first) if first else None,
                "last_time_local": _clock(*last) if last else None}

    def recover_video_area(self, dev, limit: Optional[int] = None) -> list[Recording]:
        """GOPs found by their own structure in every data block, index or
        not - what is left when the abstract zone or a block header is gone,
        and older footage past a block's write position.  One run per chain
        of adjacent GOPs; the camera is unknown, since a GOP header carries
        none."""
        sup = read_super(dev, 0)
        if sup is None:
            return []
        bdev = _Buffered(dev)
        size = getattr(dev, "size_bytes", 0)
        stop = size if limit is None else min(size, sup["dz_pos"] + limit)
        runs, cur, gops, frames = [], None, 0, 0
        for n in range(sup["units"]):
            base = self._block(sup, n)
            if base >= stop:
                break
            end = min(base + self.block_bytes, stop)
            h = block_header(bdev, base)
            write_pos = base + h["pos_pages"] * PAGE if h.get("parsed") else None
            pos = base + INDEX_AT
            while pos < end:
                page = bdev.read_at(pos, 4)
                if len(page) < 4:
                    break
                g = walk_gop(bdev, pos, end) if struct.unpack("<I", page)[0] == GOP_MAGIC else None
                if g is None:
                    if cur:
                        runs.append(cur)
                        cur = None
                    pos += PAGE
                    continue
                gops += 1
                f = sum(1 for p in g["packets"] if p["video"] and p["first"])
                frames += f
                stale = write_pos is not None and pos >= write_pos
                # adjacent GOPs join a run unless time runs backwards or jumps,
                # or the run crosses the write position: old footage never
                # merges with new
                if cur and cur["next"] == pos and cur["stale"] == stale \
                        and 0 <= g["sec"] - cur["t1"][0] <= GAP_S:
                    cur.update(next=g["next"], t1=(g["sec"], g["ms"]), gops=cur["gops"] + 1,
                               frames=cur["frames"] + f)
                else:
                    if cur:
                        runs.append(cur)
                    cur = {"block": n, "start": pos, "next": g["next"], "t0": (g["sec"], g["ms"]),
                           "t1": (g["sec"], g["ms"]), "gops": 1, "frames": f, "stale": stale}
                pos = g["next"]
            if cur:
                runs.append(cur)
                cur = None
        self.video_area_stats = {"frames": frames, "gops": gops, "runs": len(runs),
                                 "past_write_position": sum(1 for r in runs if r["stale"]),
                                 "padding_skips": 0}
        out = []
        for k, r in enumerate(runs):
            t0 = _clock(*r["t0"])
            out.append(Recording(
                id=f"unv-{'stale' if r['stale'] else 'gops'}-{k:05d}", camera_id="unknown",
                state=STATE_FRAGMENT, codec="",
                offset=r["start"], length=r["next"] - r["start"], start_utc=None, end_utc=None,
                duration_s=float(r["t1"][0] - r["t0"][0]), confidence=0.35,
                frame_count=r["frames"],
                timestamps=[TimestampClaim(
                    source="container", raw_value=f"{r['t0'][0]}.{r['t0'][1]:03d} = {t0} "
                                                  "recorder-local",
                    decoded_utc=None, confidence=0.3 if t0 else 0.0,
                    decode_rule="GOP header +0x04 seconds, +0x08 ms (UBS_DB_GetIGrpHdrCb4); "
                                "zone unknown")],
                provenance=Provenance(disk_offset=r["start"], length=r["next"] - r["start"],
                                      sector_start=r["start"] // 512, sector_end=r["next"] // 512,
                                      parser_rule=self.parser_rule + ".gop-walk")))
        return out

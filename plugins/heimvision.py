"""HeimVision DVR (K9604-W): read off a real disk image, as a drop-in plugin.

SOURCE
------
Observed on the NIST CFReDS image "Heimvision DVR .E01 Forensic Image"
(Josh Brunty and Rayna Mock, Marshall University, 2021): a HeimVision
K9604-W 4-channel DVR's 150 GB disk, imaged with FTK Imager 4.3.1.1, media
MD5 4895ea6d10b08c29fb1bb03591adc7b2.  No paper describes this format; every
field below was read off that image by this team (28 Sep 2026), and the
header field meanings were inferred from how the values behave across the
9,680 frames of the first file.  Status: spec_only - observed on real media,
not byte-matched against the recorder's own export.

LAYOUT
------
  * GPT, two partitions.  Partition 1: ext3 (mounted at /root/rec/a1), the
    recorder's own files, read by `parsers/ext3.py`:
      - dvr_log.db (SQLite): dvr_log(id, type, write_time, log_content) -
        the event log: "reload environment.", "Rec begin N,type:1",
        "Rec stop N"; write_time in Unix UTC;
      - search.db (SQLite): SEARCH, one row per camera-hour (session_rnd,
        channel, frame_count, frame_total_size, start/end time, first and
        last folder/file); DETAIL, one row per .dat file (folder, file,
        fs_index, start_time, end_time);
      - pbversion ("1.0.0.1"), manual_rec_status.bin.
    Partition 2: FAT32 made by mkdosfs, holding `ident.bin` ("ok1ormated"),
    `index.bin`, and a pre-allocated ring of 8 MiB files
    `dirNNNNN/fileNNNN.dat`, 128 to a folder.
  * index.bin: one byte per file slot, in FAT order - 'x' for a completed
    file, 'u' otherwise (the file still open when recording stopped is 'u').
  * A .dat file starts with a 0x2080-byte header, magic "luo ": Unix start
    and end (u32 +4, +8), then per channel (4): the first frame's offset
    (+0x0C..), start time (+0x8C..), a size (+0x10C..), end time (+0x18C..).
  * Then a chain of frames.  Each has a 128-byte header, "liu " ... " uil",
    and the next header is exactly header + 128 + length:

        +0x04 the recorder's camera-hour segment (search.db session_rnd)
        +0x08/+0x0C/+0x10 width, height, fps (video; 0xFFFFFFFF on audio)
        +0x18 codec tag "H265"             +0x24 type: 1 I, 2/3 P, 0 audio
        +0x28 camera number (channel + 1)  +0x2C channel, 0-based
        +0x34 per-channel sequence         +0x3C payload length
        +0x40 u64 microseconds (Unix)      +0x48 u32 Unix seconds (the same)
        +0x4C 0 on I-frames, 1 on P-frames
        +0x50 / +0x54 file offset of an earlier frame's video payload - the
              same camera's / any camera's, 0-2 s back; what they are for
              is not established

    A few audio frames carry segment 0 and time 0; audio is stamped up to
    ~1 s behind the video interleaved with it.

Unlike Dahua (camera 0 on every frame), every frame here names its camera
and carries a microsecond time, so footage can be attributed without any
index.

TIME
----
Frame headers hold Unix times; FAT directory entries hold the recorder's
local wall clock.  Their difference on the same file is the recorder's zone
setting as it applied then - measured per case and reported, never assumed.
A second, independent measurement: the ext3 inode times (the recorder's
kernel clock) of dvr_log.db and search.db against the last UTC time each
database records.  Both are the recorder's own clocks; the error of its
clock against true time is measured by neither.

THE RECORDER'S OWN RECORDS ARE CHECKED, NOT TRUSTED
---------------------------------------------------
search.db's per-file times are compared with every file's own header,
index.bin's marks with the files actually written, and the log's
'Rec begin' with each camera's first video frame; every disagreement is
reported.

Read-only: FAT32 and ext3 are read through `dev.read_at`; the SQLite
databases are opened from memory (or, before Python 3.11, from a temporary
copy deleted afterwards), and nothing is written to the evidence.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import struct
import tempfile
from collections import Counter
from datetime import datetime, timezone
from statistics import median
from typing import Iterator, Optional

from core.contract import STATE_ACTIVE, Provenance, Recording, TimestampClaim
from core.hashing import sha256_file
from detect.engine import parse_partitions
from parsers.base import (SOURCE_OBSERVED, FieldSpec, ParseResult, VendorParser,
                          register, weakest_source)
from parsers.ext3 import Ext, ExtError

IMAGE = ("observed: NIST CFReDS 'Heimvision DVR .E01' (Brunty & Mock 2021), K9604-W, "
         "media MD5 4895ea6d10b08c29fb1bb03591adc7b2")
FILE_MAGIC, FRAME_MAGIC, FRAME_END = b"luo ", b"liu ", b" uil"
FILE_HDR, FRAME_HDR = 0x2080, 128
CHANNELS = 4
FRAME_TYPES = {0: "audio", 1: "I", 2: "P", 3: "P"}
JOIN_S = 10                 # a channel's files this close in time are one recording
MAX_PAYLOAD = 8 << 20

FIELDS = [FieldSpec(n, o, f, d, SOURCE_OBSERVED, IMAGE) for n, o, f, d in (
    ("file.magic", 0x00, "magic", "'luo '"),
    ("file.start", 0x04, "<I", "Unix start"),
    ("file.end", 0x08, "<I", "Unix end"),
    ("file.ch_start", 0x8C, "<4I", "per-channel start"),
    ("file.ch_end", 0x18C, "<4I", "per-channel end"),
    ("frame.magic", 0x00, "magic", "'liu ' ... ' uil' at +124"),
    ("frame.type", 0x24, "<I", "1 I, 2/3 P, 0 audio"),
    ("frame.channel", 0x2C, "<I", "0-based channel"),
    ("frame.sequence", 0x34, "<I", "per-channel sequence"),
    ("frame.length", 0x3C, "<I", "payload length; next header follows it"),
    ("frame.time_us", 0x40, "<Q", "Unix microseconds"),
    ("frame.width", 0x08, "<I", "video width"),
    ("frame.height", 0x0C, "<I", "video height"),
    ("frame.segment", 0x04, "<I", "the recorder's camera-hour segment: search.db SEARCH.session_rnd"),
    ("frame.camera_number", 0x28, "<I", "channel + 1"),
    ("frame.second", 0x48, "<I", "Unix seconds, equal to time_us // 10**6"),
    ("frame.not_key", 0x4C, "<I", "0 on I-frames, 1 on P-frames"),
    ("frame.earlier_own", 0x50, "<I", "file offset of an earlier video payload, same camera; "
                                      "purpose not established"),
    ("frame.earlier_any", 0x54, "<I", "file offset of an earlier video payload, any camera; "
                                      "purpose not established"),
    ("index.bin", 0x00, "bytes", "one byte per file slot, in FAT order: 'x' complete, 'u' not"),
    ("ext3:dvr_log.db", 0x00, "sqlite", "dvr_log(id, type, write_time UTC, log_content)"),
    ("ext3:search.db", 0x00, "sqlite", "SEARCH per camera-hour; DETAIL(folder, file, fs_index, "
                                       "start_time, end_time) per file"),
)]
SYSTEM_FILES = ("dvr_log.db", "search.db", "pbversion", "manual_rec_status.bin")


def _utc(t: float) -> Optional[str]:
    try:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# FAT32, read-only and minimal
# ---------------------------------------------------------------------------
class Fat32:
    def __init__(self, dev, start: int):
        vbr = dev.read_at(start, 512)
        if vbr[0x52:0x5A] != b"FAT32   " or vbr[510:512] != b"\x55\xaa":
            raise ValueError("not FAT32")
        self.dev, self.start = dev, start
        self.bps, self.spc = struct.unpack_from("<HB", vbr, 11)
        rsv, nfats = struct.unpack_from("<HB", vbr, 14)
        fatsz = struct.unpack_from("<I", vbr, 36)[0]
        self.root = struct.unpack_from("<I", vbr, 44)[0]
        self.fat_at = start + rsv * self.bps
        self.data = start + (rsv + nfats * fatsz) * self.bps
        self.csize = self.bps * self.spc
        self.oem = vbr[3:11].rstrip(b"\x00 ").decode("ascii", "replace")
        self._fat_cache: dict[int, bytes] = {}

    def cluster(self, c: int) -> int:
        return self.data + (c - 2) * self.csize

    def _next(self, c: int) -> int:
        page = (c * 4) // 65536
        if page not in self._fat_cache:
            self._fat_cache[page] = self.dev.read_at(self.fat_at + page * 65536, 65536)
        return struct.unpack_from("<I", self._fat_cache[page], (c * 4) % 65536)[0] & 0x0FFFFFFF

    def extents(self, first: int, size: int) -> list[tuple[int, int]]:
        """The byte runs a file occupies, following its cluster chain."""
        out, c, left, seen = [], first, size, set()
        while 2 <= c < 0x0FFFFFF8 and left > 0 and c not in seen:
            seen.add(c)
            off, n = self.cluster(c), min(self.csize, left)
            if out and out[-1][0] + out[-1][1] == off:
                out[-1] = (out[-1][0], out[-1][1] + n)
            else:
                out.append((off, n))
            left -= n
            c = self._next(c)
        return out

    def entries(self, first: int) -> Iterator[dict]:
        for off, n in self.extents(first, 1 << 30):
            raw = self.dev.read_at(off, n)
            for i in range(0, len(raw), 32):
                e = raw[i:i + 32]
                if e[0] == 0:
                    return
                if e[0] in (0xE5, 0x2E) or e[11] == 0x0F:
                    continue
                name = e[:8].decode("ascii", "replace").strip()
                ext = e[8:11].decode("ascii", "replace").strip()
                wt, wd = struct.unpack_from("<HH", e, 22)
                yield {"name": f"{name}.{ext}" if ext else name, "attr": e[11],
                       "cluster": (struct.unpack_from("<H", e, 20)[0] << 16)
                                  | struct.unpack_from("<H", e, 26)[0],
                       "size": struct.unpack_from("<I", e, 28)[0],
                       "written": _fat_time(wd, wt)}


def _fat_time(d: int, t: int) -> Optional[datetime]:
    try:
        return datetime(1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# frames
# ---------------------------------------------------------------------------
def frame_header(b: bytes) -> Optional[dict]:
    if len(b) < FRAME_HDR or b[:4] != FRAME_MAGIC or b[124:128] != FRAME_END:
        return None
    ftype, ch = struct.unpack_from("<I", b, 0x24)[0], struct.unpack_from("<I", b, 0x2C)[0]
    n = struct.unpack_from("<I", b, 0x3C)[0]
    if ftype not in FRAME_TYPES or ch >= CHANNELS or n > MAX_PAYLOAD:
        return None
    w, h = struct.unpack_from("<II", b, 0x08)
    return {"type": FRAME_TYPES[ftype], "channel": ch, "length": n,
            "sequence": struct.unpack_from("<I", b, 0x34)[0],
            "time_us": struct.unpack_from("<Q", b, 0x40)[0],
            "width": w if ftype else None, "height": h if ftype else None,
            "codec": b[0x18:0x1C].rstrip(b"\x00").decode("ascii", "replace") if ftype else "audio"}


def walk_file(dev, extents: list[tuple[int, int]]) -> Iterator[tuple[dict, bytes]]:
    """Every frame in one .dat file, header and payload, in file order."""
    data = b"".join(dev.read_at(o, n) for o, n in extents)
    if data[:4] != FILE_MAGIC:
        return
    pos = FILE_HDR
    while pos + FRAME_HDR <= len(data):
        h = frame_header(data[pos:pos + FRAME_HDR])
        if h is None:
            nxt = data.find(FRAME_MAGIC, pos + 1)          # padding, or the end of the chain
            if nxt < 0:
                return
            pos = nxt
            continue
        end = pos + FRAME_HDR + h["length"]
        if end > len(data):
            return
        yield h, data[pos + FRAME_HDR:end]
        pos = end


# ---------------------------------------------------------------------------
# the recorder's own files: partition 1 (ext3) and index.bin
# ---------------------------------------------------------------------------
def _sqlite(blob: bytes, sql: str) -> list[tuple]:
    """Rows of one query on an SQLite database held as bytes.  Opened in
    memory where Python allows it (3.11+); otherwise from a temporary copy,
    read-only, deleted afterwards.  Either way the evidence is untouched."""
    con = sqlite3.connect(":memory:")
    if hasattr(con, "deserialize"):
        try:
            con.deserialize(blob)
            return con.execute(sql).fetchall()
        finally:
            con.close()
    con.close()
    fd, path = tempfile.mkstemp(suffix=".db")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()
    finally:
        os.remove(path)


def recorder_system(dev) -> dict:
    """The recorder's own files on GPT partition 1 (ext3): its event log and
    its recording index, with their inode times as the recorder's kernel
    clock wrote them.  {} when the partition holds no such files."""
    parts = [p for p in parse_partitions(dev.read_at(0, 64 << 10),
                                         getattr(dev, "sector_size", 512) or 512)
             if p.scheme == "gpt"]
    if not parts:
        return {}
    fs = Ext(dev, parts[0].start_offset)
    present = {e["name"]: e for e in fs.listdir() if e["kind"] == "file"}
    out: dict = {"mount_point": fs.last_mounted_on, "created_raw": fs.times["created"],
                 "files": {}}
    for name in SYSTEM_FILES:
        e = present.get(name)
        if e is None:
            continue
        body = fs.read(e)
        out["files"][name] = {"size": e["size"], "sha256": hashlib.sha256(body).hexdigest(),
                              "mtime_raw": e["mtime"], "ctime_raw": e["ctime"],
                              "atime_raw": e["atime"]}
        if name == "dvr_log.db":
            out["log"] = _sqlite(body, "select id, type, write_time, log_content "
                                       "from dvr_log order by id")
        elif name == "search.db":
            out["detail"] = _sqlite(body, "select folder, file, fs_index, start_time, end_time "
                                          "from DETAIL order by id")
            out["segments"] = _sqlite(body, "select session_rnd, channel, frame_count, "
                                            "frame_total_size, start_time, end_time "
                                            "from SEARCH order by id")
        elif name == "pbversion":
            out["pbversion"] = body.decode("ascii", "replace").strip()
    return out


def _slot(path: str) -> tuple[int, int]:
    """'DIR00006/FILE0037.DAT' -> (6, 37), as search.db names a file."""
    d, f = path.split("/")
    return int(d[3:]), int(f[4:8])


def _zone(local_raw: int, utc: int) -> int:
    """Minutes from UTC of a local clock, to the nearest quarter hour."""
    return round((local_raw - utc) / 900) * 15


@register
class HeimVisionParser(VendorParser):
    vendor = "HeimVision"
    parser_rule = "heimvision.k9604.observed.v1"

    def __init__(self):
        self.recording_files: dict[str, list[dict]] = {}

    def _fat(self, dev) -> Optional[Fat32]:
        parts = [p for p in parse_partitions(dev.read_at(0, 64 << 10),
                                             getattr(dev, "sector_size", 512) or 512)
                 if p.scheme == "gpt"]
        for p in parts[1:2]:
            try:
                return Fat32(dev, p.start_offset)
            except ValueError:
                return None
        return None

    def detect(self, dev, hint_offsets=None) -> bool:
        fat = self._fat(dev)
        if not fat:
            return False
        names = {e["name"] for e in fat.entries(fat.root)}
        return {"IDENT.BIN", "INDEX.BIN", "DIR00000"} <= names

    def _files(self, dev, fat: Fat32) -> list[dict]:
        out = []
        for d in fat.entries(fat.root):
            if not (d["attr"] & 0x10 and d["name"].startswith("DIR")):
                continue
            for f in fat.entries(d["cluster"]):
                if not f["name"].endswith(".DAT"):
                    continue
                ext = fat.extents(f["cluster"], f["size"])
                head = dev.read_at(ext[0][0], 0x1A0) if ext else b""
                rec = {"path": f"{d['name']}/{f['name']}", "extents": ext, "written": f["written"]}
                if head[:4] == FILE_MAGIC:
                    u = lambda o: struct.unpack_from("<I", head, o)[0]
                    rec.update(start=u(4), end=u(8),
                               ch_start=[u(0x8C + 4 * c) for c in range(CHANNELS)],
                               ch_end=[u(0x18C + 4 * c) for c in range(CHANNELS)])
                out.append(rec)
        return out

    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=weakest_source([f.source for f in FIELDS]))
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        fat = self._fat(dev)
        if not fat or not self.detect(dev):
            result.errors.append("no HeimVision layout: GPT, FAT32 in partition 2 with "
                                 "ident.bin, index.bin and dir00000")
            return result
        root = {e["name"]: e for e in fat.entries(fat.root)}
        ident = dev.read_at(fat.cluster(root["IDENT.BIN"]["cluster"]), 16).rstrip(b"\x00")
        files = self._files(dev, fat)
        written = sorted((f for f in files if "start" in f), key=lambda f: f["start"])
        # The recorder's zone setting: FAT write time (local) minus the file's
        # Unix end time, over every written file.
        offs = [round(((f["written"] - datetime.fromtimestamp(f["end"], tz=timezone.utc)
                        .replace(tzinfo=None)).total_seconds()) / 900) * 15
                for f in written if f.get("written") and f.get("end")]
        zone = Counter(offs).most_common(1)[0] if offs else None
        runs: dict[int, list[list[dict]]] = {c: [] for c in range(CHANNELS)}
        for f in written:
            for c in range(CHANNELS):
                s, e = f["ch_start"][c], f["ch_end"][c]
                if not s or not e:
                    continue
                lane = runs[c]
                if lane and s - lane[-1][-1]["ch_end"][c] <= JOIN_S:
                    lane[-1].append(f)
                else:
                    lane.append([f])
        for c, lanes in runs.items():
            for k, group in enumerate(lanes):
                rid = f"hv-ch{c + 1:02d}-{k:04d}"
                self.recording_files[rid] = group
                s, e = group[0]["ch_start"][c], group[-1]["ch_end"][c]
                ext0 = group[0]["extents"][0]
                size = sum(n for f in group for _, n in f["extents"])
                result.recordings.append(Recording(
                    id=rid, camera_id=f"CH{c + 1:02d}", state=STATE_ACTIVE, codec="h265",
                    offset=ext0[0], length=size, start_utc=_utc(s), end_utc=_utc(e),
                    duration_s=float(e - s), confidence=0.6,
                    timestamps=[TimestampClaim(
                        source="container", raw_value=f"{s}", decoded_utc=_utc(s),
                        confidence=0.6, decode_rule="Unix seconds from the .dat header; the "
                        "recorder's clock, error not measured")],
                    provenance=Provenance(disk_offset=ext0[0], length=size,
                                          sector_start=ext0[0] // 512,
                                          sector_end=(ext0[0] + size) // 512,
                                          parser_rule=self.parser_rule)))
        result.indexed_extents = [e for f in written for e in f["extents"]]
        span = (_utc(written[0]["start"]), _utc(written[-1]["end"])) if written else (None, None)

        # The recorder's own records - read, then checked against the files.
        system, system_error = {}, None
        try:
            system = recorder_system(dev)
        except (ExtError, sqlite3.Error) as exc:
            system_error = f"{type(exc).__name__}: {exc}"
        log, detail = system.get("log", []), system.get("detail", [])
        log_unbroken = [r[0] for r in log] == list(range(1, len(log) + 1))
        begun: dict[int, int] = {}
        for _, _, when, text in log:
            m = re.match(r"Rec begin (\d+)", text)
            if m:
                begun.setdefault(int(m.group(1)), when)
        # Each camera's first video frame, from the first file (its header
        # gives the recorder's own start, not the first frame).  Video only:
        # audio frames are stamped up to ~1 s behind the video beside them.
        first_us: dict[int, int] = {}
        if written and begun:
            for h, _ in walk_file(dev, written[0]["extents"]):
                if h["type"] != "audio":
                    c = h["channel"]
                    first_us[c] = min(first_us.get(c, h["time_us"]), h["time_us"])
        before_begin = {c: round(begun[c] - first_us[c] / 1e6, 1) + 0.0     # never -0.0
                        for c in first_us if c in begun}
        by_slot = {_slot(f["path"]): f for f in written}
        listed = {(fo, fi) for fo, fi, *_ in detail}
        listed_ok = sum(1 for fo, fi, _, s, e in detail if (fo, fi) in by_slot
                        and (by_slot[fo, fi]["start"], by_slot[fo, fi]["end"]) == (s, e))
        unlisted = [f["path"] for f in written if _slot(f["path"]) not in listed] if detail else []
        slots = b""
        if "INDEX.BIN" in root:
            for o, n in fat.extents(root["INDEX.BIN"]["cluster"], root["INDEX.BIN"]["size"]):
                slots += dev.read_at(o, min(n, len(files) - len(slots)))
                if len(slots) >= len(files):
                    break
        complete = {k for k, b in enumerate(slots) if b == ord("x")}
        written_slots = {k for k, f in enumerate(files) if "start" in f}
        index_bin = {"complete": len(complete),
                     "written_not_complete": [files[k]["path"] for k in sorted(written_slots - complete)],
                     "complete_not_written": [files[k]["path"] for k in sorted(complete - written_slots)]}
        sysfiles = system.get("files", {})
        ext_zone = {}
        if log and "dvr_log.db" in sysfiles:
            ext_zone["dvr_log.db"] = _zone(sysfiles["dvr_log.db"]["mtime_raw"], max(r[2] for r in log))
        if detail and "search.db" in sysfiles:
            ext_zone["search.db"] = _zone(sysfiles["search.db"]["mtime_raw"], max(r[4] for r in detail))
        result.volume = {
            "vendor": self.vendor, "fat32_oem": fat.oem, "ident": ident.decode("ascii", "replace"),
            "files": len(files), "files_written": len(written), "span_utc": span,
            "recorder_zone_minutes": zone[0] if zone else None,
            "recorder_zone_agreement": f"{zone[1]}/{len(offs)} files" if zone else None,
            "recorder_zone_minutes_ext3": ext_zone,
            "recorder_log": [{"id": i, "type": t, "time_utc": _utc(w), "text": x}
                             for i, t, w, x in log],
            "recorder_log_unbroken": log_unbroken,
            "recorder_index": {"files_listed": len(detail), "files_matching_headers": listed_ok,
                               "written_not_listed": unlisted,
                               "camera_hour_segments": len(system.get("segments", []))},
            "index_bin": index_bin,
            "footage_before_logged_start_s": {f"CH{c + 1:02d}": s
                                              for c, s in sorted(before_begin.items())},
            "recorder_system_files": sysfiles,
            "recorder_mount_point": system.get("mount_point"),
            "pbversion": system.get("pbversion"),
            "recorder_system_error": system_error,
            "summary": [
                ("FAT32", f"{fat.oem}, {fat.csize} B clusters, data at 0x{fat.data:X}"),
                ("ident.bin", repr(ident.decode('ascii', 'replace'))),
                ("files", f"{len(written)} written of {len(files)} pre-allocated .dat files"),
                ("recorded", f"{span[0]} -> {span[1]} (frame Unix times)"),
                ("zone", (f"FAT times are UTC{zone[0] / 60:+.2g}h from the frame times on "
                          f"{zone[1]} of {len(offs)} files - the recorder's zone setting")
                         if zone else "not measured"),
                ("recordings", f"{len(result.recordings)} across {CHANNELS} channels"),
            ("recorder log",
             (f"dvr_log.db: {len(log)} entries, ids "
              f"{'unbroken' if log_unbroken else 'with gaps'}; "
              f"'Rec begin' {_utc(min(begun.values()))} on {len(begun)} cameras; "
              f"last {_utc(log[-1][2])} '{log[-1][3]}'")
             if log and begun else (system_error or "not found")),
            ("before 'Rec begin'", ", ".join(f"CH{c + 1:02d} {s:.1f} s" for c, s in
                                             sorted(before_begin.items()) if s > 0) or "none"),
            ("recorder index",
             f"search.db lists {len(detail)} files: {listed_ok} with exactly the start and end "
             f"their own header gives, {len(unlisted)} written but not listed; "
             f"{len(system.get('segments', []))} camera-hour segments"
             if detail else (system_error or "not found")),
            ("index.bin",
             f"{index_bin['complete']} slots marked complete ('x'); written but not marked: "
             f"{', '.join(index_bin['written_not_complete']) or 'none'}; marked but not "
             f"written: {', '.join(index_bin['complete_not_written']) or 'none'}"),
            ("zone, again", ", ".join(f"{n}: UTC{m / 60:+.2g}h" for n, m in ext_zone.items())
             + " - ext3 file times (the recorder's kernel clock) against the log's own UTC"
             if ext_zone else "not measured"),
            ]}
        result.notes = [
            f"Layout read off real media: {IMAGE}. spec_only until byte-matched against a "
            "HeimVision export.",
            "Frame headers name the camera (0-based channel at +0x2C) and carry Unix "
            "microseconds, so footage is attributed without the index.",
            "The recorder's own records are read and checked, never trusted: its event log "
            "and index (ext3, partition 1) and index.bin are compared with the files, and "
            "every disagreement is reported.",
            "Footage from before a camera's logged 'Rec begin' is consistent with a "
            "pre-record buffer; that is not established.",
            "Undecoded: what frame header +0x50/+0x54 are for (file offsets of an earlier "
            "frame's video); the per-channel offsets and sizes in the file header; how "
            "search.db counts frame_count and frame_total_size (close to the frames on disk, "
            "not equal).",
        ]
        if system_error:
            result.notes.append(f"Recorder's system partition not read: {system_error}")
        return result

    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """One camera's video for one recording, as playable H.265, in time order."""
        if recording_id not in self.recording_files:
            self.parse(dev)
        group = self.recording_files.get(recording_id)
        if not group:
            raise KeyError(recording_id)
        c = int(recording_id.split("-ch")[1][:2]) - 1
        frames = audio = keys = 0
        first = last = None
        path = base_path + ".h265"
        with open(path, "wb") as fh:
            for f in group:
                for h, payload in walk_file(dev, f["extents"]):
                    if h["channel"] != c:
                        continue
                    if h["type"] == "audio":
                        audio += 1
                        continue
                    fh.write(payload)
                    frames += 1
                    keys += h["type"] == "I"
                    first = h["time_us"] if first is None else first
                    last = h["time_us"]
        return {"file": os.path.basename(path), "sha256": sha256_file(path),
                "bytes": os.path.getsize(path), "frames": frames, "keyframes": keys,
                "audio_frames_skipped": audio, "files_read": len(group),
                "first_time_utc": _utc(first / 1e6) if first else None,
                "last_time_utc": _utc(last / 1e6) if last else None}

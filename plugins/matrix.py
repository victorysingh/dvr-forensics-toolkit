"""Matrix SATATYA NVR/HVR: recordings from the recorder's own folder tree.

A drop-in plugin: nothing in the core was edited to add it.

SOURCE
------
Matrix Comsec's own documents.  No Matrix firmware is public (the download
server asks for a login), and no paper covers the format.

  * Matrix Wiki, "How to Backup recording files from HDD in SATATYA
    Devices?" (V1R1, 11 Jun 2018; wiki.matrixcomsec.com/images/b/ba/
    Backup-recording-files-from-hdd.pdf, SHA-256 2a0c91b2...ef472f).  The
    recorder's disk holds `<volume>/CameraNN/DD_Mon_YYYY/HH/` folders.  In
    them are recordings named `HH_MM_SS~HH_MM_SS.stm<N>`, and "other files
    i.e .evnt, .ifrm, .tmid".  The worked example:
    `\\\\192.168.51.254\\hvr\\RAID0\\Camera01\\21_Apr_2018\\14\\14_47_19~14_59_59.stm1`.
  * SATATYA system manual V8R7: the NVR runs embedded Linux and formats the
    disk "to create the file system of the NVR"; recordings are .stm files
    that only Matrix's Device Player plays or converts to AVI.
  * "How to Configure RAID in Matrix NVR": RAID 0 and 1 (5 and 10 on NVRX).

WHAT IS NOT KNOWN
-----------------
  * Which filesystem the recorder formats with - no Matrix document says.
    This reads ext2/3/4, the Linux default: on the whole disk, in a
    partition, or in one member of a Linux md RAID 1 mirror.  Anything else
    found (XFS, a striped RAID member) is named in the report, not read.
  * The .stm container and the sidecar files - not published.  They are
    listed and extracted as stored, with their hashes.  The codec is read
    from the first NAL unit found inside a recording.
  * What the digit after .stm means (stream 1 in the example): kept as written.

TIME
----
The folder and file names are the recorder's own clock: a date, an hour,
and a start and end time.  Whether that clock ran on UTC or local time is
not stated, so nothing is converted.  Each file's inode times are also
reported as a second, independent statement by the recorder's kernel clock.

STATUS: spec_only - the layout comes from the vendor's own published
documents.  No Matrix disk has been read by the team.
"""

from __future__ import annotations

import os
import re
import struct
from datetime import datetime, timezone
from typing import Optional

from core.contract import STATE_ACTIVE, Provenance, Recording, TimestampClaim
from core.hashing import sha256_file
from detect.engine import parse_partitions
from detect.signatures import CANDIDATE, Signature
from parsers.base import SOURCE_PUBLISHED, FieldSpec, ParseResult, VendorParser, register
from parsers.ext3 import Ext, ExtError

DOC = "Matrix Wiki, Backup recording files from HDD in SATATYA Devices (V1R1, 2018)"

CAMERA_RE = re.compile(r"^camera(\d+)$", re.I)
DATE_RE = re.compile(r"^(\d{2})_([A-Za-z]{3})_(\d{4})$")
HOUR_RE = re.compile(r"^(\d{2})$")
FILE_RE = re.compile(r"^(\d{2})_(\d{2})_(\d{2})~(\d{2})_(\d{2})_(\d{2})\.stm(\d*)$", re.I)
MONTHS = {m: k for k, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug",
                                      "sep", "oct", "nov", "dec"), 1)}
SIDECARS = (".evnt", ".ifrm", ".tmid")
SEARCH_DEPTH = 3                   # how deep below a filesystem's root to look for CameraNN

MD_MAGIC = 0xA92B4EFC              # Linux md superblock (v1.x at 0 or 4 KiB)
XFS_MAGIC = b"XFSB"

FIELDS = [
    FieldSpec("tree.camera", 0, "path", "CameraNN folder", SOURCE_PUBLISHED, DOC),
    FieldSpec("tree.date", 0, "path", "DD_Mon_YYYY folder", SOURCE_PUBLISHED, DOC),
    FieldSpec("tree.hour", 0, "path", "HH folder", SOURCE_PUBLISHED, DOC),
    FieldSpec("file.recording", 0, "name", "HH_MM_SS~HH_MM_SS.stm<N>", SOURCE_PUBLISHED, DOC),
    FieldSpec("file.sidecars", 0, "name", ".evnt, .ifrm, .tmid beside each recording",
              SOURCE_PUBLISHED, DOC),
    FieldSpec("filesystem", 1024, "ext", "ext2/3/4 superblock 0xEF53 - Linux's own format; the "
              "recorder's choice of it is not documented", SOURCE_PUBLISHED,
              "kernel Documentation/filesystems/ext4; SATATYA system manual V8R7 (embedded Linux)"),
]

SIGNATURES = [
    Signature(id="matrix.tmid", vendor="Matrix", pattern=b".tmid",
              description="SATATYA time-index file extension, seen in directory entries",
              source=DOC, validation_status=CANDIDATE, weight=2.0),
    Signature(id="matrix.stm1", vendor="Matrix", pattern=b".stm1",
              description="SATATYA recording file extension (.stm1), seen in directory entries",
              source=DOC, validation_status=CANDIDATE, weight=1.0),
]

H265_TYPES = {0, 1, 19, 20, 21, 32, 33, 34, 35, 39}


def _codec(data: bytes) -> str:
    i = data.find(b"\x00\x00\x01")
    while 0 <= i < len(data) - 5:
        nh = data[i + 3]
        if not nh & 0x81 and (nh >> 1) & 0x3F in H265_TYPES and data[i + 4] in range(1, 8):
            return "h265"
        if not nh & 0x80 and nh & 0x1F in (1, 5, 7, 8):
            return "h264"
        i = data.find(b"\x00\x00\x01", i + 3)
    return ""


def _pictures(data: bytes, codec: str) -> int:
    """Coded pictures: slices that start a picture (H.264 first_mb_in_slice
    = 0; H.265 first_slice_segment_in_pic_flag)."""
    n, i = 0, data.find(b"\x00\x00\x01")
    while 0 <= i < len(data) - 5:
        nh = data[i + 3]
        if codec == "h264" and nh & 0x1F in (1, 5) and data[i + 4] & 0x80:
            n += 1
        elif codec == "h265" and (nh >> 1) & 0x3F < 32 and data[i + 5] & 0x80:
            n += 1
        i = data.find(b"\x00\x00\x01", i + 3)
    return n


def _date(name: str) -> Optional[tuple[int, int, int]]:
    m = DATE_RE.match(name)
    if not m or m.group(2).lower() not in MONTHS:
        return None
    return int(m.group(3)), MONTHS[m.group(2).lower()], int(m.group(1))


def _clock(y, mo, d, h, mi, s) -> Optional[str]:
    try:
        return datetime(y, mo, d, h, mi, s).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _inode_clock(t: int) -> Optional[str]:
    if not 946684800 <= t <= 4102444800:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def md_member(raw4k_and_more: bytes) -> Optional[dict]:
    """A Linux md v1.x superblock at 0 or 4 KiB of the given bytes."""
    for at in (0x1000, 0):
        b = raw4k_and_more[at:at + 256]
        if len(b) == 256 and struct.unpack_from("<I", b, 0)[0] == MD_MAGIC \
                and struct.unpack_from("<I", b, 4)[0] == 1:
            return {"superblock_at": at, "name": b[32:64].split(b"\x00", 1)[0].decode("ascii", "replace"),
                    "level": struct.unpack_from("<i", b, 72)[0],
                    "raid_disks": struct.unpack_from("<I", b, 92)[0],
                    "data_offset": struct.unpack_from("<Q", b, 128)[0] * 512}
    return None


@register
class MatrixParser(VendorParser):
    vendor = "Matrix"
    parser_rule = "matrix.satatya.tree-v1r1-2018.v1"

    def __init__(self):
        self.files: dict[str, dict] = {}

    # -- finding the filesystems -------------------------------------------------
    def filesystems(self, dev) -> tuple[list[tuple[int, Ext, str]], list[str]]:
        """(offset, ext reader, how it was reached) for every ext filesystem
        found; and a note for everything else found where one was looked for."""
        ss = getattr(dev, "sector_size", 512) or 512
        starts = [0] + [p.start_offset for p in parse_partitions(dev.read_at(0, 64 << 10), ss)]
        found, notes, seen = [], [], set()
        for start in starts:
            if start in seen:
                continue
            seen.add(start)
            try:
                found.append((start, Ext(dev, start), ""))
                continue
            except ExtError as exc:
                if "not read" in str(exc):
                    notes.append(f"0x{start:X}: {exc}")
                    continue
            if dev.read_at(start, 4) == XFS_MAGIC:
                notes.append(f"0x{start:X}: XFS - not read by this tool")
                continue
            md = md_member(dev.read_at(start, 0x1100))
            if md:
                kind = {1: "RAID 1 mirror", 0: "RAID 0 stripe", 5: "RAID 5", 10: "RAID 10",
                        -1: "linear"}.get(md["level"], f"level {md['level']}")
                if md["level"] == 1:
                    try:
                        found.append((start + md["data_offset"], Ext(dev, start + md["data_offset"]),
                                      f"one mirror of md array '{md['name']}' ({kind}, "
                                      f"{md['raid_disks']} disks)"))
                        continue
                    except ExtError as exc:
                        notes.append(f"0x{start:X}: md {kind} member; {exc}")
                        continue
                notes.append(f"0x{start:X}: member of md array '{md['name']}' ({kind}, "
                             f"{md['raid_disks']} disks) - needs all its disks; not read")
        return found, notes

    def _cameras(self, fs: Ext) -> list[tuple[str, dict]]:
        """(path, entry) of every CameraNN folder within SEARCH_DEPTH of the root."""
        out, level = [], [("", 2)]
        for _ in range(SEARCH_DEPTH + 1):
            nxt = []
            for path, number in level:
                try:
                    entries = fs.listdir(number)
                except ExtError:
                    continue
                for e in entries:
                    if e["kind"] != "dir":
                        continue
                    p = f"{path}/{e['name']}"
                    if CAMERA_RE.match(e["name"]):
                        out.append((p, e))
                    else:
                        nxt.append((p, e["number"]))
            level = nxt
        return out

    def detect(self, dev, hint_offsets=None) -> bool:
        fss, _ = self.filesystems(dev)
        for _, fs, _ in fss:
            for _, cam in self._cameras(fs):
                if any(_date(e["name"]) for e in fs.listdir(cam["number"]) if e["kind"] == "dir"):
                    return True
        return False

    # -- parse ----------------------------------------------------------------------
    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status="spec_only")
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        fss, notes = self.filesystems(dev)
        recs, other, volumes = [], 0, []
        for start, fs, via in fss:
            cams = self._cameras(fs)
            volumes.append({"offset": start, "kind": fs.kind, "via": via, "label": fs.label,
                            "last_mounted_on": fs.last_mounted_on,
                            "camera_folders": [p for p, _ in cams]})
            for path, cam in cams:
                r, o = self._camera(fs, path, cam)
                recs += r
                other += o
        if not recs:
            result.errors.append("no SATATYA recording tree (CameraNN/DD_Mon_YYYY/HH/"
                                 "HH_MM_SS~HH_MM_SS.stm) on any readable ext filesystem"
                                 + (f"; also found: {'; '.join(notes)}" if notes else ""))
        result.recordings = recs
        result.indexed_extents = [(d, n) for r in recs for _, d, n in self.files[r.id]["runs"]]
        cams = sorted({r.camera_id for r in recs})
        codecs = sorted({r.codec for r in recs if r.codec})
        result.volume = {
            "vendor": self.vendor, "filesystems": volumes, "not_read": notes,
            "recordings": len(recs), "other_files_in_hour_folders": other,
            "summary": [
                ("filesystems", ", ".join(f"{v['kind']} at 0x{v['offset']:X}"
                                          + (f" ({v['via']})" if v["via"] else "") for v in volumes)
                                or "no readable ext filesystem"),
                ("not read", "; ".join(notes) or "-"),
                ("tree", ", ".join(p for v in volumes for p in v["camera_folders"]) or "not found"),
                ("recordings", f"{len(recs)} .stm files on {len(cams)} camera(s); codec "
                               f"{', '.join(codecs) or 'not found'}"),
                ("container", ".stm not published: files extracted as stored"),
                ("times", "recorder clock (folder and file names), zone unknown - not converted"),
            ]}
        if volumes:
            result.notes += [
                f"Layout from Matrix's own documents ({DOC}); no Matrix disk has been read by "
                "the team (spec_only).",
                "The recorder's filesystem type is not documented; this reads ext2/3/4 only.",
                "Times are the recorder's clock, from folder and file names; nothing converted.",
            ]
        return result

    def _camera(self, fs: Ext, path: str, cam: dict) -> tuple[list[Recording], int]:
        recs, other = [], 0
        cam_id = cam["name"]
        for d in fs.listdir(cam["number"]):
            ymd = _date(d["name"]) if d["kind"] == "dir" else None
            if not ymd:
                continue
            for h in fs.listdir(d["number"]):
                if h["kind"] != "dir" or not HOUR_RE.match(h["name"]):
                    continue
                entries = fs.listdir(h["number"])
                by_name = {e["name"]: e for e in entries if e["kind"] == "file"}
                used = set()
                for name, e in sorted(by_name.items()):
                    m = FILE_RE.match(name)
                    if not m:
                        continue
                    stem = name.rsplit(".", 1)[0]
                    sidecars = {n: by_name[n] for n in by_name
                                if n != name and n.rsplit(".", 1)[0] == stem}
                    used |= {name, *sidecars}
                    recs.append(self._recording(fs, f"{path}/{d['name']}/{h['name']}", cam_id,
                                                ymd, m, name, e, sidecars))
                other += len(set(by_name) - used)
        return recs, other

    def _recording(self, fs: Ext, folder: str, cam_id: str, ymd, m, name: str, e: dict,
                   sidecars: dict) -> Recording:
        y, mo, d = ymd
        h1, mi1, s1, h2, mi2, s2 = (int(m.group(k)) for k in range(1, 7))
        stream = m.group(7) or ""
        start, end = _clock(y, mo, d, h1, mi1, s1), _clock(y, mo, d, h2, mi2, s2)
        dur = (h2 * 3600 + mi2 * 60 + s2) - (h1 * 3600 + mi1 * 60 + s1)
        runs = fs.byte_runs(e)
        head = fs.read(e, 1 << 16)
        codec = _codec(head)
        rid = (f"mtx-{cam_id.lower()}-{y:04d}{mo:02d}{d:02d}-{h1:02d}{mi1:02d}{s1:02d}"
               + (f"-s{stream}" if stream else ""))
        self.files[rid] = {"fs": fs, "inode": e, "path": f"{folder}/{name}", "runs": runs,
                           "sidecars": sidecars, "start": start, "end": end}
        claims = [TimestampClaim(
            source="filesystem", raw_value=f"{'/'.join(folder.split('/')[-2:])}/{name} = "
                                           f"{start} recorder-local",
            decoded_utc=None, tz_offset_min=None, confidence=0.4 if start else 0.0,
            decode_rule="the recording's own folder (DD_Mon_YYYY/HH) and file name "
                        "(HH_MM_SS~HH_MM_SS), as the recorder named them; zone unknown")]
        mt = _inode_clock(e["mtime"])
        claims.append(TimestampClaim(
            source="filesystem", raw_value=f"{e['mtime']} = {mt} recorder-kernel",
            decoded_utc=None, tz_offset_min=None, confidence=0.2 if mt else 0.0,
            decode_rule="inode mtime (last write) from the recorder's kernel clock; zone unknown"))
        off = runs[0][1] if runs else 0
        sector = getattr(fs.dev, "sector_size", 512) or 512
        return Recording(
            id=rid, camera_id=cam_id, state=STATE_ACTIVE, codec=codec, offset=off,
            length=e["size"], start_utc=None, end_utc=None,
            duration_s=float(dur) if dur >= 0 else 0.0,
            confidence=0.5 if start and runs else 0.3, frame_count=0, timestamps=claims,
            provenance=Provenance(disk_offset=off, length=e["size"], sector_start=off // sector,
                                  sector_end=((runs[-1][1] + runs[-1][2]) // sector) if runs else 0,
                                  parser_rule=self.parser_rule))

    # -- footage out ----------------------------------------------------------------
    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """The .stm file and its sidecars as stored, each hashed.  The .stm
        container is not published, so it is not unwrapped; Matrix's Device
        Player converts it."""
        if recording_id not in self.files or self.files[recording_id]["fs"].dev is not dev:
            self.parse(dev)                  # read through this device, not an earlier one
        f = self.files.get(recording_id)
        if f is None:
            raise KeyError(recording_id)
        fs, ino = f["fs"], f["inode"]
        ext = "." + f["path"].rsplit(".", 1)[1]
        path = base_path + ext
        with open(path, "wb") as fh:
            for fo, d, n in fs.byte_runs(ino):
                fh.seek(fo)
                fh.write(dev.read_at(d, n))
            fh.truncate(ino["size"])
        data = open(path, "rb").read()
        codec = _codec(data[:1 << 16])
        side = {}
        for name, e in sorted(f["sidecars"].items()):
            sp = base_path + "." + name.rsplit(".", 1)[1]
            with open(sp, "wb") as fh:
                fh.write(fs.read(e))
            side[os.path.basename(sp)] = sha256_file(sp)
        return {"file": os.path.basename(path), "sha256": sha256_file(path),
                "bytes": os.path.getsize(path), "source_path": f["path"],
                "frames": _pictures(data, codec) if codec else 0, "codec": codec,
                "sidecars": side, "first_time_local": f["start"], "last_time_local": f["end"]}

"""Matrix SATATYA NVR/HVR: recordings as files, from Matrix's own documentation.

A drop-in plugin: nothing in the core was edited to add it.

SOURCE
------
Matrix's wiki, "How to Backup recording files from HDD in SATATYA Devices?"
(V1R1, 11 Jun 2018; wiki.matrixcomsec.com/images/b/ba/Backup-recording-files-
from-hdd.pdf, SHA-256 2a0c91b2774849e9d01a1511b155da8934bee3ac8a393dcd09f4c01861ef472f),
which tells a user to open the recorder's share and "Go to device/HDD/camera/
date/hour/ copy the desired .stm along with other files i.e .evnt, .ifrm,
.tmid", with the worked example RAID0\\Camera01\\21_Apr_2018\\14\\
14_47_19~14_59_59.stm1.  So a SATATYA disk is a Linux filesystem of clip
files, not a raw block store.  Matrix firmware is partner-only
(docs/research/vendor_formats.md), so nothing here comes from its code.

WHAT IS READ
------------
  <volume>/CameraNN/DD_Mon_YYYY/HH/HH_MM_SS~HH_MM_SS.stmN   one clip
  ... .evnt  .ifrm  .tmid                                   its sidecars
                                                            (event list, I-frame
                                                            and time index, by name)

  * camera: NN of CameraNN - Matrix's camera number, not a title;
  * start and end: the folder's date and the file name's two times - the
    recorder's local wall clock (Matrix sets it per site; no zone on disk);
  * where the clip lies: its file's extents, from parsers/ext3.py;
  * a check, not a trust: the hour folder must be the start's hour, and the
    end must follow the start; each disagreement is reported;
  * the recorder's zone setting, measured as for HeimVision: a clip's end on
    the wall clock minus its inode mtime (the kernel's Unix seconds), to the
    quarter hour, over every clip - reported, never applied.

STATUS: spec_only
-----------------
The tree is Matrix's own description, and the tests run on a disk built to
it.  Not established, and not guessed: the filesystem type (read here if it
is ext2/3/4; XFS or other is reported as not read), the .stm container (the
Device Player converts it to AVI; its bytes are extracted as stored, and
`carve-annexb` looks for video in them), and the sidecar formats.  No Matrix
disk has been read by the team.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from core.contract import STATE_ACTIVE, Provenance, Recording, TimestampClaim
from detect.engine import parse_partitions
from detect.signatures import SPEC_ONLY, Signature
from parsers.base import (SOURCE_PUBLISHED, FieldSpec, ParseResult, VendorParser,
                          register, weakest_source)
from parsers.ext3 import Ext, ExtError

DOC = ("Matrix wiki 'How to Backup recording files from HDD in SATATYA Devices?' V1R1 "
       "(2018), SHA-256 2a0c91b2774849e9d01a1511b155da8934bee3ac8a393dcd09f4c01861ef472f")
CAMERA_RE = re.compile(r"^Camera(\d{2,3})$")
DAY_RE = re.compile(r"^(\d{2})_([A-Z][a-z]{2})_(\d{4})$")
HOUR_RE = re.compile(r"^(\d{2})$")
CLIP_RE = re.compile(r"^(\d{2})_(\d{2})_(\d{2})~(\d{2})_(\d{2})_(\d{2})\.stm(\d*)$")
SIDECARS = (".evnt", ".ifrm", ".tmid")

FIELDS = [FieldSpec(n, 0, f, d, SOURCE_PUBLISHED, DOC) for n, f, d in (
    ("path.camera", "CameraNN", "camera number"),
    ("path.day", "DD_Mon_YYYY", "recording day, recorder-local"),
    ("path.hour", "HH", "hour folder"),
    ("path.clip", "HH_MM_SS~HH_MM_SS.stmN", "clip start and end, recorder-local"),
    ("path.sidecars", ".evnt .ifrm .tmid", "per-clip event list, I-frame and time index"),
)]

SIGNATURES = [
    Signature(id="matrix.satatya.clip", vendor="Matrix", pattern=b".stm1",
              description="SATATYA clip-file suffix in a directory entry",
              source=DOC, validation_status=SPEC_ONLY, weight=2.0),
]


def _local(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


def _utc(dt: datetime, tz: Optional[int]) -> Optional[str]:
    if tz is None:
        return None
    return (dt - timedelta(minutes=tz)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _day(name: str) -> Optional[datetime]:
    try:
        return datetime.strptime(name, "%d_%b_%Y")
    except ValueError:
        return None


@register
class MatrixParser(VendorParser):
    vendor = "Matrix"
    parser_rule = "matrix.satatya.tree.wiki-2018.v1"

    def __init__(self, tz_offset_min: Optional[int] = None):
        self.tz_offset_min = tz_offset_min
        self.clips: dict[str, dict] = {}

    # -- finding the volume ---------------------------------------------------
    def _volumes(self, dev) -> list[tuple[Ext, int, str, int]]:
        """(filesystem, partition offset, volume folder, its inode) for every
        folder that holds CameraNN folders - or the root itself."""
        head = dev.read_at(0, 64 << 10)
        starts = [p.start_offset for p in parse_partitions(head, getattr(dev, "sector_size", 512) or 512)]
        out = []
        for start in starts or [0]:
            try:
                fs = Ext(dev, start)
                root = fs.listdir()
            except ExtError:
                continue
            cands = [("", 2, root)] + [(e["name"], e["number"], None) for e in root
                                       if e["kind"] == "dir"]
            for name, number, listing in cands:
                try:
                    entries = listing if listing is not None else fs.listdir(number)
                except ExtError:
                    continue
                if any(e["kind"] == "dir" and CAMERA_RE.match(e["name"]) for e in entries):
                    out.append((fs, start, name or "/", number))
        return out

    def detect(self, dev, hint_offsets=None) -> bool:
        return bool(self._volumes(dev))

    # -- parse ------------------------------------------------------------------
    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=weakest_source([f.source for f in FIELDS]))
        result.field_provenance = [dict(f.__dict__, status=f.status) for f in FIELDS]
        vols = self._volumes(dev)
        if not vols:
            result.errors.append("no ext2/3/4 volume holding CameraNN folders (a SATATYA disk "
                                 "on another filesystem is not read)")
            return result
        tz = self.tz_offset_min
        problems: list[str] = []
        zones: list[int] = []
        times: list[datetime] = []
        sidecar_count = Counter()
        for fs, start, vol, number in vols:
            for cam in fs.listdir(number):
                mc = CAMERA_RE.match(cam["name"])
                if not (cam["kind"] == "dir" and mc):
                    continue
                for day in fs.listdir(cam["number"]):
                    d = _day(day["name"]) if day["kind"] == "dir" else None
                    if d is None:
                        continue
                    for hour in fs.listdir(day["number"]):
                        if hour["kind"] != "dir" or not HOUR_RE.match(hour["name"]):
                            continue
                        files = {e["name"]: e for e in fs.listdir(hour["number"])
                                 if e["kind"] == "file"}
                        for name, e in sorted(files.items()):
                            m = CLIP_RE.match(name)
                            if not m:
                                continue
                            h1, m1, s1, h2, m2, s2, _seg = m.groups()
                            s = d.replace(hour=int(h1), minute=int(m1), second=int(s1))
                            en = d.replace(hour=int(h2), minute=int(m2), second=int(s2))
                            path = f"{vol.strip('/')}/{cam['name']}/{day['name']}/{hour['name']}/{name}"
                            if int(hour["name"]) != s.hour:
                                problems.append(f"{path}: filed under hour {hour['name']}, "
                                                f"its name starts at {s:%H:%M:%S}")
                            if en < s:
                                problems.append(f"{path}: ends before it starts")
                            stem = name.rsplit(".", 1)[0]
                            have = [x for x in SIDECARS if stem + x in files]
                            sidecar_count[len(have)] += 1
                            if e["mtime"]:
                                wall = en.replace(tzinfo=timezone.utc).timestamp()
                                zones.append(round((wall - e["mtime"]) / 900) * 15)
                            try:
                                runs = fs.runs(e)
                            except ExtError as exc:
                                problems.append(f"{path}: {exc}")
                                continue
                            times += [s, en]
                            cam_no = int(mc.group(1))
                            rid = f"mx-cam{cam_no:02d}-{s:%Y%m%d-%H%M%S}"
                            self.clips[rid] = {"fs": fs, "inode": e, "path": path,
                                               "sidecars": have}
                            off = runs[0][0] if runs else 0
                            claims = [TimestampClaim(
                                source="index", raw_value=f"{path} = {_local(t)} recorder-local",
                                decoded_utc=_utc(t, tz), tz_offset_min=tz, confidence=0.5,
                                decode_rule=f"SATATYA clip path, {which}: folder date + file-name "
                                            "time (Matrix wiki); the recorder's wall clock"
                                            + ("" if tz is not None else "; zone not stated, "
                                               "not converted"))
                                for t, which in ((s, "start"), (en, "end"))]
                            result.recordings.append(Recording(
                                id=rid, camera_id=f"CAM{cam_no:02d}", state=STATE_ACTIVE,
                                codec="", offset=off, length=e["size"],
                                start_utc=_utc(s, tz), end_utc=_utc(en, tz),
                                duration_s=float((en - s).total_seconds()), confidence=0.5,
                                timestamps=claims,
                                provenance=Provenance(disk_offset=off, length=e["size"],
                                                      sector_start=off // 512,
                                                      sector_end=(off + e["size"]) // 512,
                                                      parser_rule=self.parser_rule)))
        zone = Counter(zones).most_common(1)[0] if zones else None
        n = len(result.recordings)
        cams = sorted({r.camera_id for r in result.recordings})
        span = (_local(min(times)), _local(max(times))) if times else (None, None)
        result.volume = {
            "vendor": self.vendor,
            "volumes": [{"partition_offset": start, "folder": vol, "fs_label": fs.label,
                         "last_mounted_on": fs.last_mounted_on, "block_size": fs.block_size}
                        for fs, start, vol, _ in vols],
            "clips": n, "cameras": cams, "span_local": span,
            "sidecars_per_clip": {f"{k} of 3": v for k, v in sorted(sidecar_count.items())},
            "problems": problems, "tz_offset_min": tz,
            "recorder_zone_minutes": zone[0] if zone else None,
            "recorder_zone_agreement": f"{zone[1]}/{len(zones)} clips" if zone else None,
            "summary": [
                ("volumes", ", ".join(f"{v} (ext, {fs.block_size} B blocks, @0x{s:X})"
                                      for fs, s, v, _ in vols)),
                ("clips", f"{n} on {len(cams)} cameras ({', '.join(cams)})"),
                ("span", f"{span[0] or '-'} -> {span[1] or '-'} recorder-local"),
                ("sidecars", ", ".join(f"{v} clips with {k} of 3"
                                       for k, v in sorted(sidecar_count.items()))),
                ("zone setting", f"UTC{zone[0] / 60:+.3g}h: clip ends on the wall clock vs "
                                 f"their inode mtimes, {zone[1]} of {len(zones)} clips - measured, "
                                 "not applied" if zone else "not measured"),
                ("checks", f"{len(problems)} disagreement(s)" + (": " + problems[0]
                                                                 if problems else "")),
            ]}
        result.notes = [
            f"Layout from Matrix's own documentation: {DOC}. spec_only: no Matrix disk read.",
            "Clip times are the recorder's wall clock from the folder and file names; the "
            "filesystem's inode times are its kernel clock. start_utc is set only when the "
            "examiner states the zone (--tz-offset).",
            "The .stm container is Matrix's own and is not decoded: clips are extracted as "
            "stored; run carve-annexb on them for raw video. Sidecars are counted, not parsed.",
        ]
        return result

    def extract_recording(self, dev, recording_id: str, base_path: str) -> dict:
        """The clip's .stm bytes as stored, read from its extents."""
        if recording_id not in self.clips:
            self.parse(dev)
        c = self.clips.get(recording_id)
        if not c:
            raise KeyError(recording_id)
        fs, ino = c["fs"], c["inode"]
        path = base_path + ".stm"
        h = hashlib.sha256()
        left = ino["size"]
        with open(path, "wb") as fh:
            for n in fs.data_blocks(ino):
                take = min(fs.block_size, left)
                chunk = fs._block(n)[:take] if n else bytes(take)
                fh.write(chunk)
                h.update(chunk)
                left -= take
        return {"file": path.replace("\\", "/").rsplit("/", 1)[-1], "sha256": h.hexdigest(),
                "bytes": ino["size"], "frames": 0, "source_path": c["path"],
                "sidecars": c["sidecars"], "note": "Matrix .stm as stored; not decoded"}

"""The recorder's model: read off the platter where it is written there,
recorded from the unit where it is not, and the two checked against each
other and against the vendor detection.

The PS asks the tool to "automatically identify DVR models".  Vendor
detection (`detect/engine.py`) answers a different question - whose FORMAT
is on the disk.  The model usually lives in the recorder's flash, not on the
platter, so there are two sources here, kept apart and never blended:

  * ON THE PLATTER - model-numbered strings (a log line, a copied config, a
    device-info block) found in the parts of the disk that are not video.
    Reported with their offsets and status `candidate`: a string proves the
    text is on the disk, not that the disk came from that model - a disk
    moves between recorders, and the team's second drive did.
  * EXAMINER OBSERVATION - model, serial and firmware read off the unit's
    label or System Info screen at seizure, with the SHA-256 of the photo
    that shows it.

`check()` compares them with each other and with the vendor detection.  A
disagreement is a finding to be explained, not an error: a disk formatted by
one recorder and seized from another says something about its history.

Stdlib only.  Reads the bytes it is handed; the CLI does the device I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

RULE = "detect.model.v1"

# Where a vendor's units are commonly built by another vendor, the disk
# carries the builder's format.  CP Plus sells Dahua-built units (observed:
# DHFS 4.1 on the CP Plus unit's drive WWD4A3NX) - not necessarily every model.
FORMAT_FAMILY = {"CP Plus": "Dahua"}


def family(vendor: str) -> str:
    return FORMAT_FAMILY.get(vendor, vendor)


@dataclass(frozen=True)
class ModelFamily:
    id: str
    vendor: str
    pattern: "re.Pattern[bytes]"
    storage: str       # how units of this family store video, and how we know
    source: str


def _p(expr: bytes) -> "re.Pattern[bytes]":
    # Not preceded by a letter, digit or hyphen, so a model is never matched
    # out of the middle of a longer token.
    return re.compile(rb"(?<![0-9A-Za-z-])" + expr)


FAMILIES = [
    ModelFamily("hikvision", "Hikvision",
                _p(rb"[iI]?DS-[0-9][0-9A-Z]{3,9}-[0-9A-Z][0-9A-Z/+]{0,10}"),
                "HIKVISION@HANGZHOU master sector + HIKBTREE index (published); "
                "MPEG-PS with 'HK' descriptors (observed, drive Z9C2632A)",
                "Hikvision model numbering: DS-7xxx/8xxx/9xxx recorders, DS-2xxx cameras"),
    ModelFamily("dahua", "Dahua",
                _p(rb"DHI?-(?:XVR|NVR|HCVR|DVR|IPC|HAC|SD)[0-9A-Z]{2,10}(?:-[0-9A-Z]{1,6}){0,3}"),
                "DHFS 4.1 + DHAV frames (observed, drive WWD4A3NX; DHAV per ffmpeg dhav.c)",
                "Dahua model numbering: XVR/NVR/HCVR recorders, IPC/HAC/SD cameras"),
    ModelFamily("cpplus", "CP Plus",
                _p(rb"CP-[A-Z]{2,4}-[0-9A-Z]{3,10}(?:-[0-9A-Z]{1,6}){0,2}"),
                "Dahua-family where the unit is Dahua-built: DHFS 4.1 observed on "
                "one CP Plus unit's drive (WWD4A3NX); not established for every model",
                "CP Plus model numbering: CP-UNR NVRs, CP-UVR DVRs"),
    ModelFamily("tplink", "TP-Link",
                _p(rb"VIGI ?NVR[0-9]{4}[0-9A-Z-]{0,8}"),
                "unknown to us", "TP-Link VIGI recorder numbering"),
    ModelFamily("uniview", "Uniview",
                _p(rb"NVR[0-9]{3}-[0-9]{2}[0-9A-Z-]{1,10}"),
                "unknown to us", "Uniview recorder numbering (NVR301-04S3 style)"),
    ModelFamily("matrix", "Matrix",
                _p(rb"SATATYA ?[A-Z]{2,5}[0-9A-Z-]{2,14}"),
                "unknown to us", "Matrix SATATYA product line"),
    ModelFamily("honeywell", "Honeywell",
                _p(rb"H(?:EN|RGX?|RDP)[0-9]{3,5}[0-9A-Z-]{0,8}"),
                "Honeywell NVR filesystem (published tools; spec only)",
                "Honeywell HEN NVRs, HRG/HRGX/HRDP DVRs"),
]
# Godrej: no model numbering we could pin down, so no pattern - its units
# are found by the brand string in detect/signatures.py or not at all.

# What the prefix says about the unit.  Only prefixes whose meaning we are
# sure of; everything else is "device" - a camera's model on an NVR's disk
# is common and does not name the recorder.
KIND = [
    ("hikvision", re.compile(r"^[iI]?DS-[789]"), "recorder"),
    ("hikvision", re.compile(r"^[iI]?DS-2"), "camera"),
    ("dahua", re.compile(r"^DHI?-(?:XVR|NVR|HCVR|DVR)"), "recorder"),
    ("dahua", re.compile(r"^DHI?-(?:IPC|HAC|SD)"), "camera"),
    ("cpplus", re.compile(r"^CP-(?:UNR|UVR|XVR|XNR)-"), "recorder"),
    ("tplink", re.compile(r"^VIGI"), "recorder"),
    ("uniview", re.compile(r"^NVR"), "recorder"),
    ("matrix", re.compile(r"^SATATYA"), "recorder"),
    ("honeywell", re.compile(r"^H"), "recorder"),
]


def kind_of(family_id: str, model: str) -> str:
    for fid, rx, kind in KIND:
        if fid == family_id and rx.search(model):
            return kind
    return "device"


def identify(model: str) -> Optional[dict]:
    """The family a model number belongs to, from its shape alone - for a
    model the examiner typed in, the same patterns the platter search uses."""
    b = model.strip().upper().encode("ascii", "replace")
    for f in FAMILIES:
        m = f.pattern.match(b)
        if m and m.end() == len(b):
            return {"family": f.id, "vendor": f.vendor, "kind": kind_of(f.id, model.upper()),
                    "storage": f.storage}
    return None


# ---------------------------------------------------------------------------
# On the platter
# ---------------------------------------------------------------------------
# A video block: incompressible AND full of start codes.  Everything else -
# indexes, logs, config copies, empty space - is searched.
VIDEO_INCOMPRESSIBILITY = 0.95
CONTEXT = 40
OFFSETS_KEPT = 8


def select_blocks(blockmap: list[dict], device_size: int, max_bytes: int,
                  ends: int = 4) -> tuple[list[tuple[int, int]], dict]:
    """(offset, length) of the blocks worth searching for model strings, from
    the scan's block map: never the video, always the two ends of the disk,
    at most `max_bytes` - and a statement of what was chosen and why."""
    def video(b):
        return b.get("incompressibility", 0) >= VIDEO_INCOMPRESSIBILITY and b.get("start_codes", 0)

    edge = blockmap[:ends] + blockmap[-ends:]
    rest = [b for b in blockmap[ends:-ends or None] if not video(b)]
    chosen, seen, total = [], set(), 0
    for b in edge + rest:
        if b["offset"] in seen:
            continue
        if total + b["length"] > max_bytes:
            break
        seen.add(b["offset"])
        chosen.append((b["offset"], b["length"]))
        total += b["length"]
    capped = len(chosen) < len({b["offset"] for b in edge + rest})
    return sorted(chosen), {
        "rule": (f"every block of the scan's block map except video (incompressibility "
                 f">= {VIDEO_INCOMPRESSIBILITY} with H.264/H.265 start codes), plus the "
                 f"first and last {ends} blocks"),
        "blocks": len(chosen), "bytes": total, "device_bytes": device_size,
        "video_blocks_skipped": sum(1 for b in blockmap if video(b)),
        "capped_at_bytes": max_bytes if capped else None}


class ModelSearch:
    """Model-numbered strings in bytes handed in order, block by block.  A
    string straddling two blocks is found once: each block is searched with
    the tail of the previous one in front of it."""

    def __init__(self):
        self.found: dict[tuple[str, str], dict] = {}
        self._tail, self._tail_end = b"", -1

    def feed(self, offset: int, data: bytes) -> None:
        if self._tail and self._tail_end == offset:
            buf, base = self._tail + data, offset - len(self._tail)
        else:
            buf, base = data, offset
        for f in FAMILIES:
            for m in f.pattern.finditer(buf):
                at = base + m.start()
                if at + len(m.group()) <= offset:        # whole match was in the tail
                    continue
                self._add(f, m.group().decode("ascii"), at, buf, m.start(), m.end())
        self._tail = data[-64:]
        self._tail_end = offset + len(data)

    def _add(self, f: ModelFamily, model: str, at: int, buf: bytes, s: int, e: int) -> None:
        row = self.found.get((f.id, model))
        if row is None:
            ctx = buf[max(0, s - CONTEXT):e + CONTEXT]
            row = self.found[(f.id, model)] = {
                "model": model, "vendor": f.vendor, "family": f.id,
                "kind": kind_of(f.id, model), "count": 0, "offsets": [],
                "context": "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)}
        row["count"] += 1
        if len(row["offsets"]) < OFFSETS_KEPT:
            row["offsets"].append(at)

    def result(self, searched: dict) -> dict:
        rows = sorted(self.found.values(),
                      key=lambda r: (r["kind"] != "recorder", -r["count"], r["model"]))
        return {"rule": RULE, "status": "candidate", "searched": searched,
                "candidates": rows,
                "notes": ["a model string on the platter shows the text is on this disk, "
                          "not that the disk was seized from that model",
                          "camera models on a recorder's disk name the cameras, not the recorder"]}


# ---------------------------------------------------------------------------
# Examiner observation, and the check
# ---------------------------------------------------------------------------
def observation(model: str, serial: str = "", firmware: str = "", where: str = "",
                photo: Optional[dict] = None, actor: str = "", when_utc: str = "") -> dict:
    return {"model": model.strip(), "serial": serial.strip() or None,
            "firmware": firmware.strip() or None, "read_from": where or None,
            "photo": photo, "recorded_by": actor or None, "recorded_utc": when_utc,
            "identified": identify(model)}


def check(observations: list[dict], platter: Optional[dict],
          detections: Optional[list[dict]]) -> list[dict]:
    """Every comparison the three sources allow, each with a verdict:
    agree, differ, or not determined - and what a disagreement could mean."""
    out = []
    obs = observations[-1] if observations else None
    ident = (obs or {}).get("identified")
    found = {d["vendor"]: d.get("confidence", 0.0) for d in (detections or [])}
    strong = {v for v, c in found.items() if c >= 0.5}

    if not obs:
        out.append({"check": "recorder model", "verdict": "not determined",
                    "detail": "no examiner observation recorded (record-device)"})
    elif not ident:
        out.append({"check": "recorder model", "verdict": "not determined",
                    "detail": f"{obs['model']!r} does not match a model numbering we know"})
    else:
        fam = family(ident["vendor"])
        on_disk = sorted({family(v) for v in strong})
        if not on_disk:
            out.append({"check": "model vs format on the disk", "verdict": "not determined",
                        "detail": "no vendor detected with confidence >= 50%"})
        elif on_disk == [fam]:
            via = (f" ({ident['vendor']} units are commonly {fam}-built)"
                   if fam != ident["vendor"] else "")
            out.append({"check": "model vs format on the disk", "verdict": "agree",
                        "detail": f"{obs['model']} is a {ident['vendor']} {ident['kind']}; "
                                  f"the disk carries {fam}-family structures{via}"})
        else:
            other = [v for v in on_disk if v != fam]
            out.append({"check": "model vs format on the disk", "verdict": "differ",
                        "detail": f"{obs['model']} is a {ident['vendor']} {ident['kind']}, but the "
                                  f"disk also carries {', '.join(other)}-family structures"
                                  + ("" if fam in on_disk else
                                     f" and no {fam}-family ones")
                                  + ". To be explained: the disk was formatted or used by "
                                  "another recorder, or the unit is built by another vendor"})

    cands = [c for c in (platter or {}).get("candidates", []) if c["kind"] == "recorder"]
    if platter is None:
        out.append({"check": "model strings on the platter", "verdict": "not determined",
                    "detail": "not searched (identify-model)"})
    elif not cands:
        out.append({"check": "model strings on the platter", "verdict": "not determined",
                    "detail": f"no recorder model string in the "
                              f"{platter['searched']['bytes']:,} bytes searched"})
    elif obs:
        same = [c for c in cands if c["model"].upper() == obs["model"].upper()]
        out.append({"check": "model strings on the platter vs the unit",
                    "verdict": "agree" if same and len(cands) == 1 else
                               "differ" if not same else "agree, with others present",
                    "detail": "on the platter: " + ", ".join(
                        f"{c['model']} ({c['count']}x)" for c in cands[:5])})
    else:
        out.append({"check": "model strings on the platter", "verdict": "not determined",
                    "detail": "found " + ", ".join(c["model"] for c in cands[:5])
                              + "; no examiner observation to compare with"})
    return out

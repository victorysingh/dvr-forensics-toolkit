"""NIST CCTV Digital Video Export Profile - Level 0, for recovered H.264 footage.

NISTIR 8161 Rev. 1 (2019; https://doi.org/10.6028/NIST.IR.8161r1), written
for the FBI, asks a CCTV export to be:

  1. an MP4 file holding one H.264 video stream (§3.1-3.2);
  2. time-stamped in every frame, inside the stream, by two SEI messages of
     type User Data Unregistered (§3.3): a MISB ST 0604 precision time stamp
     - UTC, in microseconds - and a "timesource" record saying how the
     recorder's clock was set (Table 5);
  3. closed by a UUID box (BE7ACFCB-97A9-42E8-9C71-999491E3AFAC) holding an
     XMP packet with the ClockOffset: the recorder's clock and an external
     reference clock, read at the same moment (§3.4, Tables 6-7).

It is built to NIST's own reference file as well as the text (WEB3.mp4 and
the schemas at biometrics.nist.gov/cs_links/DVR_Standards/).  The SEI bytes
match the reference file's: status 0x9F (clock lock unknown), time stamp
bytes with 0xFF after every second one, each message its own NAL unit after
the AUD, SPS and PPS and before the picture's first slice.  The XMP sits in
the same UUID box at the end of the file.  Two differences, both deliberate:

  * the "timesource" SEI declares its true length, 11 bytes; WEB3.mp4
    declares 13 for the same 11 (ffmpeg reports "SEI type 5 size 13
    truncated" on NIST's file);
  * the XMP is well-formed against NIST's ClockOffset.xsd and
    TimeValueset.xsd.  The published example is not (mismatched tags).

AS EVIDENCE
-----------
This is a derived copy for exchange and playback.  The evidence is the
extracted stream it was made from.  Nothing is re-encoded: the export adds
two SEI NAL units per picture and an MP4 container, and the manifest proves
the rest is untouched - the SHA-256 of the input's NAL units equals that of
the MP4's video NAL units with the added SEI taken out.

TIME
----
NIST's time stamps are UTC.  They are written only when the recorder's zone
is stated (`ClockModel`); the recorder's clock error is applied when it was
measured, and the manifest says when it was not.  Without a zone, no time
stamp is written and the file is marked "not Level 0".  The ClockOffset
needs both clock readings, so it is written only with them.
"""

from __future__ import annotations

import hashlib
import os
import struct
from datetime import datetime, timedelta, timezone
from typing import Optional

from recover.annexb import h264_sps

MISB_UUID = b"MISPmicrosectime"                      # MISB ST 0604, H.264
XMP_UUID = bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC")
TIMESOURCE = b"timesource"
STATUS_UNLOCKED = 0x9F       # bit 7: lock unknown; bits 4-0 reserved (1), as in WEB3.mp4
STATUS_DISCONTINUITY = 0x40  # bit 6: time did not advance linearly
STATUS_REVERSE = 0x20        # bit 5: ... it jumped backwards
TIMESCALE = 90000

# NISTIR 8161 Table 5: how the recorder's clock was set.
CLOCK_SET = {"auto-network": 0x00, "auto-nonnetwork": 0x01, "auto-unknown": 0x02,
             "manual-network": 0x03, "manual-nonnetwork": 0x04, "manual-unknown": 0x05}
# Tables 6 and 7: how each clock was read at export - here, by the examiner,
# by hand (Manual).  The code depends on how that clock itself was set.
SOURCES = ("network", "nonnetwork", "unknown")
EXPORT_MANUAL = {"network": "09", "nonnetwork": "0A", "unknown": "0B"}
REFERENCE_MANUAL = {"network": "0F", "nonnetwork": "10", "unknown": "11"}
SOURCE_NAME = {"network": "Network", "nonnetwork": "NonNetwork", "unknown": "Unknown"}

NS_CLOCK = "http://biometrics.nist.gov/cs_links/DVR_Standards/ClockOffset"
NS_TIME = "http://biometrics.nist.gov/cs_links/DVR_Standards/TimeValueset"


# -- H.264 ------------------------------------------------------------------------
def split_nals(es: bytes) -> list[bytes]:
    """The NAL units of an Annex-B stream, start codes removed."""
    out, i = [], es.find(b"\x00\x00\x01")
    while i >= 0:
        j = es.find(b"\x00\x00\x01", i + 3)
        end = len(es) if j < 0 else j
        nal = es[i + 3:end]
        if j >= 0 and nal.endswith(b"\x00"):
            nal = nal.rstrip(b"\x00")               # the zero of a 4-byte start code
        if nal:
            out.append(nal)
        i = j
    return out


def _vcl(nal: bytes) -> bool:
    return 1 <= nal[0] & 0x1F <= 5


def access_units(nals: list[bytes]) -> list[list[bytes]]:
    """NAL units grouped into pictures (H.264 7.4.1.2.3): a picture ends
    where an AUD, SPS, PPS, SEI or types 14-18 follow its slices, or a slice
    with first_mb_in_slice = 0 begins a new one."""
    aus: list[list[bytes]] = []
    cur: list[bytes] = []
    seen_vcl = False
    for nal in nals:
        t = nal[0] & 0x1F
        starts = False
        if seen_vcl:
            if t in (6, 7, 8, 9) or 14 <= t <= 18:
                starts = True
            elif _vcl(nal) and len(nal) > 1 and nal[1] & 0x80:
                starts = True
        if starts:
            aus.append(cur)
            cur, seen_vcl = [], False
        cur.append(nal)
        seen_vcl = seen_vcl or _vcl(nal)
    if cur:
        aus.append(cur)
    return aus


def _escape(rbsp: bytes) -> bytes:
    """Emulation prevention: 00 00 0x (x <= 3) becomes 00 00 03 0x."""
    out, zeros = bytearray(), 0
    for b in rbsp:
        if zeros >= 2 and b <= 3:
            out.append(3)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)


def sei_user_data(payload: bytes) -> bytes:
    """One SEI NAL unit (nal_ref_idc 0, type 6) holding one User Data
    Unregistered message (payloadType 5) and the RBSP stop bit."""
    size = bytearray()
    n = len(payload)
    while n >= 255:
        size.append(255)
        n -= 255
    size.append(n)
    return b"\x06" + _escape(b"\x05" + bytes(size) + payload + b"\x80")


def misb_payload(utc_us: int, status: int = STATUS_UNLOCKED) -> bytes:
    """MISB ST 0604 precision time stamp: the UUID, a status byte, and the
    8-byte microsecond count, big-endian, with 0xFF after bytes 2, 4 and 6
    so the value can never look like a start code."""
    t = struct.pack(">Q", utc_us)
    return MISB_UUID + bytes([status]) + t[0:2] + b"\xff" + t[2:4] + b"\xff" + t[4:6] \
        + b"\xff" + t[6:8]


def timesource_payload(code: int) -> bytes:
    return TIMESOURCE + bytes([code])


def read_misb(sei_nal: bytes) -> Optional[tuple[int, int]]:
    """(status, UTC microseconds) from a MISB precision-time-stamp SEI NAL."""
    from recover.annexb import rbsp
    r = rbsp(sei_nal[1:])
    if len(r) < 2 + 16 + 12 or r[0] != 5 or r[2:18] != MISB_UUID:
        return None
    d = r[18:30]
    return d[0], struct.unpack(">Q", d[1:3] + d[4:6] + d[7:9] + d[10:12])[0]


# -- MP4 ------------------------------------------------------------------------------
def _box(kind: bytes, *parts: bytes) -> bytes:
    body = b"".join(parts)
    return struct.pack(">I", 8 + len(body)) + kind + body


def _full(kind: bytes, version: int, flags: int, *parts: bytes) -> bytes:
    return _box(kind, struct.pack(">I", (version << 24) | flags), *parts)


def _avc1(sps: bytes, pps: bytes, width: int, height: int) -> bytes:
    avcc = _box(b"avcC", bytes([1, sps[1], sps[2], sps[3], 0xFF, 0xE1]),
                struct.pack(">H", len(sps)), sps, b"\x01", struct.pack(">H", len(pps)), pps)
    entry = (bytes(6) + struct.pack(">H", 1) + bytes(16) + struct.pack(">HH", width, height)
             + struct.pack(">II", 0x00480000, 0x00480000) + bytes(4) + struct.pack(">H", 1)
             + bytes(32) + struct.pack(">Hh", 0x18, -1))
    return _box(b"avc1", entry, avcc)


def _moov(samples: list[int], offsets: list[int], durations: list[int], sync: list[int],
          sps: bytes, pps: bytes, width: int, height: int, created: int) -> bytes:
    total = sum(durations)
    t = created + 2082844800                          # seconds since 1904, as MP4 counts
    ident = struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)
    mvhd = _full(b"mvhd", 0, 0, struct.pack(">IIII", t, t, TIMESCALE, total),
                 struct.pack(">IH", 0x10000, 0x100), bytes(10), ident, bytes(24),
                 struct.pack(">I", 2))
    tkhd = _full(b"tkhd", 0, 3, struct.pack(">IIIII", t, t, 1, 0, total), bytes(8),
                 struct.pack(">hhH", 0, 0, 0), bytes(2), ident,
                 struct.pack(">II", width << 16, height << 16))
    mdhd = _full(b"mdhd", 0, 0, struct.pack(">IIII", t, t, TIMESCALE, total),
                 struct.pack(">HH", 0x55C4, 0))       # language "und"
    hdlr = _full(b"hdlr", 0, 0, bytes(4), b"vide", bytes(12), b"VideoHandler\x00")
    runs: list[tuple[int, int]] = []
    for d in durations:
        if runs and runs[-1][1] == d:
            runs[-1] = (runs[-1][0] + 1, d)
        else:
            runs.append((1, d))
    stts = _full(b"stts", 0, 0, struct.pack(">I", len(runs)),
                 b"".join(struct.pack(">II", n, d) for n, d in runs))
    stss = _full(b"stss", 0, 0, struct.pack(">I", len(sync)),
                 b"".join(struct.pack(">I", s) for s in sync))
    stsc = _full(b"stsc", 0, 0, struct.pack(">IIII", 1, 1, 1, 1))
    stsz = _full(b"stsz", 0, 0, struct.pack(">II", 0, len(samples)),
                 b"".join(struct.pack(">I", s) for s in samples))
    if offsets and offsets[-1] > 0xFFFFFFFF:
        stco = _full(b"co64", 0, 0, struct.pack(">I", len(offsets)),
                     b"".join(struct.pack(">Q", o) for o in offsets))
    else:
        stco = _full(b"stco", 0, 0, struct.pack(">I", len(offsets)),
                     b"".join(struct.pack(">I", o) for o in offsets))
    stsd = _full(b"stsd", 0, 0, struct.pack(">I", 1), _avc1(sps, pps, width, height))
    stbl = _box(b"stbl", stsd, stts, stss, stsc, stsz, stco)
    dinf = _box(b"dinf", _full(b"dref", 0, 0, struct.pack(">I", 1), _full(b"url ", 0, 1)))
    minf = _box(b"minf", _full(b"vmhd", 0, 1, bytes(8)), dinf, stbl)
    return _box(b"moov", mvhd, _box(b"trak", tkhd, _box(b"mdia", mdhd, hdlr, minf)))


# -- ClockOffset XMP ---------------------------------------------------------------------
def _offset_time(local: datetime, tz_offset_min: int) -> str:
    sign = "+" if tz_offset_min >= 0 else "-"
    h, m = divmod(abs(tz_offset_min), 60)
    return f"{local.strftime('%Y-%m-%dT%H:%M:%S')}{sign}{h:02d}:{m:02d}"


def clock_offset_xmp(recorder_time: datetime, reference_time: datetime, tz_offset_min: int,
                     recorder_clock_source: str, reference_source: str) -> bytes:
    """The ClockOffset XMP packet (NISTIR 8161 §3.4, Appendix C-E), both
    readings taken by hand by the examiner - hence Manual, codes 09-0B and
    0F-11 - and given in UTC-offset format."""
    rec = (f"<timeval:ExportSystemTimeModeSourceCode>{EXPORT_MANUAL[recorder_clock_source]}"
           f"</timeval:ExportSystemTimeModeSourceCode>"
           f"<timeval:SetRecordMode>Manual</timeval:SetRecordMode>"
           f"<timeval:TimeSource>{SOURCE_NAME[recorder_clock_source]}</timeval:TimeSource>"
           f"<timeval:TimeValue>{_offset_time(recorder_time, tz_offset_min)}</timeval:TimeValue>")
    ref = (f"<timeval:ExternalReferenceTimeModeSourceCode>{REFERENCE_MANUAL[reference_source]}"
           f"</timeval:ExternalReferenceTimeModeSourceCode>"
           f"<timeval:SetRecordMode>Manual</timeval:SetRecordMode>"
           f"<timeval:TimeSource>{SOURCE_NAME[reference_source]}</timeval:TimeSource>"
           f"<timeval:TimeValue>{_offset_time(reference_time, tz_offset_min)}</timeval:TimeValue>")
    xml = (
        "<?xpacket begin='﻿' id='W5M0MpCehiHzreSzNTczkc9d'?>\n"
        "<x:xmpmeta xmlns:x='adobe:ns:meta/'>\n"
        "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n"
        "<rdf:Description rdf:about='' xmlns:dc='http://purl.org/dc/elements/1.1/'>"
        "<dc:title>ClockOffset</dc:title></rdf:Description>\n"
        f"<rdf:Description rdf:about='' xmlns:cloSet='{NS_CLOCK}' xmlns:timeval='{NS_TIME}'>\n"
        f"<cloSet:ExportSystemTime rdf:parseType='Resource'>{rec}</cloSet:ExportSystemTime>\n"
        f"<cloSet:ExternalReferenceTime rdf:parseType='Resource'>{ref}"
        "</cloSet:ExternalReferenceTime>\n"
        "</rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end='w'?>")
    return xml.encode("utf-8")


# -- the export -------------------------------------------------------------------------
def _parse_local(s: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            pass
    raise ValueError(f"not a time: {s!r} (want YYYY-MM-DD HH:MM:SS[.ffffff])")


def export(es: bytes, out_path: str, frame_times_local: list[datetime],
           tz_offset_min: Optional[int] = None, drift_s: Optional[float] = None,
           clock_set: str = "manual-unknown",
           clock_reading: Optional[tuple[datetime, datetime]] = None,
           recorder_clock_source: str = "unknown", reference_source: str = "network",
           gap_s: float = 2.0) -> dict:
    """Write `es` (H.264 Annex B) as a Level 0 export.  `frame_times_local`
    gives each picture's time on the recorder's clock; `drift_s` is the
    recorder clock minus true time, if measured; `clock_reading` is (what the
    recorder showed, what the reference showed) at one moment."""
    nals = split_nals(es)
    sps = next((n for n in nals if n[0] & 0x1F == 7), None)
    pps = next((n for n in nals if n[0] & 0x1F == 8), None)
    if any(n[0] & 0x7E in (0x40, 0x42) and len(n) > 1 and n[1] == 1 for n in nals[:8]) \
            and not sps:
        raise ValueError("H.265: NISTIR 8161 Level 0 is H.264, and re-encoding would "
                         "alter the evidence - not converted")
    info = h264_sps(sps) if sps else None
    if not (sps and pps and info):
        raise ValueError("no H.264 SPS/PPS in the stream - not an H.264 elementary stream")
    aus = [au for au in access_units(nals) if any(_vcl(n) for n in au)]
    if len(frame_times_local) < len(aus):
        raise ValueError(f"{len(aus)} pictures but {len(frame_times_local)} frame times")
    level0 = tz_offset_min is not None
    code = CLOCK_SET[clock_set]
    shift = timedelta(minutes=tz_offset_min or 0) + timedelta(seconds=drift_s or 0.0)

    def utc_us(local: datetime) -> int:
        t = (local - shift).replace(tzinfo=timezone.utc)
        return int(round(t.timestamp() * 1_000_000))

    samples, sync = [], []
    original = hashlib.sha256()
    prev = None
    for k, au in enumerate(aus):
        nals_out = []
        added = False
        us = utc_us(frame_times_local[k]) if level0 else None
        status = STATUS_UNLOCKED
        if level0 and prev is not None:
            if us < prev:
                status |= STATUS_DISCONTINUITY | STATUS_REVERSE
            elif us - prev > gap_s * 1_000_000:
                status |= STATUS_DISCONTINUITY
        for nal in au:
            original.update(nal)
            if level0 and not added and _vcl(nal):
                nals_out += [sei_user_data(misb_payload(us, status)),
                             sei_user_data(timesource_payload(code))]
                added = True
            nals_out.append(nal)
        samples.append(b"".join(struct.pack(">I", len(n)) + n for n in nals_out))
        if any(n[0] & 0x1F == 5 for n in au):
            sync.append(k + 1)
        if us is not None:
            prev = us
    ticks = [int(round(t.timestamp() * TIMESCALE)) for t in
             (ft.replace(tzinfo=timezone.utc) for ft in frame_times_local[:len(aus)])]
    durations = [max(1, b - a) for a, b in zip(ticks, ticks[1:])]
    durations.append(durations[-1] if durations else TIMESCALE // 25)

    ftyp = _box(b"ftyp", b"isom", struct.pack(">I", 0x200), b"isomiso2avc1mp41")
    mdat_head = struct.pack(">I", 8 + sum(len(s) for s in samples)) + b"mdat"
    offsets, pos = [], len(ftyp) + len(mdat_head)
    for s in samples:
        offsets.append(pos)
        pos += len(s)
    created = utc_us(frame_times_local[0]) // 1_000_000 if level0 else 0
    moov = _moov([len(s) for s in samples], offsets, durations, sync, sps, pps,
                 info["width"], info["height"], max(0, created))
    xmp = None
    if level0 and clock_reading:
        xmp = clock_offset_xmp(clock_reading[0], clock_reading[1], tz_offset_min,
                               recorder_clock_source, reference_source)
    with open(out_path, "wb") as fh:
        fh.write(ftyp + mdat_head)
        for s in samples:
            fh.write(s)
        fh.write(moov)
        if xmp:
            fh.write(_box(b"uuid", XMP_UUID, xmp))
    back = read_back(out_path)                   # checked from the file, not from memory
    missing = []
    if not level0:
        missing.append("precision time stamps: the recorder's zone was not stated, so no "
                       "UTC can be asserted")
    if not xmp:
        missing.append("ClockOffset: needs the recorder's zone and one reading of its "
                       "clock against a reference")
    stamps = back["stamps"]
    return {"file": os.path.basename(out_path), "sha256": back["sha256"],
            "bytes": os.path.getsize(out_path),
            "profile": "NISTIR 8161 Rev.1 Level 0", "level0": not missing,
            "not_level0_because": missing, "pictures": back["samples"], "keyframes": len(sync),
            "width": info["width"], "height": info["height"],
            "first_utc": _iso(stamps[0][1]) if stamps else None,
            "last_utc": _iso(stamps[-1][1]) if stamps else None,
            "time_stamps": len(stamps), "timesource_seis": back["timesource_seis"],
            "discontinuities": sum(1 for st, _ in stamps if st & STATUS_DISCONTINUITY),
            "timesource_code": f"{code:02X} ({clock_set})",
            "clock_error_applied_s": drift_s, "clock_error_measured": drift_s is not None,
            "clock_offset_box": back["xmp"] is not None,
            "input_nal_sha256": original.hexdigest(),
            "video_nal_sha256": back["video_nal_sha256"],
            "pictures_unchanged": original.hexdigest() == back["video_nal_sha256"]}


def _iso(us: int) -> str:
    return datetime.fromtimestamp(us / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _walk(buf: bytes, start: int, end: int):
    """(box type, payload start, box end) for each box in buf[start:end]."""
    pos = start
    while pos + 8 <= end:
        size, kind = struct.unpack(">I4s", buf[pos:pos + 8])
        hdr = 8
        if size == 1:
            size, hdr = struct.unpack(">Q", buf[pos + 8:pos + 16])[0], 16
        elif size == 0:
            size = end - pos
        if size < hdr:
            return
        yield kind, pos + hdr, pos + size
        pos += size


def _find(buf: bytes, path: list[bytes], a: int, b: int) -> Optional[tuple[int, int]]:
    for kind, x, y in _walk(buf, a, b):
        if kind == path[0]:
            return (x, y) if len(path) == 1 else _find(buf, path[1:], x, y)
    return None


def read_back(path: str) -> dict:
    """Read an exported MP4 from disk, as a checker would: its samples through
    the sample tables, each sample's NAL units, the precision time stamps and
    "timesource" records, the ClockOffset box - and the hash of the video NAL
    units with those two SEI messages taken out, which must equal the input's."""
    buf = open(path, "rb").read()
    xmp = None
    for kind, a, b in _walk(buf, 0, len(buf)):
        if kind == b"uuid" and buf[a:a + 16] == XMP_UUID:
            xmp = buf[a + 16:b]
    stbl = _find(buf, [b"moov", b"trak", b"mdia", b"minf", b"stbl"], 0, len(buf))
    boxes = {kind: (x, y) for kind, x, y in _walk(buf, *stbl)}
    x, _ = boxes[b"stsz"]
    count = struct.unpack(">I", buf[x + 8:x + 12])[0]
    sizes = struct.unpack(f">{count}I", buf[x + 12:x + 12 + 4 * count])
    if b"co64" in boxes:
        x, _ = boxes[b"co64"]
        offsets = struct.unpack(f">{count}Q", buf[x + 8:x + 8 + 8 * count])
    else:
        x, _ = boxes[b"stco"]
        offsets = struct.unpack(f">{count}I", buf[x + 8:x + 8 + 4 * count])
    video, stamps, timesource = hashlib.sha256(), [], 0
    for off, size in zip(offsets, sizes):
        p = off
        while p < off + size:
            n = struct.unpack(">I", buf[p:p + 4])[0]
            nal = buf[p + 4:p + 4 + n]
            p += 4 + n
            if nal[0] & 0x1F == 6:
                m = read_misb(nal)
                if m is not None:
                    stamps.append(m)
                    continue
                if nal[3:3 + len(TIMESOURCE)] == TIMESOURCE:
                    timesource += 1
                    continue
            video.update(nal)
    return {"sha256": hashlib.sha256(buf).hexdigest(), "samples": count, "stamps": stamps,
            "timesource_seis": timesource, "xmp": xmp, "video_nal_sha256": video.hexdigest()}

"""Dahua DHFS 4.1 filesystem parser (Dahua and Dahua-derived boards, e.g. CP Plus).

A DHFS disk carries no conventional filesystem.  A superblock at offset 0
(`DHFS4.1` + a volume UUID string) is followed by a partition table that
splits the platter into several large volumes (~250 GB each on the 1 TB disk
we hold).  Each volume has a header, a flat table of 32-byte cluster records,
and a data area of fixed 2 MiB clusters.  A recording is a doubly-linked chain
of clusters: one head record per hourly file per camera, then continuation
records in sequence.  Video inside a cluster is wrapped in DHAV frames.

WHERE EACH PIECE OF THIS COMES FROM
-----------------------------------
  * The DHAV frame container - 24-byte header, extension tags, `dhav` trailer
    carrying the frame length, the packed date bitfield, the codec byte - is
    published: ffmpeg's libavformat/dhav.c demuxer.  SOURCE_PUBLISHED.

  * Everything at the filesystem level - partition table layout, volume
    header fields, the 32-byte cluster record, the data-area base, the rule
    that an overflowing frame continues in the *physically* next cluster - was
    read off real media: the Seagate ST1000VX013 (s/n WWD4A3NX), first 20 GiB
    imaged 2026-09-23, SHA-256 c4098d59...e610.  SOURCE_OBSERVED.  Each field
    below says what observation supports it.  The DHAV header checksum rule
    (sum of bytes 0..22) is also ours: ffmpeg skips that byte, and it held for
    every frame we tested.

That is real media, but it is not validation.  Nothing here has been
byte-matched against the recorder's own export, so the parser reports
`spec_only` (see parsers/base.py), and fields we could not explain are listed
as undecoded rather than guessed at.

Vendor attribution: DHFS is used by Dahua and by boards OEM'd from Dahua (CP
Plus is frequently a rebadge).  Nothing on the platter distinguishes the two,
so a parse says "Dahua-family", never "this is a Dahua recorder".

THREE THINGS ABOUT THIS FORMAT THAT A NAIVE CARVE GETS WRONG
------------------------------------------------------------
  1. The DHAV channel byte is 0 for every camera.  Camera identity lives only
     in the DHFS cluster index.  Carving DHAV frames by magic alone interleaves
     every camera into one stream.
  2. A frame that overflows its cluster is finished in the physically next
     cluster - which normally belongs to a *different* camera - overwriting
     that cluster's first bytes.  So the start of a cluster can hold the tail
     of another camera's stream.  Frames are assigned to a recording by stream
     continuity (frame counter, millisecond clock, date), never by position.
     Less often (57 of the 371 missing frames in one real recording) the
     frame is cut at the cluster end and finished at the start of the
     recording's NEXT CHAIN cluster, so its halves are not adjacent on disk.
     Most of those second halves were later overwritten by other overflow;
     7 of the 57 rejoin intact.
  3. Clusters are reused without being cleared.  Past the point where the
     current recording stopped writing, a cluster still holds older footage.
     Those frames are dated outside the cluster's index window and are
     recoverable remnants of overwritten recordings, reported as fragments.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

from core.contract import (
    STATE_ACTIVE,
    STATE_FRAGMENT,
    Provenance,
    Recording,
    TimestampClaim,
)
from core.hashing import sha256_bytes
from parsers.base import (
    SOURCE_OBSERVED,
    SOURCE_PUBLISHED,
    FieldSpec,
    ParseResult,
    VendorParser,
    register,
    weakest_source,
)

VENDOR = "Dahua"

SB_MAGIC = b"DHFS"
DHAV_MAGIC = b"DHAV"
DHAV_TRAILER = b"dhav"

_CITE_REAL = ("observed: ST1000VX013 s/n WWD4A3NX, first 20 GiB image "
              "sha256 c4098d59cff3973de9d281ba5613005ba52165743c36edfcf56f61aad8f4e610")
_CITE_FFMPEG = "ffmpeg libavformat/dhav.c (DHAV demuxer)"

# --- superblock (offset 0) -------------------------------------------------
SB_FIELDS = [
    FieldSpec("magic", 0x00, "magic", "'DHFS' + version string, e.g. DHFS4.1",
              SOURCE_OBSERVED, _CITE_REAL + "; also dvrdecode"),
    FieldSpec("version", 0x04, "bytes:8", "filesystem version string",
              SOURCE_OBSERVED, _CITE_REAL),
    FieldSpec("uuid", 0x20, "bytes:64", "'uuid:{...}' volume identifier",
              SOURCE_OBSERVED, _CITE_REAL),
]

# --- partition table ---------------------------------------------------------
# Primary at 0x3C00, byte-identical backup at 0x7C00 on the real disk.  Entries
# are 0x40 bytes from 0x3C40.  On the real disk: 4 entries splitting 1 TB into
# ~250 GB volumes, starts at 0, 0x1D1C2000, 0x3A383800, 0x57545800 sectors.
PTABLE_OFFSET = 0x3C00
PTABLE_BACKUP_OFFSET = 0x7C00
PTABLE_FIRST_ENTRY = 0x40
PTABLE_ENTRY_SIZE = 0x40
PTABLE_MAX_ENTRIES = 16
PART_FIELDS = [
    FieldSpec("start_sector", 0x24, "<I", "volume start, in 512 B sectors",
              SOURCE_OBSERVED, _CITE_REAL + "; starts tile the disk with no gaps"),
    FieldSpec("sector_count", 0x2C, "<I", "volume length, in 512 B sectors",
              SOURCE_OBSERVED, _CITE_REAL + "; start+count < next start"),
]

# --- volume header (volume start + 0x4400, backup at +0x8400) ------------------
VHDR_OFFSET = 0x4400
VHDR_BACKUP_OFFSET = 0x8400
VHDR_FIELDS = [
    FieldSpec("earliest_recording", 0x10, "<I", "DHAV-packed date",
              SOURCE_OBSERVED, _CITE_REAL + "; equals the earliest head-record start"),
    FieldSpec("latest_recording", 0x14, "<I", "DHAV-packed date",
              SOURCE_OBSERVED, _CITE_REAL + "; within 2 s of the latest head-record end"),
    FieldSpec("sector_size", 0x2C, "<I", "bytes per sector",
              SOURCE_OBSERVED, _CITE_REAL + "; 0x200"),
    FieldSpec("sectors_per_cluster", 0x30, "<I", "cluster size in sectors",
              SOURCE_OBSERVED, _CITE_REAL + "; 0x1000 = 2 MiB, matches frame layout"),
    FieldSpec("first_data_cluster", 0x38, "<I", "first cluster number in use",
              SOURCE_OBSERVED, _CITE_REAL + "; equals the count of leading 0xFE records"),
    FieldSpec("index_start_sector", 0x44, "<I", "cluster table start, volume-relative",
              SOURCE_OBSERVED, _CITE_REAL + "; 0xBB -> table found at 0x17600"),
    FieldSpec("cluster_capacity", 0x4C, "<I", "cluster slots in this volume",
              SOURCE_OBSERVED, _CITE_REAL + "; volume size / 2 MiB, rounded down"),
]
# Present on the real disk, meaning not established.  Listed so a reader can
# see they were seen and deliberately left alone.
VHDR_UNDECODED = [0x08, 0x0C, 0x18, 0x3C, 0x40, 0x48, 0x54, 0x58, 0x5C]

# --- cluster record (32 bytes) -------------------------------------------------
REC_SIZE = 32
REC_FMT = "<BBHIIIIIIHH"
REC_HEAD, REC_CONT, REC_RESERVED, REC_EMPTY = 0x01, 0x02, 0xFE, 0x00
REC_FIELDS = [
    FieldSpec("kind", 0x00, "<B", "01 head of file, 02 continuation, FE reserved, 00 empty",
              SOURCE_OBSERVED, _CITE_REAL + "; 513 heads + 114550 continuations, all chains close"),
    FieldSpec("channel", 0x01, "<B", "camera as ASCII digit, '0' = first camera",
              SOURCE_OBSERVED, _CITE_REAL + "; '0'/'1'/'2', 171 files each"),
    FieldSpec("count_or_seq", 0x02, "<H", "head: continuation count; continuation: sequence no.",
              SOURCE_OBSERVED, _CITE_REAL + "; head value == chain length - 1 for all 513"),
    FieldSpec("start", 0x04, "<I", "DHAV-packed date of first frame", SOURCE_OBSERVED,
              _CITE_REAL + "; frame dates in each cluster fall inside [start, end]"),
    FieldSpec("end", 0x08, "<I", "DHAV-packed date of last frame", SOURCE_OBSERVED,
              _CITE_REAL + "; head end = file end, on the hour"),
    FieldSpec("next", 0x0C, "<I", "next cluster in chain, 0 terminates",
              SOURCE_OBSERVED, _CITE_REAL + "; 0 broken links across 115063 clusters"),
    FieldSpec("prev", 0x14, "<I", "previous cluster (continuations)",
              SOURCE_OBSERVED, _CITE_REAL),
    FieldSpec("head", 0x18, "<I", "head cluster of this file",
              SOURCE_OBSERVED, _CITE_REAL),
]
REC_UNDECODED = [0x10, 0x1C, 0x1E]

# --- DHAV frame (published) ------------------------------------------------------
DHAV_HDR = 24
DHAV_TAIL = 8
DHAV_HDR_FMT = "<4sBBBBIIIHBB"
DHAV_FIELDS = [
    FieldSpec("magic", 0x00, "magic", "'DHAV'", SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("type", 0x04, "<B", "FD I-frame, FC P-frame, F0 audio, F1 aux",
              SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("frame_number", 0x08, "<I", "per-stream counter", SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("frame_length", 0x0C, "<I", "whole frame incl. header+trailer",
              SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("date", 0x10, "<I", "packed Y/M/D h:m:s bitfield", SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("ms_clock", 0x14, "<H", "millisecond clock, wraps at 65536",
              SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("ext_length", 0x16, "<B", "extension bytes after header",
              SOURCE_PUBLISHED, _CITE_FFMPEG),
    FieldSpec("checksum", 0x17, "<B", "sum of header bytes 0..22, mod 256",
              SOURCE_OBSERVED, _CITE_REAL + "; ffmpeg ignores this byte"),
]

TYPE_I, TYPE_P, TYPE_B, TYPE_AUDIO, TYPE_AUX = 0xFD, 0xFC, 0xFB, 0xF0, 0xF1
VIDEO_TYPES = {TYPE_I, TYPE_P, TYPE_B}
KNOWN_TYPES = VIDEO_TYPES | {TYPE_AUDIO, TYPE_AUX}
# ffmpeg dhav.c codec byte (extension tag 0x81).
VIDEO_CODECS = {0x01: "mpeg4", 0x02: "h264", 0x08: "h264", 0x0C: "h265"}

MAX_FRAME = 4 << 20          # an I-frame is ~180 KB; 4 MiB means garbage
# A frame only counts as a remnant of an OLDER recording when it is at least
# this far outside its cluster's index window.  Frames just outside it are
# stray overflow from the same recording period, not deleted footage, and are
# counted separately rather than reported as recovered evidence.
REMNANT_MIN_AGE_S = 3600
SPILL_READ = 1 << 20         # how far into the next cluster an overflow may run
PRED_TAIL_READ = 512 << 10   # tail of the physically previous cluster we inspect

# Stream-continuity tolerances between consecutive frames of ONE stream.
# Parallel camera streams on the real disk sit ~20-60 frames and ~1 s apart
# at any instant, while a cross-camera overflow arrives ~8-10 s later than the
# cluster it lands in - so these bounds separate them with room to spare.
FN_BACK, FN_FWD = 4, 128
MS_FWD, MS_BACK = 4000, 500
DATE_BACK_S, DATE_FWD_S = 1, 4
WINDOW_SLACK_S = 3


# ---------------------------------------------------------------------------
# DHAV frames
# ---------------------------------------------------------------------------
def decode_date(value: int) -> Optional[datetime]:
    """DHAV/DHFS packed date -> naive datetime on the RECORDER's wall clock.

    Layout per ffmpeg dhav.c: sec[0:6] min[6:12] hour[12:17] day[17:22]
    month[22:26] year-2000[26:32].  Returns None for an impossible date rather
    than raising, because this runs over overwritten and half-written data.
    """
    try:
        return datetime((value >> 26 & 0x3F) + 2000, value >> 22 & 0x0F,
                        value >> 17 & 0x1F, value >> 12 & 0x1F,
                        value >> 6 & 0x3F, value & 0x3F)
    except ValueError:
        return None


def fmt_date(value: int) -> str:
    dt = decode_date(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else f"0x{value:08X}(invalid)"


def _seconds(value: int) -> Optional[int]:
    dt = decode_date(value)
    return int((dt - datetime(2000, 1, 1)).total_seconds()) if dt else None


@dataclass
class DhavFrame:
    offset: int                 # absolute byte offset of the header
    ftype: int
    frame_number: int
    length: int
    date: int
    ms: int
    ext_length: int

    @property
    def is_video(self) -> bool:
        return self.ftype in VIDEO_TYPES

    @property
    def seconds(self) -> Optional[int]:
        return _seconds(self.date)


def header_ok(hdr: bytes) -> bool:
    return (len(hdr) >= DHAV_HDR and hdr[:4] == DHAV_MAGIC
            and sum(hdr[:23]) & 0xFF == hdr[23])


def walk_frames(buf: bytes, base: int, start: int = 0,
                stop: Optional[int] = None) -> Iterator[DhavFrame]:
    """Yield every complete, validated DHAV frame whose header lies in
    buf[start:stop].  A frame is accepted only if its header checksum holds
    and its trailer repeats the length - on overwritten media a bare 'DHAV'
    match is not evidence of anything.  Never raises."""
    n = len(buf)
    stop = n if stop is None else min(stop, n)
    i = start
    while i < stop:
        p = buf.find(DHAV_MAGIC, i, stop + 3)
        if p < 0 or p + DHAV_HDR > n:
            return
        hdr = buf[p:p + DHAV_HDR]
        if not header_ok(hdr):
            i = p + 1
            continue
        _, ftype, _sub, _ch, _subn, fn, flen, date, ms, ext, _ck = \
            struct.unpack_from(DHAV_HDR_FMT, hdr)
        end = p + flen
        if (ftype not in KNOWN_TYPES or flen < DHAV_HDR + DHAV_TAIL
                or flen > MAX_FRAME or DHAV_HDR + ext > flen - DHAV_TAIL):
            i = p + 1
            continue
        if end > n:
            return                                   # incomplete at buffer end
        if (buf[end - 8:end - 4] != DHAV_TRAILER
                or struct.unpack_from("<I", buf, end - 4)[0] != flen):
            i = p + 1
            continue
        yield DhavFrame(base + p, ftype, fn, flen, date, ms, ext)
        i = end


def frame_ext(buf: bytes, rel: int, fr: DhavFrame) -> dict:
    """Decode the extension tags ffmpeg documents: 0x80 resolution,
    0x81 codec + fps, 0x83 audio.  Unknown tags stop the walk."""
    out: dict = {}
    ext = buf[rel + DHAV_HDR: rel + DHAV_HDR + fr.ext_length]
    lengths = {0x80: 4, 0x81: 4, 0x82: 8, 0x83: 4, 0x88: 8, 0x8C: 8}
    i = 0
    while i < len(ext):
        tag = ext[i]
        ln = lengths.get(tag)
        if ln is None or i + ln > len(ext):
            break
        if tag == 0x80:
            out["width"], out["height"] = ext[i + 2] * 8, ext[i + 3] * 8
        elif tag == 0x81:
            out["codec"] = VIDEO_CODECS.get(ext[i + 2], f"unknown:0x{ext[i + 2]:02X}")
            out["fps"] = ext[i + 3]
        elif tag == 0x83:
            out["audio_channels"], out["audio_codec"] = ext[i + 1], ext[i + 2]
        i += ln
    return out


def _kind(fr: DhavFrame) -> str:
    if fr.is_video:
        return "video"
    return "audio" if fr.ftype == TYPE_AUDIO else "aux"


class Stream:
    """Continuity state of one DHAV stream: its last frame, plus its last
    frame of each kind.

    Video, audio and aux frames each run their OWN frame counter.  They start
    in near-lockstep, which hides the fact - on the real disk they drift
    apart (78 apart after ~6 hours), so a frame counter can only be compared
    with the previous frame of the same kind.  The millisecond clock and the
    date are shared by all kinds and are compared with the last frame of any.
    """

    __slots__ = ("last", "by_kind")

    def __init__(self, fr: Optional[DhavFrame] = None):
        self.last: Optional[DhavFrame] = None
        self.by_kind: dict[str, DhavFrame] = {}
        if fr is not None:
            self.feed(fr)

    def feed(self, fr: DhavFrame) -> "Stream":
        self.last = fr
        self.by_kind[_kind(fr)] = fr
        return self

    def copy(self) -> "Stream":
        s = Stream()
        s.last, s.by_kind = self.last, dict(self.by_kind)
        return s

    def distance(self, cur: DhavFrame) -> Optional[float]:
        """How closely `cur` follows this stream, or None if it cannot.
        Lower is closer.  Used to pick between two streams that could both
        claim a frame rather than taking the first that fits: on the real
        disk another camera's overflow can sit only ~2 s and ~60 frames away
        from the stream it lands in."""
        prev = self.last
        if prev is None:
            return None
        dms = (cur.ms - prev.ms) & 0xFFFF
        if dms > MS_FWD:
            if (0x10000 - dms) > MS_BACK:
                return None
            dms = dms - 0x10000
        ps, cs = prev.seconds, cur.seconds
        if ps is None or cs is None or not -DATE_BACK_S <= cs - ps <= DATE_FWD_S:
            return None
        score = abs(dms) / 40.0
        ref = self.by_kind.get(_kind(cur))
        if ref is not None:
            dfn = cur.frame_number - ref.frame_number
            if not -FN_BACK <= dfn <= FN_FWD:
                return None
            score += abs(dfn - 1)
        return score


def continues(prev, cur: DhavFrame) -> bool:
    """Could `cur` be the next frame of the stream `prev` (a Stream, or a
    single frame standing for one)?"""
    s = prev if isinstance(prev, Stream) else Stream(prev)
    return s.distance(cur) is not None


# ---------------------------------------------------------------------------
# Filesystem structures
# ---------------------------------------------------------------------------
@dataclass
class ClusterRecord:
    index: int
    kind: int
    channel: int
    count_or_seq: int
    start: int
    end: int
    next: int
    prev: int
    head: int
    raw: bytes = b""


@dataclass
class DhfsFile:
    """One recording: a head record plus its continuation chain."""
    volume: int
    head: ClusterRecord
    clusters: list[int] = field(default_factory=list)   # continuation clusters, in order
    chain_ok: bool = True
    chain_notes: list[str] = field(default_factory=list)

    @property
    def camera(self) -> int:
        return self.head.channel


@dataclass
class DhfsVolume:
    number: int
    start: int                  # absolute byte offset
    length: int
    header: dict = field(default_factory=dict)
    header_backup_matches: Optional[bool] = None
    cluster_size: int = 0
    data_base: Optional[int] = None
    calibration: dict = field(default_factory=dict)
    records: list[ClusterRecord] = field(default_factory=list)
    files: list[DhfsFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def cluster_offset(self, cluster: int) -> int:
        return (self.data_base or 0) + cluster * self.cluster_size


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", "replace").strip()


def _read(dev, off: int, n: int) -> bytes:
    size = getattr(dev, "size_bytes", 0)
    if off < 0 or (size and off >= size):
        return b""
    try:
        return dev.read_at(off, n if not size else min(n, size - off))
    except Exception:                                    # noqa: BLE001
        return b""


def decode_record(i: int, raw: bytes) -> ClusterRecord:
    kind, ch, a, start, end, nxt, _f10, prev, head, _f1c, _f1e = \
        struct.unpack_from(REC_FMT, raw)
    channel = ch - 0x30 if 0x30 <= ch <= 0x39 else -1
    return ClusterRecord(i, kind, channel, a, start, end, nxt, prev, head, raw)


# ---------------------------------------------------------------------------
# Reassembly of one recording
# ---------------------------------------------------------------------------
@dataclass
class ClusterYield:
    cluster: int
    offset: int
    own: list[DhavFrame] = field(default_factory=list)
    spill_in: int = 0            # frames that belong to the previous physical cluster
    remnants: list[DhavFrame] = field(default_factory=list)   # older footage
    unassigned: int = 0          # validated, in-window, but not continuous
    resynced: bool = False       # own stream picked up again after a gap
    overflow_out: int = 0        # own frames recovered from the next physical cluster
    # Own frames cut at the cluster end and finished in the next chain
    # cluster: frame offset -> the rejoined bytes, and where each half lies.
    joined: dict[int, bytes] = field(default_factory=dict)
    joined_parts: list[dict] = field(default_factory=list)
    in_image: bool = True
    state: Optional["Stream"] = None   # own stream state after this cluster


def classify_cluster(dev, vol: DhfsVolume, rec: ClusterRecord,
                     own_state: Optional[Stream]) -> tuple[ClusterYield, bytes]:
    """Split one cluster's frames into this recording's own frames, overflow
    from the physically previous cluster, and older remnants.

    Returns the classification plus the raw buffer (cluster + overflow read),
    so the caller can copy frame bytes out without reading twice.
    """
    cs = vol.cluster_size
    off = vol.cluster_offset(rec.index)
    y = ClusterYield(rec.index, off)
    buf = _read(dev, off, cs + SPILL_READ)
    if len(buf) < cs:
        y.in_image = False
        return y, b""

    # Stream state of whatever was written into the physically previous
    # cluster: its overflow is what sits at the start of this one.
    pred_state: Optional[Stream] = None
    tail = _read(dev, off - PRED_TAIL_READ, PRED_TAIL_READ + SPILL_READ)
    for fr in walk_frames(tail, off - PRED_TAIL_READ, 0, PRED_TAIL_READ):
        pred_state = (pred_state or Stream()).feed(fr)

    lo = _seconds(rec.start)
    hi = _seconds(rec.end)
    lo = None if lo is None else lo - WINDOW_SLACK_S
    hi = None if hi is None else hi + WINDOW_SLACK_S

    def in_window(fr: DhavFrame) -> bool:
        s = fr.seconds
        return s is not None and lo is not None and hi is not None and lo <= s <= hi

    state = own_state.copy() if own_state is not None else None
    started = False
    ended = False
    for fr in walk_frames(buf, off, 0, cs):
        if ended:
            if in_window(fr):
                y.unassigned += 1
            else:
                y.remnants.append(fr)
            continue
        d_own = state.distance(fr) if state is not None else None
        if started:
            if d_own is not None:
                y.own.append(fr)
                state.feed(fr)
                continue
            # The recording's own run has ended inside this cluster; what
            # follows is older data the recorder never overwrote.
            ended = True
            if in_window(fr):
                y.unassigned += 1
            else:
                y.remnants.append(fr)
            continue
        # Leading frames: overflow from the physically previous cluster, or
        # the start of this recording's own data.  The closer match wins;
        # a tie goes to our own stream, which is also what happens when the
        # previous physical cluster IS our chain's previous cluster.
        d_pred = pred_state.distance(fr) if pred_state is not None else None
        if d_pred is not None and (d_own is None or d_pred < d_own):
            y.spill_in += 1
            pred_state.feed(fr)
            continue
        if d_own is not None:
            y.own.append(fr)
            state.feed(fr)
            started = True
            continue
        if in_window(fr):
            # Nothing continues the stream we carried in (the frames between
            # were lost to an overwrite), so resynchronise on the first
            # in-window frame that is not someone else's overflow.
            y.own.append(fr)
            y.resynced = own_state is not None
            state = Stream(fr)
            started = True
            continue
        y.remnants.append(fr)

    # Overflow out of this cluster.  When the recorder's write runs past the
    # cluster end it carries on into the physically next cluster - the frame
    # that crossed the boundary AND the rest of that write, typically an
    # audio frame or two.  Those frames are this recording's; the next
    # cluster's owner sees them as spill-in and excludes them, so they are
    # collected here or nowhere.  Skipped when the next physical cluster is
    # also our chain's next, where they are simply our own leading frames.
    #
    # Continuity is NOT enough to claim them: cameras started together keep
    # near-identical counters and clocks, and on the real disk a continuity-
    # only walk ran straight on into the next camera's data.  The write is
    # sequential, so a genuine overflow frame starts exactly where the
    # previous one ended, beginning at the end of the frame that crossed the
    # boundary.  The first gap ends the overflow.
    last = y.own[-1] if y.own else None
    if (started and not ended and rec.next != rec.index + 1
            and last.offset - off + last.length > cs):
        expected = last.offset + last.length
        for fr in walk_frames(buf, off, expected - off, len(buf)):
            if fr.offset != expected or state.distance(fr) is None:
                break
            y.own.append(fr)
            y.overflow_out += 1
            state.feed(fr)
            expected = fr.offset + fr.length

    # A frame cut at the cluster end and finished in our NEXT CHAIN cluster.
    # The bytes after the cut belong to whoever owns the physically next
    # cluster, so the walk above rejected it.  Rejoined with the start of our
    # next cluster it must pass the same checks as any frame - header
    # checksum, a trailer repeating the length - and continue our stream.  As
    # with overflow, it must start exactly where our last frame ended: the
    # write is sequential.  Nothing is claimed when any of that fails.
    last = y.own[-1] if y.own else None
    if (started and not ended and rec.next and rec.next != rec.index + 1
            and last.offset - off + last.length < cs):
        fr, data = _join_at_chain_next(dev, vol, rec, buf, off,
                                       last.offset + last.length)
        if fr is not None and state.distance(fr) is not None:
            y.own.append(fr)
            y.joined[fr.offset] = data
            head_len = off + cs - fr.offset
            y.joined_parts.append({
                "frame_number": fr.frame_number, "type": f"0x{fr.ftype:02X}",
                "parts": [[fr.offset, head_len],
                          [vol.cluster_offset(rec.next), fr.length - head_len]]})
            state.feed(fr)

    y.state = state if y.own else None
    return y, buf


def _join_at_chain_next(dev, vol: DhfsVolume, rec: ClusterRecord, buf: bytes,
                        off: int, at: int) -> tuple[Optional[DhavFrame], bytes]:
    """The frame starting at `at` (absolute), cut at the end of the cluster at
    `off` and finished at the start of chain cluster `rec.next` - or
    (None, b"") when the two pieces do not make one valid frame."""
    cs = vol.cluster_size
    tail = buf[at - off:cs]
    nxt = vol.cluster_offset(rec.next)
    hdr = (tail + _read(dev, nxt, DHAV_HDR))[:DHAV_HDR]
    if not header_ok(hdr):
        return None, b""
    flen = struct.unpack_from("<I", hdr, 12)[0]
    if flen <= len(tail) or flen > MAX_FRAME:
        return None, b""
    data = tail + _read(dev, nxt, flen - len(tail))
    got = next(walk_frames(data, at, 0, 1), None)
    if got is None or got.offset != at or got.length != flen:
        return None, b""
    # The start of a cluster is where other cameras' overflow lands.  One
    # shorter than our second half overwrites its middle and leaves the
    # header and trailer - all the checks above see - intact.  Such a write
    # always leaves a DHAV marker (the trailer of the frame that crossed
    # into this cluster, or a header), so any marker inside our second half
    # means it is no longer ours alone.
    second = data[len(tail):flen - DHAV_TAIL]
    if DHAV_MAGIC in second or DHAV_TRAILER in second:
        return None, b""
    return got, data


def reassemble(dev, vol: DhfsVolume, f: DhfsFile, sink=None,
               raw_sink=None) -> dict:
    """Walk a recording's continuation chain in order, emitting its own
    frames.  `sink` receives whole DHAV frames (a .dav stream ffmpeg's dhav
    demuxer reads); `raw_sink` receives the bare video payload (Annex-B
    elementary stream).  Returns counts for the extraction manifest.

    The head cluster is not extracted.  On the real disk it holds under one
    second of data - a partial I-frame whose frame counter belongs to a
    neighbouring stream - followed by older footage.  We do not yet understand
    its role, so we report it rather than splice it into evidence output.
    """
    if vol.data_base is None:
        # Without a calibrated base, cluster N could be read from any
        # camera's data - extracting would splice cameras together.
        raise ValueError(f"volume {vol.number}: data base not calibrated - refusing "
                         f"to reassemble; see the parse notes")
    by_index = {r.index: r for r in vol.records}
    stats = {"clusters": 0, "clusters_beyond_image": 0, "frames": 0,
             "video_frames": 0, "i_frames": 0, "bytes": 0, "spill_in": 0,
             "unassigned": 0, "remnant_frames": 0, "stream_breaks": 0,
             "overflow_recovered": 0, "boundary_joined": 0, "joined_frames": [],
             "first_date": None, "last_date": None, "codec": "",
             "width": 0, "height": 0, "fps": 0, "cluster_sha256": []}
    counters: dict[str, set[int]] = {"video": set(), "audio": set()}
    state: Optional[Stream] = None
    for c in f.clusters:
        rec = by_index.get(c)
        if rec is None:
            continue
        y, buf = classify_cluster(dev, vol, rec, state)
        if not y.in_image:
            stats["clusters_beyond_image"] += 1
            state = None
            continue
        stats["clusters"] += 1
        stats["spill_in"] += y.spill_in
        stats["overflow_recovered"] += y.overflow_out
        stats["boundary_joined"] += len(y.joined)
        stats["joined_frames"].extend(y.joined_parts)
        stats["unassigned"] += y.unassigned
        stats["remnant_frames"] += len(y.remnants)
        stats["cluster_sha256"].append(
            {"cluster": c, "offset": y.offset, "sha256": sha256_bytes(buf[:vol.cluster_size])})
        if y.resynced:
            stats["stream_breaks"] += 1
        for fr in y.own:
            rel = fr.offset - y.offset
            frame = y.joined.get(fr.offset) or buf[rel:rel + fr.length]
            if not stats["codec"] and fr.ftype == TYPE_I:
                ext = frame_ext(frame, 0, fr)
                stats["codec"] = ext.get("codec", "")
                stats["width"] = ext.get("width", 0)
                stats["height"] = ext.get("height", 0)
                stats["fps"] = ext.get("fps", 0)
            if sink is not None:
                sink.write(frame)
            if raw_sink is not None and fr.is_video:
                raw_sink.write(frame[DHAV_HDR + fr.ext_length: fr.length - DHAV_TAIL])
            if fr.is_video:
                counters["video"].add(fr.frame_number)
            elif fr.ftype == TYPE_AUDIO:
                counters["audio"].add(fr.frame_number)
            stats["frames"] += 1
            stats["bytes"] += fr.length
            if fr.is_video:
                stats["video_frames"] += 1
            if fr.ftype == TYPE_I:
                stats["i_frames"] += 1
            if stats["first_date"] is None:
                stats["first_date"] = fmt_date(fr.date)
            stats["last_date"] = fmt_date(fr.date)
        if y.own:
            state = y.state
    # Video and audio each carry their own frame counter.  Numbers absent
    # from a counter's range are frames with no intact copy on the disk - on
    # the real disk ~1 per cluster: an overflow frame written into the next
    # physical cluster whose header survives there but whose body does not.
    # Reported, never interpolated.
    for kind, seen in counters.items():
        span = (max(seen) - min(seen) + 1) if seen else 0
        stats[f"{kind}_counter_missing"] = span - len(seen)
        stats[f"{kind}_counter_span"] = span
    return stats


def find_remnants(dev, vol: DhfsVolume, clusters: Optional[list[int]] = None,
                  min_frames: int = 25, stats: Optional[dict] = None) -> list[dict]:
    """Older footage surviving in reused clusters, grouped into continuous
    runs.  The DHAV header carries no camera number and the index now points
    at the cluster's NEW owner, so a remnant's camera is reported unknown.

    Only runs dated at least REMNANT_MIN_AGE_S outside the cluster's window
    are returned.  Runs closer than that are tallied in `stats` as
    "in_period_unexplained" - they exist, but calling them recovered deleted
    footage would overstate what they are."""
    by_index = {r.index: r for r in vol.records}
    out: list[dict] = []
    if stats is not None:
        stats.setdefault("clusters_scanned", 0)
        stats.setdefault("in_period_unexplained_runs", 0)
        stats.setdefault("in_period_unexplained_frames", 0)
        stats.setdefault("short_runs_dropped", 0)
    # Walk clusters in chain order, carrying the recording's stream state
    # from one cluster to the next exactly as extraction does - otherwise a
    # cluster's own first frames, which can sit a few seconds before its index
    # window, would be mistaken for someone else's data.
    size = getattr(dev, "size_bytes", 0)
    wanted = set(clusters) if clusters is not None else None
    order: list[tuple[int, bool]] = []          # (cluster, carries state)
    for f in vol.files:
        order.append((f.head.index, False))
        order.extend((c, True) for c in f.clusters)
    state: Optional[Stream] = None
    for c, carry in order:
        if not carry:
            state = None
        if wanted is not None and c not in wanted:
            state = None
            continue
        rec = by_index.get(c)
        if rec is None or (size and vol.cluster_offset(c) + vol.cluster_size > size):
            state = None
            continue
        y, _ = classify_cluster(dev, vol, rec, state if carry else None)
        state = y.state
        if stats is not None and y.in_image:
            stats["clusters_scanned"] += 1
        rs, re_ = _seconds(rec.start), _seconds(rec.end)
        run: list[DhavFrame] = []
        run_state: Optional[Stream] = None
        for fr in y.remnants + [None]:                   # sentinel flushes
            if fr is not None and (not run or run_state.distance(fr) is not None):
                run.append(fr)
                run_state = (run_state or Stream()).feed(fr)
                continue
            old_enough = False
            if run and rs is not None and re_ is not None:
                first, last = run[0].seconds, run[-1].seconds
                old_enough = (last is not None and last < rs - REMNANT_MIN_AGE_S) or \
                    (first is not None and first > re_ + REMNANT_MIN_AGE_S)
            if run and not old_enough and stats is not None:
                stats["in_period_unexplained_runs"] += 1
                stats["in_period_unexplained_frames"] += len(run)
            elif run and len(run) < min_frames and stats is not None:
                stats["short_runs_dropped"] += 1
            if old_enough and len(run) >= min_frames:
                vids = [x for x in run if x.is_video]
                out.append({
                    "cluster": c, "offset": run[0].offset,
                    "length": run[-1].offset + run[-1].length - run[0].offset,
                    "frames": len(run), "video_frames": len(vids),
                    "i_frames": sum(1 for x in run if x.ftype == TYPE_I),
                    "first_date": fmt_date(run[0].date),
                    "last_date": fmt_date(run[-1].date),
                    "first_raw": run[0].date, "last_raw": run[-1].date,
                    "overwritten_by_camera": rec.channel,
                })
            run = [fr] if fr is not None else []
            run_state = Stream(fr) if fr is not None else None
    return out


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------
@register
class DahuaParser(VendorParser):
    """Parses DHFS 4.1: superblock, partition table, volume headers, cluster
    index and recording chains; reassembles DHAV streams per camera."""

    vendor = VENDOR
    parser_rule = "dahua.dhfs41.v1"

    def __init__(self, tz_offset_min: Optional[int] = None):
        # The recorder stores wall-clock time with no zone.  Only an
        # investigator-supplied offset (read off the DVR's own settings) lets
        # us state UTC; without it every time stays "recorder-local".
        self.tz_offset_min = tz_offset_min

    # -- detection -----------------------------------------------------------
    def detect(self, dev, hint_offsets: Optional[list[int]] = None) -> bool:
        return _read(dev, 0, 4) == SB_MAGIC

    # -- structures ----------------------------------------------------------
    def read_superblock(self, dev) -> dict:
        raw = _read(dev, 0, 512)
        if raw[:4] != SB_MAGIC:
            return {}
        return {"magic": raw[:4].decode(), "version": _cstr(raw[0:16]),
                "uuid": _cstr(raw[0x20:0x60]).removeprefix("uuid:"),
                "boot_marker_ok": raw[0x1F4:0x1F8] == b"\xAA\x55\xAA\x55"}

    def read_partitions(self, dev) -> tuple[list[DhfsVolume], list[str]]:
        notes: list[str] = []
        prim = _read(dev, PTABLE_OFFSET, 0x400)
        back = _read(dev, PTABLE_BACKUP_OFFSET, 0x400)
        if back and prim != back:
            notes.append("partition table differs from its backup at 0x7C00 - "
                         "using the primary; the difference is itself a finding")
        vols: list[DhfsVolume] = []
        for k in range(PTABLE_MAX_ENTRIES):
            e = PTABLE_FIRST_ENTRY + k * PTABLE_ENTRY_SIZE
            if e + PTABLE_ENTRY_SIZE > len(prim):
                break
            start, count = struct.unpack_from("<I", prim, e + 0x24)[0], \
                struct.unpack_from("<I", prim, e + 0x2C)[0]
            if count == 0:
                break
            if vols and start * 512 < vols[-1].start + vols[-1].length:
                notes.append(f"partition entry {k} overlaps the previous one - "
                             f"table ends here")
                break
            if struct.unpack_from("<I", prim, e + 0x28)[0] or \
                    struct.unpack_from("<I", prim, e + 0x30)[0]:
                notes.append(f"partition entry {k}: dword after start/count is "
                             f"non-zero - fields may be 64-bit on this disk")
            vols.append(DhfsVolume(k + 1, start * 512, count * 512))
        return vols, notes

    def read_volume(self, dev, vol: DhfsVolume) -> None:
        raw = _read(dev, vol.start + VHDR_OFFSET, 512)
        if len(raw) < 512:
            vol.notes.append(f"volume {vol.number} header at 0x"
                             f"{vol.start + VHDR_OFFSET:X} lies beyond the image")
            return
        backup = _read(dev, vol.start + VHDR_BACKUP_OFFSET, 512)
        vol.header_backup_matches = (backup == raw) if backup else None
        h = {f.name: struct.unpack_from(f.fmt, raw, f.offset)[0] for f in VHDR_FIELDS}
        h["undecoded"] = {f"0x{o:02X}": struct.unpack_from("<I", raw, o)[0]
                          for o in VHDR_UNDECODED}
        vol.header = h
        if h["sector_size"] != 512 or not 0 < h["sectors_per_cluster"] <= 0x10000:
            vol.notes.append(f"volume {vol.number}: implausible sector/cluster size "
                             f"{h['sector_size']}/{h['sectors_per_cluster']} - not parsed")
            return
        vol.cluster_size = h["sectors_per_cluster"] * h["sector_size"]

        table = vol.start + h["index_start_sector"] * 512
        cap = min(h["cluster_capacity"], vol.length // vol.cluster_size + 1)
        tbl = _read(dev, table, cap * REC_SIZE)
        if len(tbl) < cap * REC_SIZE:
            vol.notes.append(f"volume {vol.number}: cluster table truncated by the "
                             f"end of the image ({len(tbl) // REC_SIZE}/{cap} records)")
        vol.records = [decode_record(i, tbl[i * REC_SIZE:(i + 1) * REC_SIZE])
                       for i in range(len(tbl) // REC_SIZE)]
        vol.files = self._chains(vol)
        self._calibrate(dev, vol)

    def _chains(self, vol: DhfsVolume) -> list[DhfsFile]:
        recs = vol.records
        files: list[DhfsFile] = []
        for r in recs:
            if r.kind != REC_HEAD:
                continue
            f = DhfsFile(vol.number, r)
            seen = {r.index}
            prev, c, seq = r.index, r.next, 1
            while c:
                if c >= len(recs):
                    f.chain_ok = False
                    f.chain_notes.append(f"next -> {c} is outside the table")
                    break
                n = recs[c]
                if c in seen:
                    f.chain_ok = False
                    f.chain_notes.append(f"loop at cluster {c}")
                    break
                if n.kind != REC_CONT or n.head != r.index:
                    f.chain_ok = False
                    f.chain_notes.append(f"cluster {c} is not a continuation of head "
                                         f"{r.index} (kind 0x{n.kind:02X})")
                    break
                if n.prev != prev or n.count_or_seq != seq:
                    f.chain_ok = False
                    f.chain_notes.append(f"cluster {c}: prev/seq mismatch")
                seen.add(c)
                f.clusters.append(c)
                prev, c, seq = c, n.next, seq + 1
            if r.count_or_seq != len(f.clusters):
                f.chain_notes.append(f"head declares {r.count_or_seq} continuations, "
                                     f"chain has {len(f.clusters)}")
            files.append(f)
        return files

    def _calibrate(self, dev, vol: DhfsVolume) -> None:
        """Find where cluster 0 of the data area sits on the disk.

        We do not trust a header field for this: the obvious candidates in
        the volume header do not produce the observed base directly.  Instead,
        clusters that begin exactly with a fresh I-frame vote: each such frame
        at offset X, dated inside the time window of index record R, proposes
        base = X - R * cluster_size.  The true base wins by a wide margin; the
        vote tally is kept in the output so the choice can be audited.
        """
        cs = vol.cluster_size
        first = vol.header.get("first_data_cluster", 0)
        windows: dict[int, list[ClusterRecord]] = {}
        for r in vol.records:
            if r.kind in (REC_HEAD, REC_CONT):
                s = _seconds(r.start)
                if s is not None:
                    windows.setdefault(s, []).append(r)
        votes: dict[int, int] = {}
        scan_from = vol.start + first * cs
        scan_len = 96 << 20
        buf = _read(dev, scan_from, scan_len)
        pos = 0
        while True:
            p = buf.find(DHAV_MAGIC, pos)
            if p < 0 or p + DHAV_HDR > len(buf):
                break
            pos = p + 1
            absolute = scan_from + p
            if absolute % 512 or buf[p + 4] != TYPE_I or not header_ok(buf[p:p + DHAV_HDR]):
                continue
            s = _seconds(struct.unpack_from("<I", buf, p + 16)[0])
            if s is None:
                continue
            for w in range(s - 12, s + 2):
                for r in windows.get(w, []):
                    rs, re_ = _seconds(r.start), _seconds(r.end)
                    if rs is not None and re_ is not None and rs - 2 <= s <= re_ + 2:
                        b = absolute - r.index * cs
                        if b >= vol.start:
                            votes[b] = votes.get(b, 0) + 1
        if not votes:
            vol.notes.append(f"volume {vol.number}: no cluster-aligned I-frames in the "
                             f"first {scan_len >> 20} MiB of data - data base unknown, "
                             f"recordings listed from the index only")
            vol.calibration = {"votes": 0}
            return

        # Votes alone cannot decide, and neither can stream continuity: the
        # cameras record concurrently and are allocated clusters in rotation,
        # so a base shifted by whole clusters lands on other cameras' clusters
        # from nearly the same seconds, and their chains are just as
        # continuous.  What does separate them is timing.  Clusters are
        # allocated in time order, so at a shifted base the frames found are
        # systematically early or late against the index window; on the real
        # disk the true base averages 1.2 s of error and each cluster of shift
        # adds 1.5-4 s, all in one direction.  So every voted base and its
        # neighbours up to three clusters either side are scored by mean
        # timing error, over clusters where footage is found.
        sample = self._sample_clusters(vol, scan_from, scan_len)
        pairs = self._sample_pairs(vol, scan_from, scan_len)
        candidates = set()
        for b, _ in sorted(votes.items(), key=lambda kv: -kv[1])[:8]:
            for k in range(-3, 4):
                if b + k * cs >= vol.start:
                    candidates.add(b + k * cs)
        scored = []
        for b in candidates:
            vol.data_base = b
            found, err = self._timing_error(dev, vol, sample)
            scored.append({"base": b, "found": found, "err": err, "votes": votes.get(b, 0)})
        most = max(s["found"] for s in scored)
        eligible = [s for s in scored if s["found"] and s["found"] >= most * 0.8]
        eligible.sort(key=lambda s: (s["err"], -s["votes"]))
        if not eligible:
            vol.data_base = None
            vol.notes.append(f"volume {vol.number}: no candidate data base finds footage "
                             f"matching the index - recordings listed from the index only")
            vol.calibration = {"votes": max(votes.values()), "candidates": len(scored)}
            return
        best = eligible[0]
        runner = eligible[1] if len(eligible) > 1 else None
        vol.data_base = best["base"]
        ok, tested = self._continuity(dev, vol, pairs)
        vol.calibration = {
            "data_base": best["base"],
            "clusters_sampled": len(sample), "clusters_with_footage": best["found"],
            "mean_timing_error_s": round(best["err"], 2),
            "runner_up_timing_error_s": round(runner["err"], 2) if runner else None,
            "continuous_pairs": ok, "pairs_tested": tested,
            "votes": best["votes"], "candidates": len(scored),
            "method": ("candidates from cluster-aligned I-frames voting against index "
                       "time windows, +/-3 cluster shifts; chosen by the lowest mean "
                       "|frame date - index date| over sampled clusters; then checked "
                       "for stream continuity along chains")}
        margin = (runner["err"] - best["err"]) if runner else None
        if best["err"] > 2.0 or (margin is not None and margin < 0.5) or \
                (tested and ok < tested // 2):
            vol.notes.append(f"volume {vol.number}: data-base calibration is weak (timing "
                             f"error {best['err']:.2f} s, margin "
                             f"{'n/a' if margin is None else f'{margin:.2f} s'}, continuity "
                             f"{ok}/{tested}) - treat extents with caution")

    def _sample_clusters(self, vol: DhfsVolume, scan_from: int, scan_len: int,
                         want: int = 30) -> list[ClusterRecord]:
        cs = vol.cluster_size
        lo_c = max(0, (scan_from - vol.start) // cs)
        hi_c = lo_c + scan_len // cs + 8
        return [r for r in vol.records[lo_c:hi_c] if r.kind == REC_CONT][:want]

    def _timing_error(self, dev, vol: DhfsVolume,
                      sample: list[ClusterRecord]) -> tuple[int, float]:
        found = 0
        total = 0.0
        for r in sample:
            y, _ = classify_cluster(dev, vol, r, None)
            rs, re_ = _seconds(r.start), _seconds(r.end)
            if not y.own or rs is None or re_ is None:
                continue
            found += 1
            total += abs(y.own[0].seconds - rs) + abs(y.own[-1].seconds - re_)
        return found, (total / (2 * found)) if found else float("inf")

    def _sample_pairs(self, vol: DhfsVolume, scan_from: int, scan_len: int,
                      want: int = 8) -> list[tuple[ClusterRecord, ClusterRecord]]:
        """Consecutive continuation clusters of one recording whose index
        numbers put them inside the region we calibrate on."""
        cs = vol.cluster_size
        lo_c = max(0, (scan_from - vol.start) // cs - 4)
        hi_c = lo_c + (scan_len // cs) + 8
        pairs = []
        for r in vol.records:
            if r.kind == REC_CONT and lo_c <= r.index <= hi_c and r.next:
                n = vol.records[r.next] if r.next < len(vol.records) else None
                if n is not None and n.kind == REC_CONT and n.head == r.head:
                    pairs.append((r, n))
            if len(pairs) >= want:
                break
        return pairs

    def _continuity(self, dev, vol: DhfsVolume,
                    pairs: list[tuple[ClusterRecord, ClusterRecord]]) -> tuple[int, int]:
        ok = tested = 0
        for a, b in pairs:
            ya, _ = classify_cluster(dev, vol, a, None)
            if not ya.in_image or not ya.own:
                continue
            tested += 1
            yb, _ = classify_cluster(dev, vol, b, ya.state)
            if yb.own and not yb.resynced:
                ok += 1
        return ok, tested

    # -- full parse ------------------------------------------------------------
    def parse(self, dev, hint_offsets: Optional[list[int]] = None) -> ParseResult:
        result = ParseResult(vendor=VENDOR, parser_rule=self.parser_rule)
        result.field_provenance = [
            {"struct": s, "field": f.name, "offset": f.offset, "source": f.source,
             "implies_status": f.status, "citation": f.citation}
            for s, fields in (("superblock", SB_FIELDS), ("partition_entry", PART_FIELDS),
                              ("volume_header", VHDR_FIELDS), ("cluster_record", REC_FIELDS),
                              ("dhav_header", DHAV_FIELDS))
            for f in fields]

        sb = self.read_superblock(dev)
        if not sb:
            result.errors.append("no DHFS superblock at offset 0 - not a DHFS volume, "
                                 "or the image does not start at the disk origin")
            return result
        vols, pnotes = self.read_partitions(dev)
        result.notes.extend(pnotes)
        size = getattr(dev, "size_bytes", 0)
        for v in vols:
            self.read_volume(dev, v)
            result.notes.extend(v.notes)
        self.volumes = vols

        sources = [f.source for f in SB_FIELDS + PART_FIELDS]
        if any(v.records for v in vols):
            sources += [f.source for f in VHDR_FIELDS + REC_FIELDS + DHAV_FIELDS]

        for v in vols:
            for n, f in enumerate(v.files):
                rec = self._to_recording(dev, v, n, f)
                result.recordings.append(rec)
                if v.data_base is not None:
                    for c in f.clusters:
                        result.indexed_extents.append((v.cluster_offset(c), v.cluster_size))

        result.volume = {
            "vendor": "Dahua-family (Dahua or a Dahua-derived OEM such as CP Plus)",
            "superblock": sb,
            "image_bytes": size,
            "tz_offset_min": self.tz_offset_min,
            "volumes": [self._volume_summary(v, size) for v in vols],
            "summary": self._summary_lines(sb, vols, size),
        }
        result.validation_status = weakest_source(sources)
        result.notes.append(
            f"status {result.validation_status}: filesystem fields were read off real "
            f"media but never byte-matched against the recorder's own export - only "
            f"that justifies 'validated'.")
        if self.tz_offset_min is None:
            result.notes.append(
                "times are the recorder's wall clock, zone unknown - start_utc is left "
                "empty. Pass --tz-offset (minutes, from the DVR's own settings) to "
                "state UTC.")
        return result

    def _volume_summary(self, v: DhfsVolume, size: int) -> dict:
        h = v.header
        in_image = 0
        if v.data_base is not None and size:
            in_image = sum(1 for f in v.files for c in f.clusters
                           if v.cluster_offset(c) + v.cluster_size <= size)
        return {
            "number": v.number, "start": v.start, "length": v.length,
            "header_parsed": bool(h), "header_backup_matches": v.header_backup_matches,
            "cluster_size": v.cluster_size,
            "earliest": fmt_date(h["earliest_recording"]) if h else None,
            "latest": fmt_date(h["latest_recording"]) if h else None,
            "records": len(v.records),
            "files": len(v.files),
            "cameras": sorted({f.camera for f in v.files}),
            "chains_broken": sum(1 for f in v.files if not f.chain_ok),
            "clusters_in_chains": sum(len(f.clusters) + 1 for f in v.files),
            "continuation_clusters_in_image": in_image,
            "calibration": v.calibration,
            "header_undecoded": h.get("undecoded", {}) if h else {},
        }

    def _summary_lines(self, sb: dict, vols: list[DhfsVolume], size: int) -> list[tuple[str, str]]:
        lines = [("filesystem", f"{sb['version']}  uuid {sb['uuid']}"),
                 ("vendor", "Dahua-family (Dahua / CP Plus - indistinguishable on disk)"),
                 ("volumes", str(len(vols)))]
        for v in vols:
            label = f"volume {v.number}"
            span = f"@0x{v.start:X} {v.length / 1e9:.1f} GB"
            if not v.header:
                lines.append((label, f"{span}  beyond the image - not read"))
                continue
            cams = sorted({f.camera for f in v.files})
            broken = sum(1 for f in v.files if not f.chain_ok)
            lines.append((label, f"{span}  {len(v.files)} files, cameras "
                                 f"{[c + 1 for c in cams]}, chains broken {broken}"))
            lines.append(("", f"recorded {fmt_date(v.header['earliest_recording'])} -> "
                              f"{fmt_date(v.header['latest_recording'])} (recorder clock)"))
            if v.data_base is not None:
                total = sum(len(f.clusters) for f in v.files)
                inimg = sum(1 for f in v.files for c in f.clusters
                            if v.cluster_offset(c) + v.cluster_size <= size)
                cal = v.calibration
                lines.append(("", f"data base 0x{v.data_base:X} (timing error "
                                  f"{cal.get('mean_timing_error_s')} s vs next-best "
                                  f"{cal.get('runner_up_timing_error_s')} s, chain continuity "
                                  f"{cal.get('continuous_pairs')}/{cal.get('pairs_tested')})"))
                lines.append(("", f"footage inside this image for {inimg}/{total} "
                                  f"continuation clusters; the rest is indexed only"))
        return lines

    def _claim(self, value: int, source: str, rule: str) -> TimestampClaim:
        dt = decode_date(value)
        utc = None
        if dt is not None and self.tz_offset_min is not None:
            utc = (dt - timedelta(minutes=self.tz_offset_min)).replace(
                tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return TimestampClaim(
            source=source,
            raw_value=f"0x{value:08X} = {fmt_date(value)} recorder-local",
            decoded_utc=utc,
            tz_offset_min=self.tz_offset_min,
            # A recorder clock is the thing under suspicion; one source is a
            # claim for the timeline stage to corroborate, never a conclusion.
            confidence=(0.5 if utc else 0.3) if dt else 0.0,
            decode_rule=rule + ("" if self.tz_offset_min is not None else
                                "; zone unknown, not converted"),
        )

    def _to_recording(self, dev, v: DhfsVolume, n: int, f: DhfsFile) -> Recording:
        h = f.head
        claims = [
            self._claim(h.start, "index", "DHFS head record +0x04, DHAV-packed date"),
            self._claim(h.end, "index", "DHFS head record +0x08, DHAV-packed date"),
        ]
        size = getattr(dev, "size_bytes", 0)
        first = f.clusters[0] if f.clusters else h.index
        off = v.cluster_offset(first) if v.data_base is not None else 0
        confidence = 0.5 if f.chain_ok else 0.2
        codec = ""
        sha = ""
        # Look at the first two continuation clusters only: enough to confirm
        # the index points at one continuous stream of the right date, without
        # reading the whole recording during a listing.  A date match alone
        # proves little - the other cameras recorded the same seconds - so the
        # confidence that matters is continuity from one cluster to the next.
        if v.data_base is not None and f.clusters and size and off + v.cluster_size <= size:
            rec = v.records[first]
            y, buf = classify_cluster(dev, v, rec, None)
            if y.own:
                confidence += 0.15
                i_frames = [x for x in y.own if x.ftype == TYPE_I]
                if i_frames:
                    fr = i_frames[0]
                    joined = y.joined.get(fr.offset)
                    codec = (frame_ext(joined, 0, fr) if joined
                             else frame_ext(buf, fr.offset - off, fr)).get("codec", "")
                claims.append(self._claim(y.own[0].date, "container",
                                          "first DHAV frame +0x10 of first continuation cluster"))
                if len(f.clusters) > 1:
                    y2, _ = classify_cluster(dev, v, v.records[f.clusters[1]], y.state)
                    if y2.own and not y2.resynced:
                        confidence += 0.25
            sha = sha256_bytes(buf[:v.cluster_size])
        elif v.data_base is not None and f.clusters:
            confidence -= 0.1                            # index only, data not acquired
        ds, de = decode_date(h.start), decode_date(h.end)
        start_utc = claims[0].decoded_utc
        end_utc = claims[1].decoded_utc
        prov = Provenance(
            disk_offset=off,
            length=(len(f.clusters)) * v.cluster_size,
            sector_start=off // 512,
            sector_end=(off + v.cluster_size) // 512,
            parser_rule=self.parser_rule,
            sha256=sha,
        )
        return Recording(
            id=f"dhfs-v{v.number}-c{h.index:06d}",
            camera_id=f"CH{f.camera + 1:02d}" if f.camera >= 0 else "UNKNOWN",
            state=STATE_ACTIVE,
            codec=codec,
            offset=off,
            length=len(f.clusters) * v.cluster_size,
            start_utc=start_utc,
            end_utc=end_utc,
            duration_s=(de - ds).total_seconds() if ds and de else None,
            confidence=round(max(0.0, min(confidence, 0.95)), 4),
            frame_count=0,
            timestamps=claims,
            provenance=prov,
        )

    def remnant_recordings(self, dev, clusters: Optional[list[int]] = None) -> list[Recording]:
        """Remnants of overwritten footage as contract Recordings (fragments).
        Scan totals, including what was deliberately not called a remnant,
        are left in `self.remnant_stats`."""
        out: list[Recording] = []
        self.remnant_stats: dict = {}
        for v in getattr(self, "volumes", []):
            if v.data_base is None:
                continue
            size = getattr(dev, "size_bytes", 0)
            todo = clusters
            if todo is None:
                todo = [r.index for r in v.records if r.kind in (REC_HEAD, REC_CONT)
                        and v.cluster_offset(r.index) + v.cluster_size <= size]
            for k, rem in enumerate(find_remnants(dev, v, todo, stats=self.remnant_stats)):
                ds, de = decode_date(rem["first_raw"]), decode_date(rem["last_raw"])
                claim = self._claim(rem["first_raw"], "container",
                                    "DHAV +0x10 of first surviving remnant frame")
                out.append(Recording(
                    id=f"dhfs-v{v.number}-rem{k:05d}",
                    camera_id="UNKNOWN",
                    state=STATE_FRAGMENT,
                    codec="",
                    offset=rem["offset"],
                    length=rem["length"],
                    start_utc=claim.decoded_utc,
                    end_utc=self._claim(rem["last_raw"], "container", "").decoded_utc,
                    duration_s=(de - ds).total_seconds() if ds and de else None,
                    # Validated frames with a coherent stream, but the camera is
                    # unknown and nothing corroborates the date.
                    confidence=0.4,
                    frame_count=rem["frames"],
                    timestamps=[claim],
                    provenance=Provenance(
                        disk_offset=rem["offset"], length=rem["length"],
                        sector_start=rem["offset"] // 512,
                        sector_end=(rem["offset"] + rem["length"] + 511) // 512,
                        parser_rule=self.parser_rule + ".remnant"),
                ))
        return out

    def file_for(self, recording_id: str) -> tuple[Optional[DhfsVolume], Optional[DhfsFile]]:
        for v in getattr(self, "volumes", []):
            for f in v.files:
                if f"dhfs-v{v.number}-c{f.head.index:06d}" == recording_id:
                    return v, f
        return None, None

"""Indexless DHAV carver: separate camera streams from raw bytes alone.

The fallback for when a DHFS index is damaged, wiped, or simply not in the
image - and the only route to footage in regions no index describes.  It reads
the region front to back, validates every DHAV frame (header checksum AND
trailer length, see parsers/dahua.py), and assigns each frame to the stream it
continues most closely.  A frame that continues nothing starts a new stream.

WHY THIS IS HARDER THAN IT LOOKS
--------------------------------
Every camera writes "channel 0" in its DHAV headers, so the header cannot say
which camera a frame came from.  Cameras started together also keep near-
identical frame counters and clocks.  What does separate them is continuity at
fine grain - each stream's own counters (one per frame kind), its millisecond
clock and its date - and taking the CLOSEST continuing stream rather than the
first, exactly as the index-guided parser does.  The two are built on the same
`Stream` so they cannot drift apart in how they judge continuity.

WHAT A CARVED STREAM IS, AND IS NOT
-----------------------------------
A carved stream is a run of frames that are mutually continuous.  It is not a
camera: with no index there is no camera number, so it is reported as
"UNKNOWN", and one camera's footage can come out as several streams wherever
continuity broke (a lost cluster, a recorder restart).  Nor does carving say
whether footage was deleted - only where it sits and what it claims about its
own time.  Crossing a carve against an index, where one exists, is what turns
"a stream" into "camera 2" or "not in any index".

Status: the DHAV layer is published (ffmpeg dhav.c) and the separation rule was
checked against real media by comparison with index-guided extraction, but no
carve has been byte-matched against a recorder export - so `spec_only`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

from core.contract import STATE_FRAGMENT, Provenance, Recording, TimestampClaim
from parsers.dahua import (
    DHAV_HDR,
    DHAV_TAIL,
    MAX_FRAME,
    TYPE_I,
    DhavFrame,
    Stream,
    _kind,
    _read,
    decode_date,
    fmt_date,
    frame_ext,
    walk_frames,
)

PARSER_RULE = "carve.dhav.continuity.v1"

CHUNK = 64 << 20
# A stream that has had no frame for this many bytes is closed.  Cameras
# interleave cluster by cluster (2 MiB each on the real disk), so a live
# stream's next frame is normally a few MiB on; 256 MiB is generous.
RETIRE_BYTES = 256 << 20
# Streams shorter than this are reported as a count, not as footage: a few
# stray frames are not a clip anyone can review.
MIN_FRAMES = 25
# At a discontinuity, the best candidate stream must beat the runner-up by
# this factor, or the frame starts a new stream instead.  Mixing two cameras
# into one output is a false statement; splitting one camera into two
# fragments is only an inconvenience.
CLEAR_WIN = 4.0


@dataclass
class Extent:
    offset: int
    length: int


@dataclass
class CarvedStream:
    sid: int
    state: Stream
    first: DhavFrame
    extents: list[Extent] = field(default_factory=list)
    frames: int = 0
    video_frames: int = 0
    i_frames: int = 0
    duplicates: int = 0
    counters: dict[str, set[int]] = field(default_factory=dict)

    @property
    def last(self) -> DhavFrame:
        return self.state.last

    def add(self, fr: DhavFrame) -> None:
        if self.extents and self.extents[-1].offset + self.extents[-1].length == fr.offset:
            self.extents[-1].length += fr.length
        else:
            self.extents.append(Extent(fr.offset, fr.length))
        self.state.feed(fr)
        self.frames += 1
        if fr.is_video:
            self.video_frames += 1
        if fr.ftype == TYPE_I:
            self.i_frames += 1
        self.counters.setdefault(_kind(fr), set()).add(fr.frame_number)

    @property
    def span_bytes(self) -> int:
        return sum(e.length for e in self.extents)


def _is_repeat(s: Stream, fr: DhavFrame) -> bool:
    """A frame whose counter does not advance past the last of its kind is a
    second copy, not the next frame.  On the real disk head clusters hold such
    copies; admitting them would put a frame into the output twice."""
    ref = s.by_kind.get(_kind(fr))
    return ref is not None and fr.frame_number <= ref.frame_number


def iter_region(dev, start: int, end: int) -> Iterator[DhavFrame]:
    """Validated frames with headers in [start, end), read in overlapping
    chunks so a frame crossing a chunk edge is still seen whole - once."""
    pos = start
    while pos < end:
        want = min(CHUNK, end - pos)
        buf = _read(dev, pos, want + MAX_FRAME)
        if not buf:
            return
        yield from walk_frames(buf, pos, 0, want)
        pos += want


def carve(dev, start: int = 0, end: Optional[int] = None,
          progress=None) -> tuple[list[CarvedStream], dict]:
    """Carve DHAV streams out of [start, end).  Returns the streams (all of
    them, including short ones) and totals for the report."""
    size = getattr(dev, "size_bytes", 0)
    end = size if end is None else min(end, size or end)
    active: list[CarvedStream] = []
    done: list[CarvedStream] = []
    stats = {"region_start": start, "region_end": end, "frames": 0,
             "streams_opened": 0, "repeats_dropped": 0,
             "joined_by_contiguity": 0, "joined_by_closest": 0,
             "ambiguous_splits": 0}
    next_id = 0
    last_report = start
    prev: Optional[DhavFrame] = None
    prev_stream: Optional[CarvedStream] = None
    for fr in iter_region(dev, start, end):
        stats["frames"] += 1
        # Close streams that have gone quiet, so the candidate list stays
        # short and an old stream cannot capture a new recording's frames.
        if active and fr.offset - min(s.last.offset for s in active) > RETIRE_BYTES:
            keep = []
            for s in active:
                (keep if fr.offset - s.last.offset <= RETIRE_BYTES else done).append(s)
            active = keep

        # 1. Byte contiguity: the recorder writes a stream sequentially, so a
        #    frame starting exactly where the previous one ended, and
        #    continuing its stream, is that stream's.  No contest needed -
        #    and this settles almost every frame inside a cluster.
        target: Optional[CarvedStream] = None
        if (prev is not None and prev_stream is not None
                and fr.offset == prev.offset + prev.length
                and prev_stream in active
                and prev_stream.state.distance(fr) is not None):
            target = prev_stream
            stats["joined_by_contiguity"] += 1
        else:
            # 2. A discontinuity (cluster start, overflow, stale data): the
            #    closest continuing stream - but only if it clearly wins.
            scored = sorted((d, i) for i, s in enumerate(active)
                            if (d := s.state.distance(fr)) is not None)
            if scored:
                best_d, bi = scored[0]
                runner = scored[1][0] if len(scored) > 1 else None
                if runner is None or runner > max(best_d, 1.0) * CLEAR_WIN:
                    target = active[bi]
                    stats["joined_by_closest"] += 1
                else:
                    stats["ambiguous_splits"] += 1
        if target is not None:
            if _is_repeat(target.state, fr):
                target.duplicates += 1
                stats["repeats_dropped"] += 1
                continue
            target.add(fr)
        else:
            target = CarvedStream(next_id, Stream(), fr)
            next_id += 1
            stats["streams_opened"] += 1
            target.add(fr)
            active.append(target)
        prev, prev_stream = fr, target
        if progress and fr.offset - last_report > (1 << 30):
            last_report = fr.offset
            progress(fr.offset - start, end - start, len(active))
    done.extend(active)
    done.sort(key=lambda s: s.first.offset)
    stats["streams_kept"] = sum(1 for s in done if s.frames >= MIN_FRAMES)
    stats["frames_in_short_streams"] = sum(s.frames for s in done if s.frames < MIN_FRAMES)
    return done, stats


def write_stream(dev, s: CarvedStream, sink=None, raw_sink=None) -> tuple[int, str]:
    """Copy one carved stream's frames out, in order: whole DHAV frames to
    `sink`, bare video payload to `raw_sink`.  Returns (frames written, codec
    read from the first I-frame's extension, or "").

    Re-reads each extent rather than holding millions of frames in memory,
    and re-validates every frame on the way out."""
    n = 0
    codec = ""
    last_by_kind: dict[str, int] = {}
    for e in s.extents:
        buf = _read(dev, e.offset, e.length)
        for fr in walk_frames(buf, e.offset, 0, len(buf)):
            k = _kind(fr)
            if k in last_by_kind and fr.frame_number <= last_by_kind[k]:
                continue
            last_by_kind[k] = fr.frame_number
            rel = fr.offset - e.offset
            frame = buf[rel:rel + fr.length]
            if not codec and fr.ftype == TYPE_I:
                codec = frame_ext(buf, rel, fr).get("codec", "")
            if sink is not None:
                sink.write(frame)
            if raw_sink is not None and fr.is_video:
                raw_sink.write(frame[DHAV_HDR + fr.ext_length: fr.length - DHAV_TAIL])
            n += 1
    return n, codec


def to_recording(s: CarvedStream, tz_offset_min: Optional[int] = None) -> Recording:
    first, last = s.first, s.last
    ds, de = decode_date(first.date), decode_date(last.date)

    def claim(fr: DhavFrame) -> TimestampClaim:
        return TimestampClaim(
            source="container",
            raw_value=f"0x{fr.date:08X} = {fmt_date(fr.date)} recorder-local",
            decoded_utc=None,
            tz_offset_min=tz_offset_min,
            confidence=0.3 if decode_date(fr.date) else 0.0,
            decode_rule="DHAV +0x10 packed date of a carved frame; zone unknown, "
                        "not converted; no index corroborates it",
        )

    missing = 0
    for seen in s.counters.values():
        if seen:
            missing += (max(seen) - min(seen) + 1) - len(seen)
    span = sum((max(v) - min(v) + 1) for v in s.counters.values() if v)
    completeness = 1 - missing / span if span else 0.0
    # Validated frames, mutually continuous: the stream itself is solid.
    # What is uncertain is whose it is and whether it is whole - so
    # confidence never climbs high without an index to corroborate.
    confidence = round(min(0.6, 0.3 + 0.3 * completeness), 4)
    off = s.extents[0].offset
    return Recording(
        id=f"carve-{s.sid:05d}",
        camera_id="UNKNOWN",
        state=STATE_FRAGMENT,
        codec="",
        offset=off,
        length=s.span_bytes,
        start_utc=None,
        end_utc=None,
        duration_s=(de - ds).total_seconds() if ds and de else None,
        confidence=confidence,
        frame_count=s.frames,
        timestamps=[claim(first), claim(last)],
        provenance=Provenance(
            disk_offset=off, length=s.span_bytes,
            sector_start=off // 512,
            sector_end=(s.extents[-1].offset + s.extents[-1].length + 511) // 512,
            parser_rule=PARSER_RULE),
    )


def cross_reference(dev, streams: list[CarvedStream], vol) -> dict[int, dict]:
    """Label carved streams using a DHFS index, where one exists.

    For every frame, the index record of the cluster it physically sits in
    says which camera owned that cluster and when.  A frame dated inside that
    window counts for that camera; a frame dated outside it is footage the
    index does not account for.  Overflow means a few frames sit in another
    camera's cluster, so a stream's label is its clear majority, and the
    minority is reported rather than hidden.
    """
    from parsers.dahua import REC_CONT, REC_HEAD, _seconds
    out: dict[int, dict] = {}
    if vol is None or vol.data_base is None:
        return out
    cs = vol.cluster_size
    recs = vol.records
    for s in streams:
        tally: dict = {}
        for e in s.extents:
            buf = _read(dev, e.offset, e.length)
            for fr in walk_frames(buf, e.offset, 0, len(buf)):
                c = (fr.offset - vol.data_base) // cs
                key = "outside_index"
                if 0 <= c < len(recs) and recs[c].kind in (REC_HEAD, REC_CONT):
                    r = recs[c]
                    lo, hi, t = _seconds(r.start), _seconds(r.end), fr.seconds
                    if None not in (lo, hi, t) and lo - 5 <= t <= hi + 5:
                        key = f"CH{r.channel + 1:02d}"
                tally[key] = tally.get(key, 0) + 1
        total = sum(tally.values()) or 1
        top, n = max(tally.items(), key=lambda kv: kv[1]) if tally else ("", 0)
        out[s.sid] = {"tally": tally, "label": top if n / total >= 0.9 else "mixed-evidence",
                      "share": round(n / total, 4)}
    return out

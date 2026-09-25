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

import os
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
    # Per frame kind: [first counter, last counter, frames].  Repeats are
    # dropped before `add`, so counters rise strictly and this is exact -
    # and constant-size, where a set of every counter would not fit in
    # memory for a whole drive.
    counters: dict[str, list[int]] = field(default_factory=dict)
    # Index label tally, filled while carving when an index is supplied.
    tally: dict[str, int] = field(default_factory=dict)

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
        c = self.counters.get(_kind(fr))
        if c is None:
            self.counters[_kind(fr)] = [fr.frame_number, fr.frame_number, 1]
        else:
            c[0] = min(c[0], fr.frame_number)
            c[1] = max(c[1], fr.frame_number)
            c[2] += 1

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


class Carver:
    """The carve as a consumer: frames are pushed in disk order with `add`,
    so the same logic runs over a device (`carve`) or inside the single
    acquisition pass (`CarveTap`), where the bytes are already in hand."""

    def __init__(self, start: int = 0, end: int = 0, labeler=None, progress=None):
        self.active: list[CarvedStream] = []
        self.done: list[CarvedStream] = []
        self.stats = {"region_start": start, "region_end": end, "frames": 0,
                      "streams_opened": 0, "repeats_dropped": 0,
                      "joined_by_contiguity": 0, "joined_by_closest": 0,
                      "ambiguous_splits": 0}
        self.labeler = labeler
        self.progress = progress
        self._next_id = 0
        self._start = start
        self._last_report = start
        self._prev: Optional[DhavFrame] = None
        self._prev_stream: Optional[CarvedStream] = None

    def add(self, fr: DhavFrame) -> None:
        stats, active = self.stats, self.active
        stats["frames"] += 1
        # Close streams that have gone quiet, so the candidate list stays
        # short and an old stream cannot capture a new recording's frames.
        if active and fr.offset - min(s.last.offset for s in active) > RETIRE_BYTES:
            keep = []
            for s in active:
                (keep if fr.offset - s.last.offset <= RETIRE_BYTES else self.done).append(s)
            self.active = active = keep

        # 1. Byte contiguity: the recorder writes a stream sequentially, so a
        #    frame starting exactly where the previous one ended, and
        #    continuing its stream, is that stream's.  No contest needed -
        #    and this settles almost every frame inside a cluster.
        prev, prev_stream = self._prev, self._prev_stream
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
                return
            target.add(fr)
        else:
            target = CarvedStream(self._next_id, Stream(), fr)
            self._next_id += 1
            stats["streams_opened"] += 1
            target.add(fr)
            active.append(target)
        if self.labeler is not None:
            key = self.labeler.label(fr)
            target.tally[key] = target.tally.get(key, 0) + 1
        self._prev, self._prev_stream = fr, target
        if self.progress and fr.offset - self._last_report > (1 << 30):
            self._last_report = fr.offset
            self.progress(fr.offset - self._start,
                          stats["region_end"] - self._start, len(active))

    def finish(self) -> tuple[list[CarvedStream], dict]:
        done = self.done + self.active
        self.done, self.active = done, []
        done.sort(key=lambda s: s.first.offset)
        self.stats["streams_kept"] = sum(1 for s in done if s.frames >= MIN_FRAMES)
        self.stats["frames_in_short_streams"] = sum(s.frames for s in done
                                                   if s.frames < MIN_FRAMES)
        return done, self.stats


def carve(dev, start: int = 0, end: Optional[int] = None,
          progress=None, labeler=None) -> tuple[list[CarvedStream], dict]:
    """Carve DHAV streams out of [start, end).  Returns the streams (all of
    them, including short ones) and totals for the report."""
    size = getattr(dev, "size_bytes", 0)
    end = size if end is None else min(end, size or end)
    c = Carver(start, end, labeler=labeler, progress=progress)
    for fr in iter_region(dev, start, end):
        c.add(fr)
    return c.finish()


class FrameFeeder:
    """`iter_region` for bytes that arrive in order instead of being read.

    Walks exactly the same windows as `iter_region` - headers in
    [pos, pos + CHUNK), with MAX_FRAME of look-ahead so a frame crossing the
    window edge is seen whole, once - so a carve fed block by block yields
    the same frames as a carve that reads the device itself."""

    def __init__(self, start: int, end: int):
        self.pos = start           # start of the next window
        self.end = end
        self.buf = bytearray()     # bytes from self.pos onwards

    def push(self, offset: int, data: bytes) -> Iterator[DhavFrame]:
        if offset != self.pos + len(self.buf):
            raise ValueError(f"FrameFeeder: bytes at 0x{offset:X} arrived out of "
                             f"order (expected 0x{self.pos + len(self.buf):X})")
        self.buf += data
        while self.pos < self.end and len(self.buf) >= CHUNK + MAX_FRAME:
            yield from self._window()

    def close(self) -> Iterator[DhavFrame]:
        while self.pos < self.end and self.buf:
            yield from self._window()

    def _window(self) -> Iterator[DhavFrame]:
        want = min(CHUNK, self.end - self.pos)
        view = bytes(self.buf[:want + MAX_FRAME])
        yield from walk_frames(view, self.pos, 0, want)
        del self.buf[:want]
        self.pos += want


class IndexLabeler:
    """Which index record, if any, accounts for a frame - by the cluster it
    physically sits in and the frame's own date.  Works across every volume
    whose data area was located."""

    def __init__(self, volumes):
        from parsers.dahua import REC_CONT, REC_HEAD, _seconds
        self._vols = []
        for v in volumes:
            if v.data_base is None or not v.cluster_size:
                continue
            windows = []
            for r in v.records:
                if r.kind in (REC_HEAD, REC_CONT):
                    windows.append((_seconds(r.start), _seconds(r.end), r.channel))
                else:
                    windows.append(None)
            self._vols.append((v.data_base, v.start + v.length, v.cluster_size, windows))
        self._vols.sort()

    def __bool__(self) -> bool:
        return bool(self._vols)

    def label(self, fr: DhavFrame) -> str:
        t = fr.seconds
        for base, vend, cs, windows in self._vols:
            if base <= fr.offset < vend:
                c = (fr.offset - base) // cs
                w = windows[c] if c < len(windows) else None
                if w is not None and None not in (w[0], w[1], t) and \
                        w[0] - 5 <= t <= w[1] + 5:
                    return f"CH{w[2] + 1:02d}"
                return "outside_index"
        return "outside_index"


def label_streams(streams: list[CarvedStream]) -> dict[int, dict]:
    """Turn per-stream tallies into labels: the clear majority (90%), or
    'mixed-evidence' - the minority is reported rather than hidden."""
    out: dict[int, dict] = {}
    for s in streams:
        if not s.tally:
            continue
        total = sum(s.tally.values()) or 1
        top, n = max(s.tally.items(), key=lambda kv: kv[1])
        out[s.sid] = {"tally": dict(s.tally),
                      "label": top if n / total >= 0.9 else "mixed-evidence",
                      "share": round(n / total, 4)}
    return out


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

    span = sum(hi - lo + 1 for lo, hi, _ in s.counters.values())
    missing = sum(hi - lo + 1 - n for lo, hi, n in s.counters.values())
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


def build_report(streams: list[CarvedStream], stats: dict, xref: dict[int, dict],
                 info, index_used: bool, tz_offset_min: Optional[int] = None,
                 outputs: Optional[dict] = None, tool: str = "carve") -> dict:
    """The carve report - one shape whether the carve ran standalone or
    inside the acquisition pass."""
    from core.contract import SCHEMA_VERSION, to_dict, utc_now

    rows = []
    for s in streams:
        if s.frames < MIN_FRAMES:
            continue
        x = xref.get(s.sid, {})
        rows.append({"recording": to_dict(to_recording(s, tz_offset_min)),
                     "index_label": x.get("label"), "index_tally": x.get("tally"),
                     "duplicates_dropped": s.duplicates,
                     "extents": [[e.offset, e.length] for e in s.extents]})
    return {
        "schema_version": SCHEMA_VERSION, "generated_utc": utc_now(),
        "tool": f"ps26150-forensics {tool}", "rule": PARSER_RULE,
        "validation_status": "spec_only",
        "source_device": info.path, "source_bytes": info.size_bytes,
        "write_block_method": info.write_block_method,
        "stats": stats, "index_used_for_labels": index_used,
        "streams": rows, "outputs": outputs or {},
        "notes": [
            "A carved stream is a run of mutually continuous, validated DHAV frames. "
            "It is not a camera: frames carry no camera number.",
            "Where continuity was ambiguous the carve split rather than guessed, so one "
            "camera can span several streams; streams never knowingly mix cameras.",
            "index_label comes from the DHFS index; 'outside_index' means no index "
            "record accounts for those frames at their dates.",
        ],
    }


class CarveTap:
    """Carve inside the acquisition pass: the scan already holds every byte
    once, so carving there costs CPU instead of a second multi-hour read.

    `prepare` reads the DHFS index (a few MB of random reads) before the
    pass; each frame is then labelled as it is carved, so no frame is ever
    read twice.  A tap never touches the hashes: if it fails, the scanner
    switches it off and the acquisition carries on unchanged."""

    name = "carve"

    def __init__(self, tz_offset_min: Optional[int] = None):
        self.tz_offset_min = tz_offset_min
        self.labeler: Optional[IndexLabeler] = None
        self.feeder: Optional[FrameFeeder] = None
        self.carver: Optional[Carver] = None
        self.index_notes: list[str] = []

    def prepare(self, dev, start: int, end: int, log=print) -> None:
        from parsers.dahua import DahuaParser
        p = DahuaParser()
        if p.detect(dev):
            # Only the index and the data-area calibration are needed to
            # label frames.  A full `parse` also samples clusters of every
            # recording - gigabytes of scattered reads on a USB 2 bridge.
            vols, self.index_notes = p.read_partitions(dev)
            for v in vols:
                p.read_volume(dev, v)
                self.index_notes += v.notes
            self.labeler = IndexLabeler(vols) or None
            n = sum(1 for v in vols if v.data_base is not None)
            log(f"[*] carve    DHFS index read: {len(vols)} volume(s), "
                f"{n} with a located data area - frames labelled as carved")
        else:
            log("[*] carve    no DHFS index - carving unlabelled")
        self.feeder = FrameFeeder(start, end)
        self.carver = Carver(start, end, labeler=self.labeler)

    def feed(self, offset: int, data: bytes) -> None:
        for fr in self.feeder.push(offset, data):
            self.carver.add(fr)

    def finish(self, out_dir: str, info) -> dict:
        from core.contract import dump_json
        from core.hashing import sha256_file
        for fr in self.feeder.close():
            self.carver.add(fr)
        streams, stats = self.carver.finish()
        report = build_report(streams, stats, label_streams(streams), info,
                              self.labeler is not None, self.tz_offset_min,
                              tool="scan --carve (inline)")
        report["index_notes"] = self.index_notes
        os.makedirs(os.path.join(out_dir, "carve"), exist_ok=True)
        path = os.path.join(out_dir, "carve", "carve_report.json")
        dump_json(report, path)
        labels: dict[str, int] = {}
        for r in report["streams"]:
            k = r["index_label"] or "unlabelled"
            labels[k] = labels.get(k, 0) + 1
        return {"report": "carve/carve_report.json", "sha256": sha256_file(path),
                "frames": stats["frames"], "streams_kept": stats["streams_kept"],
                "labels": labels}


@dataclass
class ReportedStream:
    """A carved stream as the carve report recorded it: enough to copy its
    frames out again (`write_stream` needs only the extents)."""
    sid: str
    extents: list[Extent]
    frames: int
    label: Optional[str]


def streams_from_report(report: dict, label: Optional[str] = None,
                        ids: Optional[set[str]] = None) -> list[ReportedStream]:
    out = []
    for row in report.get("streams", []):
        rec = row["recording"]
        if label and row.get("index_label") != label:
            continue
        if ids and rec["id"] not in ids:
            continue
        out.append(ReportedStream(rec["id"], [Extent(o, n) for o, n in row["extents"]],
                                  rec["frame_count"], row.get("index_label")))
    return out


def extract_from_report(dev, streams: list[ReportedStream], out_dir: str,
                        manifest_path: str, log=print) -> dict:
    """Write each stream's frames to <id>.dav and its bare video to
    <id>.h265/.h264, reading only the stream's own extents - a targeted read,
    never a second pass over the drive.

    The manifest is rewritten after every stream, so an extraction that
    stops (a USB drop) keeps what it finished and a re-run skips it.  Every
    frame is re-validated on the way out; the frame count written is checked
    against the count the carve recorded, and a mismatch is reported."""
    from core.hashing import sha256_file
    import json

    os.makedirs(out_dir, exist_ok=True)
    manifest = {"streams": {}}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    done = manifest["streams"]
    for i, s in enumerate(streams):
        if s.sid in done and all(os.path.exists(os.path.join(out_dir, f))
                                 for f in done[s.sid]["files"]):
            continue
        base = os.path.join(out_dir, s.sid)
        with open(base + ".dav", "wb") as dav, open(base + ".es", "wb") as es:
            n, codec = write_stream(dev, s, dav, es)
        es_path = base + (f".{codec}" if codec in ("h264", "h265") else ".es")
        os.replace(base + ".es", es_path)
        files = {os.path.basename(p): {"bytes": os.path.getsize(p), "sha256": sha256_file(p)}
                 for p in (base + ".dav", es_path)}
        done[s.sid] = {"label": s.label, "frames_written": n, "frames_carved": s.frames,
                       "frames_match": n == s.frames, "codec": codec,
                       "extents": [[e.offset, e.length] for e in s.extents],
                       "files": files}
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        log(f"  [{i + 1}/{len(streams)}] {s.sid}  {n:,} frames  "
            f"{sum(f['bytes'] for f in files.values()) / 2**20:,.1f} MiB"
            + ("" if n == s.frames else f"  (!) carve recorded {s.frames:,}"))
    return manifest

"""Why do some recovered frames not decode?  Frame by frame, against the
stream's own counter.

VALIDATION_REPORT.md section 7: on drive 1, 2,087 video frames failed to
decode even after a keyframe, and the suspected cause was a reference frame
lost mid-stream.  Measured since, stream by stream (28 Sep): streams whose
counter is complete lose 0.13% of their frames after the keyframe, streams
with a gap 22.2%.  This makes the same test frame by frame.  A DHAV frame carries a per-stream
counter, so a frame missing from the disk leaves a gap in it.  This asks the
decoder which frames it could not decode, and puts each one in a class:

  before_first_keyframe  nothing earlier in the stream to decode it from -
                         expected, not a finding
  after_a_gap            the counter skipped since the last keyframe: a frame
                         it may depend on is not on the disk - the hypothesis
  unexplained            neither; the hypothesis does not cover it, and the
                         frame is listed for someone to look at

How a frame is matched to the decoder's output: extraction writes the bare
video as each DHAV video frame's payload, in order, so a decoder packet's
byte position in the .h265/.h264 file names the frame it came from.

Needs `ffprobe` (the optional layer, like the rest of analytics/).  The
classification is stdlib-only and tested without it.
"""

from __future__ import annotations

import mmap
import os
import shutil
import subprocess
from bisect import bisect_right
from typing import Optional

from core import proc
from parsers.dahua import DHAV_HDR, DHAV_TAIL, TYPE_I, walk_frames

RULE = "analytics.decode-check.counter-gap.v1"
KEEP_UNEXPLAINED = 20


def video_frames(dav_path: str) -> list[dict]:
    """The stream's video frames in file order: counter, keyframe or not,
    and where the frame's payload sits in the extracted bare video."""
    out, pos = [], 0
    with open(dav_path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if not size:
            return out
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            last = None
            for fr in walk_frames(mm, 0):
                if not fr.is_video:
                    continue
                if last is not None and fr.frame_number <= last:
                    continue                       # the same rule write_stream applies
                last = fr.frame_number
                n = fr.length - DHAV_HDR - fr.ext_length - DHAV_TAIL
                out.append({"number": fr.frame_number, "key": fr.ftype == TYPE_I,
                            "es_offset": pos, "es_length": n})
                pos += n
    return out


def probe(es_path: str, codec: str) -> tuple[list[int], list[int]]:
    """(byte position of every packet, packet position of every frame that
    decoded), from one ffprobe run."""
    fmt = {"h265": "hevc", "h264": "h264"}.get(codec, codec)
    cmd = ["ffprobe", "-v", "error", "-f", fmt, "-i", es_path,
           "-show_packets", "-show_frames", "-select_streams", "v:0",
           "-show_entries", "packet=pos:frame=pkt_pos", "-of", "csv"]
    r = proc.run(cmd, timeout=proc.STREAM_S, capture_output=True, text=True)
    if r.timed_out:
        raise RuntimeError(f"ffprobe did not finish {es_path} within {proc.STREAM_S} s")
    out = r.stdout
    packets, decoded = [], []
    for line in out.splitlines():
        kind, _, val = line.partition(",")
        val = val.strip().rstrip(",")
        if not val.lstrip("-").isdigit() or int(val) < 0:
            continue
        (packets if kind == "packet" else decoded if kind == "frame" else []).append(int(val))
    return packets, decoded


def classify(frames: list[dict], packets: list[int], decoded: list[int]) -> dict:
    """Each frame the decoder was given but did not return, by class."""
    starts = [f["es_offset"] for f in frames]

    def frame_at(pos: int) -> Optional[int]:
        k = bisect_right(starts, pos) - 1
        return k if k >= 0 and pos < starts[k] + max(frames[k]["es_length"], 1) else None

    given = {frame_at(p) for p in packets} - {None}
    ok = {frame_at(p) for p in decoded} - {None}
    counts = {"before_first_keyframe": 0, "after_a_gap": 0, "unexplained": 0}
    unexplained, gaps = [], 0
    seen_key, gap_since_key, prev = False, False, None
    for i, f in enumerate(frames):
        gap = prev is not None and f["number"] != prev + 1
        gaps += gap
        prev = f["number"]
        if f["key"]:
            seen_key, gap_since_key = True, False
        elif gap:
            gap_since_key = True
        if i not in given or i in ok:
            continue
        if not seen_key:
            counts["before_first_keyframe"] += 1
        elif gap_since_key:
            counts["after_a_gap"] += 1
        else:
            counts["unexplained"] += 1
            if len(unexplained) < KEEP_UNEXPLAINED:
                unexplained.append({"frame": i, "counter": f["number"],
                                    "es_offset": f["es_offset"]})
    return {"video_frames": len(frames), "given_to_decoder": len(given),
            "decoded": len(ok), "not_decoded": sum(counts.values()), "classes": counts,
            "counter_gaps": gaps, "unexplained_examples": unexplained}


def check_stream(dav_path: str, es_path: str, codec: str) -> dict:
    frames = video_frames(dav_path)
    packets, decoded = probe(es_path, codec)
    return classify(frames, packets, decoded)


def have_ffprobe() -> bool:
    return shutil.which("ffprobe") is not None


def summarise(per_stream: dict[str, dict]) -> dict:
    tot = {"streams": len(per_stream), "video_frames": 0, "decoded": 0, "not_decoded": 0,
           "classes": {"before_first_keyframe": 0, "after_a_gap": 0, "unexplained": 0}}
    for r in per_stream.values():
        for k in ("video_frames", "decoded", "not_decoded"):
            tot[k] += r[k]
        for k, v in r["classes"].items():
            tot["classes"][k] += v
    after_key = tot["classes"]["after_a_gap"] + tot["classes"]["unexplained"]
    tot["after_first_keyframe"] = after_key
    tot["share_explained_by_a_gap"] = (round(tot["classes"]["after_a_gap"] / after_key, 4)
                                       if after_key else None)
    return tot

"""Read the burned-in OSD of recovered footage: channel title, and the clock.

Optional layer, like analytics/detect.py: the forensic core never imports it.
Unlike the detection layer it needs no Python packages at all - two external
binaries, `ffmpeg` and `tesseract`, and nothing else.  The rules it applies
live in analytics/osd_rules.py (stdlib only, tested by tests/test_pipeline.py).

Why it exists: a stream carved from outside every filesystem index has no
camera anywhere in its bytes - on Dahua media every camera is "channel 0"
(docs/DAHUA_DHFS.md section 4), and footage the index does not account for has
no index record either.  2,246 such streams came off the CP Plus drive and 495
off the Hikvision drive.  The picture still names the camera, because the
recorder painted the title into it, and it still shows the recorder's clock.

Two outputs, and they are not equal:

  * **A camera label** for a stream no index accounts for.  A lead: OCR of
    pixels, carrying the share of sampled frames that agreed.
  * **A clock cross-check** - the clock in the picture against the date decoded
    from the container.  Both are the recorder's own wall clock reached by
    different routes, so a disagreement means something is wrong and is worth
    stating; agreement is the output verification the validation report wants.

Neither is evidence of identity and neither converts anything to UTC.  Only an
examiner who read the recorder's zone and measured its error against a trusted
clock can do that (analyse/timeline.py::ClockModel).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta
from typing import Optional

from analytics.osd_rules import (BANDS, CLOCK_CHARS, CLOCK_TOL_S, OSD_RULE, TITLE_CHARS,
                                 clock_check, normalise_title, parse_osd_clock, pick_band,
                                 resolve_against, summarise, vote_title)

# OSD text is small.  Tesseract wants roughly 30 px of cap height, so the crop
# is upscaled before it ever sees it; this single filter is worth more than any
# threshold tuning.
UPSCALE = 4
# Frames sampled per stream, and the seconds from the start they are taken
# from.  The title does not change, so the opening seconds are enough, and a
# short window keeps a 900 GiB case from becoming another overnight job.
FRAMES = 6
WINDOW_S = 30
# Calibration (which corner holds the text) runs on this many streams.
CALIBRATE_CLIPS = 5
CALIBRATE_FRAMES = 4


def have_tools() -> None:
    """Both binaries, or a message naming the missing one."""
    missing = [b for b in ("ffmpeg", "tesseract") if not shutil.which(b)]
    if missing:
        raise RuntimeError(
            f"{' and '.join(missing)} not found - the OSD reader needs both "
            "(apt install ffmpeg tesseract-ocr); see analytics/README.md")


def codec_of(path: str) -> str:
    """Bare elementary streams need the codec stated; a PS container does not."""
    if path.endswith(".h264"):
        return "h264"
    if path.endswith(".ps"):
        return ""
    return "hevc"


def _crop(band: tuple[float, float, float, float]) -> str:
    x1, y1, x2, y2 = band
    return (f"crop=iw*{x2 - x1:.4f}:ih*{y2 - y1:.4f}:iw*{x1:.4f}:ih*{y1:.4f}")


def sample(clip: str, band: tuple[float, float, float, float], out_dir: str,
           frames: int = FRAMES, window_s: int = WINDOW_S, negate: bool = False) -> list[str]:
    """Write up to `frames` upscaled greyscale crops of one band to `out_dir`.

    Decoding stops after `window_s` seconds of footage, so this reads the head
    of a stream rather than all of it.  A stream that does not decode at all
    yields nothing and is not an error: on the CP Plus drive 2,087 frames after
    a keyframe never decoded (docs/STATUS.md section 6, item 4)."""
    fps = max(frames / float(window_s), 0.01)
    vf = [_crop(band), f"fps={fps}", "format=gray",
          f"scale=iw*{UPSCALE}:ih*{UPSCALE}:flags=lanczos"]
    if negate:
        # Tesseract is trained on dark text on light paper; DVR OSD is the
        # other way round, and inverting is sometimes the difference between
        # a clean read and nothing at all.  Which polarity wins is measured
        # during calibration, not assumed.
        vf.append("negate")
    fmt = ["-f", codec_of(clip)] if codec_of(clip) else []
    cmd = ["ffmpeg", "-v", "quiet", "-t", str(window_s), *fmt, "-i", clip,
           "-vf", ",".join(vf), "-frames:v", str(frames),
           os.path.join(out_dir, "f%03d.pgm")]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return sorted(os.path.join(out_dir, f) for f in os.listdir(out_dir)
                  if f.endswith(".pgm"))


def ocr(image: str, chars: str) -> str:
    """One line of text from one crop.

    The whitelist is passed to Tesseract *and* re-applied to its output by the
    rules module: `tessedit_char_whitelist` is honoured by the legacy engine
    but quietly ignored by the LSTM engine in Tesseract 4 and 5, so relying on
    the flag alone would silently do nothing on a modern install."""
    r = subprocess.run(["tesseract", image, "stdout", "--psm", "7",
                        "-c", f"tessedit_char_whitelist={chars}"],
                       capture_output=True, text=True, check=False)
    return (r.stdout or "").strip()


def _read_band(clip: str, band_name: str, chars: str, frames: int, negate: bool,
               window_s: int = WINDOW_S) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="osd_") as tmp:
        return [ocr(p, chars) for p in
                sample(clip, BANDS[band_name], tmp, frames=frames,
                       window_s=window_s, negate=negate)]


def calibrate(clips: list[str], window_s: int = WINDOW_S, log=print) -> dict:
    """Find where this recorder paints the title and the clock.

    Every band and both polarities are read on a few streams; the combination
    whose readings agree with themselves wins and is then used for the whole
    case.  The scores for everything tried are kept, which is both the audit
    trail and - for the comparative-analysis deliverable - a statement of where
    this OEM puts its OSD."""
    # One group of readings per stream per band: a band is scored on whether it
    # agrees with itself within a stream, never across streams (two streams are
    # two cameras with two different titles).
    per_band: dict[str, list[list[str]]] = {b: [] for b in BANDS}
    polarity: dict[str, list[str]] = {"normal": [], "negated": []}
    for clip in clips[:CALIBRATE_CLIPS]:
        for band in BANDS:
            for neg in (False, True):
                got = _read_band(clip, band, TITLE_CHARS + CLOCK_CHARS,
                                 CALIBRATE_FRAMES, neg, window_s)
                per_band[band].append(got)
                polarity["negated" if neg else "normal"] += got
    title = pick_band(per_band, "title")
    clock = pick_band(per_band, "clock")
    # Count readings that came out as *something* - a parseable clock or a
    # plausible title.  (Not vote_title([r]): one reading can never reach the
    # agreement threshold, so that would have scored titles at zero and decided
    # polarity on the clock alone.)
    readable = lambda rs: sum(1 for r in rs if parse_osd_clock(r) or normalise_title(r))
    neg_better = readable(polarity["negated"]) > readable(polarity["normal"])
    out = {"clips_used": clips[:CALIBRATE_CLIPS], "frames_per_band": CALIBRATE_FRAMES,
           "title": title, "clock": clock, "negate": neg_better,
           "readable_frames": {"normal": readable(polarity["normal"]),
                               "negated": readable(polarity["negated"])}}
    log(f"  calibration   title band: {title['band'] if title else 'none found'}"
        f"   clock band: {clock['band'] if clock else 'none found'}"
        f"   polarity: {'negated' if neg_better else 'normal'}")
    return out


def read_clip(clip: str, layout: dict, container_start: Optional[datetime],
              frames: int = FRAMES, window_s: int = WINDOW_S) -> dict:
    """Title and clock for one stream, against the container's own date.

    `container_start` is the recorder-local time the container gives for the
    stream's first frame - the DHAV packed date, or the Hikvision `HK`
    descriptor.  Each sampled frame's OSD clock is compared with that date plus
    the frame's own offset into the stream."""
    out: dict = {"clip": os.path.basename(clip), "label": None,
                 "clock": {"verdict": "not compared", "detail": "no OSD reading"}}
    neg = bool(layout.get("negate"))
    if layout.get("title"):
        readings = _read_band(clip, layout["title"]["band"], TITLE_CHARS, frames, neg,
                              window_s)
        out["title_readings"] = readings
        out["label"] = vote_title(readings)
    if not layout.get("clock"):
        return out
    band = layout["clock"]["band"]
    readings = _read_band(clip, band, CLOCK_CHARS, frames, neg, window_s)
    out["clock_readings"] = readings
    checks = []
    step = window_s / float(frames)
    for i, raw in enumerate(readings):
        p = parse_osd_clock(raw)
        if not p:
            continue
        at = container_start + timedelta(seconds=i * step) if container_start else None
        r = resolve_against(p, at)
        c = clock_check(r.get("resolved"), at)
        c["t_s"] = round(i * step, 2)
        c["ambiguous_reading"] = p["ambiguous"]
        c["resolved_by"] = r.get("resolved_by")
        checks.append(c)
    out["clock_frames"] = checks
    agreed = [c for c in checks if c["verdict"] == "agrees"]
    compared = [c for c in checks if c["verdict"] in ("agrees", "disagrees")]
    if compared:
        offs = sorted(c["offset_s"] for c in compared)
        out["clock"] = {
            "verdict": "agrees" if len(agreed) >= (len(compared) + 1) // 2 else "disagrees",
            "frames_compared": len(compared), "frames_agreeing": len(agreed),
            "offset_s": offs[len(offs) // 2],
            "tolerance_s": CLOCK_TOL_S,
            "detail": f"{len(agreed)} of {len(compared)} sampled frames agree with the "
                      "container's own date for the same moment",
        }
    elif checks:
        out["clock"] = {"verdict": "read, not compared", "frames_read": len(checks),
                        "detail": "the picture's clock was read but the container gave no "
                                  "date for this stream to check it against"}
    return out


def container_times(out_dir: str) -> dict[str, datetime]:
    """Recorder-local start time per stream id, from whichever carve ran.

    Hikvision PS streams get theirs from the `HK` descriptor (`ps_report.json`);
    Dahua streams from the DHAV packed date in the carve report."""
    times: dict[str, datetime] = {}

    def keep(sid: str, raw: Optional[str]) -> None:
        if not sid or not raw:
            return
        try:
            times[sid] = datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    ps = os.path.join(out_dir, "carve", "ps_report.json")
    if os.path.exists(ps):
        with open(ps, "r", encoding="utf-8") as fh:
            for s in json.load(fh).get("streams", []):
                keep(s.get("id"), s.get("time_first_local"))
    cr = os.path.join(out_dir, "carve", "carve_report.json")
    if os.path.exists(cr):
        from analyse.timeline import parse_local
        with open(cr, "r", encoding="utf-8") as fh:
            for row in json.load(fh).get("streams", []):
                rec = row.get("recording", {})
                claim = next((c for c in rec.get("timestamps", [])
                              if c.get("source") == "container"), None)
                dt = parse_local(claim.get("raw_value", "")) if claim else None
                if dt:
                    times[rec.get("id")] = dt
    return times


def run(clips: list[str], case_dir: str, frames: int = FRAMES, window_s: int = WINDOW_S,
        layout: Optional[dict] = None, log=print) -> dict:
    """Read the OSD of every stream; writes <case_dir>/analytics/osd.json."""
    have_tools()
    out_dir = os.path.join(case_dir, "analytics")
    starts = container_times(case_dir)
    if layout is None:
        layout = calibrate(clips, window_s=window_s, log=log)
    if not layout.get("title") and not layout.get("clock"):
        raise RuntimeError(
            "no band of the picture read as a title or a clock on the "
            "calibration streams - this footage may carry no OSD, or the text "
            "may sit outside the four bands in analytics/osd_rules.py::BANDS")
    rows = []
    for i, clip in enumerate(clips):
        sid = os.path.splitext(os.path.basename(clip))[0]
        r = read_clip(clip, layout, starts.get(sid), frames=frames, window_s=window_s)
        r["container_local"] = (starts[sid].strftime("%Y-%m-%d %H:%M:%S")
                                if sid in starts else None)
        rows.append(r)
        lab = r["label"]["title"] if r["label"] else "-"
        log(f"  [{i + 1}/{len(clips)}] {r['clip']}  title {lab!r}  "
            f"clock {r['clock']['verdict']}")
    out = {
        "rule": OSD_RULE, "status": "lead, not evidence",
        "validation_status": "synthetic_only",
        "tools": {b: (shutil.which(b) or "") for b in ("ffmpeg", "tesseract")},
        "layout": layout, "frames_per_stream": frames, "window_s": window_s,
        "whitelists": {"title": TITLE_CHARS, "clock": CLOCK_CHARS},
        "streams": rows, "summary": summarise(rows),
        "notes": [
            "A camera label here is OCR of pixels, not a decoded field: it is what "
            "the recorder painted into the picture, read by a machine. It carries the "
            "share of sampled frames that agreed and is a lead for an examiner, who "
            "can confirm it by looking at the frame itself.",
            "The label names a camera; it identifies no person. There is no "
            "recognition of any kind in this tool.",
            "The clock check compares the picture's clock with the date decoded from "
            "the container. Both are the recorder's own wall clock, so they should "
            "agree; a disagreement says one of the two is wrong, not which.",
            "Nothing here converts a time to UTC. The recorder's zone and its error "
            "against a trusted clock are read from the unit at seizure, not from "
            "footage (analyse/timeline.py::ClockModel).",
            "A date painted as 01/02/2024 is two dates. Such a reading is flagged "
            "ambiguous and is only resolved where the container's own date chooses "
            "between the two readings; that choice is recorded as the container's.",
            "Where a stream did not decode, or its OSD was not readable, no label is "
            "emitted. An unnamed stream stays unnamed rather than being guessed.",
        ],
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "osd.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, default=str)
    return out

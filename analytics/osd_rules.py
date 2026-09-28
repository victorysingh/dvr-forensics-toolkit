"""Rules for reading a DVR's burned-in on-screen display - stdlib only, so
the core test suite can check them without Tesseract or ffmpeg installed.

The picture carries what the container often does not: the channel title the
installer typed ("Parking", "Road View 1"), and the recorder's own clock as it
was displayed.  Footage carved from outside every filesystem index has no
camera number anywhere in its bytes (docs/DAHUA_DHFS.md section 4: every Dahua
camera is "channel 0"), so for those streams the OSD is the only attribution
left.

Three things here are deliberate:

  * **No hardcoded text position.**  Where a recorder paints the title and the
    clock differs by vendor, by firmware and by installer.  Rather than assert
    coordinates we do not have, the reader OCRs four candidate bands and lets
    the footage say which one carried the text (`BANDS`, `pick_band`).
  * **A vote, not a reading.**  One OCR pass on one frame is a guess.  A label
    is only emitted when enough frames agree, and it carries the share that
    agreed (Rule 4 in docs/START_HERE.md: confidence, never yes/no).
  * **An ambiguous date stays ambiguous.**  `01/02/2024` is two dates.  This
    module returns both readings and flags them; only a second source - the
    container's own decoded date - is allowed to choose between them.

Everything produced here is an OSD *claim*: pixels an examiner can look at,
not a decoded field.  It is weaker evidence than a container timestamp and is
recorded as `source="osd_ocr"` in the data contract (core/contract.py).
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Optional

OSD_RULE = "osd.tesseract_title_clock.v1"

# Candidate bands for burned-in text, as (x1, y1, x2, y2) fractions of the
# frame.  A DVR paints the OSD in a corner; which corner is the recorder's
# choice, so all four are tried during calibration and the one that reads
# consistently is used for the rest of the case.
BANDS = {
    "top_left": (0.00, 0.00, 0.55, 0.12),
    "top_right": (0.45, 0.00, 1.00, 0.12),
    "bottom_left": (0.00, 0.88, 0.55, 1.00),
    "bottom_right": (0.45, 0.88, 1.00, 1.00),
}

# Tesseract character whitelists.  The clock one is the reason Tesseract was
# chosen over a heavier OCR (docs/TECH_STACK.md): fixed font, fixed position,
# high contrast, and few characters possible.  Real recorders put letters in
# their clocks too - Hikvision `28-07-2024 Sun 02:07:20`, CP Plus
# `01/05/2026 01:20:26 PM` - and a whitelist of digits alone read neither
# (VALIDATION_REPORT 8c), so the weekday and AM/PM letters are allowed.
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
_CLOCK_LETTERS = "".join(sorted(set("".join(WEEKDAYS) + "apm")))
CLOCK_CHARS = "0123456789-/:. " + _CLOCK_LETTERS + _CLOCK_LETTERS.upper()
TITLE_CHARS = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
               "0123456789 -_")

# A title must have at least one letter and this many characters to be a title
# rather than OCR noise off a brick wall.
MIN_TITLE_CHARS = 3
MAX_TITLE_CHARS = 32
# A label is emitted only when at least this many frames were read and at
# least this share of them agreed.
TITLE_MIN_FRAMES = 3
TITLE_MIN_SHARE = 0.6
# The same, for accepting a band during calibration.
BAND_MIN_SHARE = 0.5
# The OSD clock and the container's own date should agree to within this; DVRs
# paint the second they are in, so a second or two of slack is normal.
CLOCK_TOL_S = 3

_WS = re.compile(r"\s+")
# Digit-shaped letters, corrected only inside a group that is otherwise digits
# ("Camera O1" -> "Camera 01", but "Road View" is left alone).
_DIGIT_CONFUSION = {"O": "0", "o": "0", "D": "0", "Q": "0",
                    "I": "1", "l": "1", "i": "1", "|": "1",
                    "S": "5", "s": "5", "B": "8", "Z": "2", "z": "2"}


def _fix_digits(word: str) -> str:
    """'O1' -> '01'.  Only when the word is already mostly digits, so a real
    word is never mangled."""
    digits = sum(c.isdigit() for c in word)
    if not digits or digits + sum(c in _DIGIT_CONFUSION for c in word) != len(word):
        return word
    return "".join(_DIGIT_CONFUSION.get(c, c) for c in word)


def normalise_title(raw: str) -> Optional[str]:
    """OCR output -> a title, or None if it is not plausibly one.

    Keeps only whitelist characters, collapses whitespace, repairs digit-shaped
    letters inside numeric words, and rejects anything with no letter in it (a
    bare number is the clock, not a camera name)."""
    if not raw:
        return None
    kept = "".join(c if c in TITLE_CHARS else " " for c in raw)
    text = _WS.sub(" ", kept).strip(" -_")
    if not text:
        return None
    text = " ".join(_fix_digits(w) for w in text.split(" "))
    if not (MIN_TITLE_CHARS <= len(text) <= MAX_TITLE_CHARS):
        return None
    if not any(c.isalpha() for c in text):
        return None
    return text


def canonical(title: str) -> str:
    """Comparison form: case and spacing carry no meaning across frames."""
    return _WS.sub(" ", title.replace("_", " ")).strip().casefold()


def vote_title(readings: list[str]) -> Optional[dict]:
    """Agree on one title across frames, or return None with nothing claimed.

    `readings` is raw OCR text, one per frame.  The result carries the share of
    readable frames that agreed and every rejected alternative, so a weak
    attribution is visible as weak instead of looking decided."""
    titles = [t for t in (normalise_title(r) for r in readings) if t]
    if len(titles) < TITLE_MIN_FRAMES:
        return None
    groups = Counter(canonical(t) for t in titles)
    key, n = groups.most_common(1)[0]
    share = n / len(titles)
    if share < TITLE_MIN_SHARE:
        return None
    # report the commonest spelling of the winning group, not its casefold
    spellings = Counter(t for t in titles if canonical(t) == key)
    return {
        "title": spellings.most_common(1)[0][0],
        "confidence": round(share, 3),
        "frames_agreeing": n,
        "frames_read": len(titles),
        "frames_sampled": len(readings),
        "alternatives": {k: v for k, v in groups.items() if k != key},
    }


def _band_score(readings: list[str], kind: str) -> float:
    if not readings:
        return 0.0
    if kind == "clock":
        return sum(1 for r in readings if parse_osd_clock(r)) / len(readings)
    v = vote_title(readings)
    return v["confidence"] * v["frames_read"] / len(readings) if v else 0.0


def pick_band(per_band: dict[str, list[list[str]]], kind: str = "title") -> Optional[dict]:
    """Which candidate band actually carried the text.

    `per_band` maps a band name to one list of OCR readings PER CALIBRATION
    STREAM.  Scoring is per stream and then averaged, because two streams are
    two cameras with two different titles: pooling their readings would make a
    band that reads perfectly on both look like a band that cannot agree with
    itself.  A band where nothing parses scores zero and is discarded.

    Returning the score for every band keeps the choice auditable - and says,
    for the comparative-analysis deliverable, where this OEM paints its OSD."""
    scores: dict[str, float] = {}
    for band, groups in per_band.items():
        per_clip = [_band_score(g, kind) for g in groups if g]
        scores[band] = sum(per_clip) / len(per_clip) if per_clip else 0.0
    band, score = max(scores.items(), key=lambda kv: kv[1])
    if score < BAND_MIN_SHARE:
        return None
    return {"band": band, "score": round(score, 3),
            "scores": {k: round(v, 3) for k, v in sorted(scores.items())}}


# --- the burned-in clock ---------------------------------------------------
# Every layout a DVR is known to paint.  Two of them are the same eight digits
# in a different order, which is the whole problem.
_CLOCK_FORMATS = [
    ("%Y-%m-%d %H:%M:%S", "yyyy-mm-dd"),
    ("%d-%m-%Y %H:%M:%S", "dd-mm-yyyy"),
    ("%m-%d-%Y %H:%M:%S", "mm-dd-yyyy"),
]
# A DVR's clock reads in this range or the reading is OCR noise.  It also
# rejects a two-digit year being taken for a year in the first century.
YEAR_MIN, YEAR_MAX = 2000, 2100
_CLOCK_RE = re.compile(r"(\d{1,4})\D(\d{1,2})\D(\d{1,4})\D+(\d{1,2})\D(\d{2})\D(\d{2})")
_AMPM_RE = re.compile(r"(?<![a-z])([ap])\.?\s?m\b", re.IGNORECASE)
_WEEKDAY_RE = re.compile(r"(?<![a-z])(mon|tue|wed|thu|fri|sat|sun)[a-z]*", re.IGNORECASE)
# a run of digits and digit-shaped letters: "2O24" -> "2024", but a letter
# standing alone ("S" of "Sun") is left for the weekday
_DIGITISH = re.compile("[0-9" + re.escape("".join(_DIGIT_CONFUSION)) + "]+")


def parse_osd_clock(raw: str) -> Optional[dict]:
    """OCR text -> the date and time the recorder displayed.

    Returns every reading the digits allow, never a single guessed one:

        {"readings": [datetime, ...], "ambiguous": bool, "formats": [...],
         "twelve_hour": "AM" | "PM" | None, "weekday": "Sun" | None,
         "weekday_checked": bool, "weekday_disagrees": bool}

    `01/02/2024` yields two readings and `ambiguous: True`.  Choosing between
    them needs a second source.  The container's date is one (`resolve_against`);
    the weekday the recorder painted beside the date is the other, and it is
    applied here: of the readings the digits allow, only those falling on that
    weekday are kept.  A weekday that fits none of them is reported, not
    trusted over the digits.  AM/PM turns the hour to 24-hour time; an hour
    over 12 next to AM/PM is not a clock."""
    if not raw:
        return None
    text = _WS.sub(" ", "".join(c if c in CLOCK_CHARS else " " for c in raw))
    text = _DIGITISH.sub(lambda m: _fix_digits(m.group()), text)
    m = _CLOCK_RE.search(text)
    if not m:
        return None
    a, b, c, hh, mm, ss = m.groups()
    # the weekday usually sits between the date and the time, inside the
    # match; AM/PM after it - so both are looked for in the whole line
    ampm = _AMPM_RE.search(text)
    hour = int(hh)
    if ampm:
        if not 1 <= hour <= 12:
            return None
        hour = hour % 12 + (12 if ampm.group(1).lower() == "p" else 0)
    out: list[datetime] = []
    formats: list[str] = []
    for fmt, name in _CLOCK_FORMATS:
        # The three groups go in as they were read; the format decides which
        # is the year.  An impossible combination raises and is skipped.
        try:
            dt = datetime.strptime(f"{a}-{b}-{c} {hour}:{mm}:{ss}", fmt)
        except ValueError:
            continue
        if not YEAR_MIN <= dt.year <= YEAR_MAX or dt in out:
            continue
        out.append(dt)
        formats.append(name)
    if not out:
        return None
    wd = _WEEKDAY_RE.search(text)
    checked = disagrees = False
    if wd:
        day = [d[:3] for d in WEEKDAYS].index(wd.group(1).lower())
        fit = [(r, f) for r, f in zip(out, formats) if r.weekday() == day]
        if fit:
            out, formats = [r for r, _ in fit], [f for _, f in fit]
            checked = True
        else:
            disagrees = True
    return {"readings": out, "ambiguous": len(out) > 1, "formats": formats,
            "twelve_hour": ampm.group(1).upper() + "M" if ampm else None,
            "weekday": wd.group(1).title() if wd else None,
            "weekday_checked": checked, "weekday_disagrees": disagrees,
            "raw": raw.strip()}


def resolve_against(parsed: dict, container: Optional[datetime]) -> dict:
    """Let the container's decoded date choose between ambiguous OSD readings.

    This is the only place a reading may be picked, and it records that the
    container did the picking - the OSD did not suddenly become unambiguous.
    With no container date an ambiguous reading stays unresolved."""
    out = dict(parsed)
    readings = parsed["readings"]
    if container is None:
        out["resolved"] = None if parsed["ambiguous"] else readings[0]
        out["resolved_by"] = None if parsed["ambiguous"] else "single reading"
        return out
    near = [(abs((r - container).total_seconds()), r, f)
            for r, f in zip(readings, parsed["formats"])]
    near.sort(key=lambda t: t[0])
    if len(near) > 1 and near[0][0] == near[1][0]:
        out["resolved"], out["resolved_by"] = None, "two readings fit equally"
        return out
    out["resolved"] = near[0][1]
    out["resolved_format"] = near[0][2]
    out["resolved_by"] = ("container date" if parsed["ambiguous"]
                          else "single reading")
    return out


def clock_check(osd: Optional[datetime], container: Optional[datetime]) -> dict:
    """Compare the clock in the picture with the clock in the container.

    Both are the recorder's own wall clock reached by different routes, so they
    should match.  A disagreement is worth a line in the validation report: it
    means the decode rule, the OCR, or the recorder itself is wrong.  This does
    NOT measure the recorder's error against true time - only an examiner with
    a trusted clock at seizure can do that (analyse/timeline.py::ClockModel)."""
    if osd is None or container is None:
        return {"verdict": "not compared",
                "detail": "no OSD reading" if osd is None else "no container date"}
    delta = (osd - container).total_seconds()
    agrees = abs(delta) <= CLOCK_TOL_S
    return {
        "verdict": "agrees" if agrees else "disagrees",
        "offset_s": delta,
        "osd_local": osd.strftime("%Y-%m-%d %H:%M:%S"),
        "container_local": container.strftime("%Y-%m-%d %H:%M:%S"),
        "tolerance_s": CLOCK_TOL_S,
        "detail": (f"the picture and the container agree to within {CLOCK_TOL_S} s"
                   if agrees else
                   f"the picture reads {delta:+.0f} s from the container's own date - "
                   "one of the two is wrong, and which is not decided here"),
    }


def summarise(streams: list[dict]) -> dict:
    """Case-level tally: how many streams the picture named, and how the two
    clocks compared across all of them."""
    labelled = [s for s in streams if s.get("label")]
    checks = Counter(s.get("clock", {}).get("verdict", "not compared") for s in streams)
    by_label: Counter = Counter(s["label"]["title"] for s in labelled)
    offsets = [s["clock"]["offset_s"] for s in streams
               if s.get("clock", {}).get("offset_s") is not None]
    out = {
        "streams": len(streams),
        "streams_named_by_the_picture": len(labelled),
        "titles": dict(by_label.most_common()),
        "clock_checks": dict(checks),
    }
    if offsets:
        offsets.sort()
        out["clock_offset_s"] = {
            "min": offsets[0], "max": offsets[-1],
            "median": offsets[len(offsets) // 2],
        }
    return out

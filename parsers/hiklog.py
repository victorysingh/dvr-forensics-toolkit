"""Hikvision system log: the recorder's own record of what happened to it.

A Hikvision disk keeps a system log next to its master sector: every power
on, abnormal shutdown, login, configuration change, playback, disk format and
recording start, each with the recorder's time.  Han, Jeong & Lee (2015)
describe the area and its `RATS` record marker; Dragonas, Lambrinoudakis &
Kotsis (J Forensic Sci 68(6), 2023) revisit the records and their meaning.
Their tool carries no licence, so nothing here is taken from it.

WHAT THIS READS, AND WHERE EACH PIECE COMES FROM
------------------------------------------------
  * The master sector (`HIKVISION@HANGZHOU` at +0x10) and the fields used
    below were read off real media: drive ST1000VX005 s/n Z9C2632A, whose
    primary master at 0x200 a later reformat overwrote and whose backup
    survived at 0x4C56000.  Each field is cross-checked against the others
    and against structures found independently: log start + log size equals
    the log-end field; block count x block size equals the data size; the
    data offset equals the data base the HIKBTREE index gave; both HIKBTREE
    offsets are where those copies were found.  SOURCE_OBSERVED.
  * A log record is `RATS`, a u32 (0x14 on this disk; the 2015 paper saw
    0x01), the u32 Unix-style time, a u16 major type and a u16 minor type,
    then a payload up to the next record.  A length field was not
    identified, so a record runs to the next header.  On operation records
    the payload opens with the user name.  SOURCE_OBSERVED.
  * The meaning of each (major, minor) pair is Hikvision's own, from its
    SDK (parsers/hik_log_codes.py).  On the real disk every record whose
    code that SDK version lists is named by it; the rest are reported as
    undefined, not guessed.
  * The log's clock is the recorder's wall clock - the same clock as the
    footage: power-on records are followed by a new stream a median 80 s
    later, and by nothing at +/-5:30.  So its times are recorder-local, zone
    unknown, exactly like the footage's.

Status `spec_only`: read off real media and checked for consistency, but not
matched against the log the recorder itself shows or exports.
"""

from __future__ import annotations

import re
import struct
from datetime import datetime, timezone
from statistics import median
from typing import Optional

from parsers.hik_log_codes import MAJOR, MINOR

PARSER_RULE = "hikvision.systemlog.rats.v1"
VALIDATION_STATUS = "spec_only"

MASTER_MAGIC = b"HIKVISION@HANGZHOU"
MAGIC_AT = 0x10                  # the magic sits 0x10 into the master sector
PRIMARY_MASTER = 0x200
MASTER_SEARCH = 256 << 20        # the backup follows the log area
RECORD_MAGIC = b"RATS"
HDR = struct.Struct("<4sIIHH")  # magic, version, time, major, minor
MAX_PAYLOAD = 8 << 10
READ_CHUNK = 8 << 20

# (name, offset, format) - relative to the master sector's start.
MASTER_FIELDS = [
    ("fs_version", 0x30, "str16"),
    ("capacity", 0x48, "<Q"),
    ("log_offset", 0x50, "<Q"),
    ("log_size", 0x58, "<Q"),
    ("log_end", 0x60, "<Q"),
    ("area2_size", 0x68, "<Q"),
    ("data_offset", 0x78, "<Q"),
    ("data_size", 0x80, "<Q"),
    ("block_size", 0x88, "<Q"),
    ("block_count", 0x90, "<Q"),
    ("hikbtree1_offset", 0x98, "<Q"),
    ("hikbtree1_size", 0xA0, "<Q"),
    ("hikbtree2_offset", 0xA8, "<Q"),
    ("hikbtree2_size", 0xB0, "<Q"),
    ("init_time", 0xF0, "<I"),
]


def _read(dev, off: int, n: int) -> bytes:
    size = getattr(dev, "size_bytes", 0)
    if off < 0 or (size and off >= size):
        return b""
    try:
        return dev.read_at(off, n if not size else min(n, size - off))
    except Exception:                                    # noqa: BLE001
        return b""


def _fmt_time(t: int) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def find_masters(dev) -> list[int]:
    """Start offsets of every master-sector copy: the primary at 0x200 and
    whatever copies lie in the first 256 MiB."""
    found = []
    if _read(dev, PRIMARY_MASTER + MAGIC_AT, len(MASTER_MAGIC)) == MASTER_MAGIC:
        found.append(PRIMARY_MASTER)
    pos, tail = 0, b""
    limit = min(MASTER_SEARCH, getattr(dev, "size_bytes", 0) or MASTER_SEARCH)
    while pos < limit:
        chunk = _read(dev, pos, READ_CHUNK)
        if not chunk:
            break
        buf, base = tail + chunk, pos - len(tail)
        i = buf.find(MASTER_MAGIC)
        while i >= 0:
            start = base + i - MAGIC_AT
            if start >= 0 and start not in found:
                found.append(start)
            i = buf.find(MASTER_MAGIC, i + 1)
        tail = buf[-(len(MASTER_MAGIC) - 1):]
        pos += len(chunk)
    return sorted(found)


def read_master(dev, start: int) -> dict:
    raw = _read(dev, start, 0x100)
    out = {"offset": start}
    if len(raw) < 0x100:                     # the image ends inside it: the rest reads as zeros
        out["truncated"] = True
        raw = raw.ljust(0x100, b"\0")
    for name, off, fmt in MASTER_FIELDS:
        if fmt == "str16":
            out[name] = raw[off:off + 16].split(b"\x00", 1)[0].decode("ascii", "replace")
        else:
            out[name] = struct.unpack_from(fmt, raw, off)[0]
    return out


def check_master(dev, m: dict) -> list[dict]:
    """Each field against the others and against the disk.  A check that
    cannot be made (the structure lies beyond this image) says so."""
    size = getattr(dev, "size_bytes", 0)
    checks = [
        {"check": "log start + log size = log end",
         "ok": m["log_offset"] + m["log_size"] == m["log_end"]},
        {"check": "block count x block size = data size",
         "ok": m["block_count"] * m["block_size"] == m["data_size"]},
        {"check": "the data area ends inside the capacity",
         "ok": 0 < m["data_offset"] + m["data_size"] <= m["capacity"]},
        {"check": "the log lies before the data area",
         "ok": 0 < m["log_offset"] < m["log_end"] <= m["data_offset"]},
    ]
    for k in ("hikbtree1", "hikbtree2"):
        off = m[f"{k}_offset"]
        if size and off + 0x20 > size:
            checks.append({"check": f"HIKBTREE at {k} offset", "ok": None,
                           "detail": "beyond this image"})
        else:
            checks.append({"check": f"HIKBTREE at {k} offset",
                           "ok": b"HIKBTREE" in _read(dev, off, 0x20)})
    return checks


def _cstr(b: bytes) -> str:
    s = b.split(b"\x00", 1)[0]
    return s.decode("ascii") if s and all(32 <= c < 127 for c in s) else ""


def read_log(dev, start: int, end: int, init_time: int = 0) -> list[dict]:
    """Every record between `start` and `end`, in disk order."""
    heads, pos = [], start
    while pos < end:
        buf = _read(dev, pos, min(READ_CHUNK, end - pos) + HDR.size)
        if not buf:
            break
        i = buf.find(RECORD_MAGIC)
        while 0 <= i and pos + i < end:
            if i + HDR.size <= len(buf):
                _, ver, t, major, minor = HDR.unpack_from(buf, i)
                # A record marker in payload bytes is chance; a real record
                # has a known major type and a time after the disk began.
                if major in MAJOR and t >= init_time - 86400 and t > 946684800:
                    heads.append((pos + i, ver, t, major, minor))
            i = buf.find(RECORD_MAGIC, i + 1)
        pos += min(READ_CHUNK, end - pos)
    records = []
    for k, (off, ver, t, major, minor) in enumerate(heads):
        nxt = heads[k + 1][0] if k + 1 < len(heads) else min(end, off + HDR.size + MAX_PAYLOAD)
        payload = _read(dev, off + HDR.size, min(nxt - off - HDR.size, MAX_PAYLOAD))
        user = _cstr(payload[:32]) if major == 3 else ""
        text = [s.decode("ascii") for s in re.findall(rb"[ -~]{4,}", payload)
                if s.decode("ascii") != user][:8]
        name, desc = MINOR.get((major, minor), ("UNDEFINED", ""))
        records.append({
            "offset": off, "version": ver, "time_local": _fmt_time(t), "t": t,
            "major": major, "minor": minor,
            "type": f"{MAJOR[major]}: {desc or name}" if name != "UNDEFINED"
                    else f"{MAJOR[major]}: undefined 0x{minor:02X}",
            "defined": name != "UNDEFINED", "user": user, "text": text,
            "bytes": nxt - off})
    return records


POWER = {(3, 0x41): "power on", (3, 0x42): "power off", (3, 0x43): "abnormal shutdown"}


def log_clock_vs_footage(power_on: list[int], stream_starts: list[int],
                         window: int = 120) -> dict:
    """Which clock the log keeps, from the footage.  A power-on is followed
    by a new stream once the recorder has booted; count how many are, within
    `window` seconds, at every shift from -14 h to +14 h in half hours.  If
    no shift is clearly best, nothing is claimed."""
    import bisect
    starts = sorted(stream_starts)

    def hits(shift):
        n, delays = 0, []
        for t in power_on:
            i = bisect.bisect_left(starts, t + shift)
            if i < len(starts) and starts[i] - (t + shift) <= window:
                n += 1
                delays.append(starts[i] - (t + shift))
        return n, delays

    score = {s: hits(s) for s in range(-14 * 3600, 14 * 3600 + 1, 1800)}
    best = max(score, key=lambda s: score[s][0])
    runner = max((v[0] for s, v in score.items() if s != best), default=0)
    n, delays = score[best]
    clear = n >= 5 and n >= 3 * max(runner, 1)
    return {"power_on_records": len(power_on), "window_s": window,
            "best_shift_s": best if clear else None,
            "followed_by_a_stream": n, "next_best": runner,
            "median_delay_s": median(delays) if delays else None,
            "verdict": ("the log keeps the footage's clock" if clear and best == 0
                        else f"the log runs {best / 3600:+.1f} h from the footage's clock"
                        if clear else "not determined")}


def summarise(records: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    for r in records:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    newest = max(records, key=lambda r: r["t"]) if records else None
    return {
        "records": len(records),
        "defined_by_the_sdk": sum(1 for r in records if r["defined"]),
        "first_local": min((r["time_local"] for r in records), default=None),
        "last_local": max((r["time_local"] for r in records), default=None),
        "newest_at": newest["offset"] if newest else None,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "power": {v: sum(1 for r in records if (r["major"], r["minor"]) == k)
                  for k, v in POWER.items()},
        "user_actions": [{k: r[k] for k in ("time_local", "type", "user", "offset")}
                         for r in records if r["user"]],
    }


def read(dev, stream_starts: Optional[list[int]] = None) -> dict:
    """Master sector, checks, every log record and a summary."""
    masters = find_masters(dev)
    if not masters:
        return {"rule": PARSER_RULE, "error": "no HIKVISION@HANGZHOU master sector found "
                                              "at 0x200 or in the first 256 MiB"}
    m = read_master(dev, masters[0])
    checks = check_master(dev, m)
    notes = []
    if masters[0] != PRIMARY_MASTER:
        notes.append(f"no master sector at 0x{PRIMARY_MASTER:X}; the copy at "
                     f"0x{masters[0]:X} was used")
    if any(c["ok"] is False for c in checks):
        notes.append("a master-sector check failed: log offsets may be wrong")
    records = read_log(dev, m["log_offset"], m["log_end"], m["init_time"])
    out = {"rule": PARSER_RULE, "validation_status": VALIDATION_STATUS,
           "master_copies": masters, "master": m, "checks": checks,
           "log_area": [m["log_offset"], m["log_end"]],
           "init_time_local": _fmt_time(m["init_time"]),
           "summary": summarise(records), "notes": notes,
           "time_basis": "the recorder's wall clock, zone unknown - not UTC"}
    if stream_starts is not None:
        pon = [r["t"] for r in records if (r["major"], r["minor"]) == (3, 0x41)]
        out["clock_vs_footage"] = log_clock_vs_footage(pon, stream_starts)
    out["recorder_log"] = [{k: r[k] for k in ("offset", "time_local", "major", "minor",
                                              "type", "user", "text")} for r in records]
    return out

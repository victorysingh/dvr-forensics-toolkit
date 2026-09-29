"""The recorder's clock offset from UTC, measured from daylight.

A recorder's clock carries no time zone, and its error against true time is
normally measured at the unit (SOP 1.2).  When the unit is out of reach, an
outdoor camera still holds a clock no one can set: the sun.  Most CCTV
cameras switch to infrared - a black-and-white picture - when the light
falls below a threshold at dusk, and back to colour when it rises past it at
dawn.  A light threshold is, to first order, a sun elevation.

So: find every dusk and dawn switch in footage sampled over several days,
stamped with the recorder's clock.  For a trial offset T (recorder clock =
UTC + T), compute the sun's elevation at each switch.  At the right T, every
switch - dusk and dawn alike - happens at the same elevation; a wrong T
moves the dusk elevations one way and the dawn ones the other, because the
sun is setting at one and rising at the other.  The T that makes them agree
is the recorder's zone plus its clock error, measured without the unit and
without knowing the camera's threshold.  Checks: at a dusk switch the sun
must be setting and at a dawn switch rising (which also rules out the
12-hour alias), and the switch elevation must be a twilight one.

Limits, stated with the result: cloud and weather move the light threshold
(the spread of the per-switch offsets shows by how much); a street lamp or
a camera without infrared gives no switch; the result settles a zone or an
hour and a clock error of minutes, not seconds.  Estimating clocks from
daylight is not new (e.g. Sundial, EWSN 2009); reading it from DVR footage's
infrared switches is the application here.

Sun position: NOAA's solar calculator equations (the Meeus-based spreadsheet
at gml.noaa.gov/grad/solcalc), no refraction.  Stdlib only, read-only.

    python -m analyse.daylight sample CLIP --out series.jsonl [--start T --fps F] [--every 60]
    python -m analyse.daylight estimate series.jsonl --lat 12.97 --lon 77.59 [--zone 330]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from core import proc

RULE = "analyse.daylight.v1"
MONO_MAX = 4.0          # mean chroma (max-min of R,G,B, 0-255) at or below: infrared picture
MIN_RUN = 3             # samples a mode must hold to count (a headlight flash does not)
MAX_GAP = timedelta(minutes=30)   # a switch between samples further apart is not placed
T_RANGE = range(-14 * 60, 14 * 60 + 1)          # trial offsets, minutes
TWILIGHT = (-12.0, 10.0)                         # plausible switch elevations, degrees


# -- the sun (NOAA solar calculator) -----------------------------------------------
def solar_elevation(utc: datetime, lat: float, lon: float) -> float:
    """Sun elevation in degrees at a UTC instant (naive = UTC), no refraction."""
    if utc.tzinfo is not None:
        utc = utc.astimezone(timezone.utc).replace(tzinfo=None)
    jd = (utc - datetime(2000, 1, 1, 12)).total_seconds() / 86400 + 2451545.0
    jc = (jd - 2451545.0) / 36525
    l0 = (280.46646 + jc * (36000.76983 + jc * 0.0003032)) % 360
    m = 357.52911 + jc * (35999.05029 - 0.0001537 * jc)
    e = 0.016708634 - jc * (0.000042037 + 0.0000001267 * jc)
    rad = math.radians
    c = (math.sin(rad(m)) * (1.914602 - jc * (0.004817 + 0.000014 * jc))
         + math.sin(rad(2 * m)) * (0.019993 - 0.000101 * jc) + math.sin(rad(3 * m)) * 0.000289)
    omega = 125.04 - 1934.136 * jc
    app_long = l0 + c - 0.00569 - 0.00478 * math.sin(rad(omega))
    obliq0 = 23 + (26 + (21.448 - jc * (46.815 + jc * (0.00059 - jc * 0.001813))) / 60) / 60
    obliq = obliq0 + 0.00256 * math.cos(rad(omega))
    decl = math.degrees(math.asin(math.sin(rad(obliq)) * math.sin(rad(app_long))))
    y = math.tan(rad(obliq / 2)) ** 2
    eot = 4 * math.degrees(y * math.sin(2 * rad(l0)) - 2 * e * math.sin(rad(m))
                           + 4 * e * y * math.sin(rad(m)) * math.cos(2 * rad(l0))
                           - 0.5 * y * y * math.sin(4 * rad(l0))
                           - 1.25 * e * e * math.sin(2 * rad(m)))
    minutes = utc.hour * 60 + utc.minute + utc.second / 60
    tst = (minutes + eot + 4 * lon) % 1440
    ha = tst / 4 - 180
    cos_z = (math.sin(rad(lat)) * math.sin(rad(decl))
             + math.cos(rad(lat)) * math.cos(rad(decl)) * math.cos(rad(ha)))
    return 90 - math.degrees(math.acos(max(-1.0, min(1.0, cos_z))))


# -- switches ---------------------------------------------------------------------
def switches(series: Iterable[tuple[datetime, float]], mono_max: float = MONO_MAX,
             min_run: int = MIN_RUN) -> list[dict]:
    """Dusk (colour -> infrared) and dawn (infrared -> colour) switches, each at
    the midpoint of the two samples around it, with half their gap as its
    uncertainty.  A mode must hold for min_run samples to count."""
    pts = sorted(series)
    runs: list[list] = []                      # [mode, first index, last index]
    for i, (_, chroma) in enumerate(pts):
        mode = "ir" if chroma <= mono_max else "colour"
        if runs and runs[-1][0] == mode:
            runs[-1][2] = i
        else:
            runs.append([mode, i, i])
    # absorb runs too short to be a real change (a headlight, a flash)
    kept: list[list] = []
    for r in runs:
        if r[2] - r[1] + 1 < min_run and kept:
            kept[-1][2] = r[2]
            continue
        if kept and kept[-1][0] == r[0]:
            kept[-1][2] = r[2]
        else:
            kept.append(r)
    out = []
    for a, b in zip(kept, kept[1:]):
        if a[2] - a[1] + 1 < min_run or b[2] - b[1] + 1 < min_run:
            continue
        t0, t1 = pts[a[2]][0], pts[b[1]][0]
        if t1 - t0 > MAX_GAP:
            continue
        out.append({"kind": "dusk" if a[0] == "colour" else "dawn",
                    "time": t0 + (t1 - t0) / 2, "uncertainty_s": (t1 - t0).total_seconds() / 2})
    return out


# -- the offset -----------------------------------------------------------------------
def estimate(events: list[dict], lat: float, lon: float, zone: Optional[int] = None) -> dict:
    kinds = {e["kind"] for e in events}
    if kinds != {"dusk", "dawn"}:
        return {"rule": RULE, "offset_min": None, "events": len(events),
                "why": "needs at least one dusk and one dawn switch: with one kind, every "
                       "offset looks equally good"}
    best = None
    for t in T_RANGE:
        elev, ok = [], True
        for e in events:
            utc = e["time"] - timedelta(minutes=t)
            h = solar_elevation(utc, lat, lon)
            rising = solar_elevation(utc + timedelta(minutes=2), lat, lon) > h
            if (e["kind"] == "dusk") == rising:     # dusk needs a setting sun, dawn a rising one
                ok = False
                break
            elev.append(h)
        if not ok:
            continue
        mean = statistics.fmean(elev)
        if not TWILIGHT[0] <= mean <= TWILIGHT[1]:
            continue
        spread = statistics.pstdev(elev)
        if best is None or spread < best[1]:
            best = (t, spread, mean)
    if best is None:
        return {"rule": RULE, "offset_min": None, "events": len(events),
                "why": "no offset puts every dusk switch at a setting sun and every dawn "
                       "switch at a rising one at a twilight elevation"}
    t_best, spread, h_star = best
    # each switch's own offset: where the sun stood at the common elevation
    per = []
    for e in events:
        cands = []
        for t in range(t_best - 180, t_best + 181):
            utc = e["time"] - timedelta(minutes=t)
            cands.append((abs(solar_elevation(utc, lat, lon) - h_star), t))
        per.append({"kind": e["kind"], "time": e["time"].strftime("%Y-%m-%d %H:%M:%S"),
                    "offset_min": min(cands)[1], "uncertainty_s": e["uncertainty_s"]})
    offs = sorted(p["offset_min"] for p in per)
    q = statistics.quantiles(offs, n=4) if len(offs) >= 4 else [offs[0], 0, offs[-1]]
    res = {"rule": RULE, "lat": lat, "lon": lon, "events": len(events),
           "dusk": sum(e["kind"] == "dusk" for e in events),
           "dawn": sum(e["kind"] == "dawn" for e in events),
           "offset_min": t_best, "switch_elevation_deg": round(h_star, 2),
           "elevation_spread_deg": round(spread, 2),
           "per_switch_offset_min": {"median": statistics.median(offs),
                                     "iqr": [q[0], q[-1]], "range": [offs[0], offs[-1]]},
           "switches": per,
           "reading": (f"recorder clock = UTC {t_best / 60:+.2f} h (per-switch median "
                       f"{statistics.median(offs):+.0f} min, middle half {q[0]:+.0f} to "
                       f"{q[-1]:+.0f}); the camera switches at a sun elevation of "
                       f"{h_star:.1f} deg")}
    if zone is not None:
        res["zone_min"] = zone
        res["clock_error_min"] = t_best - zone
        res["reading"] += (f"; with the zone at UTC{zone / 60:+g} h, the clock runs "
                           f"{t_best - zone:+d} min from true time")
    return res


# -- sampling footage -------------------------------------------------------------
def chroma(rgb: bytes) -> float:
    """Mean over pixels of max(R,G,B) - min(R,G,B): ~0 for an infrared picture."""
    n = len(rgb) // 3
    return sum(max(rgb[i:i + 3]) - min(rgb[i:i + 3]) for i in range(0, 3 * n, 3)) / max(n, 1)


def sample(clip: str, every: int = 60, start: Optional[str] = None,
           fps: Optional[float] = None, ffmpeg: str = "ffmpeg") -> list[tuple[datetime, float]]:
    """(recorder time, chroma) every `every` seconds of a clip.  A .dav keeps the
    recorder's own frame times (ffmpeg -copyts: the DHAV date as if UTC, i.e.
    the recorder's wall clock); a clip without times needs --start (and --fps
    for a raw stream)."""
    w, h = 64, 36
    fmt = ["-f", "dhav"] if clip.lower().endswith(".dav") else []
    rate = ["-r", str(fps)] if fps else []
    cmd = [ffmpeg, "-hide_banner", "-nostdin", "-copyts", *fmt, *rate, "-i", clip,
           "-vf", f"fps=1/{every},scale={w}:{h},showinfo", "-f", "rawvideo",
           "-pix_fmt", "rgb24", "-"]
    p = proc.run(cmd, timeout=proc.STREAM_S, capture_output=True)
    if p.timed_out:
        raise RuntimeError(f"ffmpeg did not finish sampling {clip} within {proc.STREAM_S} s")
    times = [float(m) for m in re.findall(rb"pts_time:(-?[0-9.]+)", p.stderr)]
    size = w * h * 3
    frames = [p.stdout[i:i + size] for i in range(0, len(p.stdout) - size + 1, size)]
    base = datetime.strptime(start, "%Y-%m-%d %H:%M:%S") if start else None
    out = []
    for k, frame in enumerate(frames):
        t = times[k] if k < len(times) else k * every
        when = (base + timedelta(seconds=t - (times[0] if times else 0)) if base
                else datetime(1970, 1, 1) + timedelta(seconds=t))
        out.append((when, round(chroma(frame), 2)))
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("clips", nargs="+")
    s.add_argument("--out", required=True, help="series file (JSON lines), appended to")
    s.add_argument("--every", type=int, default=60, help="seconds between samples")
    s.add_argument("--start", help="recorder time of the first frame, for clips without times")
    s.add_argument("--fps", type=float, help="frame rate, for a raw stream")
    s.add_argument("--ffmpeg", default="ffmpeg")
    e = sub.add_parser("estimate")
    e.add_argument("series")
    e.add_argument("--lat", type=float, required=True)
    e.add_argument("--lon", type=float, required=True)
    e.add_argument("--zone", type=int, help="the zone to test, minutes (e.g. 330 for IST)")
    e.add_argument("--mono-max", type=float, default=MONO_MAX)
    a = ap.parse_args(argv)
    if a.cmd == "sample":
        n = 0
        with open(a.out, "a", encoding="utf-8") as fh:
            for clip in a.clips:
                for when, c in sample(clip, a.every, a.start, a.fps, a.ffmpeg):
                    fh.write(json.dumps({"time": when.strftime("%Y-%m-%d %H:%M:%S"),
                                         "chroma": c, "clip": clip}) + "\n")
                    n += 1
        print(f"{n} samples -> {a.out}")
        return 0
    series = []
    with open(a.series, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                series.append((datetime.strptime(r["time"], "%Y-%m-%d %H:%M:%S"), r["chroma"]))
    ev = switches(series, a.mono_max)
    res = estimate(ev, a.lat, a.lon, a.zone)
    print(json.dumps({k: v for k, v in res.items() if k != "switches"}, indent=1))
    return 0 if res.get("offset_min") is not None else 1


if __name__ == "__main__":
    sys.exit(main())

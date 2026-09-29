"""How often the OSD reader reads the burned-in clock and title right, on real footage.

    python -m validate.osd_eval sample CLIP[@SECONDS] [...] --out DIR
    #   ... fill in DIR/osd_labels.csv: clock_true, title_true, as the eye reads them ...
    python -m validate.osd_eval score DIR

A clip is anything ffmpeg reads (a recorder's .dav/.mp4/.avi export, or the
tool's own extracted streams).  Each clip is treated as its own recorder.
read-osd samples FRAMES frames from the first WINDOW_S seconds of a stream,
which suits carved streams minutes long; CLIP@SECONDS shortens the window for
a short clip, so it is still read on as many frames:

  sample  calibrates on the clip exactly as `read-osd` calibrates on a case
          (analytics/osd.py: every band, both polarities), reads the title
          and clock bands it chose on the frames `read-osd` samples, and
          saves those same frames whole as frames/CC_K.jpg, so the labels
          come from the picture and not from the reader.  It writes
          osd.json (layouts and raw readings) and osd_labels.csv, one row per
          sampled frame, with what the reader got beside two blank columns.
  score   per clip and overall: whether the reader found the clock and the
          title at all, and, frame by frame, whether the clock it parsed is
          the one painted (to the second), wrong, or unread; the title vote
          against the painted title.  Stdlib only.

Labels: `clock_true` as YYYY-MM-DD HH:MM:SS (24-hour), `title_true` the
camera's name as painted.  Leave a cell empty when the frame has no clock or
no title; write `?` when the eye cannot read it either (not scored).  Needs
ffmpeg and tesseract to sample.  Read-only on the clips.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime


def _frames(clip: str, out_dir: str, stem: str, window_s: float) -> list[str]:
    """The frames read-osd samples (the same -t window and fps), whole."""
    from analytics import osd
    fmt = ["-f", osd.codec_of(clip)] if osd.codec_of(clip) else []
    pattern = os.path.join(out_dir, f"{stem}_%d.jpg")
    subprocess.run(["ffmpeg", "-nostdin", "-v", "quiet", "-y", "-t", str(window_s), *fmt,
                    "-i", clip, "-vf", f"fps={osd.FRAMES / float(window_s)},scale=960:-2",
                    "-frames:v", str(osd.FRAMES), "-start_number", "0", pattern], check=False)
    return sorted((f for f in os.listdir(out_dir) if f.startswith(stem + "_")),
                  key=lambda f: int(f.rsplit("_", 1)[1].split(".")[0]))


def sample(clips: list[str], out: str, log=print) -> dict:
    from analytics import osd
    from analytics.osd_rules import parse_osd_clock
    osd.have_tools()
    os.makedirs(os.path.join(out, "frames"), exist_ok=True)
    runs, rows = [], []
    for ci, clip in enumerate(clips):
        window = osd.WINDOW_S
        path, _, secs = clip.rpartition("@")     # CLIP@SECONDS: a short clip's window
        if path and secs.replace(".", "", 1).isdigit():
            clip, window = path, float(secs)
        layout = osd.calibrate([clip], window_s=window, log=lambda *a: None)
        read = osd.read_clip(clip, layout, None, window_s=window)
        stem = f"{ci:02d}"
        files = _frames(clip, os.path.join(out, "frames"), stem, window)
        clocks, titles = read.get("clock_readings") or [], read.get("title_readings") or []
        for k, f in enumerate(files):
            raw = clocks[k] if k < len(clocks) else ""
            p = parse_osd_clock(raw) if raw else None
            rows.append({"clip": os.path.basename(clip), "frame": k, "file": f"frames/{f}",
                         "clock_read": raw,
                         "clock_parsed": str(p["readings"][0]) if p and p["readings"] else "",
                         "title_read": titles[k] if k < len(titles) else "",
                         "clock_true": "", "title_true": ""})
        runs.append({"clip": os.path.basename(clip), "window_s": window, "layout": layout,
                     "read": read})
        log(f"{os.path.basename(clip)}: title "
            f"{(layout['title'] or {}).get('band', 'not found')}, clock "
            f"{(layout['clock'] or {}).get('band', 'not found')}; {len(files)} frames")
    with open(os.path.join(out, "osd.json"), "w", encoding="utf-8") as fh:
        json.dump({"clips": runs}, fh, indent=1, default=str)
    with open(os.path.join(out, "osd_labels.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    return {"clips": len(clips), "frames": len(rows)}


def score(out: str) -> dict:
    from analytics.osd_rules import canonical
    with open(os.path.join(out, "osd.json"), encoding="utf-8") as fh:
        runs = {r["clip"]: r for r in json.load(fh)["clips"]}
    with open(os.path.join(out, "osd_labels.csv"), newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    per_clip: dict = {}
    for row in rows:
        c = per_clip.setdefault(row["clip"], {"frames_with_clock": 0, "clock_exact": 0,
                                              "clock_wrong": 0, "clock_unread": 0,
                                              "wrong": [], "titles": set()})
        truth = row["clock_true"].strip()
        if row["title_true"].strip() not in ("", "?"):
            c["titles"].add(row["title_true"].strip())
        if truth in ("", "?"):
            continue
        c["frames_with_clock"] += 1
        got = row["clock_parsed"].strip()
        if not got:
            c["clock_unread"] += 1
        elif datetime.fromisoformat(got) == datetime.fromisoformat(truth):
            c["clock_exact"] += 1
        else:
            c["clock_wrong"] += 1
            c["wrong"].append({"frame": int(row["frame"]), "read": row["clock_read"],
                               "parsed": got, "painted": truth})
    total = {"clips": 0, "clocks_painted": 0, "clocks_found": 0, "titles_painted": 0,
             "titles_right": 0, "titles_wrong": 0, "frames_with_clock": 0,
             "clock_exact": 0, "clock_wrong": 0, "clock_unread": 0}
    for name, c in per_clip.items():
        layout = runs[name]["layout"]
        label = runs[name]["read"].get("label") or {}
        title = (label.get("title") or "") if isinstance(label, dict) else ""
        c["clock_band"] = (layout.get("clock") or {}).get("band")
        c["title_band"] = (layout.get("title") or {}).get("band")
        truth_title = sorted(c.pop("titles"))
        c["title_painted"] = truth_title[0] if truth_title else None
        c["title_voted"] = title or None
        c["title_right"] = bool(truth_title) and canonical(title) == canonical(truth_title[0])
        total["clips"] += 1
        total["clocks_painted"] += c["frames_with_clock"] > 0
        total["clocks_found"] += c["frames_with_clock"] > 0 and c["clock_band"] is not None
        total["titles_painted"] += bool(truth_title)
        total["titles_right"] += c["title_right"]
        total["titles_wrong"] += bool(truth_title) and bool(title) and not c["title_right"]
        for k in ("frames_with_clock", "clock_exact", "clock_wrong", "clock_unread"):
            total[k] += c[k]
    res = {"total": total, "clips": per_clip}
    with open(os.path.join(out, "score.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("clip", nargs="+")
    s.add_argument("--out", required=True)
    sc = sub.add_parser("score")
    sc.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "sample":
        sample(a.clip, a.out)
        return 0
    t = score(a.out)["total"]
    print(f"{t['clips']} clips: clock found on {t['clocks_found']} of {t['clocks_painted']} "
          f"that paint one; title right on {t['titles_right']} of {t['titles_painted']} "
          f"({t['titles_wrong']} wrong)")
    print(f"{t['frames_with_clock']} frames with a clock: {t['clock_exact']} read exactly, "
          f"{t['clock_wrong']} wrong, {t['clock_unread']} unread")
    return 0


if __name__ == "__main__":
    sys.exit(main())

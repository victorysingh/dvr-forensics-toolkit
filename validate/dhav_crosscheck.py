"""Second implementation: our DHAV frame walker against ffmpeg's dhav demuxer.

WHAT IT CHECKS
--------------
ffmpeg (libavformat/dhav.c) reads Dahua's DHAV container with code written
independently of this tool.  Both read the same .dav file - a stream as
stored, from `extract` or `extract-carved` - and are compared frame for frame:
payload size, payload checksum (Adler-32 from 0, as ffmpeg's framecrc prints
it), keyframe flag, and time.  Where they agree on every frame, an error in
one implementation would have to be repeated exactly by the other.

WHAT IT DOES NOT
----------------
This tool's DHAV field layout was TAKEN FROM dhav.c (the DHAV_FIELDS in
parsers/dahua.py cite it).  A misreading of the format that the two share is
therefore not tested: this is an independent-implementation check, not
independent knowledge of the format.  Status stays spec_only; only a
byte-match with the recorder's own export is `validated`.

Known, expected differences are reported, not hidden:
  * ffmpeg does not emit 0xF1 aux frames;
  * it ignores the header checksum byte this tool enforces, so a frame with a
    bad checksum is ffmpeg's and not ours (a real difference, reported);
  * it emits no video before the first keyframe - a file that opens
    mid-group (observed on real Dahua files) is aligned at that keyframe,
    and the frames before it are counted;
  * it emits the payload bytes present of a last frame the file cuts short,
    which this tool rejects (no trailer) - counted when the extra packet is
    exactly those bytes.

Usage:
  python -m validate.dhav_crosscheck FILE_OR_DIR [...] [--ffmpeg PATH] [--out report.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import zlib
from datetime import datetime, timezone
from typing import Iterator, Optional

from parsers import dahua as D

RULE = "validate.dhav_crosscheck.v1"
WINDOW = 64 << 20


def our_frames(path: str) -> Iterator[D.DhavFrame]:
    """Every validated DHAV frame in the file, read in windows."""
    with open(path, "rb") as fh:
        pos = 0
        while True:
            fh.seek(pos)
            buf = fh.read(WINDOW + D.MAX_FRAME)
            if not buf:
                return
            end = None
            for fr in D.walk_frames(buf, pos, 0, min(len(buf), WINDOW)):
                end = fr.offset + fr.length
                yield fr
            if len(buf) <= WINDOW:                       # the last window
                return
            pos = end if end and end > pos else pos + WINDOW


def _truncated_tail(fh, after: int, size: int) -> Optional[dict]:
    """A valid DHAV header after the last complete frame whose frame runs past
    the end of the file: the file was cut inside it."""
    fh.seek(after)
    rest = fh.read(size - after)
    p = rest.find(D.DHAV_MAGIC)
    if p < 0 or not D.header_ok(rest[p:p + D.DHAV_HDR]):
        return None
    _, ftype, *_, flen, _date, _ms, ext, _ck = struct.unpack_from(D.DHAV_HDR_FMT, rest, p)
    if after + p + flen <= size:
        return None
    kind = "video" if ftype in D.VIDEO_TYPES else "audio" if ftype == D.TYPE_AUDIO else "aux"
    return {"offset": after + p, "kind": kind, "declared": flen, "present": len(rest) - p,
            "payload_present": max(0, len(rest) - p - D.DHAV_HDR - ext)}


def ours(path: str) -> dict:
    video, audio, aux, end = [], [], 0, 0
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        for fr in our_frames(path):
            end = fr.offset + fr.length
            fh.seek(fr.offset + D.DHAV_HDR + fr.ext_length)
            pay = fh.read(fr.length - D.DHAV_HDR - fr.ext_length - D.DHAV_TAIL)
            row = (len(pay), zlib.adler32(pay, 0))
            if fr.is_video:
                dt = D.decode_date(fr.date)
                sec = dt.replace(tzinfo=timezone.utc).timestamp() if dt else None
                video.append(row + (fr.ftype == D.TYPE_I, sec, fr.offset))
            elif fr.ftype == D.TYPE_AUDIO:
                audio.append(row)
            else:
                aux += 1
        tail = _truncated_tail(fh, end, size) if size - end >= D.DHAV_HDR else None
    return {"video": video, "audio": audio, "aux": aux, "truncated_tail": tail}


def ffmpeg_frames(path: str, ffmpeg: str) -> dict:
    """ffmpeg's packets, with the recorder-local times kept (-copyts)."""
    cmd = [ffmpeg, "-hide_banner", "-nostdin", "-v", "quiet", "-copyts", "-f", "dhav",
           "-i", path, "-map", "0", "-c", "copy", "-f", "framecrc", "-"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
    kinds: dict[str, str] = {}
    video, audio = [], []
    for line in out.splitlines():
        if line.startswith("#media_type"):
            k, v = line[len("#media_type"):].split(":")
            kinds[k.strip()] = v.strip()
            continue
        if not line or line.startswith("#"):
            continue
        f = [x.strip() for x in line.split(",")]
        size, crc = int(f[4]), int(f[5], 16)
        key = not any(x.startswith("F=") and int(x[2:], 16) & 1 == 0 for x in f[6:])
        if kinds.get(f[0]) == "video":
            video.append((size, crc, key, int(f[2]) / 1000.0))
        elif kinds.get(f[0]) == "audio":
            audio.append((size, crc))
    return {"video": video, "audio": audio}


def compare(a: dict, b: dict) -> dict:
    """a = ours, b = ffmpeg's.  Frame-by-frame, in file order."""
    def first_diff(x, y, width):
        for i, (p, q) in enumerate(zip(x, y)):
            if p[:width] != q[:width]:
                return i
        return None if len(x) == len(y) else min(len(x), len(y))

    def cut_tail(theirs, mine, kind):
        """Drop ffmpeg's last packet when it is exactly the payload bytes of a
        frame the file cuts short - which we reject."""
        t = a.get("truncated_tail")
        if (t and t["kind"] == kind and len(theirs) == len(mine) + 1
                and theirs[-1][0] == t["payload_present"]):
            return theirs[:-1], True
        return theirs, False

    v_all, v_ff = a["video"], b["video"]
    # ffmpeg emits no video before the first keyframe: align there, when that
    # is what makes the two agree (a file that opens mid-group)
    lead = next((i for i, x in enumerate(v_all) if x[2]), 0)
    v_ours = v_all
    if lead and first_diff(v_all, v_ff, 3) is not None:
        v_ours = v_all[lead:]
    v_ff, v_cut = cut_tail(v_ff, v_ours, "video")
    a_ff, a_cut = cut_tail(b["audio"], a["audio"], "audio")
    k = first_diff(v_ours, v_ff, 3)
    deltas = [f[3] - o[3] for o, f in zip(v_ours, v_ff) if o[3] is not None]
    within = sum(1 for d in deltas if 0 <= d < 1.0)
    ka = first_diff(a["audio"], a_ff, 2)
    res = {
        "video": {"ours": len(v_all), "ffmpeg": len(b["video"]),
                  "identical": k is None,
                  "matching_prefix": len(v_ours) if k is None else k},
        "audio": {"ours": len(a["audio"]), "ffmpeg": len(b["audio"]),
                  "identical": ka is None},
        "expected_differences": {
            "ours_before_first_keyframe": len(v_all) - len(v_ours),
            "ffmpeg_truncated_last_frame": v_cut or a_cut,
            "truncated_tail": a.get("truncated_tail")},
        "time": {"frames_compared": len(deltas),
                 "ffmpeg_within_the_frames_own_second": within,
                 "max_offset_s": round(max((abs(d) for d in deltas), default=0.0), 3)},
        "aux_frames_ours_only": a["aux"],
    }
    if k is not None:
        o = v_ours[k] if k < len(v_ours) else None
        f = v_ff[k] if k < len(v_ff) else None
        res["video"]["first_difference"] = {
            "frame": k, "ours": o and {"size": o[0], "adler32": f"0x{o[1]:08x}", "key": o[2],
                                       "offset": o[4]},
            "ffmpeg": f and {"size": f[0], "adler32": f"0x{f[1]:08x}", "key": f[2]}}
    return res


def check_file(path: str, ffmpeg: str) -> dict:
    return dict(compare(ours(path), ffmpeg_frames(path, ffmpeg)),
                file=os.path.basename(path), bytes=os.path.getsize(path))


def _files(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += sorted(os.path.join(p, n) for n in os.listdir(p) if n.lower().endswith(".dav"))
        else:
            out.append(p)
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+", help=".dav files, or folders of them")
    ap.add_argument("--ffmpeg", default=os.environ.get("FFMPEG") or shutil.which("ffmpeg") or "")
    ap.add_argument("--out", default="dhav_crosscheck.json")
    args = ap.parse_args(argv)
    if not args.ffmpeg or not os.path.exists(args.ffmpeg) and not shutil.which(args.ffmpeg):
        print("[!] ffmpeg not found - pass --ffmpeg PATH")
        return 2
    rows = [check_file(p, args.ffmpeg) for p in _files(args.paths)]
    total = {k: sum(r["video"][k] for r in rows) for k in ("ours", "ffmpeg", "matching_prefix")}
    agree = [r for r in rows if r["video"]["identical"] and r["audio"]["identical"]]
    report = {"rule": RULE, "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "ffmpeg": subprocess.run([args.ffmpeg, "-version"], capture_output=True,
                                       text=True).stdout.split("\n")[0],
              "files": len(rows), "files_identical": len(agree), "video_frames": total,
              "status_note": "independent implementation, shared field layout (dhav.c): "
                             "spec_only stays spec_only",
              "per_file": rows}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(f"files {len(rows)}: {len(agree)} identical frame for frame "
          f"(video {total['ours']:,} ours / {total['ffmpeg']:,} ffmpeg)")
    for r in rows:
        if r not in agree:
            print(f"  {r['file']}: video {r['video']}  audio {r['audio']}")
    print(f"[+] {args.out}")
    return 0 if len(agree) == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())

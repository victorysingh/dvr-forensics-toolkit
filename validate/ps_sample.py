"""Check the MPEG-PS carver and the Hikvision "HK" time on a vendor-made file.

Our Hikvision decoding was worked out on the team's own drive.  A file that
Hikvision's own software wrote, from another recorder, is outside evidence:

  * carve     the carver must find the Program Stream where it starts and
              keep every complete pack (a Hikvision IMKH player file is a
              40-byte header, then the stream);
  * frames    with ffmpeg: every video frame decoded from our carved bytes
              must be identical (MD5 per frame) to the same frame decoded
              from the vendor's file - nothing dropped, nothing added;
  * time      every stream map's "HK" time is listed next to the keyframe it
              precedes, and a contact sheet of those keyframes' painted
              clocks is written for a person to read (`--painted` records
              what they read, and the offsets).

It proves the decoding on material we did not make; it is not a byte-match
with an export of OUR drive, so status stays spec_only.

Usage:
  python -m validate.ps_sample FILE --out DIR [--ffmpeg PATH]
         [--osd-box x0,y0,x1,y1] [--painted HH:MM:SS,HH:MM:SS,...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Optional

from acquire.device import BlockDevice
from recover import pscarve

RULE = "validate.ps_sample.v1"
PSM = b"\x00\x00\x01\xbc"


def psm_times(data: bytes) -> list[Optional[str]]:
    """The HK time of every stream map, in stream order."""
    out, i = [], data.find(PSM)
    while i >= 0:
        n = int.from_bytes(data[i + 4:i + 6], "big")
        out.append(pscarve.hk_time(data[i:i + 6 + n]))
        i = data.find(PSM, i + 4)
    return out


def _md5s(ffmpeg: str, args: list[str]) -> list[str]:
    r = subprocess.run([ffmpeg, "-hide_banner", "-nostdin", "-v", "quiet", *args,
                        "-map", "0:v", "-f", "framemd5", "-"], capture_output=True, text=True)
    return [line.rsplit(",", 1)[1].strip() for line in r.stdout.splitlines()
            if line and not line.startswith("#")]


def offsets(times: list[Optional[str]], painted: list[str]) -> list[Optional[float]]:
    """Painted clock minus HK time, per keyframe, in seconds."""
    out = []
    for t, p in zip(times, painted):
        if not t or not p:
            out.append(None)
            continue
        day = t[:10]
        out.append((datetime.strptime(f"{day} {p}", "%Y-%m-%d %H:%M:%S")
                    - datetime.strptime(t, "%Y-%m-%d %H:%M:%S")).total_seconds())
    return out


def check(path: str, out: str, ffmpeg: str = "", osd_box: Optional[tuple] = None,
          painted: Optional[list[str]] = None) -> dict:
    os.makedirs(out, exist_ok=True)
    with open(path, "rb") as fh:
        raw = fh.read()
    with BlockDevice(path) as dev:
        streams, stats = pscarve.carve(dev)
    rows = [s.to_row() for s in streams]
    rep: dict = {"rule": RULE, "file": os.path.basename(path), "bytes": len(raw),
                 "sha256": hashlib.sha256(raw).hexdigest(), "header_hex": raw[:8].hex(),
                 "carve_stats": stats,
                 "streams": [{k: r[k] for k in ("id", "offset", "bytes", "packs", "video_packets",
                                                "audio_packets", "stream_maps", "duration_s",
                                                "time_first_local", "time_last_local")}
                             | {"resolution": pscarve.resolution(r),
                                "stream_types": [s["type"] for s in r["streams"]],
                                "end": r["extents"][-1][0] + r["extents"][-1][1]}
                             for r in rows]}
    if not rows:
        rep["verdict"] = "no Program Stream found"
        return rep
    r0 = rows[0]
    carved = b"".join(raw[o:o + n] for o, n in r0["extents"])
    rep["uncarved_bytes"] = {"before": r0["offset"], "after": len(raw) - rep["streams"][0]["end"]}
    rep["psm_times"] = psm_times(carved)
    cpath = os.path.join(out, "carved.ps")
    with open(cpath, "wb") as fh:
        fh.write(carved)
    if ffmpeg:
        a = _md5s(ffmpeg, ["-i", path])
        b = _md5s(ffmpeg, ["-f", "mpeg", "-i", cpath])
        common = min(len(a), len(b))
        rep["frames"] = {"vendor_file": len(a), "carved": len(b),
                         "common_identical": sum(1 for x, y in zip(a, b) if x == y),
                         "common": common}
        kdir = os.path.join(out, "keyframes")
        os.makedirs(kdir, exist_ok=True)
        subprocess.run([ffmpeg, "-hide_banner", "-nostdin", "-v", "quiet", "-f", "mpeg",
                        "-i", cpath, "-vf", "select=eq(pict_type\\,I)", "-vsync", "vfr",
                        os.path.join(kdir, "key_%03d.png"), "-y"], check=False)
        keys = sorted(os.listdir(kdir))
        rep["keyframes"] = keys
        try:
            from PIL import Image
            ims = [Image.open(os.path.join(kdir, k)) for k in keys]
            if ims:
                w, h = ims[0].size
                box = osd_box or (0, 0, w, max(40, h // 12))
                bh = box[3] - box[1]
                sheet = Image.new("RGB", (box[2] - box[0], bh * len(ims)), "white")
                for i, im in enumerate(ims):
                    sheet.paste(im.crop(box), (0, bh * i))
                sheet.save(os.path.join(out, "keyframe_clocks.png"))
                rep["clock_sheet"] = "keyframe_clocks.png"
        except ImportError:
            rep["clock_sheet"] = None
    if painted:
        offs = offsets(rep["psm_times"], painted)
        rep["painted"] = painted
        rep["painted_minus_hk_s"] = offs
    return rep


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ffmpeg", default=os.environ.get("FFMPEG") or shutil.which("ffmpeg") or "")
    ap.add_argument("--osd-box", default="", help="x0,y0,x1,y1 of the painted clock")
    ap.add_argument("--painted", default="", help="clocks read off keyframe_clocks.png, in order")
    args = ap.parse_args(argv)
    box = tuple(int(v) for v in args.osd_box.split(",")) if args.osd_box else None
    rep = check(args.file, args.out, args.ffmpeg, box,
                [p.strip() for p in args.painted.split(",")] if args.painted else None)
    path = os.path.join(args.out, "ps_sample.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    s = rep["streams"][0] if rep["streams"] else None
    print(f"{rep['file']}  {rep['bytes']:,} B  sha256 {rep['sha256'][:16]}...")
    if s:
        print(f"  stream        @0x{s['offset']:X}, {s['packs']} packs, {s['duration_s']} s, "
              f"{s['resolution']}, {'/'.join(s['stream_types'])}; "
              f"{rep['uncarved_bytes']['after']:,} B after the last complete pack")
        print(f"  HK times      {len(rep['psm_times'])} stream maps, "
              f"{rep['psm_times'][0]} -> {rep['psm_times'][-1]}")
    if "frames" in rep:
        f = rep["frames"]
        print(f"  frames        {f['common_identical']}/{f['common']} identical "
              f"(vendor file {f['vendor_file']}, carved {f['carved']})")
    if rep.get("painted_minus_hk_s"):
        print(f"  painted - HK  {rep['painted_minus_hk_s']} s")
    print(f"[+] {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The no-parser carver on a real disk, scored by the parser that knows it.

    python -m validate.heimvision_carve "HeimVision K9604-W.E01" [--out result.json]

`carve-annexb` (recover/annexb.py) is meant for recorders we cannot parse:
it knows H.264 / H.265 and nothing else.  On the NIST CFReDS HeimVision
K9604-W image the HeimVision plugin knows every frame - where it starts,
which camera, which type - so the carver can be scored there, which no
generated test can do.  Two passes, both read-only:

  1. CARVE - every part of the image that holds data goes through
     AnnexBCarver, as a whole-disk carve would.  "Holds data" is read off
     the E01's chunk table: a chunk stored, or compressed to more than 200
     bytes (a 32 KiB chunk of zeros compresses to 52); the near-empty rest
     is skipped only to save time.  On a raw image the whole disk is carved.
  2. ACCOUNT - every 00 00 01 in the written .dat files (read as files,
     through their FAT chains) is placed by the parser: file header, frame
     header, audio payload, video payload, or past the end of the frame
     chain; and judged by the carver's own rule: not a NAL unit (passed
     over), a NAL unit, a slice, a keyframe slice.

The slice-shaped start codes outside video payloads are what the carver
counts as footage but is not.  VALIDATION_REPORT.md section 8e has the result.
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import sys
import time
from collections import Counter

from acquire.device import BlockDevice
from acquire.ewf import EwfImage, is_ewf
from plugins import heimvision as hv
from recover.annexb import AnnexBCarver, classify, is_key, is_vcl

EMPTY_CHUNK = 200           # compressed bytes at or under which a chunk is near-empty
START_CODE = re.compile(b"\x00\x00\x01")


def data_regions(path: str, size: int) -> list[tuple[int, int]]:
    """(offset, length) of each run of chunks that hold data."""
    if not is_ewf(path):
        return [(0, size)]
    img = EwfImage(path)
    try:
        cs, runs = img.chunk_size, []
        for k, (_, _, stored, compressed) in enumerate(img.chunks):
            if compressed and stored <= EMPTY_CHUNK:
                continue
            if runs and runs[-1][1] == k:
                runs[-1][1] = k + 1
            else:
                runs.append([k, k + 1])
    finally:
        img.close()
    return [(a * cs, min(b * cs, size) - a * cs) for a, b in runs]


def carve(dev: BlockDevice, regions: list[tuple[int, int]]) -> dict:
    streams, stats = [], Counter()
    for off, n in regions:
        c = AnnexBCarver(off)
        pos = off
        while pos < off + n:
            data = dev.read_at(pos, min(8 << 20, off + n - pos))
            if not data:
                raise IOError(f"no bytes at {pos}, inside the image")
            c.push(pos, data)
            pos += len(data)
        c.close()
        kept, st = c.finish()
        streams += kept
        stats.update(st)
    return {"regions": len(regions), "bytes_read": sum(n for _, n in regions),
            "streams": len(streams),
            "by_codec_size": dict(Counter(f"{s.codec} {s.sps['width']}x{s.sps['height']}"
                                          for s in streams)),
            "parameter_sets": len({s.sps_key for s in streams}),
            "slices": sum(s.vcl for s in streams),
            "keyframes": sum(s.keyframes for s in streams),
            "start_codes_passed_over": sum(s.spurious for s in streams),
            "stats": dict(stats)}


def frame_chain(data: bytes) -> tuple[list[tuple[int, dict]], int]:
    """(offset, header) of each frame in a .dat file, and where the chain ends."""
    out, pos = [], hv.FILE_HDR
    while pos + hv.FRAME_HDR <= len(data):
        h = hv.frame_header(data[pos:pos + hv.FRAME_HDR])
        if h is None:
            nxt = data.find(hv.FRAME_MAGIC, pos + 1)
            if nxt < 0:
                break
            pos = nxt
            continue
        end = pos + hv.FRAME_HDR + h["length"]
        if end > len(data):
            break
        out.append((pos, h))
        pos = end
    return out, pos


def account(dev: BlockDevice) -> dict:
    p = hv.HeimVisionParser()
    fat = p._fat(dev)
    if fat is None:
        raise SystemExit("not a HeimVision disk: no FAT32 second partition")
    files = [f for f in p._files(dev, fat) if "start" in f]      # written ones
    tally, frames, slices_per_frame = Counter(), Counter(), Counter()
    after_chain = 0
    for f in files:
        data = b"".join(dev.read_at(o, n) for o, n in f["extents"])
        chain, chain_end = frame_chain(data)
        after_chain += len(data) - chain_end
        starts = [o for o, _ in chain]
        slices_in = Counter()
        for m in START_CODE.finditer(data):
            at = m.end()                                 # the NAL header's first byte
            if at + 2 > len(data):
                continue
            k = bisect.bisect_right(starts, at) - 1
            if k < 0:
                where = "file header"
            elif at >= chain_end:
                where = "after the frame chain"
            elif at < starts[k] + hv.FRAME_HDR:
                where = "frame header"
            else:
                where = "audio payload" if chain[k][1]["type"] == "audio" else "video payload"
            t = classify(data[at], data[at + 1])[1]
            verdict = ("not a NAL unit" if t is None else "keyframe slice" if is_key("h265", t)
                       else "slice" if is_vcl("h265", t) else "other NAL unit")
            tally[where, verdict] += 1
            if where == "video payload" and verdict.endswith("slice"):
                slices_in[k] += 1
        for k, (_, h) in enumerate(chain):
            frames[h["type"]] += 1
            if h["type"] != "audio":
                slices_per_frame[slices_in[k]] += 1
    return {"files_written": len(files), "frames": dict(frames),
            "video_frames_by_slices_in_them": {str(k): v for k, v in sorted(slices_per_frame.items())},
            "bytes_after_frame_chains": after_chain,
            "start_codes": {f"{w} / {v}": c for (w, v), c in sorted(tally.items())}}


def score(carved: dict, acc: dict) -> dict:
    sc = acc["start_codes"]
    shaped = lambda kind: {k: v for k, v in sc.items() if k.endswith("/ " + kind)}
    true_slices = sum(v for k, v in shaped("slice").items() if k.startswith("video payload"))
    true_keys = sum(v for k, v in shaped("keyframe slice").items() if k.startswith("video payload"))
    all_slices = sum(shaped("slice").values()) + sum(shaped("keyframe slice").values())
    all_keys = sum(shaped("keyframe slice").values())
    return {
        "video_slices_in_the_files": true_slices + true_keys,
        "slice_shaped_start_codes_elsewhere": all_slices - true_slices - true_keys,
        "keyframe_shaped_start_codes_elsewhere": all_keys - true_keys,
        # A carved stream leaves out its last NAL unit (its end is not known):
        # one per stream, so this is 0 when the carver counted every one.
        "carved_slices_minus_expected": carved["slices"] - (all_slices - carved["streams"]),
        "carved_keyframes_minus_expected": carved["keyframes"] - all_keys,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("image", help="the CFReDS HeimVision K9604-W .E01 (or a raw image of it)")
    ap.add_argument("--out", help="write the result here as JSON")
    a = ap.parse_args()
    t0 = time.time()
    with BlockDevice(a.image) as dev:
        regions = data_regions(a.image, dev.size_bytes)
        print(f"carving {len(regions)} regions, "
              f"{sum(n for _, n in regions) / 2**30:.2f} GiB ...", file=sys.stderr)
        carved = carve(dev, regions)
        print(f"  {time.time() - t0:.0f}s; placing every start code ...", file=sys.stderr)
        acc = account(dev)
    res = {"image": a.image, "carver": carved, "parser": acc, "score": score(carved, acc),
           "seconds": round(time.time() - t0)}
    text = json.dumps(res, indent=1)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

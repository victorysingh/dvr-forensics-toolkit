"""High-entropy data with no video structure: what an encrypted disk looks like.

A carver finds nothing on an encrypted disk, and "0 streams recovered" reads
like "no footage".  This classifies every block of the acquisition's block
map - no second read of the drive - from what the single pass already
measured per block: how incompressible its sample was, how many H.264/H.265
start codes (00 00 01) it held, and how many vendor signatures matched.

Compressed video is as incompressible as ciphertext, so entropy alone
separates nothing.  Start codes do: random bytes contain 00 00 01 about once
per 2**24 bytes (0.5 per 8 MiB block), while any H.264/H.265 stream carries
at least one per frame - hundreds per block.  So a dense block is:

  video                    start codes far above chance
  container_without_video  vendor headers (DHAV, IMKH, ...) around payloads
                           with no start codes: consistent with encrypted
                           payloads inside a plaintext container
  unstructured             neither: encrypted, or compressed non-video data
                           (archives, images, firmware)

Reported as "high entropy, no video structure - not parsed", never as
"encrypted": entropy cannot prove encryption, and the block's sample is its
first 4 KiB, so a block that is part video, part not can go either way.
"""

from __future__ import annotations

import math
from typing import Iterable

DENSE = 0.95              # incompressibility at or above which a block is dense
EMPTY = 0.05              # below this: zeros or one repeated byte
CHANCE = 1 << 24          # one 3-byte start code per 2**24 random bytes
MOSTLY = 0.5              # share of written blocks for a whole-disk verdict
FLAGGED = ("unstructured", "container_without_video")

MEANING = {
    "unstructured": "high entropy, no video structure: encrypted, or compressed "
                    "non-video data (archives, images, firmware) - not parsed; "
                    "carving recovers nothing from it",
    "container_without_video": "vendor container headers around high-entropy payloads "
                               "with no video start codes: consistent with encrypted "
                               "video - not parsed; the vendor's key would be needed",
}


def start_code_limit(length: int) -> float:
    """The most start codes random data of this length plausibly holds: the
    Poisson mean plus six standard deviations plus a margin.  About 9 for an
    8 MiB block, where even sparse video has hundreds."""
    lam = length / CHANCE
    return lam + 6 * math.sqrt(lam) + 4


def classify(block: dict) -> str:
    """One block-map row -> video | empty | structured | container_without_video
    | unstructured.

    Start codes are counted over the whole block but incompressibility over
    its first 4 KiB, so start codes decide first: a block of video whose
    first 4 KiB is a zero-padded file header (every HeimVision file) is video,
    not empty.  The same sampling means an encrypted block that opens with a
    plaintext header is missed - a false negative, never a false flag."""
    if block.get("start_codes", 0) > start_code_limit(block.get("length", 0)):
        return "video"
    ratio = block.get("incompressibility", 0.0)
    if ratio < EMPTY:
        return "empty"
    if ratio < DENSE:
        return "structured"
    return "container_without_video" if block.get("hits", 0) else "unstructured"


def summarise(blocks: Iterable[dict]) -> dict:
    """Counts per class, the flagged regions as merged runs, and a verdict."""
    counts = dict.fromkeys(("empty", "structured", "video", "container_without_video",
                            "unstructured"), 0)
    runs: list[dict] = []
    for b in blocks:
        if b.get("bad"):
            continue                 # unreadable: reported with the bad regions
        kind = classify(b)
        counts[kind] += 1
        if kind not in FLAGGED:
            continue
        last = runs[-1] if runs else None
        if last and last["kind"] == kind and last["offset"] + last["length"] == b["offset"]:
            last["length"] += b["length"]
            last["blocks"] += 1
        else:
            runs.append({"kind": kind, "offset": b["offset"], "length": b["length"], "blocks": 1})
    written = sum(n for k, n in counts.items() if k != "empty")
    flagged = sum(counts[k] for k in FLAGGED)
    share = flagged / written if written else 0.0
    if not flagged:
        verdict = "no high-entropy region without video structure"
    elif share >= MOSTLY:
        verdict = (f"{share:.0%} of the written blocks are high-entropy with no video "
                   "structure: consistent with an encrypted disk or encrypted recordings. "
                   "Carving cannot recover video from them; footage status "
                   "detected_not_parsed. Not claimed as encrypted.")
    else:
        verdict = (f"{flagged} written block(s) ({share:.1%}) are high-entropy with no video "
                   f"structure, in {len(runs)} region(s) - reported, not parsed")
    return {"rule": "regions.v1", "counts": counts, "written_blocks": written,
            "flagged_blocks": flagged, "flagged_share": round(share, 4),
            "start_code_limit_per_8mib": round(start_code_limit(8 << 20), 2),
            "regions": [dict(r, meaning=MEANING[r["kind"]]) for r in runs],
            "verdict": verdict}

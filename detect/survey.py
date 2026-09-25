"""Survey an unknown disk: draft its layout before anyone writes a parser.

The add-a-vendor pipeline is detect -> carve -> SURVEY -> plugin -> validate.
Given a disk (or image) from a recorder we have never seen, this reads a
spread of samples and reports what a researcher would otherwise find by hand
in a hex editor:

  * frame/record headers  - short all-caps-ish tokens recurring far more often
                            than chance (DHAV, IMKH, ...)
  * length fields         - a u32 inside the header that equals the distance
                            to the next header, i.e. self-describing records
  * record strides        - a header that recurs at a fixed distance
  * timestamp fields      - header offsets whose u32 decodes as a plausible
                            date, and in which encoding
  * codec                 - H.264/H.265 NAL census
  * strings               - brand names, config keys, firmware versions
  * structure map         - which samples are empty, structured, or dense
  * known vendors         - every signature the detection engine knows

It proposes; it does not conclude.  Every finding is a count over the
samples read, and the output says how much of the disk that was.  Draft
signatures are marked `candidate` - the lowest status there is.

Read-only: it is handed an open BlockDevice.
"""

from __future__ import annotations

import re
import struct
import zlib
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

SAMPLE = 1 << 20
# A 4-byte token is a candidate header when it recurs across many samples
# and far more often than the typical token does.  (Comparing against "any
# random token" is the wrong baseline: on a video disk every specific token
# would look ordinary.)
TOKEN_RE = re.compile(rb"[A-Z][A-Z0-9]{3}")
MIN_TOKEN_COUNT = 50
MIN_SPREAD = 0.1          # share of non-empty samples a token must appear in
MIN_ENRICHMENT = 20       # times the median token count
STRING_RE = re.compile(rb"[\x20-\x7e]{6,64}")
_REPEAT_RE = re.compile(rb"(.)\1{3,}")
YEAR_LO, YEAR_HI = 2005, 2035


def sample_offsets(size: int, n: int = 64, sample: int = SAMPLE) -> list[int]:
    """The first and last 8 MiB, plus `n` samples spread evenly between -
    enough to see structures at both ends and the pattern of the data area."""
    if size <= (n + 16) * sample:
        return list(range(0, size - size % sample, sample)) or [0]
    head = [i * sample for i in range(8)]
    tail = [size - (8 - i) * sample for i in range(8)]
    lo, hi = 8 * sample, size - 8 * sample
    step = (hi - lo) // n
    mid = [lo + k * step - (lo + k * step) % 512 for k in range(n)]
    return sorted(set(head + mid + tail))


def _dhav_date_ok(v: int) -> bool:
    y, mo, d = (v >> 26 & 0x3F) + 2000, v >> 22 & 0x0F, v >> 17 & 0x1F
    h, mi, s = v >> 12 & 0x1F, v >> 6 & 0x3F, v & 0x3F
    return YEAR_LO <= y <= YEAR_HI and 1 <= mo <= 12 and 1 <= d <= 31 \
        and h < 24 and mi < 60 and s < 60


def _unix_ok(v: int) -> bool:
    lo = datetime(YEAR_LO, 1, 1, tzinfo=timezone.utc).timestamp()
    hi = datetime(YEAR_HI, 1, 1, tzinfo=timezone.utc).timestamp()
    return lo <= v <= hi


DATE_ENCODINGS = {"unix_seconds": _unix_ok, "packed_ymdhms_dhav": _dhav_date_ok}


def _kind(buf: bytes) -> str:
    if not buf.strip(b"\x00"):
        return "zero"
    if len(set(buf[::61])) <= 2:           # judged across the whole sample,
        return "fill"                        # not just its first bytes
    ratio = len(zlib.compress(buf[:65536], 1)) / min(len(buf), 65536)
    return "dense" if ratio > 0.9 else "structured"


def analyse_token(bufs: list[tuple[int, bytes]], token: bytes, max_hits: int = 20000) -> dict:
    """What the headers starting with `token` look like."""
    positions: list[tuple[bytes, int]] = []           # (buffer, index)
    for _, b in bufs:
        i = b.find(token)
        while i >= 0 and len(positions) < max_hits:
            positions.append((b, i))
            i = b.find(token, i + 1)
    gaps: Counter = Counter()
    length_hits: Counter = Counter()
    pairs = 0
    for (b1, i1), (b2, i2) in zip(positions, positions[1:]):
        if b1 is not b2:
            continue
        gap = i2 - i1
        pairs += 1
        gaps[gap] += 1
        for off in range(4, 32, 2):
            if i1 + off + 4 <= len(b1) and struct.unpack_from("<I", b1, i1 + off)[0] == gap:
                length_hits[off] += 1
    dates: dict[str, Counter] = {k: Counter() for k in DATE_ENCODINGS}
    for b, i in positions:
        for off in range(4, 32, 4):
            if i + off + 4 <= len(b):
                v = struct.unpack_from("<I", b, i + off)[0]
                for name, ok in DATE_ENCODINGS.items():
                    if ok(v):
                        dates[name][off] += 1
    n = len(positions)
    out = {"token": token.decode("ascii"), "occurrences_sampled": n,
           "aligned_512": sum(1 for b, i in positions if i % 512 == 0)}
    if pairs:
        stride, count = gaps.most_common(1)[0]
        out["most_common_gap"] = {"bytes": stride, "share": round(count / pairs, 4)}
    if length_hits:
        off, count = length_hits.most_common(1)[0]
        out["length_field"] = {"offset": off, "encoding": "u32le",
                               "matches_distance_to_next": round(count / pairs, 4)}
    best = [(c / n, name, off) for name, cnt in dates.items() for off, c in cnt.items()] if n else []
    best.sort(reverse=True)
    out["date_fields"] = [{"offset": off, "encoding": name, "share": round(sh, 4)}
                          for sh, name, off in best[:3] if sh >= 0.5]
    tied = Counter(f["offset"] for f in out["date_fields"])
    if any(n > 1 for n in tied.values()):
        out["date_note"] = ("more than one date encoding is plausible at the same "
                            "offset; decode a few values by hand to choose")
    return out


def survey(dev, offsets: Optional[list[int]] = None, sample: int = SAMPLE,
           top: int = 8) -> dict:
    from detect.engine import SignatureScanner

    size = dev.size_bytes
    offsets = offsets if offsets is not None else sample_offsets(size, sample=sample)
    bufs: list[tuple[int, bytes]] = []
    kinds: Counter = Counter()
    tokens: Counter = Counter()
    spread: Counter = Counter()
    strings: Counter = Counter()
    known: Counter = Counter()
    codec = {"start_codes": 0, "sps": 0, "pps": 0, "idr": 0, "hevc_ps": 0}
    regions = []
    for off in offsets:
        buf = dev.read_at(off, min(sample, size - off))
        if not buf:
            continue
        bufs.append((off, buf))
        k = _kind(buf)
        kinds[k] += 1
        regions.append({"offset": off, "kind": k})
        if k in ("zero", "fill"):
            continue
        found = Counter(m.group() for m in TOKEN_RE.finditer(buf))
        tokens.update(found)
        spread.update(found.keys())
        # drop runs of one repeated byte (padding) before judging a string,
        # so "UUUUdhavp" (a frame trailer in 0x55 fill) is not reported
        strings.update(t for t in (_REPEAT_RE.sub(b"", m.group())
                                   for m in STRING_RE.finditer(buf))
                       if len(t) >= 6 and len(set(t)) >= 4)
        sc = SignatureScanner()
        s = sc.scan_block(off, buf, 0, "")
        for key in codec:
            codec[key] += getattr(s, key, 0)
        for h in sc.hits:
            known[h.vendor] += 1
    read = sum(len(b) for _, b in bufs)
    busy = kinds["dense"] + kinds["structured"]
    # baseline: the typical token over ALL tokens seen - on any disk about 1.
    # (Over only repeated tokens, a clean format's own header would be its
    # own baseline and never stand out.)
    counts = sorted(tokens.values())
    median = max(1, counts[len(counts) // 2]) if counts else 1
    cands = [(t, c) for t, c in tokens.most_common(200)
             if c >= MIN_TOKEN_COUNT and len(set(t)) >= 3
             and spread[t] >= max(2, MIN_SPREAD * busy) and c / median >= MIN_ENRICHMENT]
    headers = [dict(analyse_token(bufs, t), enrichment=round(c / median, 1),
                    samples_with_token=spread[t])
               for t, c in cands[:top]]
    hevc = codec["hevc_ps"] > codec["sps"]
    return {
        "rule": "survey.v1",
        "disk_bytes": size,
        "sampled": {"samples": len(bufs), "bytes": read,
                    "fraction": round(read / size, 6) if size else 0,
                    "sample_bytes": sample},
        "structure": dict(kinds),
        "regions": regions,
        "header_candidates": headers,
        # a string built around a header marker (e.g. a "dhav" trailer next to
        # padding) is structure, not text
        "strings": [{"text": s.decode("ascii"), "count": c}
                    for s, c in strings.most_common(200)
                    if c >= 2 and not any(h["token"].encode() in s or
                                          h["token"].lower().encode() in s
                                          for h in headers)][:40],
        "codec": dict(codec, likely=("h265" if hevc else "h264") if codec["start_codes"] else ""),
        "known_signatures": dict(known),
        "draft_signatures": [
            {"id": f"survey.{h['token'].lower()}", "pattern": h["token"],
             "validation_status": "candidate",
             "why": f"{h['occurrences_sampled']} occurrences in the samples, "
                    f"{h['enrichment']}x the median token, in "
                    f"{h['samples_with_token']} samples"
                    + (f"; u32 at +0x{h['length_field']['offset']:X} equals the distance "
                       f"to the next header in {h['length_field']['matches_distance_to_next']:.0%}"
                       if h.get("length_field") else "")}
            for h in headers],
        "notes": [
            "Counts are over the samples read, not the whole disk.",
            "A candidate header is a lead for a researcher with a hex editor, not a "
            "format. Draft signatures are 'candidate', the weakest status.",
        ],
    }


def diff_blockmaps(a: list[dict], b: list[dict]) -> dict:
    """Which blocks differ between two scans of the same disk - the core of a
    before/after experiment (record, delete a clip on the recorder, re-scan):
    the changed regions are where the index, allocation map and logs live."""
    by_a = {x["offset"]: x["sha256"] for x in a}
    by_b = {x["offset"]: x["sha256"] for x in b}
    common = sorted(set(by_a) & set(by_b))
    changed = [o for o in common if by_a[o] != by_b[o]]
    bs = a[0]["length"] if a else 0
    runs: list[list[int]] = []
    for o in changed:
        if runs and o == runs[-1][1]:
            runs[-1][1] = o + bs
        else:
            runs.append([o, o + bs])
    return {"blocks_compared": len(common), "blocks_changed": len(changed),
            "block_size": bs,
            "changed_regions": [{"start": s, "end": e, "bytes": e - s} for s, e in runs],
            "only_in_first": len(set(by_a) - set(by_b)),
            "only_in_second": len(set(by_b) - set(by_a))}

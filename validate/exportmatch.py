"""Byte-match footage recovered from a disk against the recorder's own export.

This is the test `VALIDATION_REPORT.md` §9 names as the only route to
`validated`: the recorder exports a clip with its own export function, we
recover the same period from the disk, and the two are compared byte for
byte.

WHAT IS COMPARED
----------------
The compressed pictures themselves: every VCL NAL unit (the slices that carry
picture data) of the H.264 / H.265 stream, in order.  An export is allowed to
wrap those slices differently - a new container, rewritten frame headers,
parameter sets repeated, SEI inserted - and none of that means our reading of
the disk is wrong.  If every slice is byte-identical and in the same order,
the pictures are the same pictures.  Container-level differences are
measured and reported separately; they never decide the verdict.

WHY IN ORDER, AND WHY ANCHORS
-----------------------------
A static scene produces tiny slices ("nothing changed") that can be
byte-identical from one frame to the next, and between two cameras watching
still scenes.  Matched as an unordered set, those would match anywhere.  So
the match is built in two steps:

  1. Anchors: slices of at least ANCHOR_MIN bytes that occur exactly once in
     the export.  Entropy-coded picture data of that size does not repeat by
     chance.  The longest chain of anchors appearing in the same order on
     both sides is kept, each slice used at most once.
  2. Fill: every other export slice must sit at the position its neighbouring
     anchors predict, and be byte-identical there.

Identical tiny slices alone can therefore never produce a match.

WHAT IT DOES NOT DECIDE
-----------------------
It does not change any vendor's validation status.  A full match meets the
criterion in `VALIDATION_REPORT.md` §9; recording it there and moving the
status in the code is a reviewed change, because the weakest evidence still
sets the status.

Stdlib only, like the rest of the forensic core.  Reads the files it is
given through read-only memory maps; writes nothing.
"""

from __future__ import annotations

import hashlib
import mmap
import os
from bisect import bisect_left, bisect_right
from typing import Iterator, Optional

from parsers.dahua import DHAV_HDR, DHAV_MAGIC, fmt_date, frame_ext, header_ok, walk_frames
from recover.pscarve import PACK, hk_time, parse_pack, psm_info

RULE = "validate.export.vcl-in-order.v1"
CRITERION = ("every VCL NAL unit (picture slice) of the recorder's export is found "
             "byte-identical, in the same order, in the footage recovered from the disk")
# Slices smaller than this can repeat (static scenes); they are checked by
# position but never used to find where the export sits in the recovered data.
ANCHOR_MIN = 64
# An export this short proves too little to meet the criterion.
MIN_VCL = 25
UNMATCHED_RANGES_KEPT = 20

SC3 = b"\x00\x00\x01"
ASF_GUID = bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c")
DHAV_CODECS = {"h264", "h265"}
PS_CODECS = {"h264": "h264", "h265": "h265"}


# ---------------------------------------------------------------------------
# What kind of file is this?
# ---------------------------------------------------------------------------
def sniff(head: bytes) -> str:
    """Container of a file from its first bytes: dhav, ps, annexb, mp4, avi,
    asf, or unknown.  By content, never by extension - recorders name their
    exports inconsistently (Hikvision writes Program Streams as `.mp4`)."""
    if head[:4] == b"IMKH" or head[:4] == PACK:         # Hikvision export header / PS pack
        return "ps"
    if head[4:8] == b"ftyp":
        return "mp4"
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        return "avi"
    if head[:16] == ASF_GUID:
        return "asf"
    if head[:3] == SC3 or head[:4] == b"\x00" + SC3:
        return "annexb"
    i = head.find(DHAV_MAGIC)
    while i >= 0:
        if header_ok(head[i:i + DHAV_HDR]):
            return "dhav"
        i = head.find(DHAV_MAGIC, i + 1)
    if head.find(PACK) >= 0:
        return "ps"
    return "unknown"


def sniff_file(path: str) -> str:
    with open(path, "rb") as fh:
        return sniff(fh.read(1 << 20))


# ---------------------------------------------------------------------------
# NAL units
# ---------------------------------------------------------------------------
def split_annexb(data) -> Iterator[bytes]:
    """NAL units of a complete Annex-B buffer.  Trailing zero bytes belong to
    the next start code (00 00 00 01), not to the NAL, and are dropped."""
    i = data.find(SC3)
    while i >= 0:
        j = data.find(SC3, i + 3)
        nal = bytes(data[i + 3:j if j >= 0 else len(data)]).rstrip(b"\x00")
        if nal:
            yield nal
        i = j


class NalSplitter:
    """NAL units from Annex-B bytes arriving in pieces, where a NAL may span
    pieces (an MPEG-PS frame is split across several PES packets).  Each NAL
    is tagged with the piece its body starts in."""

    def __init__(self):
        self.buf = bytearray()
        self.open = False            # buf holds the body of a NAL whose start code we saw
        self.tag = None
        self.prev_tag = None

    def feed(self, data, tag) -> Iterator[tuple[bytes, object]]:
        before = len(self.buf)
        self.buf += data
        b = self.buf
        i, cut = max(0, before - 2), 0      # a start code may straddle two pieces
        while True:
            j = b.find(SC3, i)
            if j < 0:
                break
            if self.open:
                nal = bytes(b[cut:j]).rstrip(b"\x00")
                if nal:
                    yield nal, self.tag
            self.open = True
            self.tag = tag if j + 3 >= before else self.prev_tag
            cut = i = j + 3
        del b[:cut if self.open else max(0, len(b) - 2)]
        self.prev_tag = tag

    def flush(self) -> Iterator[tuple[bytes, object]]:
        if self.open:
            nal = bytes(self.buf).rstrip(b"\x00")
            if nal:
                yield nal, self.tag
        self.buf, self.open = bytearray(), False


def guess_codec(nals: list[bytes]) -> str:
    """h264 or h265 from NAL headers.  An H.265 header is two bytes and its
    second byte is almost always 0x01 (layer 0, temporal id 1), with the low
    bit of the first byte clear; H.264 has a one-byte header, so its second
    byte is slice data and varies."""
    heads = [n[:2] for n in nals if len(n) >= 2]
    if not heads:
        return "unknown"
    h265 = sum(1 for h in heads if h[0] & 0x81 == 0 and 1 <= h[1] <= 7)
    return "h265" if h265 >= 0.9 * len(heads) else "h264"


def nal_type(nal: bytes, codec: str) -> int:
    return (nal[0] >> 1) & 0x3F if codec == "h265" else nal[0] & 0x1F


def is_vcl(nal: bytes, codec: str) -> bool:
    t = nal_type(nal, codec)
    return t <= 31 if codec == "h265" else 1 <= t <= 5


def is_param_set(nal: bytes, codec: str) -> bool:
    return nal_type(nal, codec) in ((32, 33, 34) if codec == "h265" else (7, 8))


def digest(b) -> bytes:
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------------------
# A file of footage, read through a read-only memory map
# ---------------------------------------------------------------------------
class Source:
    """One file of footage - an export or a recovered stream - as a sequence
    of (NAL unit, frame info).  Frame info is a small dict shared by every
    NAL of one container frame: its ordinal in the file and whatever the
    container says about it (DHAV counter and date, Hikvision `HK` time)."""

    def __init__(self, path: str, codec: str = "auto"):
        self.path = path
        self.kind = sniff_file(path)
        self.codec_arg = codec
        self.codec = codec
        self.codec_source = "stated by the examiner" if codec != "auto" else ""
        self.fh = None
        self.mm = None

    def __enter__(self) -> "Source":
        self.fh = open(self.path, "rb")
        size = os.fstat(self.fh.fileno()).st_size
        self.mm = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
        if self.codec == "auto":
            self.codec, self.codec_source = self._detect_codec()
        return self

    def __exit__(self, *exc) -> None:
        if isinstance(self.mm, mmap.mmap):
            self.mm.close()
        self.fh.close()

    # -- codec ------------------------------------------------------------
    def _detect_codec(self) -> tuple[str, str]:
        hint = self._container_codec()
        if hint in ("h264", "h265"):
            return hint, f"{self.kind} container"
        sample = []
        for nal, _ in self.units():
            sample.append(nal)
            if len(sample) >= 200:
                break
        return guess_codec(sample), "NAL headers"

    def _container_codec(self) -> Optional[str]:
        if self.kind == "dhav":
            for fr in walk_frames(self.mm, 0):
                if fr.is_video and fr.ext_length:
                    c = frame_ext(self.mm, fr.offset, fr).get("codec")
                    if c:
                        return c if c in DHAV_CODECS else None
            return None
        if self.kind == "ps":
            for p, _ in self._packs():
                if p.psm:
                    for st in psm_info(p.psm)["streams"]:
                        if st["type"] in PS_CODECS:
                            return PS_CODECS[st["type"]]
                    return None
        return None

    # -- units --------------------------------------------------------------
    def units(self) -> Iterator[tuple[bytes, dict]]:
        if self.kind == "dhav":
            yield from self._dhav_units()
        elif self.kind == "ps":
            yield from self._ps_units()
        elif self.kind == "annexb":
            for k, nal in enumerate(split_annexb(self.mm)):
                yield nal, {"frame": k}
        else:
            raise ValueError(f"{self.path}: cannot read a {self.kind!r} file directly")

    def _dhav_units(self) -> Iterator[tuple[bytes, dict]]:
        k = 0
        for fr in walk_frames(self.mm, 0):
            if not fr.is_video:
                continue
            info = {"frame": k, "number": fr.frame_number, "date": fmt_date(fr.date),
                    "ms": fr.ms, "span": (fr.offset, fr.length)}
            k += 1
            payload = self.mm[fr.offset + DHAV_HDR + fr.ext_length:fr.offset + fr.length - 8]
            for nal in split_annexb(payload):
                yield nal, info

    def _packs(self):
        mm = self.mm
        i = mm.find(PACK) if len(mm) else -1
        while i >= 0:
            p = parse_pack(mm, i, at_end=True)
            if p is None:
                i = mm.find(PACK, i + 1)
                continue
            yield p, i
            i = i + p.length if i + p.length < len(mm) else -1

    def _ps_units(self) -> Iterator[tuple[bytes, dict]]:
        mm, sp, time = self.mm, NalSplitter(), None
        for k, (p, i) in enumerate(self._packs()):
            if p.psm:
                time = hk_time(p.psm) or time
            info = {"frame": k, "time": time, "span": (i, p.length)}
            q, end = i + 14 + (mm[i + 13] & 0x07), i + p.length
            while q + 6 <= end:
                sid = mm[q + 3]
                if sid == 0xB9:                         # program end code
                    q += 4
                    continue
                n = (mm[q + 4] << 8) | mm[q + 5]
                if 0xE0 <= sid <= 0xEF:
                    body = q + 6
                    if n >= 3 and (mm[q + 6] & 0xC0) == 0x80:   # MPEG-2 PES header
                        body = q + 9 + mm[q + 8]
                    yield from sp.feed(mm[body:q + 6 + n], info)
                q += 6 + n
        yield from sp.flush()

    def keep_frame(self, info: dict) -> None:
        """For a DHAV frame that matters to the result: the SHA-256 of the
        whole frame (header, extension, payload, trailer) and its header, to
        say whether the export kept the frame as stored.  Done only for
        matched frames - hashing every frame of a recovered hour is waste."""
        if self.kind != "dhav" or "frame_sha256" in info:
            return
        off, n = info["span"]
        info["frame_sha256"] = hashlib.sha256(self.mm[off:off + n]).hexdigest()
        info["header_hex"] = bytes(self.mm[off:off + DHAV_HDR]).hex()


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def _public(info: dict) -> dict:
    return {k: v for k, v in info.items() if k not in ("span", "header_hex")}


def longest_chain(anchors: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Longest subsequence of (recovered position, export index) pairs, given
    in recovered order, whose export indices strictly increase."""
    tails: list[int] = []        # export index ending the best chain of each length
    tail_at: list[int] = []      # position in `anchors` of that chain's last pair
    parent = [-1] * len(anchors)
    for n, (_g, i) in enumerate(anchors):
        k = bisect_left(tails, i)
        if k == len(tails):
            tails.append(i)
            tail_at.append(n)
        else:
            tails[k], tail_at[k] = i, n
        parent[n] = tail_at[k - 1] if k else -1
    chain, n = [], tail_at[-1] if tail_at else -1
    while n >= 0:
        chain.append(anchors[n])
        n = parent[n]
    return chain[::-1]


def fill(chain: list[tuple[int, int]], hashed: dict[int, bytes],
         export: list[tuple[bytes, int, dict]]) -> dict[int, int]:
    """Export index -> recovered position, for the anchors and for every
    other export slice found byte-identical where its neighbouring anchors
    say it should be."""
    got = {i: g for g, i in chain}
    if not chain:
        return got
    ai = [i for _, i in chain]
    ag = [g for g, _ in chain]
    used = set(ag)
    for i, (d, _n, _info) in enumerate(export):
        if i in got:
            continue
        k = bisect_right(ai, i)
        lo = ag[k - 1] if k else -1                     # stay between the neighbouring
        hi = ag[k] if k < len(ag) else float("inf")     # anchors: order is kept
        guesses = []
        if k:
            guesses.append(ag[k - 1] + (i - ai[k - 1]))
        if k < len(ag):
            guesses.append(ag[k] - (ai[k] - i))
        for g in guesses:
            if lo < g < hi and g not in used and hashed.get(g) == d:
                got[i] = g
                used.add(g)
                break
    # Guesses from the anchor before and the anchor after can cross where the
    # recovered side holds extra slices.  Keep only what stays in order.
    ordered, last = {}, -1
    for i in sorted(got):
        if got[i] > last:
            ordered[i] = last = got[i]
    return ordered


def _ranges(idx: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for i in idx:
        if out and out[-1][1] == i - 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def read_export(path: str, codec: str = "auto") -> dict:
    """The export's slices, parameter sets and frames."""
    with Source(path, codec) as ex:
        slices, params, frames = [], set(), set()
        for nal, info in ex.units():
            if is_vcl(nal, ex.codec):
                ex.keep_frame(info)
                slices.append((digest(nal), len(nal), info))
                frames.add(info["frame"])
            elif is_param_set(nal, ex.codec):
                params.add(digest(nal))
        return {"path": path, "container": ex.kind, "codec": ex.codec,
                "codec_source": ex.codec_source, "slices": slices, "params": params,
                "frames": len(frames)}


def match_source(path: str, export: dict, progress=None) -> dict:
    """One recovered file against the export: which export slices it holds,
    in order, and at which of its own positions."""
    slices = export["slices"]
    sizes = {n for _, n, _ in slices}
    where: dict[bytes, list[int]] = {}
    for i, (d, _n, _) in enumerate(slices):
        where.setdefault(d, []).append(i)
    anchor = {d: ix[0] for d, ix in where.items()
              if len(ix) == 1 and slices[ix[0]][1] >= ANCHOR_MIN}

    with Source(path, export["codec"]) as src:
        hashed: dict[int, bytes] = {}
        info_at: dict[int, dict] = {}
        anchors: list[tuple[int, int]] = []
        params: set[bytes] = set()
        g = 0
        for nal, info in src.units():
            if not is_vcl(nal, src.codec):
                if is_param_set(nal, src.codec):
                    params.add(digest(nal))
                continue
            if len(nal) in sizes:                        # a different size cannot be equal
                d = digest(nal)
                hashed[g] = d
                if d in where:
                    src.keep_frame(info)
                    info_at[g] = info
                    if d in anchor:
                        anchors.append((g, anchor[d]))
            g += 1
            if progress and g % 200_000 == 0:
                progress(path, g)
        got = fill(longest_chain(anchors), hashed, slices)
        return {"path": path, "container": src.kind, "codec": src.codec, "slices": g,
                "anchors_found": len(anchors), "got": got,
                "info": {gg: info_at[gg] for gg in got.values()}, "params": params}


def compare(export_path: str, recovered_paths: list[str], codec: str = "auto",
            progress=None) -> dict:
    """The whole comparison, as a JSON-ready result (hashes of the files
    themselves are added by the caller, which knows which ones to trust)."""
    ex = read_export(export_path, codec)
    slices = ex["slices"]
    total = len(slices)
    per = [match_source(p, ex, progress) for p in recovered_paths]

    # Each export slice is credited to one recovered file, the best first.
    owner: dict[int, tuple[int, int]] = {}
    for s_ix in sorted(range(len(per)), key=lambda k: -len(per[k]["got"])):
        for i, g in per[s_ix]["got"].items():
            owner.setdefault(i, (s_ix, g))

    matched = len(owner)
    verdict = ("identical" if matched == total and total else
               "partial" if matched else "none")
    missing = [i for i in range(total) if i not in owner]
    unmatched = [{"export_slices": [a, b],
                  "from": _public(slices[a][2]), "to": _public(slices[b][2])}
                 for a, b in _ranges(missing)[:UNMATCHED_RANGES_KEPT]]
    frames_all = {}
    for i, (_d, _n, info) in enumerate(slices):
        frames_all.setdefault(info["frame"], []).append(i in owner)

    rec_params = set().union(*(s["params"] for s in per)) if per else set()
    result = {
        "rule": RULE,
        "criterion": CRITERION,
        "export": {"path": ex["path"], "container": ex["container"], "codec": ex["codec"],
                   "codec_source": ex["codec_source"], "frames": ex["frames"],
                   "slices": total,
                   "first": _public(slices[0][2]) if slices else None,
                   "last": _public(slices[-1][2]) if slices else None},
        "recovered": [],
        "match": {
            "verdict": verdict,
            "slices_matched": matched, "slices_total": total,
            "share": round(matched / total, 6) if total else 0.0,
            "frames_fully_matched": sum(1 for v in frames_all.values() if all(v)),
            "frames_total": len(frames_all),
            "unmatched_ranges": unmatched,
            "unmatched_ranges_total": len(_ranges(missing)),
        },
        "parameter_sets": {"in_both": len(ex["params"] & rec_params),
                           "export_only": len(ex["params"] - rec_params),
                           "recovered_only": len(rec_params - ex["params"])},
        "container": _container_diff(slices, per, owner),
        "meets_criterion": verdict == "identical" and total >= MIN_VCL,
        "notes": [],
    }
    for k, s in enumerate(per):
        mine = sorted(i for i, (s_ix, _) in owner.items() if s_ix == k)
        result["recovered"].append({
            "path": s["path"], "container": s["container"], "codec": s["codec"],
            "slices": s["slices"], "anchors_found": s["anchors_found"],
            "slices_credited": len(mine),
            "export_range": [mine[0], mine[-1]] if mine else None,
            "first": _public(s["info"][owner[mine[0]][1]]) if mine else None,
            "last": _public(s["info"][owner[mine[-1]][1]]) if mine else None})
    if total < MIN_VCL:
        result["notes"].append(f"the export holds {total} slices; at least {MIN_VCL} "
                               f"are needed before a full match meets the criterion")
    if verdict == "partial":
        result["notes"].append("some export slices were not found where the matched "
                               "ones place them - see unmatched_ranges; each needs an "
                               "explanation (a frame lost on the disk, a frame the "
                               "export added) before this can be called validated")
    return result


def _container_diff(slices, per, owner) -> dict:
    """Frame-level comparison of matched frames, where both sides carry
    container fields: did the export keep the frame bytes, the counter, the
    date?  Informative only - the verdict rests on the slices."""
    pairs = {}
    for i, (s_ix, g) in owner.items():
        e = slices[i][2]
        r = per[s_ix]["info"][g]
        pairs.setdefault((e["frame"], s_ix, r["frame"]), (e, r))
    out = {"frames_compared": len(pairs)}
    if not pairs:
        return out
    es = [e for e, _ in pairs.values()]
    rs = [r for _, r in pairs.values()]
    if all("frame_sha256" in x for x in es + rs):
        same = [e["frame_sha256"] == r["frame_sha256"] for e, r in zip(es, rs)]
        out["frames_byte_identical"] = sum(same)
        out["frame_counter_equal"] = sum(e["number"] == r["number"] for e, r in zip(es, rs))
        out["date_equal"] = sum(e["date"] == r["date"] for e, r in zip(es, rs))
        diff = next((k for k, s in enumerate(same) if not s), None)
        if diff is not None:
            out["first_difference"] = {"export_header_hex": es[diff]["header_hex"],
                                       "recovered_header_hex": rs[diff]["header_hex"]}
    elif all(x.get("time") for x in es + rs):
        out["time_equal"] = sum(e["time"] == r["time"] for e, r in zip(es, rs))
    return out

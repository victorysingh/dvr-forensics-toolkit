"""Signature scanning, codec profiling and confidence-scored vendor detection.

The engine is fed the device block by block by the acquisition pass, so the
drive is read exactly once for hashing, signature detection and codec
profiling together.  On a multi-TB DVR disk a second pass is hours, not
minutes, so single-pass is a hard design constraint rather than an
optimisation.

Three things happen per block:

  1. multi-pattern signature search (one compiled regex alternation, so the
     matching runs in C rather than per-pattern Python loops)
  2. codec profiling - cheap start-code density plus targeted SPS/PPS/IDR
     matching, because raw start codes number in the millions and are not
     individually interesting
  3. an incompressibility ratio, used to flag encrypted or already-compressed
     regions.  Reported as "high entropy, not parsed" - never as "encrypted",
     which we cannot prove from entropy alone.
"""

from __future__ import annotations

import math
import re
from collections import Counter
import zlib
from dataclasses import dataclass, field
from typing import Optional

from core.contract import (Partition, SignatureHit, VendorDetection,
                           VALIDATION_DETECTED, VALIDATION_SPEC_ONLY,
                           VALIDATION_VALIDATED)
from detect import signatures as sig

MAX_HITS_PER_SIGNATURE = 500      # record this many, count the rest
CONTEXT_BYTES = 32

# Targeted NAL patterns.  A 3-byte start code followed by a NAL header whose
# low 5 bits carry the type and whose top bit must be zero (forbidden_zero).
_H264_SPS = re.compile(rb"\x00\x00\x01[\x07\x27\x47\x67]")
_H264_PPS = re.compile(rb"\x00\x00\x01[\x08\x28\x48\x68]")
_H264_IDR = re.compile(rb"\x00\x00\x01[\x05\x25\x45\x65]")
# HEVC: type is bits 1-6 of the first header byte; VPS=32, SPS=33, PPS=34.
_H265_PS = re.compile(rb"\x00\x00\x01[\x40\x42\x44]")

# All four in ONE pass, classified by the header byte captured.  The counts
# equal four separate passes exactly: every match is 00 00 01 X with X never
# 0x00, and a second start code cannot begin inside such a match unless X
# were 0x00 - so no two matches of the patterns above can overlap.
_NAL_KIND = {**{b: "sps" for b in b"\x07\x27\x47\x67"},
             **{b: "pps" for b in b"\x08\x28\x48\x68"},
             **{b: "idr" for b in b"\x05\x25\x45\x65"},
             **{b: "hevc_ps" for b in b"\x40\x42\x44"}}
_NAL_ANY = re.compile(rb"\x00\x00\x01([" + b"".join(
    re.escape(bytes([b])) for b in sorted(_NAL_KIND)) + rb"])")


@dataclass
class BlockSummary:
    """One row of the block map. Doubles as the Merkle leaf record."""
    index: int
    offset: int
    length: int
    sha256: str
    incompressibility: float = 0.0
    start_codes: int = 0
    sps: int = 0
    pps: int = 0
    idr: int = 0
    hevc_ps: int = 0
    hits: int = 0
    bad: bool = False


@dataclass
class CodecProfile:
    start_codes: int = 0
    sps: int = 0
    pps: int = 0
    idr: int = 0
    hevc_ps: int = 0
    sps_offsets: list[int] = field(default_factory=list)

    @property
    def likely_codec(self) -> str:
        if self.hevc_ps > self.sps and self.hevc_ps > 0:
            return "h265"
        if self.sps > 0 or self.start_codes > 1000:
            return "h264"
        return ""

    def to_dict(self) -> dict:
        return {"start_codes": self.start_codes, "sps": self.sps,
                "pps": self.pps, "idr": self.idr, "hevc_param_sets": self.hevc_ps,
                "likely_codec": self.likely_codec,
                "first_sps_offsets": self.sps_offsets[:20]}


class SignatureScanner:
    """Streaming multi-pattern matcher with correct block-boundary handling."""

    def __init__(self, sigs: Optional[list[sig.Signature]] = None,
                 sample_bytes: int = 4096):
        self.signatures = sigs if sigs is not None else sig.ALL_SIGNATURES
        self._by_pattern: dict[bytes, list[sig.Signature]] = {}
        for s in self.signatures:
            self._by_pattern.setdefault(s.pattern, []).append(s)
        patterns = sorted(self._by_pattern, key=len, reverse=True)
        self._re = re.compile(b"|".join(re.escape(p) for p in patterns))
        self._overlap = max(len(p) for p in patterns) - 1 if patterns else 0
        self._tail = b""
        self._tail_offset = 0
        self.sample_bytes = sample_bytes

        self.hits: list[SignatureHit] = []
        self.hit_counts: dict[str, int] = {}
        self.codec = CodecProfile()
        self.blocks: list[BlockSummary] = []

    # -- per block ---------------------------------------------------------
    def scan_block(self, offset: int, data: bytes, index: int,
                   sha256_hex: str, bad: bool = False) -> BlockSummary:
        # Prepend the carry-over tail so a magic straddling the block boundary
        # is still found, then discard hits that belong to the previous block.
        if self._tail and self._tail_offset + len(self._tail) == offset:
            buf = self._tail + data
            base = offset - len(self._tail)
        else:
            buf = data
            base = offset

        found = 0
        # This loop runs once per match - on a Dahua disk, once per frame -
        # so each match's text and position are read once and the lookups
        # held locally.  The matches, counts and hits are unchanged.
        counts, by_pattern, has_tail = self.hit_counts, self._by_pattern, bool(self._tail)
        for m in self._re.finditer(buf):
            start, g = m.start(), m.group()
            abs_off = base + start
            # Skip only matches that lie WHOLLY inside the carry-over tail -
            # those were complete in the previous block and already reported.
            # A match that starts in the tail but ends past the boundary was
            # invisible last time and must be reported now, which is the whole
            # reason the tail exists.
            if has_tail and abs_off + len(g) <= offset:
                continue
            found += 1
            for s in by_pattern[g]:
                n = counts.get(s.id, 0) + 1
                counts[s.id] = n
                if n <= MAX_HITS_PER_SIGNATURE:
                    self.hits.append(self._make_hit(s, abs_off, buf, start, base))

        summary = BlockSummary(
            index=index, offset=offset, length=len(data), sha256=sha256_hex,
            hits=found, bad=bad,
        )
        self._profile_codec(data, offset, summary)
        summary.incompressibility = self._incompressibility(data)

        self._tail = data[-self._overlap:] if self._overlap else b""
        self._tail_offset = offset + len(data) - len(self._tail)
        self.blocks.append(summary)
        return summary

    def _make_hit(self, s: sig.Signature, abs_off: int, buf: bytes,
                  rel: int, base: int) -> SignatureHit:
        at_expected = any(abs(abs_off - e) <= s.offset_tolerance
                          for e in s.expected_offsets)
        ctx_start = max(0, rel - CONTEXT_BYTES)
        return SignatureHit(
            signature_id=s.id, vendor=s.vendor, offset=abs_off,
            length=len(s.pattern), matched_hex=s.pattern.hex(),
            at_expected_offset=at_expected,
            context_hex=buf[ctx_start:rel + len(s.pattern) + CONTEXT_BYTES].hex(),
        )

    def _profile_codec(self, data: bytes, offset: int, summary: BlockSummary) -> None:
        summary.start_codes = data.count(sig.START_CODE_3)
        if summary.start_codes == 0:
            return
        kinds = {"sps": 0, "pps": 0, "idr": 0, "hevc_ps": 0}
        for header, n in Counter(_NAL_ANY.findall(data)).items():
            kinds[_NAL_KIND[header[0]]] += n
        summary.sps, summary.pps = kinds["sps"], kinds["pps"]
        summary.idr, summary.hevc_ps = kinds["idr"], kinds["hevc_ps"]

        self.codec.start_codes += summary.start_codes
        self.codec.sps += summary.sps
        self.codec.pps += summary.pps
        self.codec.idr += summary.idr
        self.codec.hevc_ps += summary.hevc_ps
        if summary.sps and len(self.codec.sps_offsets) < 200:
            for m in _H264_SPS.finditer(data):
                self.codec.sps_offsets.append(offset + m.start())
                if len(self.codec.sps_offsets) >= 200:
                    break

    def _incompressibility(self, data: bytes) -> float:
        """1.0 = incompressible (encrypted or already-compressed payload),
        near 0 = highly structured/empty.  zlib at level 1 keeps this at C
        speed; true Shannon entropy per block would dominate the scan time."""
        sample = data[:self.sample_bytes]
        if not sample:
            return 0.0
        # Clamped at 1.0: zlib adds a small header, so incompressible input
        # comes back slightly larger than it went in, and a report that says
        # "100.3% random" invites exactly the wrong question in court.
        return round(min(1.0, len(zlib.compress(sample, 1)) / len(sample)), 4)

    # -- conclusions -------------------------------------------------------
    def detections(self) -> list[VendorDetection]:
        """Score each vendor. Confidence saturates rather than maxing out, so
        the tool never reports a bare 100% it cannot defend."""
        per_vendor: dict[str, list[sig.Signature]] = {}
        for s in self.signatures:
            if s.category != "vendor" or not self.hit_counts.get(s.id):
                continue
            per_vendor.setdefault(s.vendor, []).append(s)

        out: list[VendorDetection] = []
        for vendor, sigs_found in per_vendor.items():
            score = 0.0
            evidence: list[str] = []
            total_hits = 0
            statuses: list[str] = []
            for s in sigs_found:
                count = self.hit_counts[s.id]
                total_hits += count
                at_expected = any(h.at_expected_offset for h in self.hits
                                  if h.signature_id == s.id)
                base = s.weight * (2.0 if at_expected else 1.0)
                # Repeats corroborate, but with strongly diminishing returns -
                # a magic that appears a million times in video payload is
                # noise, not a million proofs.
                score += base * (1.0 + math.log10(min(count, 10_000)))
                statuses.append(s.validation_status)
                evidence.append(
                    f"{s.id} x{count}"
                    f"{' @expected offset' if at_expected else ''}"
                    f" ({s.description}; source: {s.source})")

            # Multiple independent signatures for one vendor matter a lot more
            # than many repeats of a single one.
            score *= 1.0 + 0.30 * (len(sigs_found) - 1)
            confidence = round(1.0 - math.exp(-score / 18.0), 4)

            out.append(VendorDetection(
                vendor=vendor,
                confidence=confidence,
                validation_status=_weakest(statuses),
                evidence=evidence,
                hit_count=total_hits,
                parser_available=vendor in sig.PARSERS_AVAILABLE,
            ))
        out.sort(key=lambda d: d.confidence, reverse=True)
        return out

    def coverage_statement(self) -> list[dict]:
        """Explicit per-OEM position for the report. Answers the question a
        judge or an investigator will actually ask: what did you test?"""
        detected = {d.vendor: d for d in self.detections()}
        rows = []
        for vendor in sig.PS_VENDORS:
            d = detected.get(vendor)
            rows.append({
                "vendor": vendor,
                "detected_on_this_disk": bool(d),
                "confidence": d.confidence if d else 0.0,
                "parser_available": vendor in sig.PARSERS_AVAILABLE,
                "status": (d.validation_status if d
                           else "not_detected_on_this_disk"),
            })
        return rows


_STATUS_RANK = {sig.CANDIDATE: 0, sig.DETECTED_ONLY: 1,
                sig.SPEC_ONLY: 2, sig.VALIDATED: 3}
_STATUS_TO_CONTRACT = {
    sig.CANDIDATE: VALIDATION_DETECTED,
    sig.DETECTED_ONLY: VALIDATION_DETECTED,
    sig.SPEC_ONLY: VALIDATION_SPEC_ONLY,
    sig.VALIDATED: VALIDATION_VALIDATED,
}


def _weakest(statuses: list[str]) -> str:
    """Report the most conservative status among the evidence, never the best
    one - claiming the strongest is how tools end up overstating support."""
    if not statuses:
        return VALIDATION_DETECTED
    worst = min(statuses, key=lambda s: _STATUS_RANK.get(s, 0))
    return _STATUS_TO_CONTRACT.get(worst, VALIDATION_DETECTED)


# ---------------------------------------------------------------------------
# Partition tables.  DVR disks are often "unpartitioned" from Windows' point
# of view precisely because the whole platter is a proprietary volume - that
# absence is itself a finding, so we report it rather than erroring out.
# ---------------------------------------------------------------------------
MBR_TYPES = {0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32-LBA",
             0x83: "Linux", 0x82: "Linux swap", 0xEE: "GPT protective"}


def parse_partitions(head: bytes, sector_size: int = 512) -> list[Partition]:
    parts: list[Partition] = []
    if len(head) < 512 or head[510:512] != b"\x55\xaa":
        return parts

    gpt = head[sector_size:sector_size + 8] == b"EFI PART"
    for i in range(4):
        e = head[446 + i * 16: 462 + i * 16]
        ptype = e[4]
        lba = int.from_bytes(e[8:12], "little")
        count = int.from_bytes(e[12:16], "little")
        if ptype == 0 or count == 0:
            continue
        parts.append(Partition(
            index=i, start_offset=lba * sector_size, length=count * sector_size,
            scheme="gpt-protective-mbr" if ptype == 0xEE else "mbr",
            type_hint=MBR_TYPES.get(ptype, f"0x{ptype:02X}"),
            confidence=0.95,
        ))

    if gpt and len(head) >= sector_size * 3:
        hdr = head[sector_size:sector_size * 2]
        entry_lba = int.from_bytes(hdr[72:80], "little")
        n_entries = int.from_bytes(hdr[80:84], "little")
        entry_size = int.from_bytes(hdr[84:88], "little")
        base = entry_lba * sector_size
        gpt_parts = []
        for i in range(min(n_entries, 128)):
            off = base + i * entry_size
            if off + entry_size > len(head):
                break
            e = head[off:off + entry_size]
            if e[0:16] == b"\x00" * 16:
                continue
            first = int.from_bytes(e[32:40], "little")
            last = int.from_bytes(e[40:48], "little")
            name = e[56:128].decode("utf-16-le", "ignore").rstrip("\x00")
            gpt_parts.append(Partition(
                index=i, start_offset=first * sector_size,
                length=(last - first + 1) * sector_size,
                scheme="gpt", type_hint=name or "gpt-entry", confidence=0.98,
            ))
        if gpt_parts:
            parts = gpt_parts
    return parts

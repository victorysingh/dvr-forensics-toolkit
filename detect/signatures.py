"""Vendor and filesystem signature database.

HONESTY RULE (project-wide): every signature carries a `source` and a
`validation_status`.  We never let the UI or the report imply we support a
vendor we have only read a paper about.  Four states:

    validated        confirmed against a real disk or image we possess
    spec_only        from published research / open-source parser, untested
    detected_only    we can recognise it but have no parser
    candidate        plausible magic, NOT yet corroborated - lowest weight

`weight` feeds the confidence score.  A magic sitting at its documented
offset counts for much more than the same bytes found loose on the platter,
because video payload can contain any byte sequence by chance.
"""

from __future__ import annotations

from dataclasses import dataclass, field

VALIDATED = "validated"
SPEC_ONLY = "spec_only"
DETECTED_ONLY = "detected_only"
CANDIDATE = "candidate"


@dataclass(frozen=True)
class Signature:
    id: str
    vendor: str
    pattern: bytes
    description: str
    source: str
    validation_status: str = SPEC_ONLY
    weight: float = 1.0
    expected_offsets: tuple[int, ...] = field(default_factory=tuple)
    offset_tolerance: int = 0
    category: str = "vendor"          # vendor | filesystem | codec


# ---------------------------------------------------------------------------
# Hikvision.  Best-documented of the DVR filesystems and the one vendor we
# have physical hardware for (DS-80xx board), so it is the only one that can
# reach `validated` once we image the drive.
# ---------------------------------------------------------------------------
HIKVISION = [
    Signature(
        id="hik.master",
        vendor="Hikvision",
        pattern=b"HIKVISION@HANGZHOU",
        description="Master sector magic of the Hikvision proprietary FS",
        source="Han/Jeong/Lee DVR filesystem analysis; hikextractor",
        validation_status=SPEC_ONLY,
        weight=10.0,
        expected_offsets=(0x200,),
        offset_tolerance=0x200,
    ),
    Signature(
        id="hik.btree",
        vendor="Hikvision",
        pattern=b"HIKBTREE",
        description="HIKBTREE index header - maps recordings to data blocks",
        source="published Hikvision FS analyses",
        validation_status=SPEC_ONLY,
        weight=8.0,
    ),
    Signature(
        id="hik.offset",
        vendor="Hikvision",
        pattern=b"OFFSET",
        description="Data-block header marker inside HIKBTREE page areas",
        source="published Hikvision FS analyses",
        validation_status=CANDIDATE,
        weight=1.5,
    ),
]

# ---------------------------------------------------------------------------
# Dahua (and the many boards OEM'd from it - CP Plus is frequently a rebadge,
# which is exactly why vendor attribution needs a confidence score and not a
# yes/no answer).
# ---------------------------------------------------------------------------
DAHUA = [
    Signature(
        id="dahua.dhfs",
        vendor="Dahua",
        pattern=b"DHFS",
        description="Dahua filesystem superblock magic",
        source="dvrdecode; Dahua FS write-ups",
        validation_status=SPEC_ONLY,
        weight=7.0,
    ),
    Signature(
        id="dahua.dhav",
        vendor="Dahua",
        pattern=b"DHAV",
        description="DHAV frame container header (video payload wrapper)",
        source="DHAV format documentation; ffmpeg dhav demuxer",
        validation_status=SPEC_ONLY,
        weight=6.0,
    ),
    Signature(
        id="dahua.dhav_end",
        vendor="Dahua",
        pattern=b"dhav",
        description="DHAV frame trailer - pairs with the DHAV header",
        source="ffmpeg dhav demuxer",
        validation_status=SPEC_ONLY,
        weight=4.0,
    ),
]

# ---------------------------------------------------------------------------
# Remaining OEMs named in the problem statement.  We are explicit that these
# are recognition-only: the PS asks for 5-6 OEMs, and the defensible way to
# claim breadth is "detected, not parsed" plus a plugin SDK, never a silent
# implication of full support.
# ---------------------------------------------------------------------------
OTHER_OEMS = [
    Signature(
        id="honeywell.fs",
        vendor="Honeywell",
        pattern=b"HONEYWELL",
        description="Honeywell NVR volume label / firmware string",
        source="Honeywell-NVR-Filesystem-Tools",
        validation_status=DETECTED_ONLY,
        weight=5.0,
    ),
    Signature(
        id="uniview.fs",
        vendor="Uniview",
        pattern=b"UNIVIEW",
        description="Uniview firmware / volume identifier string",
        source="firmware string observation",
        validation_status=DETECTED_ONLY,
        weight=4.0,
    ),
    Signature(
        id="cpplus.brand",
        vendor="CP Plus",
        pattern=b"CPPLUS",
        description="CP Plus branding string (often a Dahua-derived board)",
        source="firmware string observation",
        validation_status=DETECTED_ONLY,
        weight=4.0,
    ),
    Signature(
        id="cpplus.osd_title",
        vendor="CP Plus",
        pattern=b"CPPlusIPCam",
        description="default channel title in the TEXT block of DHAV auxiliary "
                    "(0xF1) frames - on-platter evidence of CP Plus cameras. A user "
                    "can rename channels, so absence proves nothing",
        source="observed: ST1000VX013 s/n WWD4A3NX (CP Plus unit), 17,557 occurrences "
               "in the first 20 GiB, found by detect/survey.py",
        validation_status=SPEC_ONLY,
        weight=4.0,
    ),
    Signature(
        id="tplink.brand",
        vendor="TP-Link",
        pattern=b"TP-LINK",
        description="TP-Link / VIGI branding string",
        source="firmware string observation",
        validation_status=DETECTED_ONLY,
        weight=3.0,
    ),
    Signature(
        id="godrej.brand",
        vendor="Godrej",
        pattern=b"GODREJ",
        description="Godrej branding string",
        source="firmware string observation",
        validation_status=DETECTED_ONLY,
        weight=3.0,
    ),
    Signature(
        id="matrix.brand",
        vendor="Matrix",
        pattern=b"MATRIX",
        description="Matrix branding string (weak - common English word)",
        source="firmware string observation",
        validation_status=CANDIDATE,
        weight=1.0,
    ),
    Signature(
        id="heimvision.brand",
        vendor="Heimvision",
        pattern=b"HEIMVISION",
        description="Heimvision string - the NIST CFReDS reference DVR image",
        source="NIST CFReDS DVR dataset",
        validation_status=DETECTED_ONLY,
        weight=5.0,
    ),
]

# ---------------------------------------------------------------------------
# Standard filesystems.  A DVR disk very often carries a small conventional
# partition (firmware, config, logs) alongside the proprietary video area -
# finding one tells us where the proprietary region is NOT.
# ---------------------------------------------------------------------------
FILESYSTEMS = [
    Signature(id="fs.ntfs", vendor="-", pattern=b"NTFS    ",
              description="NTFS boot sector OEM ID", source="Microsoft spec",
              validation_status=VALIDATED, weight=3.0, category="filesystem"),
    Signature(id="fs.exfat", vendor="-", pattern=b"EXFAT   ",
              description="exFAT boot sector OEM ID", source="Microsoft spec",
              validation_status=VALIDATED, weight=3.0, category="filesystem"),
    Signature(id="fs.fat32", vendor="-", pattern=b"FAT32   ",
              description="FAT32 boot sector label", source="Microsoft spec",
              validation_status=VALIDATED, weight=3.0, category="filesystem"),
    Signature(id="fs.xfs", vendor="-", pattern=b"XFSB",
              description="XFS superblock magic", source="XFS spec",
              validation_status=VALIDATED, weight=3.0, category="filesystem"),
    Signature(id="fs.squashfs", vendor="-", pattern=b"hsqs",
              description="SquashFS magic - typical of embedded DVR firmware",
              source="SquashFS spec", validation_status=VALIDATED,
              weight=3.0, category="filesystem"),
]

ALL_SIGNATURES: list[Signature] = HIKVISION + DAHUA + OTHER_OEMS + FILESYSTEMS

BY_ID = {s.id: s for s in ALL_SIGNATURES}

# Vendors the PS names, so the report can state coverage explicitly rather
# than listing only what happened to be found.
PS_VENDORS = ["Hikvision", "Dahua", "CP Plus", "Honeywell", "TP-Link",
              "Godrej", "Uniview", "Matrix"]

# Which vendors we actually ship a filesystem parser for, today.
#
# Populated by `parsers/__init__.py` from the plugin registry when that
# package is imported, so it cannot drift from the plugins that actually
# exist.  It stays empty for callers that only ever import `detect`, which is
# the honest answer for them: detection alone parses nothing.  Note that a
# parser existing says nothing about whether it has been validated - that is
# `VendorDetection.validation_status`, and the two are deliberately separate.
PARSERS_AVAILABLE: set[str] = set()

# ---------------------------------------------------------------------------
# Codec-level markers, handled separately from the byte-signature scan.
#
# H.264/H.265 Annex-B start codes occur millions of times on a video disk, so
# recording each one as a "hit" is useless.  The engine counts them per block
# and records only the rare, structurally meaningful NAL units (SPS/PPS/VPS),
# which are what a carver needs to rebuild a playable clip.
# ---------------------------------------------------------------------------
START_CODE_4 = b"\x00\x00\x00\x01"
START_CODE_3 = b"\x00\x00\x01"

H264_NAL = {1: "non-IDR slice", 5: "IDR slice", 6: "SEI",
            7: "SPS", 8: "PPS", 9: "AUD"}
H264_KEY_NAL = {5, 7, 8}

H265_NAL = {19: "IDR_W_RADL", 20: "IDR_N_LP", 32: "VPS", 33: "SPS", 34: "PPS"}
H265_KEY_NAL = {19, 20, 32, 33, 34}

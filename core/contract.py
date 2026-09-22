"""Frozen shared JSON data contract for the PS26150 forensic pipeline.

Every engine (acquisition, parsing, recovery, timeline, report) reads and
writes these shapes and nothing else.  Teams build against the mock fixtures
in tests/fixtures/ before real parsers exist.

SCHEMA_VERSION is frozen.  Additive changes bump the minor version; any
change that removes or retypes a field bumps the major version and must be
raised at the Saturday integration sync.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Optional

SCHEMA_VERSION = "1.0.0"
FROZEN_ON = "2026-09-22"


def utc_now() -> str:
    """Single source of truth for timestamps. Always UTC, always ISO-8601 Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --------------------------------------------------------------------------
# Honesty vocabulary.  Every vendor claim the tool makes must carry one of
# these.  We never imply support we have not demonstrated.
# --------------------------------------------------------------------------
VALIDATION_VALIDATED = "validated"      # tested against real hardware/image
VALIDATION_SPEC_ONLY = "spec_only"      # implemented from published spec, untested
VALIDATION_DETECTED = "detected_not_parsed"   # recognised, parser not implemented
VALIDATION_SYNTHETIC = "synthetic_only"  # only ever tested against generated data

# Region / recording lifecycle states
STATE_ACTIVE = "active"
STATE_DELETED = "deleted"
STATE_FRAGMENT = "fragment"
STATE_OVERWRITTEN = "overwritten"


@dataclass
class CaseInfo:
    case_id: str
    investigator: str
    organization: str = ""
    notes: str = ""
    opened_utc: str = field(default_factory=utc_now)


@dataclass
class DeviceInfo:
    """What we are reading. `write_blocked` records HOW, not just that."""
    path: str
    size_bytes: int
    sector_size: int
    model: str = ""
    serial: str = ""
    bus_type: str = ""
    removable: bool = False
    write_block_method: str = ""       # e.g. "software:read-only-handle"
    write_blocked: bool = False
    acquired_utc: str = field(default_factory=utc_now)


@dataclass
class HashRecord:
    algorithm: str
    value: str
    scope: str = "full_device"          # full_device | region | artifact
    offset: Optional[int] = None
    length: Optional[int] = None
    computed_utc: str = field(default_factory=utc_now)


@dataclass
class BadRegion:
    """Unreadable sectors. Reported, never silently skipped."""
    offset: int
    length: int
    error: str
    substituted_with: str = "zero_fill"


@dataclass
class Partition:
    index: int
    start_offset: int
    length: int
    scheme: str = ""                    # mbr | gpt | none
    type_hint: str = ""                 # ntfs | ext | proprietary:hikvision | ...
    confidence: float = 0.0


@dataclass
class SignatureHit:
    """One magic-byte match at one absolute offset on the device."""
    signature_id: str
    vendor: str
    offset: int
    length: int
    matched_hex: str
    at_expected_offset: bool = False
    context_hex: str = ""


@dataclass
class VendorDetection:
    """Scored conclusion about which OEM this disk came from."""
    vendor: str
    confidence: float                   # 0.0 - 1.0
    validation_status: str
    evidence: list[str] = field(default_factory=list)
    hit_count: int = 0
    parser_available: bool = False


@dataclass
class Provenance:
    """Where an artifact physically came from. Attached to everything."""
    disk_offset: int
    length: int
    sector_start: int
    sector_end: int
    parser_rule: str
    sha256: str = ""


@dataclass
class TimestampClaim:
    """A time assertion from ONE source. Never trusted alone - the clock-lie
    detector compares claims from different sources against each other."""
    source: str                         # container | index | osd_ocr | fs_meta
    raw_value: str
    decoded_utc: Optional[str] = None
    tz_offset_min: Optional[int] = None
    confidence: float = 0.0
    decode_rule: str = ""


@dataclass
class Frame:
    index: int
    offset: int
    length: int
    nal_type: int
    codec: str = ""                     # h264 | h265
    is_keyframe: bool = False
    pts: Optional[int] = None


@dataclass
class Recording:
    id: str
    camera_id: str
    state: str = STATE_ACTIVE
    codec: str = ""
    offset: int = 0
    length: int = 0
    start_utc: Optional[str] = None
    end_utc: Optional[str] = None
    duration_s: Optional[float] = None
    confidence: float = 0.0
    frame_count: int = 0
    timestamps: list[TimestampClaim] = field(default_factory=list)
    provenance: Optional[Provenance] = None


@dataclass
class ScanStats:
    bytes_read: int = 0
    blocks_hashed: int = 0
    block_size: int = 0
    bad_sectors: int = 0
    duration_s: float = 0.0
    throughput_mbps: float = 0.0
    complete_pass: bool = True


@dataclass
class ScanReport:
    """Top-level artifact of the acquire+detect stage."""
    schema_version: str = SCHEMA_VERSION
    tool: str = "ps26150-forensics"
    tool_version: str = "0.1.0"
    case: Optional[CaseInfo] = None
    device: Optional[DeviceInfo] = None
    hashes: list[HashRecord] = field(default_factory=list)
    merkle_root: str = ""
    partitions: list[Partition] = field(default_factory=list)
    signature_hits: list[SignatureHit] = field(default_factory=list)
    detections: list[VendorDetection] = field(default_factory=list)
    bad_regions: list[BadRegion] = field(default_factory=list)
    recordings: list[Recording] = field(default_factory=list)
    stats: Optional[ScanStats] = None
    ledger_head: str = ""
    generated_utc: str = field(default_factory=utc_now)


# --------------------------------------------------------------------------
# Serialisation.  Canonical form matters: the ledger hashes these bytes, so
# key order and separators must be deterministic across machines.
# --------------------------------------------------------------------------
def to_dict(obj: Any) -> Any:
    if is_dataclass(obj):
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


def canonical_json(obj: Any) -> bytes:
    """Deterministic bytes for hashing. Sorted keys, no whitespace padding."""
    return json.dumps(
        to_dict(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def dump_json(obj: Any, path: str, indent: int = 2) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(obj), fh, indent=indent, ensure_ascii=False)
        fh.write("\n")
    return path

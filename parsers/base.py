"""Vendor filesystem parser plugin SDK.

The problem statement names eight OEMs and asks for five to six.  We hold
media for two (a Dahua-family CP Plus drive and a Hikvision drive), so the
defensible way to answer it is detection across all eight plus a documented
plugin interface - never an implied claim of full support for formats nobody
on the team can test.  This module is that interface.

A plugin declares which vendor it handles, locates its own structures on the
platter, and returns contract objects.  It never opens a device itself: it is
handed a read-only `BlockDevice` by the caller, so the safety contract in
`acquire/device.py` holds for every plugin automatically and a third-party
plugin cannot introduce a write path.

FIELD PROVENANCE
----------------
Every field a parser decodes carries where its layout came from.  This exists
because of the trap described in START_HERE Rule 3: a magic string documented
in published research is not the same kind of evidence as a struct offset we
inferred from our own synthetic fixture, and a parser that blurs the two
overstates what we know.

    SOURCE_PUBLISHED  offset/layout attested by published research or an
                      existing open-source parser
    SOURCE_FIRMWARE   offset/layout read from the vendor's own firmware code
                      (static disassembly, nothing executed) - what the
                      recorder is programmed to write, not yet seen on a disk
    SOURCE_FIXTURE    offset/layout corroborated ONLY by tests/synth_dvr.py,
                      whose non-magic field layout is our own invention
    SOURCE_OBSERVED   offset/layout read off real vendor media we possess

The parser's overall status is set by its weakest field, the same rule the
detection engine applies in `detect/engine.py::_weakest`.  Nothing here may
report `validated`; only a byte-match against a DVR's own native export can
justify that, and that is a human decision recorded after the fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.contract import (
    VALIDATION_DETECTED,
    VALIDATION_SPEC_ONLY,
    VALIDATION_SYNTHETIC,
    Recording,
)

# Where a decoded field's layout comes from.  Ordered weakest to strongest.
SOURCE_FIXTURE = "fixture"
SOURCE_PUBLISHED = "published"
SOURCE_FIRMWARE = "vendor_firmware"
SOURCE_OBSERVED = "observed_real_media"

# Firmware ranks with a paper: both say what the recorder should write, and
# neither has been checked against a disk it wrote.
_SOURCE_RANK = {SOURCE_FIXTURE: 0, SOURCE_PUBLISHED: 1, SOURCE_FIRMWARE: 1,
                SOURCE_OBSERVED: 2}

# A field sourced only from our fixture can never support more than
# `synthetic_only`, however cleanly it parses.
_SOURCE_TO_STATUS = {
    SOURCE_FIXTURE: VALIDATION_SYNTHETIC,
    SOURCE_PUBLISHED: VALIDATION_SPEC_ONLY,
    SOURCE_FIRMWARE: VALIDATION_SPEC_ONLY,
    SOURCE_OBSERVED: VALIDATION_SPEC_ONLY,
}


@dataclass(frozen=True)
class FieldSpec:
    """One decoded struct field, with the evidence for its position."""
    name: str
    offset: int
    fmt: str                     # struct format, or "bytes:<n>" / "magic"
    description: str
    source: str = SOURCE_FIXTURE
    citation: str = ""

    @property
    def status(self) -> str:
        return _SOURCE_TO_STATUS.get(self.source, VALIDATION_SYNTHETIC)


def weakest_source(sources: list[str]) -> str:
    """The most conservative status among the evidence, never the best one.

    Mirrors `detect/engine.py::_weakest`.  Kept as a separate implementation
    because the inputs differ (field provenance here, signature status there),
    but the principle is identical and deliberately not relaxed.
    """
    if not sources:
        return VALIDATION_DETECTED
    worst = min(sources, key=lambda s: _SOURCE_RANK.get(s, 0))
    return _SOURCE_TO_STATUS.get(worst, VALIDATION_SYNTHETIC)


@dataclass
class ParseResult:
    """What every vendor plugin returns.  Shapes come from the frozen
    contract; the metadata around them records how far to trust the parse."""
    vendor: str
    parser_rule: str
    validation_status: str = VALIDATION_SYNTHETIC
    volume: dict = field(default_factory=dict)
    recordings: list[Recording] = field(default_factory=list)
    indexed_extents: list[tuple[int, int]] = field(default_factory=list)
    field_provenance: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # set when the parser stopped on data it could not handle (see register())
    stopped: str = ""

    @property
    def parsed(self) -> bool:
        return bool(self.recordings) or bool(self.volume)


class VendorParser:
    """Base class for a vendor filesystem plugin.

    Subclasses set `vendor` and implement `detect()` and `parse()`.  Register
    with `@register` to make the plugin discoverable by vendor name.
    """

    vendor: str = ""
    parser_rule: str = ""

    def detect(self, dev, hint_offsets: Optional[list[int]] = None) -> bool:
        """Cheap check: do this vendor's structures exist on the device?

        `hint_offsets` carries absolute offsets the detection engine already
        found, so a plugin need not re-scan the platter.  Honouring the hints
        is what keeps the single-pass design decision intact.
        """
        raise NotImplementedError

    def parse(self, dev, hint_offsets: Optional[list[int]] = None) -> ParseResult:
        """Full parse. Must attach Provenance to every artifact it emits."""
        raise NotImplementedError


REGISTRY: dict[str, type[VendorParser]] = {}


def _where(exc: BaseException) -> str:
    """The exception and the last line of this tool's code it passed through."""
    import os
    import traceback
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frames = [f for f in traceback.extract_tb(exc.__traceback__)
              if os.path.abspath(f.filename).startswith(root)]
    at = (f" at {os.path.relpath(frames[-1].filename, root)}:{frames[-1].lineno}"
          if frames else "")
    return f"{type(exc).__name__}: {str(exc)[:200]}{at}"


def _guard(cls: type[VendorParser]) -> None:
    """A parser is handed evidence that may be damaged or tampered with, and
    cli.py catches only device errors - so no parser may end in a traceback.
    Anything else raised by detect() makes it answer False, and by parse() a
    result that says where the parser stopped (validation_status
    detected_not_parsed).  Device errors still propagate: the device, not the
    data, failed.  validate/fuzz_parsers.py counts these apart, so a stop is
    found and fixed rather than hidden."""
    from acquire.device import DeviceError
    detect, parse = cls.__dict__.get("detect"), cls.__dict__.get("parse")
    if detect and not getattr(detect, "_guarded", False):
        def safe_detect(self, dev, *a, **k):
            try:
                return bool(detect(self, dev, *a, **k))
            except DeviceError:
                raise
            except Exception as exc:                     # noqa: BLE001
                self.detect_stopped = _where(exc)
                return False
        safe_detect._guarded = True
        safe_detect.__doc__, safe_detect.__name__ = detect.__doc__, "detect"
        cls.detect = safe_detect
    if parse and not getattr(parse, "_guarded", False):
        def safe_parse(self, dev, *a, **k):
            try:
                return parse(self, dev, *a, **k)
            except DeviceError:
                raise
            except Exception as exc:                     # noqa: BLE001
                where = _where(exc)
                return ParseResult(vendor=cls.vendor, parser_rule=cls.parser_rule,
                                   validation_status=VALIDATION_DETECTED, stopped=where,
                                   errors=[f"the parser stopped on damaged or unexpected data "
                                           f"and read nothing further: {where}"])
        safe_parse._guarded = True
        safe_parse.__doc__, safe_parse.__name__ = parse.__doc__, "parse"
        cls.parse = safe_parse


def register(cls: type[VendorParser]) -> type[VendorParser]:
    if not cls.vendor:
        raise ValueError(f"{cls.__name__} must declare a vendor name")
    _guard(cls)
    REGISTRY[cls.vendor] = cls
    return cls


def get_parser(vendor: str) -> Optional[VendorParser]:
    cls = REGISTRY.get(vendor)
    return cls() if cls else None


def available_vendors() -> set[str]:
    """Vendors a filesystem parser actually ships for, today.

    `detect/signatures.py::PARSERS_AVAILABLE` is kept in step with this so
    detection can never be mistaken for parsing in the report.
    """
    return set(REGISTRY)

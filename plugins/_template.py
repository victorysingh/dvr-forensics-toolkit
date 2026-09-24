"""Template for a new vendor plugin - copy to plugins/<vendor>.py and fill in.

Files starting with "_" are not loaded, so this template is inert.  A real
plugin is picked up automatically the next time the tool starts; nothing in
the core needs editing.

The rules every plugin inherits (see parsers/base.py and START_HERE Rule 3):

  * It is handed a read-only device (`dev.read_at(offset, length)`) and must
    never open a device itself - so it cannot introduce a write path.
  * Every decoded field records where its layout came from (FieldSpec.source).
    A layout inferred from our own test fixture is `fixture`; from a paper or
    an open-source parser, `published`; read off real media we hold,
    `observed_real_media`.  The weakest one sets the plugin's status.
  * It never reports `validated`.  That is a human decision, recorded after a
    byte-match against the recorder's own native export.
  * Every Recording it returns carries Provenance (disk offset, sectors, rule).
"""

from core.contract import VALIDATION_DETECTED, Recording  # noqa: F401
from detect.signatures import DETECTED_ONLY, Signature  # noqa: F401
from parsers.base import ParseResult, VendorParser, register  # noqa: F401

# Detection signatures this plugin adds to the scan.  `weight` is how strongly
# one hit points at the vendor; keep generic strings low.
SIGNATURES = [
    # Signature(id="examplevendor.magic", vendor="ExampleVendor",
    #           pattern=b"EXMPLFS1", description="superblock magic",
    #           source="where this came from", validation_status=DETECTED_ONLY,
    #           weight=6.0),
]


# @register                      # uncomment once detect() and parse() work
class ExampleVendorParser(VendorParser):
    vendor = "ExampleVendor"
    parser_rule = "examplevendor.fs.v0"

    def detect(self, dev, hint_offsets=None) -> bool:
        return dev.read_at(0, 8) == b"EXMPLFS1"

    def parse(self, dev, hint_offsets=None) -> ParseResult:
        result = ParseResult(vendor=self.vendor, parser_rule=self.parser_rule,
                             validation_status=VALIDATION_DETECTED)
        # 1. read the superblock / index with dev.read_at(...)
        # 2. build Recording objects, each with Provenance
        # 3. record every decoded field in result.field_provenance
        return result

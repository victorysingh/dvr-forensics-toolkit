"""Vendor filesystem parser plugins.

Importing this package registers every shipped plugin, so
`parsers.base.available_vendors()` is the single answer to "which vendors do
we actually parse today?" - which is what keeps `parser_available` in the
report honest.
"""

from parsers import dahua, hikvision  # noqa: F401  (import registers the plugins)
from parsers.base import (  # noqa: F401
    REGISTRY,
    ParseResult,
    VendorParser,
    available_vendors,
    get_parser,
)

# Keep the detection engine's view of "which vendors do we parse?" in step
# with the plugin registry, so `VendorDetection.parser_available` can never
# drift from reality and claim a parser that does not exist.  The dependency
# runs one way only - parsers know about detect, detect never imports parsers -
# so a third-party plugin cannot reach into the detection engine.
from detect import signatures as _sig

_sig.PARSERS_AVAILABLE.clear()
_sig.PARSERS_AVAILABLE.update(available_vendors())

__all__ = ["REGISTRY", "ParseResult", "VendorParser", "available_vendors",
           "get_parser"]

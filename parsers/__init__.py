"""Vendor filesystem parser plugins.

Importing this package registers every shipped plugin, so
`parsers.base.available_vendors()` is the single answer to "which vendors do
we actually parse today?" - which is what keeps `parser_available` in the
report honest.
"""

import importlib.util
import os
import sys

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

# -- drop-in plugins -----------------------------------------------------------
# Any `plugins/*.py` (not starting with "_") is loaded at import.  A plugin
# registers a parser with `@register`, and may add detection signatures by
# defining `SIGNATURES = [Signature(...)]`.  Onboarding a new vendor is then
# one file - no edit to the core.  A plugin that fails to load is recorded in
# PLUGIN_ERRORS and skipped; it never takes the tool down with it.
PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "plugins")
# A packaged build (packaging/) unpacks the shipped plugins with the program;
# a plugins/ folder next to the executable is loaded as well, so onboarding a
# vendor is still one dropped-in file, with no rebuild.
DROP_IN_DIR = (os.path.join(os.path.dirname(sys.executable), "plugins")
               if getattr(sys, "frozen", False) else None)
LOADED_PLUGINS: dict[str, dict] = {}
PLUGIN_ERRORS: dict[str, str] = {}


def plugin_dirs() -> list[str]:
    """Where plugins load from, the shipped folder first.  Read at load time,
    so pointing PLUGIN_DIR or DROP_IN_DIR elsewhere (the tests do) takes effect."""
    return [PLUGIN_DIR] + ([DROP_IN_DIR] if DROP_IN_DIR else [])


def _plugin_files() -> list[tuple[str, str]]:
    """(file name, path) of every plugin, the shipped ones first; a dropped-in
    file never replaces a shipped plugin of the same name."""
    out: dict[str, str] = {}
    for d in plugin_dirs():
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if not name.endswith(".py") or name.startswith("_"):
                continue
            if name in out:
                PLUGIN_ERRORS[f"{d}{os.sep}{name}"] = "a shipped plugin has this name - not loaded"
                continue
            out[name] = os.path.join(d, name)
    return list(out.items())


def _load_plugins() -> None:
    for name, path in _plugin_files():
        before = set(REGISTRY)
        try:
            spec = importlib.util.spec_from_file_location(f"ps26150_plugin_{name[:-3]}", path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
        except Exception as exc:                         # noqa: BLE001
            PLUGIN_ERRORS[name] = f"{type(exc).__name__}: {exc}"
            continue
        sigs = list(getattr(mod, "SIGNATURES", []))
        known = {s.id for s in _sig.ALL_SIGNATURES}
        for s in sigs:
            if s.id not in known:
                _sig.ALL_SIGNATURES.append(s)
                _sig.BY_ID[s.id] = s
        LOADED_PLUGINS[name] = {"vendors": sorted(set(REGISTRY) - before),
                                "signatures": [s.id for s in sigs],
                                "doc": (mod.__doc__ or "").strip().split("\n")[0]}


_load_plugins()
_sig.PARSERS_AVAILABLE.clear()
_sig.PARSERS_AVAILABLE.update(available_vendors())

__all__ = ["REGISTRY", "ParseResult", "VendorParser", "available_vendors",
           "get_parser", "LOADED_PLUGINS", "PLUGIN_ERRORS"]

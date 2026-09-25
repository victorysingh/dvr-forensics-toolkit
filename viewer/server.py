"""Dependency-free case viewer - standard library only, bound to 127.0.0.1.

This is the fallback viewer that runs on a bare Python install.  The
planned product UI (docs/TECH_STACK.md: FastAPI in api/, React in ui/)
wraps the same seam: report/case.py::load_case.

The UI is a viewer.  It reads what the pipeline wrote and never touches an
evidence device: there is no route that opens a block device, and nothing
here writes anywhere except the report it is asked to render.  It listens
on the loopback interface only - on an air-gapped workstation there is no
one else to serve, and on a connected one there must not be.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import parsers  # noqa: E402,F401  (registers plugins, loads drop-ins)
from report.case import list_cases, load_case, plugins_view, vendor_matrix  # noqa: E402
from report.html import render  # noqa: E402

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# How a new vendor goes from "unknown disk" to "parsed" - shown in the UI so
# the onboarding path is part of the product, not a slide.
ONBOARDING = [
    {"step": "Detect", "what": "Signature scan during acquisition scores every known vendor; "
                               "an unknown disk still gets entropy, codec and filesystem maps.",
     "tool": "scan", "state": "built"},
    {"step": "Carve", "what": "Vendor-agnostic recovery: DHAV today, raw H.264/H.265 next - "
                              "footage out before any parser exists.",
     "tool": "scan --carve", "state": "built (DHAV)"},
    {"step": "Survey", "what": "Recurring headers, self-describing length fields, date fields, "
                               "codec and strings from samples; a before/after block-map diff.",
     "tool": "survey", "state": "built"},
    {"step": "Plugin", "what": "One file in plugins/: signatures + a parser on the SDK. Loaded "
                               "automatically; cannot open a device for writing.",
     "tool": "plugins/*.py", "state": "built"},
    {"step": "Validate", "what": "Byte-match recovered footage against the recorder's own "
                                 "export. Only this moves a vendor to 'validated'.",
     "tool": "human sign-off", "state": "per vendor"},
]


def _case_dir(out_root: str, case_id: str) -> str | None:
    name = os.path.basename(unquote(case_id))
    if name in {c["id"] for c in list_cases(out_root)}:
        return os.path.join(out_root, name)
    return None


class Handler(BaseHTTPRequestHandler):
    out_root = "out"
    server_version = "ps26150-ui"

    def log_message(self, fmt, *args):             # quiet by default
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self):                              # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/cases":
                return self._json(list_cases(self.out_root))
            if path == "/api/vendors":
                return self._json({"vendors": vendor_matrix(), "plugins": plugins_view(),
                                   "onboarding": ONBOARDING})
            if path.startswith("/api/case/"):
                d = _case_dir(self.out_root, path[len("/api/case/"):])
                if not d:
                    return self._json({"error": "no such case"}, 404)
                return self._json(load_case(d))
            if path.startswith("/report/"):
                d = _case_dir(self.out_root, path[len("/report/"):])
                if not d:
                    return self._send(404, b"no such case", "text/plain")
                case = load_case(d)
                if not case.get("scan"):
                    return self._send(409, b"acquisition not complete - no report yet",
                                      "text/plain")
                return self._send(200, render(case).encode(), "text/html; charset=utf-8")
            if path.startswith("/thumb/"):
                # /thumb/<case>/<file>: analytics thumbnails only, by basename
                parts = path[len("/thumb/"):].split("/")
                d = _case_dir(self.out_root, parts[0]) if len(parts) == 2 else None
                f = os.path.join(d, "analytics", "thumbnails",
                                 os.path.basename(unquote(parts[1]))) if d else ""
                if f and f.endswith(".jpg") and os.path.isfile(f):
                    with open(f, "rb") as fh:
                        return self._send(200, fh.read(), "image/jpeg")
                return self._send(404, b"not found", "text/plain")
            name = "index.html" if path in ("/", "") else os.path.basename(path)
            f = os.path.join(STATIC, name)
            if os.path.isfile(f):
                with open(f, "rb") as fh:
                    ctype = mimetypes.guess_type(f)[0] or "application/octet-stream"
                    return self._send(200, fh.read(), ctype)
            return self._send(404, b"not found", "text/plain")
        except Exception as exc:                   # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


def serve(out_root: str = "out", port: int = 8150) -> None:
    Handler.out_root = out_root
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"PS26150 UI on http://127.0.0.1:{port}/  (cases from {os.path.abspath(out_root)})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    serve(*(sys.argv[1:2] or ["out"]))

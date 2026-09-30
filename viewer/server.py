"""Dependency-free case viewer - standard library only, bound to 127.0.0.1.

This is the fallback viewer that runs on a bare Python install.  The
planned product UI (docs/TECH_STACK.md: FastAPI in api/, React in ui/)
wraps the same seam: report/case.py::load_case.

The UI is a viewer.  It reads what the pipeline wrote and never touches an
evidence device: there is no route that opens a block device, and nothing
here writes anywhere except the report it is asked to render.  It listens
on the loopback interface only - on an air-gapped workstation there is no
one else to serve, and on a connected one there must not be.

Optionally, and only when asked, an approval gate stands in front of all of
this: `serve(require_access=True)` puts every route behind a signed-in,
administrator-approved, time-limited grant (see access/__init__.py).  With the
flag absent nothing in access/ is imported and this server behaves exactly as
it did before the gate existed.
"""

from __future__ import annotations

import json
import mimetypes
import ntpath
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


def _static_file(url_path: str) -> str | None:
    """Resolve a URL path inside viewer/static/, or None if it escapes.

    The UI is split into ES modules under static/js/, so a flat basename is
    not enough any more.  Everything is still confined to STATIC: the real
    path is resolved (following any symlink) and must stay inside it.
    """
    rel = unquote(url_path).lstrip("/")
    if not rel or rel.endswith("/"):
        rel = "index.html"
    if os.path.isabs(rel) or ntpath.isabs(rel):
        return None
    full = os.path.realpath(os.path.join(STATIC, rel))
    root = os.path.realpath(STATIC)
    if full != root and not full.startswith(root + os.sep):
        return None
    return full if os.path.isfile(full) else None


def _case_dir(out_root: str, case_id: str) -> str | None:
    name = os.path.basename(unquote(case_id))
    if name in {c["id"] for c in list_cases(out_root)}:
        return os.path.join(out_root, name)
    return None


class Handler(BaseHTTPRequestHandler):
    out_root = "out"
    server_version = "anokhidrishti-ui"
    gate = None                 # access.routes.Gate, or None for an open viewer

    #: Set by the gate when it rotates a session token on a request it is
    #: passing through, so the new cookie rides out on the real response.
    access_set_cookie = ""

    def log_message(self, fmt, *args):             # quiet by default
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.access_set_cookie:
            self.send_header("Set-Cookie", self.access_set_cookie)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self):                              # noqa: N802
        if self.gate is not None and self.gate.dispatch(self, "GET"):
            return                                 # the gate answered it
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
            f = _static_file(path)
            if f:
                with open(f, "rb") as fh:
                    ctype = mimetypes.guess_type(f)[0] or "application/octet-stream"
                    return self._send(200, fh.read(), ctype)
            return self._send(404, b"not found", "text/plain")
        except Exception as exc:                   # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):                             # noqa: N802
        """Only the gate posts. The viewer itself remains read-only."""
        if self.gate is not None and self.gate.dispatch(self, "POST"):
            return
        return self._send(405, b"method not allowed", "text/plain")


def serve(out_root: str = "out", port: int = 8150, require_access: bool = False,
          access_dir: str = "", allow_signup: bool = True,
          access_store: str = "sqlite", supabase_env: str = "",
          cookie_secure: bool = False, trust_proxy: bool = False) -> None:
    """Serve the console on loopback, optionally behind the approval gate.

    `access_dir` defaults to a dot-directory inside the case folder.  It holds
    the sqlite database and the audit log, and it is deliberately not a case
    directory: report.case.list_cases treats any folder holding a
    custody_ledger.jsonl as a case, and the access log is named differently so
    it can never show up in the console's own case list.
    """
    Handler.out_root = out_root
    Handler.gate = None
    if require_access:
        from access.routes import build_gate

        directory = access_dir or os.path.join(out_root, ".access")
        Handler.gate = build_gate(directory, allow_signup=allow_signup,
                                  backend=access_store, supabase_env=supabase_env,
                                  cookie_secure=cookie_secure, trust_proxy=trust_proxy)
        if not Handler.gate.ac.has_admin:
            print("  WARNING: no administrator account exists, so no request "
                  "can ever be approved.")
            print("           create one first:  cli.py access-admin "
                  + ("--access-store supabase " if access_store == "supabase" else "")
                  + "--username <name>")

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"AnokhiDrishti on http://127.0.0.1:{port}/  (cases from {os.path.abspath(out_root)})")
    if require_access:
        print(f"  approval gate ON - sign in at http://127.0.0.1:{port}/access/login")
        print(f"  administrators approve at http://127.0.0.1:{port}/admin")
        print(f"  accounts and audit log kept in {Handler.gate.ac.store.path}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    serve(*(sys.argv[1:2] or ["out"]))

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
from acquire.station import brand_plans  # noqa: E402  (pure: plans, opens no disk)
from parsers.base import available_vendors  # noqa: E402
from report.case import list_cases, load_case, plugins_view, vendor_matrix  # noqa: E402
from report.html import render  # noqa: E402
from report.pipeline import station_view  # noqa: E402
from viewer.guide import brand_guide  # noqa: E402

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


def _case_dir(out_root: str, case_id: str, cases: list[dict]) -> str | None:
    """The folder of one case, if it is among `cases` - the ones this request
    may see - and None otherwise, so a case hidden from a list cannot be
    opened by typing its name either."""
    name = os.path.basename(unquote(case_id))
    if name in {c["id"] for c in cases}:
        return os.path.join(out_root, name)
    return None


def visible_cases(cases: list[dict], user: dict | None,
                  real_for: frozenset | None) -> list[dict]:
    """Which cases one signed-in account may see.

    `real_for` is None unless the server was started with --real-cases-for:
    then everyone sees everything, as before.  With it, the accounts named
    there see only the real cases, administrators see all of them, and every
    other account sees only the generated ones (a SYNTHETIC file in the case
    folder).  So the real drives - real people's faces, a recorder's serial
    number - reach only the logins handed out for that purpose, never an
    ordinary sign-up.  An account the gate did not name sees only the
    generated cases: the split fails closed.
    """
    if real_for is None:
        return cases
    user = user or {}
    if user.get("role") == "admin":
        return cases
    real = user.get("username", "") in real_for
    return [c for c in cases if c["synthetic"] != real]


class Server(ThreadingHTTPServer):
    """The standard threading server with a deeper listen queue.

    socketserver queues only 5 waiting connections. A page that asks for many
    things at once - the AI leads screen loads dozens of thumbnails - overflows
    that, and every connection the kernel drops is retried by the client after
    1 s, then 3 s, then 7 s. Behind a reverse proxy each request is a fresh
    connection (this server speaks HTTP/1.0), so it bit on the hosted copy:
    20 requests at once took 9.6 s there. Measured locally, 128 brings 20
    concurrent requests from about 1 s to under 0.3 s.
    """
    request_queue_size = 128


class Handler(BaseHTTPRequestHandler):
    out_root = "out"
    server_version = "anokhidrishti-ui"
    gate = None                 # access.routes.Gate, or None for an open viewer

    #: Set by the gate when it rotates a session token on a request it is
    #: passing through, so the new cookie rides out on the real response.
    access_set_cookie = ""

    #: Usernames that see the real cases (serve --real-cases-for), or None:
    #: no split. Only ever set together with the gate.
    real_cases_for: frozenset | None = None

    #: The account the gate let this request through as. Reset on every
    #: request: one handler serves every request on a kept-alive connection.
    access_user: dict | None = None

    def log_message(self, fmt, *args):             # quiet by default
        pass

    def _send(self, code: int, body: bytes, ctype: str, cache: str = "no-store") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.access_set_cookie:
            self.send_header("Set-Cookie", self.access_set_cookie)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def _cases(self) -> list[dict]:
        """The cases this request may see (visible_cases)."""
        real_for = self.real_cases_for if self.gate is not None else None
        return visible_cases(list_cases(self.out_root), self.access_user, real_for)

    def do_GET(self):                              # noqa: N802
        self.access_user = None
        if self.gate is not None and self.gate.dispatch(self, "GET"):
            return                                 # the gate answered it
        path = urlparse(self.path).path
        try:
            if path == "/api/cases":
                return self._json(self._cases())
            if path == "/api/vendors":
                return self._json({"vendors": vendor_matrix(), "plugins": plugins_view(),
                                   "onboarding": ONBOARDING, "guide": brand_guide()})
            if path == "/api/station":
                # Plug and use: the station's status and runs, read from files
                # the station wrote. The console still opens no device.
                # `brands`: what it runs on each brand's disk, from its own plan.
                ids = [c["id"] for c in self._cases()]
                view = station_view(self.out_root, ids)
                view["brands"] = brand_plans(brand_guide()["brands"], set(available_vendors()))
                return self._json(view)
            if path == "/access/me":
                # Reached only with sign-in off: behind --require-access the
                # gate answers everything under /access/ itself. No account,
                # and the console's profile menu says so.
                return self._json({"gate": False})
            if path.startswith("/api/case/"):
                d = _case_dir(self.out_root, path[len("/api/case/"):], self._cases())
                if not d:
                    return self._json({"error": "no such case"}, 404)
                return self._json(load_case(d))
            if path.startswith("/report/"):
                d = _case_dir(self.out_root, path[len("/report/"):], self._cases())
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
                d = (_case_dir(self.out_root, parts[0], self._cases())
                     if len(parts) == 2 else None)
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
                    # The build names every file under assets/ by its content
                    # hash, so one never changes in place: a browser may keep
                    # it. `private` keeps it out of any shared cache in front
                    # of the gate. Everything else - index.html, the data -
                    # stays no-store, so a new build shows on the next load.
                    cache = ("private, max-age=31536000, immutable"
                             if path.startswith("/assets/") else "no-store")
                    return self._send(200, fh.read(), ctype, cache)
            return self._send(404, b"not found", "text/plain")
        except Exception as exc:                   # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):                             # noqa: N802
        """Only the gate posts. The viewer itself remains read-only."""
        self.access_user = None
        if self.gate is not None and self.gate.dispatch(self, "POST"):
            return
        return self._send(405, b"method not allowed", "text/plain")


def serve(out_root: str = "out", port: int = 8150, require_access: bool = False,
          access_dir: str = "", allow_signup: bool = True,
          access_store: str = "sqlite", supabase_env: str = "",
          cookie_secure: bool = False, trust_proxy: bool = False,
          mail: bool = False, mail_env: str = "", field_key: str = "",
          real_cases_for: str = "") -> None:
    """Serve the console on loopback, optionally behind the approval gate.

    `access_dir` defaults to a dot-directory inside the case folder.  It holds
    the sqlite database and the audit log, and it is deliberately not a case
    directory: report.case.list_cases treats any folder holding a
    custody_ledger.jsonl as a case, and the access log is named differently so
    it can never show up in the console's own case list.
    """
    Handler.out_root = out_root
    Handler.gate = None
    Handler.real_cases_for = None
    names = frozenset(n.strip() for n in real_cases_for.split(",") if n.strip())
    if real_cases_for and not require_access:
        raise SystemExit("  [!] --real-cases-for needs --require-access: without the "
                         "gate there is no signed-in account to tell apart")
    if require_access:
        from access.routes import build_gate

        directory = access_dir or os.path.join(out_root, ".access")
        Handler.gate = build_gate(directory, allow_signup=allow_signup,
                                  backend=access_store, supabase_env=supabase_env,
                                  cookie_secure=cookie_secure, trust_proxy=trust_proxy,
                                  mail=mail, mail_env=mail_env, field_key=field_key)
        if not Handler.gate.ac.has_admin:
            print("  WARNING: no administrator account exists, so no request "
                  "can ever be approved.")
            print("           create one first:  cli.py access-admin "
                  + ("--access-store supabase " if access_store == "supabase" else "")
                  + "--username <name>")
        if names:
            Handler.real_cases_for = names
            Handler.gate.real_cases_for = names
            for name in sorted(names):
                if not Handler.gate.ac.store.user_by_name(name):
                    print(f"  WARNING: --real-cases-for names {name!r}, which has no "
                          "account yet; create it with cli.py access-user --action add")

    httpd = Server(("127.0.0.1", port), Handler)
    print(f"AnokhiDrishti on http://127.0.0.1:{port}/  (cases from {os.path.abspath(out_root)})")
    if require_access:
        print(f"  approval gate ON - sign in at http://127.0.0.1:{port}/access/login")
        print(f"  administrators approve at http://127.0.0.1:{port}/admin")
        print(f"  accounts and audit log kept in {Handler.gate.ac.store.path}")
        m = Handler.gate.ac.mailer
        print(f"  mail notices: {'on, via ' + m.config.host if m else 'off'}")
        print(f"  email addresses: {'encrypted at rest (AES-256-GCM)' if field_key else 'stored as plain text'}")
        print("  real cases: " + (f"only {', '.join(sorted(names))} and administrators; "
                                  "every other account sees the generated cases"
                                  if names else "every approved account"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    serve(*(sys.argv[1:2] or ["out"]))

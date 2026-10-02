"""HTTP glue: cookies, forms, security headers, and the gate itself.

This is the only file in the package that knows what an HTTP request is.  It
translates between BaseHTTPRequestHandler and AccessControl, and it is written
as a mixin-free helper object so viewer/server.py needs three lines to adopt
it and none to understand it.

`Gate.dispatch()` is the whole contract:

    handled = gate.dispatch(handler, "GET")
    if handled:
        return                     # the gate answered; do nothing else

Anything the gate does not recognise is authorised and then handed back to the
viewer, which serves it exactly as it always did.  The viewer therefore has no
access-control logic in it at all - the gate either answered, or the request is
allowed.
"""

from __future__ import annotations

import json
import secrets
from http.cookies import SimpleCookie
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from access import audit as A
from access import pages
from access.policy import (ACCESS_WINDOW_HOURS, MIN_PASSWORD_LEN,
                           RATE_DECIDE_PER_MIN, RATE_GENERAL_PER_MIN,
                           ROLE_ADMIN, seconds_left)
from access.service import (AccessControl, check_csrf, csrf_token,
                            open_control)

#: The session cookie.  Named for the product, not for a framework.
COOKIE = "anokhidrishti_access"

#: A form body larger than this is refused unread.
MAX_BODY = 64 * 1024

#: Where the gate's own pages live. Nothing under here is ever gated, or the
#: login form would require being logged in.
PREFIX = "/access/"
ADMIN_PREFIX = "/admin"


def _is_public_id(path: str) -> bool:
    """True for exactly /ddddddddd - the shape the specification asks for."""
    return (len(path) == 10 and path[0] == "/" and path[1:].isdigit()
            and path[1] != "0")


class Gate:
    """The authorisation layer in front of the viewer."""

    def __init__(self, control: AccessControl, cookie_secure: bool = False,
                 allow_signup: bool = True, trust_proxy: bool = False):
        self.ac = control
        self.cookie_secure = cookie_secure
        self.allow_signup = allow_signup
        self.trust_proxy = trust_proxy

    @property
    def _mail_from(self) -> str:
        """The address notices come from, or "" when mail is off."""
        mailer = getattr(self.ac, "mailer", None)
        return mailer.config.sender if mailer is not None else ""

    # -- request helpers ---------------------------------------------------
    @staticmethod
    def _cookies(h) -> dict:
        jar = SimpleCookie()
        try:
            jar.load(h.headers.get("Cookie", "") or "")
        except Exception:                                  # noqa: BLE001
            return {}
        return {k: v.value for k, v in jar.items()}

    def _token(self, h) -> str:
        return self._cookies(h).get(COOKIE, "")

    def _client(self, h) -> str:
        """The address the per-address rate limits are keyed on.

        Behind a reverse proxy every request arrives from the proxy, so all
        visitors would share one bucket; with trust_proxy the left-most
        X-Forwarded-For entry - the visitor, as the first proxy saw it - is
        used instead.  A client that reaches this server directly can put any
        value there, so only the per-address limits lean on it: the
        per-account limit and the stored lockout do not.
        """
        if self.trust_proxy:
            fwd = (h.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
            if fwd:
                return fwd[:64]
        try:
            return h.client_address[0]
        except Exception:                                  # noqa: BLE001
            return "?"

    @staticmethod
    def _agent(h) -> str:
        return (h.headers.get("User-Agent", "") or "")[:400]

    @staticmethod
    def _form(h) -> dict:
        """Read an x-www-form-urlencoded body. {} for anything else."""
        ctype = (h.headers.get("Content-Type", "") or "").split(";")[0].strip()
        if ctype != "application/x-www-form-urlencoded":
            return {}
        try:
            length = int(h.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > MAX_BODY:
            return {}
        raw = h.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    # -- response helpers --------------------------------------------------
    def _cookie_header(self, token: str, max_age: int) -> str:
        """Build the Set-Cookie value.

        HttpOnly so script cannot read it, SameSite=Strict so no other origin
        can cause it to be sent, Path=/ because it guards the whole app.
        Secure is *not* set by default: the viewer serves plain HTTP on
        loopback and a Secure cookie would simply be discarded, leaving the
        user unable to sign in at all.
        """
        bits = [f"{COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Strict",
                f"Max-Age={max_age}"]
        if self.cookie_secure:
            bits.append("Secure")
        return "; ".join(bits)

    def _clear_cookie(self) -> str:
        return f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

    @staticmethod
    def _security_headers(h, nonce: str = "") -> None:
        csp = ("default-src 'none'; style-src 'unsafe-inline'; "
               "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
               "base-uri 'none'; frame-ancestors 'none'")
        if nonce:
            csp += f"; script-src 'nonce-{nonce}'"
        h.send_header("Content-Security-Policy", csp)
        h.send_header("X-Content-Type-Options", "nosniff")
        h.send_header("X-Frame-Options", "DENY")
        h.send_header("Referrer-Policy", "no-referrer")
        h.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        h.send_header("Pragma", "no-cache")

    def _html(self, h, body: bytes, code: int = 200, cookie: str = "",
              nonce: str = "") -> bool:
        h.send_response(code)
        h.send_header("Content-Type", "text/html; charset=utf-8")
        h.send_header("Content-Length", str(len(body)))
        self._security_headers(h, nonce)
        if cookie:
            h.send_header("Set-Cookie", cookie)
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(body)
        return True

    def _json(self, h, obj, code: int = 200) -> bool:
        body = json.dumps(obj, default=str).encode()
        h.send_response(code)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        self._security_headers(h)
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(body)
        return True

    def _redirect(self, h, where: str, cookie: str = "") -> bool:
        h.send_response(303)
        h.send_header("Location", where)
        h.send_header("Content-Length", "0")
        self._security_headers(h)
        if cookie:
            h.send_header("Set-Cookie", cookie)
        h.end_headers()
        return True

    # -- dispatch ----------------------------------------------------------
    def dispatch(self, h, method: str) -> bool:
        """Answer an access route, or authorise. True = response already sent."""
        path = urlparse(h.path).path
        query = parse_qs(urlparse(h.path).query)

        try:
            if path.startswith(PREFIX):
                return self._access_route(h, method, path, query)
            if path == ADMIN_PREFIX or path.startswith(ADMIN_PREFIX + "/"):
                return self._admin_route(h, method, path)
            if _is_public_id(path) and method in ("GET", "HEAD"):
                return self._waiting_room(h, path[1:])
            return self._guard(h, path)
        except Exception as exc:                           # noqa: BLE001
            # A failure inside the gate must never fall through into the
            # protected application: deny, and say so without a stack trace.
            return self._html(h, pages.denied_page(
                "Access control error",
                "The access-control layer could not complete this request.",
                f"{type(exc).__name__}: {exc}"), code=500)

    # -- the guard ---------------------------------------------------------
    def _guard(self, h, path: str) -> bool:
        if not self.ac.rate.allow("gen:" + self._client(h), RATE_GENERAL_PER_MIN):
            return self._html(h, pages.denied_page(
                "Too many requests", "Slow down and try again in a minute."),
                code=429)

        d = self.ac.authorize(self._token(h), self._client(h), path)
        if d.allowed:
            # Authorised. Hand the request back to the viewer untouched, but
            # carry a rotated token out on the same response if there is one,
            # and say whose request it is (the viewer shows some accounts
            # cases it hides from others: viewer/server.py::visible_cases).
            h.access_user = d.user
            if d.new_token:
                h.access_set_cookie = self._cookie_header(
                    d.new_token,
                    seconds_left((d.request or {}).get("access_expires_utc", ""))
                    or ACCESS_WINDOW_HOURS * 3600)
            return False

        if d.redirect:
            return self._redirect(h, d.redirect)
        return self._html(h, pages.denied_page("Access denied", d.message),
                          code=403)

    # -- /access/* ---------------------------------------------------------
    def _access_route(self, h, method: str, path: str, query: dict) -> bool:
        tail = path[len(PREFIX):]

        if tail.startswith("status/") and method in ("GET", "HEAD"):
            if not self.ac.rate.allow("gen:" + self._client(h),
                                      RATE_GENERAL_PER_MIN):
                return self._json(h, {"error": "rate limited"}, 429)
            state = self.ac.status_of(unquote(tail[len("status/"):]))
            if state is None:
                return self._json(h, {"error": "no such request"}, 404)
            return self._json(h, state)

        if tail == "login":
            if method == "POST":
                return self._do_login(h)
            token = self._token(h)
            # Already usable? Don't show a login form to someone signed in.
            d = self.ac.authorize(token, self._client(h), path)
            if d.allowed:
                return self._redirect(h, "/admin" if d.by_role else "/")
            if d.request and d.reason == "pending":
                return self._redirect(h, "/" + d.request["public_id"])
            note = ("Account created. Sign in to place an access request."
                    if query.get("new") else "")
            if note and self._mail_from:
                note += (f" A confirmation email is on its way from {self._mail_from};"
                         " if it is not in your inbox, check Spam.")
            form_token, cookie = self._form_token(h)
            return self._html(h, pages.login_page(
                note=note, allow_signup=self.allow_signup,
                csrf=csrf_token(form_token)), cookie=cookie)

        if tail == "signup":
            if not self.allow_signup:
                return self._html(h, pages.denied_page(
                    "Sign-up is closed",
                    "Accounts on this workstation are created by an "
                    "administrator."), code=403)
            if method == "POST":
                return self._do_signup(h)
            form_token, cookie = self._form_token(h)
            return self._html(h, pages.signup_page(
                csrf=csrf_token(form_token), min_len=MIN_PASSWORD_LEN,
                require_email=True, mail_from=self._mail_from), cookie=cookie)

        if tail == "logout" and method == "POST":
            token = self._token(h)
            if not check_csrf(token, self._form(h).get("csrf", "")):
                return self._html(h, pages.denied_page(
                    "Could not sign out", "That form was not valid. Try again."),
                    code=400)
            self.ac.logout(token)
            return self._redirect(h, "/access/login", cookie=self._clear_cookie())

        return self._html(h, pages.denied_page(
            "Not found", "There is nothing at that address."), code=404)

    def _form_token(self, h) -> tuple:
        """(token, Set-Cookie) for a form page. Mints one if there is none.

        The token and the cookie have to be decided together: deriving the
        form's CSRF value from the cookie the browser *had* while handing it a
        different one in the same response means the value can never match on
        the way back, and every sign-in fails.

        The minted token grants nothing - it is not a row in `sessions`, so
        `authorize` rejects it - it exists only so the CSRF value is specific
        to this browser instead of being a constant everyone shares.
        """
        token = self._token(h)
        if token:
            return token, ""
        token = secrets.token_urlsafe(32)
        return token, self._cookie_header(token, 1800)

    def _do_login(self, h) -> bool:
        form = self._form(h)
        token = self._token(h)
        if not check_csrf(token, form.get("csrf", "")):
            fresh, cookie = self._form_token(h)
            return self._html(h, pages.login_page(
                error="That form expired. Try again.",
                username=form.get("username", ""),
                allow_signup=self.allow_signup, csrf=csrf_token(fresh)),
                code=400, cookie=cookie)

        r = self.ac.login(form.get("username", ""), form.get("password", ""),
                          self._client(h), self._agent(h))
        if not r.ok:
            fresh, cookie = self._form_token(h)
            return self._html(h, pages.login_page(
                error=r.message, username=form.get("username", ""),
                allow_signup=self.allow_signup, csrf=csrf_token(fresh)),
                code=401, cookie=cookie)

        new_token = r.data["token"]
        user = r.data["user"]
        request = r.data.get("request")
        if user["role"] == ROLE_ADMIN:
            return self._redirect(h, ADMIN_PREFIX, cookie=self._cookie_header(
                new_token, ACCESS_WINDOW_HOURS * 3600))
        return self._redirect(h, "/" + request["public_id"],
                              cookie=self._cookie_header(new_token, 3600))

    def _do_signup(self, h) -> bool:
        form = self._form(h)
        token = self._token(h)
        keep = dict(username=form.get("username", ""), email=form.get("email", ""),
                    min_len=MIN_PASSWORD_LEN, require_email=True,
                    mail_from=self._mail_from)
        if not check_csrf(token, form.get("csrf", "")):
            fresh, cookie = self._form_token(h)
            return self._html(h, pages.signup_page(
                error="That form expired. Try again.", csrf=csrf_token(fresh),
                **keep), code=400, cookie=cookie)
        if form.get("password", "") != form.get("password2", ""):
            return self._html(h, pages.signup_page(
                error="The two passwords do not match.", csrf=csrf_token(token),
                **keep), code=400)
        r = self.ac.signup(form.get("username", ""), form.get("password", ""),
                           self._client(h), self._agent(h),
                           email=form.get("email", ""), require_email=True)
        if not r.ok:
            return self._html(h, pages.signup_page(
                error=r.message, csrf=csrf_token(token), **keep), code=400)
        return self._redirect(h, "/access/login?new=1")

    # -- the waiting room --------------------------------------------------
    def _waiting_room(self, h, public_id: str) -> bool:
        """The page at /<9 digits>.

        Anyone who knows the identifier may see this, because the
        specification makes the identifier the address of the page.  That is
        safe only because the page carries nothing worth having: the status of
        one request, and - for the browser that actually owns it - the name it
        signed in with.  It never grants anything.
        """
        state = self.ac.status_of(public_id)
        if state is None:
            return self._html(h, pages.denied_page(
                "No such request",
                "There is no access request with that identifier.",
                "It may have been completed long ago, or never existed."),
                code=404)

        token = self._token(h)
        session = self.ac.store.session_by_token(token) if token else None
        request = self.ac.store.request_by_public_id(public_id)
        mine = bool(session and request
                    and session["request_id"] == request["id"])

        # Already granted and it is this browser's request: go straight in.
        if mine and state["granted"]:
            d = self.ac.authorize(token, self._client(h), "/")
            if d.allowed:
                cookie = ""
                if d.new_token:
                    cookie = self._cookie_header(
                        d.new_token,
                        seconds_left((d.request or {}).get(
                            "access_expires_utc", ""))
                        or ACCESS_WINDOW_HOURS * 3600)
                return self._redirect(h, "/", cookie=cookie)

        username = ""
        if mine:
            user = self.ac.store.user_by_id(session["user_id"]) or {}
            username = user.get("username", "")

        nonce = secrets.token_urlsafe(16)
        return self._html(h, pages.waiting_page(
            public_id, state["status"], state["message"],
            expires_in_s=int(state.get("expires_in_s") or 0),
            username=username, csrf=csrf_token(token), nonce=nonce),
            nonce=nonce)

    # -- /admin ------------------------------------------------------------
    def _admin_route(self, h, method: str, path: str) -> bool:
        token = self._token(h)
        d = self.ac.authorize(token, self._client(h), path)
        user = d.user

        if user is None:
            return self._redirect(h, "/access/login")
        if user["role"] != ROLE_ADMIN:
            self.ac.audit.record(A.ACCESS_DENIED, user["username"],
                                 {"reason": "not_admin", "path": path})
            return self._html(h, pages.denied_page(
                "Not permitted",
                "This account cannot approve access requests.",
                "Ask an administrator to look at your request instead."),
                code=403)

        if path == ADMIN_PREFIX + "/decide" and method == "POST":
            return self._do_decide(h, user, token)

        if path not in (ADMIN_PREFIX, ADMIN_PREFIX + "/"):
            return self._html(h, pages.denied_page(
                "Not found", "There is nothing at that address."), code=404)

        return self._render_admin(h, user, token)

    def _render_admin(self, h, user: dict, token: str, error: str = "",
                      note: str = "") -> bool:
        return self._html(h, pages.admin_page(
            user["username"], self.ac.overview(), self.ac.pending(),
            self.ac.recent(40), self.ac.store.list_users(),
            self.ac.audit.recent(40), csrf_token(token),
            error=error, note=note))

    def _do_decide(self, h, user: dict, token: str) -> bool:
        form = self._form(h)
        if not check_csrf(token, form.get("csrf", "")):
            return self._render_admin(h, user, token,
                                      error="That form was not valid. Try again.")
        # A supervisor clearing a real queue makes many decisions in a
        # minute, so this is its own bucket rather than the sign-in one; the
        # action is already behind a role check and a CSRF token.
        if not self.ac.rate.allow("decide:" + self._client(h),
                                  RATE_DECIDE_PER_MIN):
            return self._render_admin(h, user, token,
                                      error="Too many decisions at once. "
                                            "Wait a moment.")
        public_id = (form.get("public_id", "") or "").strip()
        action = (form.get("action", "") or "").strip()
        note = (form.get("note", "") or "").strip()

        if action == "approve":
            r = self.ac.approve(public_id, user["username"], note)
        elif action == "reject":
            r = self.ac.reject(public_id, user["username"], note)
        elif action == "revoke":
            r = self.ac.revoke(public_id, user["username"], note)
        else:
            r = None

        if r is None:
            return self._render_admin(h, user, token, error="Unknown action.")
        return self._render_admin(h, user, token,
                                  error="" if r.ok else r.message,
                                  note=r.message if r.ok else "")


def build_gate(directory: str, cookie_secure: bool = False,
               allow_signup: bool = True, backend: str = "sqlite",
               supabase_env: str = "", trust_proxy: bool = False,
               mail: bool = False, mail_env: str = "", field_key: str = "") -> Gate:
    """Open the store (in `directory`, or Supabase) and return a gate over it."""
    return Gate(open_control(directory, backend, supabase_env, mail=mail,
                             mail_env=mail_env, field_key=field_key),
                cookie_secure=cookie_secure, allow_signup=allow_signup,
                trust_proxy=trust_proxy)

"""The access-control state machine: one class the HTTP layer can drive.

Everything policy-shaped lives here, so routes.py only has to translate
between HTTP and these methods and pages.py only has to render what they
return.  Nothing in this file knows what an HTTP request looks like.

Two decisions worth stating at the top, because they are the ones a reviewer
will ask about:

* **Administrators do not queue.**  If an administrator had to be approved
  before they could approve anyone, the very first administrator on a fresh
  database could never get in, and a single-administrator deployment would
  deadlock the moment their eight hours ran out.  The bypass is a role check,
  it is written to the audit log every time it is used, and it is the reason
  `access-admin` exists as a command-line-only operation.

* **Expiry is checked twice.**  `sweep()` moves timed-out rows to their
  terminal state for the benefit of the admin panel, but `authorize()` never
  trusts that the sweep has run: it re-reads the deadline on every single
  request.  A grant therefore stops working the instant it is due, even if no
  sweep has happened since - which matters because there is no background
  thread here, by design.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from access import audit as A
from access.audit import open_audit
from access.passwords import (PasswordError, check_strength, hash_password,
                              needs_rehash, verify_password)
from access.policy import (ACCESS_WINDOW_HOURS, ACTIVE, APPROVED, EXPIRED,
                           GRANTING_STATES, LOCKOUT_MINUTES,
                           LOGIN_FAIL_WINDOW_MINUTES, LOGIN_MAX_FAILS,
                           LOGIN_SESSION_MINUTES, PENDING,
                           RATE_AUTH_BURST_PER_MIN, RATE_AUTH_PER_MIN,
                           REJECTED, REQUEST_TTL_MINUTES,
                           REVOKED, ROLE_ADMIN, ROLE_USER, STATE_TEXT,
                           USERNAME_RE, is_past, now, parse, plus,
                           seconds_left, stamp)
from access.store import PublicIdTaken, Store, UsernameTaken, open_store

SESSION_LOGIN = "login"
SESSION_ACCESS = "access"

#: What the user is told for any failed login, whatever actually went wrong.
#: One message for "no such user" and "wrong password" together, so the form
#: cannot be used to find out which usernames exist.
GENERIC_LOGIN_ERROR = "Incorrect username or password."


# ---------------------------------------------------------------------------
@dataclass
class Result:
    """Outcome of an operation a user asked for."""
    ok: bool
    message: str = ""
    data: dict = field(default_factory=dict)

    @classmethod
    def fail(cls, message: str, **data) -> "Result":
        return cls(False, message, data)

    @classmethod
    def win(cls, message: str = "", **data) -> "Result":
        return cls(True, message, data)


@dataclass
class Decision:
    """Whether a browser may see the protected application right now."""
    allowed: bool
    reason: str                       # machine-readable, for the audit log
    message: str = ""                 # shown to the person
    user: Optional[dict] = None
    request: Optional[dict] = None
    session: Optional[dict] = None
    new_token: Optional[str] = None   # set this cookie: the token was rotated
    redirect: Optional[str] = None    # send the browser here instead
    by_role: bool = False             # allowed because they are an admin


# ---------------------------------------------------------------------------
class RateLimiter:
    """Fixed-window counter per key. In memory, deliberately.

    The server binds loopback, so this is not protection from the internet; it
    is protection from a script on this machine walking the password list or
    the 9-digit space.  Losing the counters on restart is therefore acceptable
    - the account lockout, which *is* persisted, is the durable control.
    """

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, per_minute: int) -> bool:
        cut = time.monotonic() - 60.0
        with self._lock:
            hits = [t for t in self._hits.get(key, ()) if t > cut]
            if len(hits) >= per_minute:
                self._hits[key] = hits
                return False
            hits.append(time.monotonic())
            self._hits[key] = hits
            # Keep the table from growing without bound on a long-lived server.
            if len(self._hits) > 4096:
                for k in [k for k, v in self._hits.items() if not v or max(v) < cut]:
                    self._hits.pop(k, None)
            return True

    def reset(self, key: str = "") -> None:
        with self._lock:
            self._hits.pop(key, None) if key else self._hits.clear()


# ---------------------------------------------------------------------------
def csrf_token(raw_session_token: str) -> str:
    """A form token derived from the session token.

    The session cookie is HttpOnly, so a page on another origin cannot read it
    and therefore cannot derive this.  That makes it a valid synchroniser
    token without any server-side secret to store or rotate.
    """
    return hashlib.sha256(("csrf|" + (raw_session_token or "")).encode()).hexdigest()[:32]


def check_csrf(raw_session_token: str, provided: str) -> bool:
    return hmac.compare_digest(csrf_token(raw_session_token), str(provided or ""))


def new_public_id(rand=secrets) -> str:
    """A 9-digit identifier, never starting with a zero.

    Nine digits because the specification asks for nine.  It is an identifier
    for a request, not a credential: it names a waiting room, and knowing one
    lets you look at a status page and nothing else.  The credential is the
    session cookie, which is 256 bits.
    """
    return str(rand.choice("123456789")) + "".join(
        rand.choice("0123456789") for _ in range(8))


# ---------------------------------------------------------------------------
class AccessControl:
    """Users, requests, sessions and the decisions about them."""

    def __init__(self, directory: str, store: Optional[Store] = None):
        self.dir = directory
        self.store = store or open_store(directory)
        self.audit = open_audit(directory)
        self.rate = RateLimiter()
        self._sweep_lock = threading.Lock()
        self._last_sweep = 0.0
        # A hash to check doomed logins against, so an unknown username costs
        # the same wall-clock time as a known one.  Built once; the password is
        # random and is never stored anywhere.
        self._dummy_hash = hash_password(secrets.token_urlsafe(32))

    # -- helpers -----------------------------------------------------------
    @property
    def has_admin(self) -> bool:
        return self.store.count_admins() > 0

    def _audit(self, action: str, actor: str = "system", **detail) -> None:
        self.audit.record(action, actor, detail)

    def auth_allowed(self, remote_ip: str, username: str) -> bool:
        """Two buckets an authentication attempt has to fit through.

        Per account, so one person fumbling their password cannot throttle
        anybody else on the same machine - which on a loopback server is
        everybody.  And per address on top, so a script cannot dodge the first
        bucket simply by trying a different username every time.
        """
        who = (username or "?").strip().lower()
        return (self.rate.allow(f"auth:{remote_ip or '?'}:{who}",
                                RATE_AUTH_PER_MIN)
                and self.rate.allow(f"authip:{remote_ip or '?'}",
                                    RATE_AUTH_BURST_PER_MIN))

    # -- accounts ----------------------------------------------------------
    def create_user(self, username: str, password: str, role: str = ROLE_USER,
                    actor: str = "cli") -> Result:
        """Make an account. Used by signup and by the command line."""
        username = (username or "").strip().lower()
        if not USERNAME_RE.match(username):
            return Result.fail(
                "A username is 3 to 32 characters: lower-case letters, digits, "
                "dot, dash or underscore, starting with a letter or digit.")
        try:
            check_strength(password)
        except PasswordError as exc:
            return Result.fail(str(exc))
        if role not in (ROLE_USER, ROLE_ADMIN):
            return Result.fail("Unknown role.")
        try:
            user = self.store.create_user(username, hash_password(password), role)
        except UsernameTaken:
            # Signup does leak that a username is taken - it has to, or the
            # form cannot explain itself. Login does not, which is where it
            # would actually matter.
            return Result.fail("That username is already taken.")
        self._audit(A.USER_CREATED if actor != username else A.SIGNUP,
                    actor, username=username, role=role)
        return Result.win("Account created.", user=user)

    def signup(self, username: str, password: str, remote_ip: str = "",
               user_agent: str = "") -> Result:
        if not self.auth_allowed(remote_ip, username):
            self._audit(A.RATE_LIMITED, username or "?", where="signup",
                        remote_ip=remote_ip)
            return Result.fail("Too many attempts. Wait a minute and try again.")
        # Signing yourself up never grants a role: every self-made account is a
        # plain user, and only the command line can mint an administrator.
        return self.create_user(username, password, ROLE_USER,
                                actor=(username or "").strip().lower())

    def set_password(self, username: str, password: str,
                     actor: str = "cli") -> Result:
        user = self.store.user_by_name((username or "").strip().lower())
        if not user:
            return Result.fail("No such user.")
        try:
            check_strength(password)
        except PasswordError as exc:
            return Result.fail(str(exc))
        self.store.set_password(user["id"], hash_password(password))
        self.store.clear_lock(user["id"])
        # Changing a password ends every session that password opened.
        n = self.store.revoke_sessions_for_user(user["id"])
        self._audit(A.SESSION_ROTATED, actor, username=user["username"],
                    reason="password_changed", sessions_revoked=n)
        return Result.win("Password changed.", sessions_revoked=n)

    def set_role(self, username: str, role: str, actor: str = "cli") -> Result:
        user = self.store.user_by_name((username or "").strip().lower())
        if not user:
            return Result.fail("No such user.")
        if role not in (ROLE_USER, ROLE_ADMIN):
            return Result.fail("Unknown role.")
        if (user["role"] == ROLE_ADMIN and role != ROLE_ADMIN
                and self.store.count_admins() <= 1):
            return Result.fail(
                "This is the only administrator left - promote another one first.")
        self.store.set_role(user["id"], role)
        self._audit(A.USER_CREATED, actor, username=user["username"],
                    role=role, changed="role")
        return Result.win("Role changed.")

    def set_disabled(self, username: str, disabled: bool,
                     actor: str = "cli") -> Result:
        user = self.store.user_by_name((username or "").strip().lower())
        if not user:
            return Result.fail("No such user.")
        if (disabled and user["role"] == ROLE_ADMIN
                and self.store.count_admins() <= 1):
            return Result.fail(
                "This is the only administrator left - it cannot be disabled.")
        self.store.set_disabled(user["id"], disabled)
        n = self.store.revoke_sessions_for_user(user["id"]) if disabled else 0
        self._audit(A.USER_DISABLED, actor, username=user["username"],
                    disabled=bool(disabled), sessions_revoked=n)
        return Result.win("Account disabled." if disabled else "Account enabled.")

    # -- login -------------------------------------------------------------
    def login(self, username: str, password: str, remote_ip: str = "",
              user_agent: str = "") -> Result:
        """Check a password, then open a request. Returns the session token.

        A correct password does not grant access to anything: it produces an
        identified browser and a PENDING request.  That separation is the whole
        point of the system.
        """
        username = (username or "").strip().lower()
        if not self.auth_allowed(remote_ip, username):
            self._audit(A.RATE_LIMITED, username or "?", where="login",
                        remote_ip=remote_ip)
            return Result.fail("Too many attempts. Wait a minute and try again.")

        user = self.store.user_by_name(username)
        if user is None:
            # Spend the same time as a real check so the response time does
            # not distinguish an unknown username from a wrong password.
            verify_password(password or "", self._dummy_hash)
            self._audit(A.LOGIN_FAIL, username or "?", reason="no_such_user",
                        remote_ip=remote_ip)
            return Result.fail(GENERIC_LOGIN_ERROR)

        if user["disabled"]:
            verify_password(password or "", self._dummy_hash)
            self._audit(A.LOGIN_FAIL, username, reason="disabled",
                        remote_ip=remote_ip)
            return Result.fail(GENERIC_LOGIN_ERROR)

        locked = user["locked_until_utc"]
        if locked and not is_past(locked):
            mins = max(1, seconds_left(locked) // 60)
            self._audit(A.LOGIN_FAIL, username, reason="locked_out",
                        remote_ip=remote_ip, locked_until=locked)
            return Result.fail(
                f"Too many failed attempts. Try again in {mins} minute"
                f"{'s' if mins != 1 else ''}.")

        if not verify_password(password or "", user["password_hash"]):
            # The counter only accumulates inside a window; a failure long
            # after the last one starts counting again from one, so an honest
            # typo months ago never contributes to today's lockout.
            first = user["first_fail_utc"]
            restart = (not first) or is_past(
                stamp(plus(parse(first) or now(),
                           minutes=LOGIN_FAIL_WINDOW_MINUTES)))
            count = self.store.note_login_fail(user["id"], restart)
            self._audit(A.LOGIN_FAIL, username, reason="bad_password",
                        remote_ip=remote_ip, consecutive=count)
            if count >= LOGIN_MAX_FAILS:
                until = stamp(plus(now(), minutes=LOCKOUT_MINUTES))
                self.store.lock_user(user["id"], until)
                self._audit(A.LOCKOUT, username, remote_ip=remote_ip,
                            until=until, after=count)
                return Result.fail(
                    f"Too many failed attempts. Try again in "
                    f"{LOCKOUT_MINUTES} minutes.")
            return Result.fail(GENERIC_LOGIN_ERROR)

        # -- correct password ---------------------------------------------
        self.store.note_login_ok(user["id"])
        if needs_rehash(user["password_hash"]):
            self.store.set_password(user["id"], hash_password(password))
        user = self.store.user_by_id(user["id"]) or user

        request = self._request_for_login(user, remote_ip, user_agent)
        token = secrets.token_urlsafe(32)
        # An administrator needs no request, so their session is an access
        # session from the start and lasts the same eight hours.
        if user["role"] == ROLE_ADMIN:
            expires = stamp(plus(now(), hours=ACCESS_WINDOW_HOURS))
            kind = SESSION_ACCESS
        else:
            expires = stamp(plus(now(), minutes=LOGIN_SESSION_MINUTES))
            kind = SESSION_LOGIN
        session = self.store.create_session(
            token, user["id"], kind, expires,
            request_id=request["id"] if request else None,
            remote_ip=remote_ip, user_agent=user_agent)
        self._audit(A.LOGIN_OK, user["username"], remote_ip=remote_ip,
                    role=user["role"], session_id=session["id"],
                    public_id=(request or {}).get("public_id", ""))
        return Result.win("Signed in.", token=token, user=user,
                          request=request, session=session)

    def _request_for_login(self, user: dict, remote_ip: str,
                           user_agent: str) -> Optional[dict]:
        """The request this login should land on, making one if needed.

        An administrator gets none.  Anyone else reuses a request that is
        still live - re-logging in must not queue a second waiting room, and
        must not throw away a grant that was already approved.
        """
        if user["role"] == ROLE_ADMIN:
            return None
        self.sweep(force=True)
        live = self.store.live_request_for_user(user["id"])
        if live:
            return live
        created = stamp()
        expires = stamp(plus(now(), minutes=REQUEST_TTL_MINUTES))
        for _ in range(12):
            try:
                request = self.store.create_request(
                    new_public_id(), user["id"], created, expires,
                    remote_ip=remote_ip, user_agent=user_agent)
                break
            except PublicIdTaken:
                continue                     # 9 digits collided; draw again
        else:
            raise RuntimeError("could not allocate a free access identifier")
        self._audit(A.REQUEST_CREATED, user["username"],
                    public_id=request["public_id"], remote_ip=remote_ip,
                    expires_utc=expires)
        return request

    def logout(self, token: str) -> Result:
        session = self.store.session_by_token(token or "")
        if not session:
            return Result.win("Signed out.")
        user = self.store.user_by_id(session["user_id"]) or {}
        self.store.revoke_session(session["id"])
        self._audit(A.LOGOUT, user.get("username", "?"),
                    session_id=session["id"])
        return Result.win("Signed out.")

    # -- the gate ----------------------------------------------------------
    def authorize(self, token: str, remote_ip: str = "",
                  path: str = "") -> Decision:
        """May this browser see the protected application?

        The one function the HTTP gate calls.  It re-reads every deadline
        rather than trusting the sweep, and it rotates the session token at
        the moment a grant is first used.
        """
        self.sweep()
        if not token:
            return Decision(False, "no_session",
                            "Sign in to request access.",
                            redirect="/access/login")

        session = self.store.session_by_token(token)
        if session is None:
            # The token is not live. If it belonged to a request that was
            # withdrawn, rejected or timed out, send the browser to that
            # request's own page so it says *why* rather than just "sign in".
            # This reads a revoked row, so it must never grant anything: the
            # only thing derived from it is which explanation to show.
            dead = self.store.session_by_token_any(token)
            if dead and dead["request_id"]:
                closed = self.store.request_by_id(dead["request_id"])
                if closed and closed["status"] in (REJECTED, REVOKED, EXPIRED):
                    return Decision(False, closed["status"],
                                    STATE_TEXT[closed["status"]],
                                    request=closed,
                                    redirect="/" + closed["public_id"])
            return Decision(False, "bad_session",
                            "That session is no longer valid. Sign in again.",
                            redirect="/access/login")

        if is_past(session["expires_utc"]):
            self.store.revoke_session(session["id"])
            return Decision(False, "session_expired",
                            "That session has expired. Sign in again.",
                            redirect="/access/login")

        user = self.store.user_by_id(session["user_id"])
        if user is None or user["disabled"]:
            self.store.revoke_session(session["id"])
            self._audit(A.ACCESS_DENIED, (user or {}).get("username", "?"),
                        reason="user_disabled", path=path)
            return Decision(False, "user_disabled",
                            "This account is disabled.",
                            redirect="/access/login")

        self.store.touch_session(session["id"])

        # Administrators do not queue - see the module docstring.
        if user["role"] == ROLE_ADMIN:
            return Decision(True, "admin_role", "", user=user, session=session,
                            by_role=True)

        if not session["request_id"]:
            return Decision(False, "no_request",
                            "No access request is attached to this session.",
                            user=user, session=session,
                            redirect="/access/login")

        request = self.store.request_by_id(session["request_id"])
        if request is None:
            return Decision(False, "no_request", "That access request is gone.",
                            user=user, session=session,
                            redirect="/access/login")

        status = request["status"]

        if status == PENDING:
            if is_past(request["request_expires_utc"]):
                self._expire(request, "request_ttl")
                return Decision(False, EXPIRED, STATE_TEXT[EXPIRED], user=user,
                                request=self.store.request_by_id(request["id"]),
                                session=session,
                                redirect="/" + request["public_id"])
            return Decision(False, PENDING, STATE_TEXT[PENDING], user=user,
                            request=request, session=session,
                            redirect="/" + request["public_id"])

        if status in (REJECTED, REVOKED, EXPIRED):
            self._audit(A.ACCESS_DENIED, user["username"], reason=status,
                        public_id=request["public_id"], path=path)
            return Decision(False, status, STATE_TEXT[status], user=user,
                            request=request, session=session,
                            redirect="/" + request["public_id"])

        if status in GRANTING_STATES:
            # The eight hours, checked here and not taken on trust.
            if is_past(request["access_expires_utc"] or ""):
                self._expire(request, "window_elapsed")
                return Decision(False, EXPIRED, STATE_TEXT[EXPIRED], user=user,
                                request=self.store.request_by_id(request["id"]),
                                session=session,
                                redirect="/" + request["public_id"])
            if not request["access_expires_utc"]:
                # Granted with no deadline should be impossible; treat the
                # missing deadline as the failure it is rather than as forever.
                self._expire(request, "missing_deadline")
                return Decision(False, EXPIRED, STATE_TEXT[EXPIRED], user=user,
                                session=session, redirect="/access/login")

            new_token = None
            if status == APPROVED:
                # First use of a fresh grant: promote the row to ACTIVE and
                # give the browser a new token, so the token that carried only
                # an identity is not the token that carries the access.
                moved = self.store.activate_request(request["id"], stamp())
                if moved is not None:
                    request = moved
                    new_token = secrets.token_urlsafe(32)
                    self.store.rotate_session(
                        session["id"], new_token, SESSION_ACCESS,
                        request["access_expires_utc"])
                    self._audit(A.ACCESS_ACTIVATED, user["username"],
                                public_id=request["public_id"],
                                expires_utc=request["access_expires_utc"],
                                session_id=session["id"])
                    self._audit(A.SESSION_ROTATED, user["username"],
                                session_id=session["id"], reason="activation")
                else:
                    request = self.store.request_by_id(request["id"]) or request
            return Decision(True, request["status"], "", user=user,
                            request=request, session=session,
                            new_token=new_token)

        return Decision(False, "unknown_state", "This request cannot be used.",
                        user=user, request=request, session=session,
                        redirect="/access/login")

    # -- administrator actions --------------------------------------------
    def approve(self, public_id: str, admin: str, note: str = "") -> Result:
        request = self.store.request_by_public_id(public_id or "")
        if request is None:
            return Result.fail("No such access request.")
        if request["status"] != PENDING:
            return Result.fail(
                f"That request is already {request['status']} - "
                "only a pending request can be approved.")
        if is_past(request["request_expires_utc"]):
            self._expire(request, "request_ttl")
            return Result.fail(
                "That request expired before it was decided. The user must "
                "sign in again.")
        expires = stamp(plus(now(), hours=ACCESS_WINDOW_HOURS))
        moved = self.store.decide_request(request["id"], APPROVED, admin,
                                         stamp(), expires, note)
        if moved is None:
            return Result.fail("That request was decided by someone else first.")
        self._audit(A.REQUEST_APPROVED, admin, public_id=public_id,
                    user_id=request["user_id"], access_expires_utc=expires,
                    hours=ACCESS_WINDOW_HOURS, note=note[:200])
        return Result.win(
            f"Approved - access valid for {ACCESS_WINDOW_HOURS} hours.",
            request=moved)

    def reject(self, public_id: str, admin: str, note: str = "") -> Result:
        request = self.store.request_by_public_id(public_id or "")
        if request is None:
            return Result.fail("No such access request.")
        if request["status"] != PENDING:
            return Result.fail(
                f"That request is already {request['status']} - "
                "only a pending request can be rejected.")
        moved = self.store.decide_request(request["id"], REJECTED, admin,
                                          stamp(), None, note)
        if moved is None:
            return Result.fail("That request was decided by someone else first.")
        self.store.revoke_sessions_for_request(request["id"])
        self._audit(A.REQUEST_REJECTED, admin, public_id=public_id,
                    user_id=request["user_id"], note=note[:200])
        return Result.win("Rejected.", request=moved)

    def revoke(self, public_id: str, admin: str, note: str = "") -> Result:
        """Cut a live grant short. This is the immediate-revocation path."""
        request = self.store.request_by_public_id(public_id or "")
        if request is None:
            return Result.fail("No such access request.")
        if request["status"] not in GRANTING_STATES:
            return Result.fail(
                f"Nothing to revoke - that request is {request['status']}.")
        moved = self.store.close_request(request["id"], REVOKED, stamp(),
                                         by=admin, note=note,
                                         only_if=GRANTING_STATES)
        if moved is None:
            return Result.fail("That request changed state first.")
        n = self.store.revoke_sessions_for_request(request["id"])
        self._audit(A.REQUEST_REVOKED, admin, public_id=public_id,
                    user_id=request["user_id"], sessions_revoked=n,
                    note=note[:200])
        return Result.win("Access revoked - the session is dead immediately.",
                          request=moved, sessions_revoked=n)

    # -- expiry ------------------------------------------------------------
    def _expire(self, request: dict, why: str) -> Optional[dict]:
        """Move one overdue request to EXPIRED and kill its sessions."""
        was = request["status"]
        moved = self.store.close_request(
            request["id"], EXPIRED, stamp(), note="expired: " + why,
            only_if=(PENDING,) + tuple(GRANTING_STATES))
        if moved is None:
            return None
        n = self.store.revoke_sessions_for_request(request["id"])
        self._audit(A.REQUEST_EXPIRED, "system",
                    public_id=request["public_id"], was=was, why=why,
                    sessions_revoked=n)
        return moved

    def sweep(self, force: bool = False) -> int:
        """Bring overdue rows up to date. Returns how many were closed.

        Called from the request path rather than a timer: there is no
        background thread, so nothing keeps running after the server stops.
        Throttled to once every few seconds because a status page polls, and
        correctness does not depend on it - `authorize` re-checks deadlines
        itself.
        """
        with self._sweep_lock:
            if not force and (time.monotonic() - self._last_sweep) < 5.0:
                return 0
            self._last_sweep = time.monotonic()
        closed = 0
        for request in self.store.due_requests(stamp()):
            if self._expire(request, "sweep") is not None:
                closed += 1
        return closed

    # -- views -------------------------------------------------------------
    def status_of(self, public_id: str) -> Optional[dict]:
        """The public view of one request: what the waiting room polls.

        No username, no session details, nothing about who decided it - a
        9-digit identifier is guessable, so this must be safe to hand to
        someone who guessed one.
        """
        self.sweep()
        request = self.store.request_by_public_id(public_id or "")
        if request is None:
            return None
        if request["status"] == PENDING and is_past(request["request_expires_utc"]):
            request = self._expire(request, "request_ttl") or request
        elif (request["status"] in GRANTING_STATES
              and is_past(request["access_expires_utc"] or "")):
            request = self._expire(request, "window_elapsed") or request
        status = request["status"]
        out = {
            "public_id": request["public_id"],
            "status": status,
            "message": STATE_TEXT.get(status, status),
            "created_utc": request["created_utc"],
            "final": status in (REJECTED, EXPIRED, REVOKED),
            "granted": status in GRANTING_STATES,
        }
        if status == PENDING:
            out["expires_in_s"] = seconds_left(request["request_expires_utc"])
        if status in GRANTING_STATES:
            out["access_expires_utc"] = request["access_expires_utc"]
            out["expires_in_s"] = seconds_left(request["access_expires_utc"] or "")
        return out

    def pending(self, limit: int = 100) -> list[dict]:
        self.sweep()
        return self.store.list_requests((PENDING,), limit)

    def recent(self, limit: int = 100) -> list[dict]:
        self.sweep()
        return self.store.list_requests((), limit)

    def overview(self) -> dict:
        self.sweep()
        # Another writer - the command line, most likely - may have appended
        # since this object was opened, so the panel re-reads before counting.
        self.audit.reread()
        stats = self.store.stats()
        stats["audit_entries"] = len(self.audit.entries)
        stats["audit_chain"] = self.audit.verify()
        stats["window_hours"] = ACCESS_WINDOW_HOURS
        return stats


def open_control(directory: str) -> AccessControl:
    return AccessControl(directory)

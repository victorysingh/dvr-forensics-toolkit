"""Supabase (hosted Postgres) persistence for the access gate.

The same store as access/store.py - same methods, same row shapes, same state
names - kept in a Supabase project instead of a local SQLite file, and the same
audit log as access/audit.py kept in a Supabase table instead of a JSONL file.
A hosted deployment needs this: its machine's own disk does not survive a
restart, so accounts, grants and the audit trail cannot live on it.

Nothing here runs unless it is asked for by name (`--access-store supabase`).
The examiner's workstation is air-gapped and keeps SQLite; and a test run or a
stray environment variable must never write to a cloud database whose audit
log, by design, cannot be cleaned up afterwards.

Standard library only, like the rest of the tool: Supabase's Data API
(PostgREST) is HTTPS and JSON, so http.client and json are enough.  The tables,
the checks the database enforces on its own, and the few statements REST
cannot express are in access/supabase_schema.sql.

The key is the project's *secret* key (the service_role).  It bypasses
row-level security, so it comes only from the server's environment or from a
file outside the repository that only its owner can read; it is sent only in
a request header, and it never appears in a log line, a repr or an error.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import ssl
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from access.audit import LOG_SCOPE
from access.policy import (ACTIVE, APPROVED, GRANTING_STATES, PENDING,
                           ROLE_ADMIN, ROLE_USER, stamp)
from access.store import PublicIdTaken, StoreError, UsernameTaken, token_hash
from acquire.ledger import (GENESIS_PREV, SEAL_RULE, CustodyLedger,
                            _seal_mac, load_seal_key, seal_key_id)
from core.contract import canonical_json, utc_now

ENV_URL = "SUPABASE_URL"
ENV_KEY = "SUPABASE_SERVICE_KEY"
DEFAULT_ENV_FILE = os.path.join(os.path.expanduser("~"), ".config",
                                "anokhidrishti", "supabase.env")

USERS = "access_users"
REQUESTS = "access_requests"
SESSIONS = "access_sessions"
AUDIT = "access_audit"
SEAL = "access_audit_seal"

#: Supabase caps one response at 1,000 rows; longer reads are paged.
PAGE = 1000

#: PostgreSQL's unique_violation, as PostgREST reports it.
UNIQUE_VIOLATION = "23505"


# ---------------------------------------------------------------------------
class SupabaseConfigError(StoreError):
    """The credentials are missing, unreadable or the wrong kind."""


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    key: str = field(repr=False)
    source: str = ""

    def __repr__(self) -> str:                      # the key never prints
        return f"SupabaseConfig(url={self.url!r}, key=<hidden>, source={self.source!r})"


def _read_env_file(path: str) -> dict:
    """KEY=VALUE lines. Refuses a file other users can read, as ssh does."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise SupabaseConfigError(
            f"no Supabase credentials: set {ENV_URL} and {ENV_KEY}, or write "
            f"them to {path}") from None
    except PermissionError:
        raise SupabaseConfigError(
            f"{path} exists but this user cannot read it (check the file's and "
            "its folder's owner and mode)") from None
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SupabaseConfigError(
            f"{path} can be read by other users; it holds a secret key - "
            f"run: chmod 600 {path}")
    values: dict = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def load_config(env_file: str = "") -> SupabaseConfig:
    """Credentials from the environment (how a hosting platform hands over
    secrets), else from `env_file` (default ~/.config/anokhidrishti/supabase.env)."""
    url = os.environ.get(ENV_URL, "").strip()
    key = os.environ.get(ENV_KEY, "").strip()
    source = "environment"
    if not (url and key):
        path = env_file or DEFAULT_ENV_FILE
        values = _read_env_file(path)
        url = url or values.get(ENV_URL, "")
        key = key or values.get(ENV_KEY, "")
        source = path
    if not url or not key:
        raise SupabaseConfigError(f"{source}: both {ENV_URL} and {ENV_KEY} are needed")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SupabaseConfigError(f"{ENV_URL} must be an https:// address")
    if key.startswith("sb_publishable_"):
        raise SupabaseConfigError(
            f"{ENV_KEY} is the publishable (public) key, which by design can read "
            "none of the access tables; use the project's secret key")
    return SupabaseConfig(url=f"https://{parts.netloc}", key=key, source=source)


# ---------------------------------------------------------------------------
class Rest:
    """A small PostgREST client over pooled HTTPS connections.

    Pooled because the gate authorises every request the console makes, each
    costing a few round trips, and ThreadingHTTPServer answers each request on
    a fresh thread - so a per-thread connection would never be reused.
    """

    def __init__(self, config: SupabaseConfig, timeout: float = 15.0,
                 pool_size: int = 8):
        parts = urlsplit(config.url)
        self.url = config.url
        self._host, self._port = parts.hostname, parts.port or 443
        self._timeout = timeout
        self._pool_size = pool_size
        self._pool: list[http.client.HTTPSConnection] = []
        self._lock = threading.Lock()
        self._ctx = ssl.create_default_context()
        self._headers = {"apikey": config.key, "Accept": "application/json",
                         "Content-Type": "application/json",
                         "User-Agent": "anokhidrishti-access/1"}
        # A new-style key (sb_secret_...) goes in `apikey` alone; a legacy
        # service_role key is a JWT and is expected as a bearer token as well.
        if not config.key.startswith("sb_"):
            self._headers["Authorization"] = "Bearer " + config.key

    def _take(self) -> tuple[http.client.HTTPSConnection, bool]:
        with self._lock:
            if self._pool:
                return self._pool.pop(), True
        return http.client.HTTPSConnection(self._host, self._port,
                                           timeout=self._timeout,
                                           context=self._ctx), False

    def _give(self, conn: http.client.HTTPSConnection, reusable: bool) -> None:
        with self._lock:
            if reusable and len(self._pool) < self._pool_size:
                self._pool.append(conn)
                return
        conn.close()

    def call(self, method: str, path: str, body: Any = None,
             prefer: str = "") -> tuple[int, Any]:
        """(HTTP status, decoded JSON or None). StoreError if unreachable."""
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = dict(self._headers)
        if prefer:
            headers["Prefer"] = prefer
        for attempt in (0, 1):
            conn, reused = self._take()
            try:
                conn.request(method, "/rest/v1" + path, body=data, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
            except (http.client.HTTPException, OSError) as exc:
                conn.close()
                # A pooled connection the server has closed in the meantime
                # fails before anything is sent: retry that once, fresh.  Any
                # other failure is reported rather than retried, because a
                # write may already have landed.
                if attempt == 0 and reused and isinstance(
                        exc, (http.client.RemoteDisconnected,
                              ConnectionResetError, BrokenPipeError)):
                    with self._lock:                # the rest are as old
                        stale, self._pool = self._pool, []
                    for c in stale:
                        c.close()
                    continue
                raise StoreError(f"Supabase unreachable: {type(exc).__name__}") from None
            self._give(conn, not resp.will_close)
            try:
                return resp.status, (json.loads(raw) if raw else None)
            except ValueError:
                return resp.status, None
        raise StoreError("Supabase unreachable")        # not reached


def _fail(status: int, payload: Any, what: str) -> StoreError:
    """A StoreError naming the operation and PostgREST's own reason."""
    reason = ""
    if isinstance(payload, dict):
        reason = f" [{payload.get('code', '')}] {str(payload.get('message', ''))[:200]}"
    return StoreError(f"Supabase {what}: HTTP {status}{reason}")


def _code(payload: Any) -> str:
    return str(payload.get("code", "")) if isinstance(payload, dict) else ""


def _q(value: Any) -> str:
    return quote(str(value), safe="")


def _where(**filters) -> str:
    """col=op.value pairs for a query string: _where(id=("eq", 3))."""
    parts = []
    for col, (op, value) in filters.items():
        if op == "in":
            value = "(" + ",".join(str(v) for v in value) + ")"
        parts.append(f"{col}={op}.{_q(value)}")
    return "&".join(parts)


# ---------------------------------------------------------------------------
class SupabaseStore:
    """access/store.py's Store, method for method, over Supabase."""

    def __init__(self, rest: Rest):
        self.rest = rest
        self.path = rest.url                      # where the data is, for messages

    def close(self) -> None:
        pass

    # -- plumbing ------------------------------------------------------------
    def _select(self, table: str, where: str = "", order: str = "",
                limit: Optional[int] = None, select: str = "*") -> list[dict]:
        q = f"/{table}?select={select}"
        if where:
            q += "&" + where
        if order:
            q += "&order=" + order
        if limit is not None:
            q += f"&limit={int(limit)}"
        status, payload = self.rest.call("GET", q)
        if status != 200:
            raise _fail(status, payload, f"read {table}")
        return payload or []

    def _one(self, table: str, where: str) -> Optional[dict]:
        rows = self._select(table, where, limit=1)
        return rows[0] if rows else None

    def _insert(self, table: str, row: dict) -> tuple[int, Any]:
        return self.rest.call("POST", f"/{table}", row,
                              prefer="return=representation")

    def _update(self, table: str, where: str, values: dict,
                select: str = "*") -> list[dict]:
        status, payload = self.rest.call(
            "PATCH", f"/{table}?{where}&select={select}", values,
            prefer="return=representation")
        if status != 200:
            raise _fail(status, payload, f"update {table}")
        return payload or []

    def _rpc(self, fn: str, args: dict) -> Any:
        status, payload = self.rest.call("POST", f"/rpc/{fn}", args)
        if status != 200:
            raise _fail(status, payload, f"call {fn}")
        return payload

    # -- users -------------------------------------------------------------
    def create_user(self, username: str, password_hash: str,
                    role: str = ROLE_USER) -> dict:
        status, payload = self._insert(USERS, {
            "username": username, "password_hash": password_hash,
            "role": role, "created_utc": stamp()})
        if status == 409 and _code(payload) == UNIQUE_VIOLATION:
            raise UsernameTaken("username already exists: " + str(username))
        if status != 201:
            raise _fail(status, payload, f"insert {USERS}")
        return payload[0]

    def user_by_name(self, username: str) -> Optional[dict]:
        return self._one(USERS, _where(username=("eq", username)))

    def user_by_id(self, user_id: int) -> Optional[dict]:
        return self._one(USERS, _where(id=("eq", user_id)))

    def list_users(self) -> list[dict]:
        return self._select(USERS, order="username.asc")

    def count_admins(self, enabled_only: bool = True) -> int:
        return int(self._rpc("access_count_admins",
                             {"p_admin": ROLE_ADMIN, "p_enabled_only": enabled_only}) or 0)

    def set_password(self, user_id: int, password_hash: str) -> None:
        self._update(USERS, _where(id=("eq", user_id)),
                     {"password_hash": password_hash}, select="id")

    def set_role(self, user_id: int, role: str) -> None:
        self._update(USERS, _where(id=("eq", user_id)), {"role": role}, select="id")

    def set_disabled(self, user_id: int, disabled: bool) -> None:
        self._update(USERS, _where(id=("eq", user_id)),
                     {"disabled": 1 if disabled else 0}, select="id")

    def note_login_ok(self, user_id: int) -> None:
        self._update(USERS, _where(id=("eq", user_id)),
                     {"last_login_utc": stamp(), "failed_count": 0,
                      "first_fail_utc": None, "locked_until_utc": None}, select="id")

    def note_login_fail(self, user_id: int, restart_window: bool) -> int:
        """Bump the failure counter. Returns the new count."""
        n = self._rpc("access_note_login_fail", {
            "p_user_id": user_id, "p_restart": bool(restart_window), "p_now": stamp()})
        return int(n or 0)

    def lock_user(self, user_id: int, until_utc: str) -> None:
        self._update(USERS, _where(id=("eq", user_id)),
                     {"locked_until_utc": until_utc}, select="id")

    def clear_lock(self, user_id: int) -> None:
        self._update(USERS, _where(id=("eq", user_id)),
                     {"locked_until_utc": None, "failed_count": 0,
                      "first_fail_utc": None}, select="id")

    # -- requests ----------------------------------------------------------
    def create_request(self, public_id: str, user_id: int, created_utc: str,
                       request_expires_utc: str, remote_ip: str = "",
                       user_agent: str = "") -> dict:
        status, payload = self._insert(REQUESTS, {
            "public_id": public_id, "user_id": user_id, "status": PENDING,
            "created_utc": created_utc, "request_expires_utc": request_expires_utc,
            "remote_ip": remote_ip, "user_agent": user_agent[:400]})
        if status == 409 and _code(payload) == UNIQUE_VIOLATION:
            raise PublicIdTaken(public_id)
        if status != 201:
            raise _fail(status, payload, f"insert {REQUESTS}")
        return payload[0]

    def request_by_id(self, request_id: int) -> Optional[dict]:
        return self._one(REQUESTS, _where(id=("eq", request_id)))

    def request_by_public_id(self, public_id: str) -> Optional[dict]:
        return self._one(REQUESTS, _where(public_id=("eq", public_id)))

    def list_requests(self, statuses: tuple = (), limit: int = 200,
                      user_id: Optional[int] = None) -> list[dict]:
        return self._rpc("access_list_requests", {
            "p_statuses": list(statuses), "p_limit": int(limit),
            "p_user_id": user_id}) or []

    def live_request_for_user(self, user_id: int) -> Optional[dict]:
        """The newest request for this user that is pending or granting."""
        rows = self._select(REQUESTS, _where(user_id=("eq", user_id),
                                             status=("in", (PENDING, APPROVED, ACTIVE))),
                            order="id.desc", limit=1)
        return rows[0] if rows else None

    def decide_request(self, request_id: int, status: str, decided_by: str,
                       decided_utc: str, access_expires_utc: Optional[str],
                       note: str = "") -> Optional[dict]:
        """Move a request out of PENDING; None if it was not pending.

        As in the SQLite store, the status test is part of the one UPDATE, so
        two administrators deciding at once cannot both succeed.
        """
        rows = self._update(REQUESTS, _where(id=("eq", request_id), status=("eq", PENDING)), {
            "status": status, "decided_by": decided_by, "decided_utc": decided_utc,
            "access_expires_utc": access_expires_utc, "decision_note": note[:500]})
        return rows[0] if rows else None

    def activate_request(self, request_id: int, when_utc: str) -> Optional[dict]:
        """APPROVED -> ACTIVE on the first authorised use. None if not approved."""
        rows = self._update(REQUESTS, _where(id=("eq", request_id), status=("eq", APPROVED)),
                            {"status": ACTIVE, "activated_utc": when_utc})
        return rows[0] if rows else None

    def close_request(self, request_id: int, status: str, when_utc: str,
                      by: str = "", note: str = "",
                      only_if: tuple = ()) -> Optional[dict]:
        """Move a request to a terminal state (expired / revoked)."""
        rows = self._rpc("access_close_request", {
            "p_request_id": request_id, "p_status": status, "p_now": when_utc,
            "p_by": by or "", "p_note": note[:500], "p_only_if": list(only_if)})
        return rows[0] if rows else None

    def due_requests(self, when_utc: str) -> list[dict]:
        """Requests whose clock has run out but whose status lags behind."""
        return self._rpc("access_due_requests", {
            "p_now": when_utc, "p_pending": PENDING,
            "p_granting": list(GRANTING_STATES)}) or []

    # -- sessions ----------------------------------------------------------
    def create_session(self, token: str, user_id: int, kind: str,
                       expires_utc: str, request_id: Optional[int] = None,
                       remote_ip: str = "", user_agent: str = "") -> dict:
        now_ = stamp()
        status, payload = self._insert(SESSIONS, {
            "token_hash": token_hash(token), "user_id": user_id,
            "request_id": request_id, "kind": kind, "created_utc": now_,
            "expires_utc": expires_utc, "last_seen_utc": now_,
            "remote_ip": remote_ip, "user_agent": user_agent[:400]})
        if status != 201:
            raise _fail(status, payload, f"insert {SESSIONS}")
        return payload[0]

    def session_by_id(self, session_id: int) -> Optional[dict]:
        return self._one(SESSIONS, _where(id=("eq", session_id)))

    def session_by_token(self, token: str) -> Optional[dict]:
        """Look a session up by raw token. Revoked rows are never returned."""
        return self._one(SESSIONS, _where(token_hash=("eq", token_hash(token)),
                                          revoked_utc=("is", "null")))

    def session_by_token_any(self, token: str) -> Optional[dict]:
        """Including revoked rows - only ever to explain a refusal (see store.py)."""
        return self._one(SESSIONS, _where(token_hash=("eq", token_hash(token))))

    def touch_session(self, session_id: int) -> None:
        self._update(SESSIONS, _where(id=("eq", session_id)),
                     {"last_seen_utc": stamp()}, select="id")

    def rotate_session(self, session_id: int, new_token: str, kind: str,
                       expires_utc: str) -> Optional[dict]:
        """Give a session a new token when its privilege changes (store.py)."""
        rows = self._update(SESSIONS, _where(id=("eq", session_id), revoked_utc=("is", "null")), {
            "token_hash": token_hash(new_token), "kind": kind,
            "expires_utc": expires_utc, "last_seen_utc": stamp()})
        return rows[0] if rows else None

    def revoke_session(self, session_id: int) -> None:
        self._update(SESSIONS, _where(id=("eq", session_id), revoked_utc=("is", "null")),
                     {"revoked_utc": stamp()}, select="id")

    def revoke_sessions_for_request(self, request_id: int) -> int:
        return len(self._update(
            SESSIONS, _where(request_id=("eq", request_id), revoked_utc=("is", "null")),
            {"revoked_utc": stamp()}, select="id"))

    def revoke_sessions_for_user(self, user_id: int) -> int:
        return len(self._update(
            SESSIONS, _where(user_id=("eq", user_id), revoked_utc=("is", "null")),
            {"revoked_utc": stamp()}, select="id"))

    def sessions_for_user(self, user_id: int, live_only: bool = True) -> list[dict]:
        filters: dict = {"user_id": ("eq", user_id)}
        if live_only:
            filters.update(revoked_utc=("is", "null"), expires_utc=("gt", stamp()))
        return self._select(SESSIONS, _where(**filters), order="id.desc")

    def purge_sessions(self, before_utc: str) -> int:
        """Drop rows that are long dead. Nothing depends on them any more."""
        status, payload = self.rest.call(
            "DELETE", f"/{SESSIONS}?{_where(expires_utc=('lte', before_utc))}&select=id",
            prefer="return=representation")
        if status != 200:
            raise _fail(status, payload, f"delete from {SESSIONS}")
        return len(payload or [])

    # -- reporting ---------------------------------------------------------
    def stats(self) -> dict:
        out = self._rpc("access_stats", {"p_now": stamp(), "p_admin": ROLE_ADMIN}) or {}
        by_status = out.get("requests") or {}
        return {"users": int(out.get("users", 0)), "admins": int(out.get("admins", 0)),
                "requests": by_status, "pending": int(by_status.get(PENDING, 0)),
                "live_sessions": int(out.get("live_sessions", 0))}


# ---------------------------------------------------------------------------
class SupabaseAudit(CustodyLedger):
    """access/audit.py's AccessAudit, one table row per entry.

    The chain rule is the ledger's, unchanged.  Each row keeps the exact
    canonical JSON its hash covers, so anyone can re-verify the chain from the
    table alone.  The database adds two guarantees a file cannot: it refuses
    a row whose hash or link is wrong, and it refuses every UPDATE, DELETE and
    TRUNCATE - even with the server's own key (supabase_schema.sql).

    Several writers (the server and a command line) are serialised by the
    table itself: each entry claims the next `seq` as its primary key, so the
    loser of a race gets a conflict, re-reads the head and tries again.
    """

    def __init__(self, rest: Rest):
        # Deliberately not CustodyLedger.__init__, which opens a file.
        self.rest = rest
        self.path = f"{rest.url} ({AUDIT})"
        self.actor = "system"
        self.case_id = LOG_SCOPE
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        self._reload()

    # -- reading -----------------------------------------------------------
    def _rows(self, query: str) -> list[dict]:
        status, payload = self.rest.call("GET", f"/{AUDIT}?{query}")
        if status != 200:
            raise _fail(status, payload, f"read {AUDIT}")
        return payload or []

    @staticmethod
    def _entry(row: dict) -> dict:
        entry = json.loads(row["entry"])
        entry["entry_hash"] = row["entry_hash"]
        return entry

    def _reload(self) -> None:
        entries: list[dict] = []
        while True:
            rows = self._rows(f"select=seq,entry_hash,entry&order=seq.asc"
                              f"&limit={PAGE}&offset={len(entries)}")
            entries.extend(self._entry(r) for r in rows)
            if len(rows) < PAGE:
                break
        self.entries = entries

    def reread(self) -> "SupabaseAudit":
        with self._lock:
            self._reload()
        return self

    def recent(self, limit: int = 200, action_prefix: str = "") -> list[dict]:
        """Newest first, read fresh - other writers may have appended."""
        if action_prefix:
            self.reread()
            rows = [e for e in self.entries
                    if str(e.get("action", "")).startswith(action_prefix)]
            return list(reversed(rows[-limit:]))
        return [self._entry(r) for r in self._rows(
            f"select=seq,entry_hash,entry&order=seq.desc&limit={int(limit)}")]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            a = str(e.get("action", "?"))
            out[a] = out.get(a, 0) + 1
        return out

    # -- writing -----------------------------------------------------------
    def record(self, action: str, actor: str = "system",
               detail: dict | None = None) -> dict:
        """Append one event. Returns the entry, including its hash."""
        with self._lock:
            for attempt in range(8):
                last = self._rows("select=seq,entry_hash&order=seq.desc&limit=1")
                seq = last[0]["seq"] + 1 if last else 0
                entry = {
                    "seq": seq,
                    "ts_utc": utc_now(),
                    "case_id": self.case_id,
                    "actor": actor or "system",
                    "action": action,
                    "detail": detail or {},
                    "data_hash": "",
                    "prev_hash": last[0]["entry_hash"] if last else GENESIS_PREV,
                }
                body = canonical_json(entry)
                entry["entry_hash"] = hashlib.sha256(body).hexdigest()
                status, payload = self.rest.call("POST", f"/{AUDIT}", {
                    "seq": seq, "prev_hash": entry["prev_hash"],
                    "entry_hash": entry["entry_hash"], "entry": body.decode("utf-8"),
                }, prefer="return=minimal")
                if status == 201:
                    break
                if status == 409 and _code(payload) == UNIQUE_VIOLATION:
                    time.sleep(0.05 * (attempt + 1))  # another writer took this seq
                    continue
                raise _fail(status, payload, f"append to {AUDIT}")
            else:
                raise StoreError("Supabase: the audit log stayed contended; entry not written")
            if len(self.entries) == seq:
                self.entries.append(entry)
            else:                                 # another writer appended too
                self._reload()
            self._seal_row(seq + 1, entry["entry_hash"])
            return entry

    def append(self, action: str, detail: Optional[dict[str, Any]] = None,
               data_hash: str = "") -> dict:
        """The ledger's append writes a file; here it is record()."""
        return self.record(action, self.actor, detail)

    # -- the seal ------------------------------------------------------------
    def _seal_row(self, count: int, head: str) -> None:
        """Re-seal under this machine's key, never moving a seal backwards.

        The database already refuses edits and deletes; the seal is for what
        it cannot refuse - someone with the database owner's password turning
        those checks off and rewriting the log.  Only the seal key's holder
        can re-seal, and that key never leaves this machine.
        """
        key = load_seal_key(create=True)
        if key is None:
            return
        kid = seal_key_id(key)
        values = {"count": count, "head": head, "hmac": _seal_mac(key, count, head),
                  "updated_utc": stamp()}
        status, payload = self.rest.call(
            "PATCH", f"/{SEAL}?{_where(key_id=('eq', kid), count=('lt', count))}&select=key_id",
            values, prefer="return=representation")
        if status == 200 and payload:
            return
        if status != 200:
            raise _fail(status, payload, f"update {SEAL}")
        # No row yet for this key (or a later seal is already there, which
        # the insert then leaves alone).
        status, payload = self.rest.call(
            "POST", f"/{SEAL}?on_conflict=key_id", dict(values, key_id=kid),
            prefer="resolution=ignore-duplicates,return=minimal")
        if status not in (200, 201, 204):
            raise _fail(status, payload, f"insert {SEAL}")

    def _read_seals(self) -> dict:
        status, payload = self.rest.call("GET", f"/{SEAL}?select=key_id,count,head,hmac")
        if status != 200:
            raise _fail(status, payload, f"read {SEAL}")
        return {"rule": SEAL_RULE,
                "seals": {r["key_id"]: {"count": r["count"], "head": r["head"],
                                        "hmac": r["hmac"]} for r in payload or []}}

    def verify_seal(self) -> dict:
        """CustodyLedger.verify_seal, reading the seal table instead of a file."""
        seals = self._read_seals()["seals"]
        if not seals:
            return {"sealed": False, "checked": False, "valid": True,
                    "message": "not sealed (no seal key could be kept)"}
        key = load_seal_key(create=False)
        kid = seal_key_id(key) if key else None
        mine = seals.get(kid) if kid else None
        if mine is None:
            others = sorted(seals)
            return {"sealed": True, "checked": False, "valid": True, "keys": others,
                    "message": f"sealed with key {', '.join(others)}; not on this "
                               "machine, so the seal cannot be checked here"}
        count, head = mine["count"], mine["head"]
        if not hmac.compare_digest(str(mine["hmac"]), _seal_mac(key, count, head)):
            return {"sealed": True, "checked": True, "valid": False, "key": kid,
                    "message": f"SEAL BROKEN (key {kid}): the seal row was edited"}
        if len(self.entries) < count:
            return {"sealed": True, "checked": True, "valid": False, "key": kid,
                    "message": f"SEAL BROKEN (key {kid}): entries were removed - the "
                               f"seal covers {count}, the log holds {len(self.entries)}"}
        if count and self.entries[count - 1].get("entry_hash") != head:
            return {"sealed": True, "checked": True, "valid": False, "key": kid,
                    "message": f"SEAL BROKEN (key {kid}): the log was rewritten - "
                               f"entry {count - 1} is not the one sealed"}
        return {"sealed": True, "checked": True, "valid": True, "key": kid,
                "count": count,
                "message": f"seal intact (key {kid}): all {count} entries it covers "
                           "are there, unchanged"}


def open_supabase(env_file: str = "") -> tuple[SupabaseStore, SupabaseAudit]:
    """The store and the audit log over one Supabase project."""
    rest = Rest(load_config(env_file))
    return SupabaseStore(rest), SupabaseAudit(rest)

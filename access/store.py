"""SQLite persistence for users, access requests and sessions.

sqlite3 is in the standard library, so this keeps the zero-dependency rule
(requirements.txt) while giving something a pile of JSON files cannot: an
atomic write.  Two threads approving the same request, or a crash halfway
through issuing a session, cannot leave a half-written row behind.

Threading: ThreadingHTTPServer handles each request on its own thread and a
sqlite3 connection may not be shared across threads, so connections are
thread-local.  WAL mode lets readers carry on while one writer commits, and
busy_timeout makes a contended write wait rather than raise.

Tokens: the `sessions` table stores only sha256(token).  The raw token exists
in the user's cookie and nowhere else, so a copy of this database - a backup,
or a forensic image of the workstation itself - does not hand over live
sessions.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from typing import Any, Optional

from access.policy import (ACTIVE, APPROVED, GRANTING_STATES, PENDING,
                           ROLE_ADMIN, ROLE_USER, stamp)

FILENAME = "access.db"

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY,
    username         TEXT    NOT NULL UNIQUE,
    password_hash    TEXT    NOT NULL,
    role             TEXT    NOT NULL DEFAULT 'user',
    created_utc      TEXT    NOT NULL,
    last_login_utc   TEXT,
    failed_count     INTEGER NOT NULL DEFAULT 0,
    first_fail_utc   TEXT,
    locked_until_utc TEXT,
    disabled         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS requests (
    id                  INTEGER PRIMARY KEY,
    public_id           TEXT    NOT NULL UNIQUE,
    user_id             INTEGER NOT NULL REFERENCES users(id),
    status              TEXT    NOT NULL,
    created_utc         TEXT    NOT NULL,
    request_expires_utc TEXT    NOT NULL,
    decided_utc         TEXT,
    decided_by          TEXT,
    decision_note       TEXT,
    access_expires_utc  TEXT,
    activated_utc       TEXT,
    closed_utc          TEXT,
    remote_ip           TEXT,
    user_agent          TEXT
);
CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS ix_requests_user   ON requests(user_id);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY,
    token_hash    TEXT    NOT NULL UNIQUE,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    request_id    INTEGER REFERENCES requests(id),
    kind          TEXT    NOT NULL,
    created_utc   TEXT    NOT NULL,
    expires_utc   TEXT    NOT NULL,
    last_seen_utc TEXT,
    remote_ip     TEXT,
    user_agent    TEXT,
    revoked_utc   TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_request ON sessions(request_id);
"""


def token_hash(token: str) -> str:
    """What the database stores in place of a session token."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


class StoreError(Exception):
    pass


class UsernameTaken(StoreError):
    pass


class PublicIdTaken(StoreError):
    pass


def _dict(row: Optional[sqlite3.Row]) -> Optional[dict]:
    return dict(row) if row is not None else None


class Store:
    """Every SQL statement this package runs. No SQL anywhere else."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._local = threading.local()
        self._migrate()

    # -- connections -------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _migrate(self) -> None:
        conn = self._conn()
        with conn:
            conn.executescript(SCHEMA)
            conn.execute("PRAGMA user_version=%d" % SCHEMA_VERSION)

    # -- users -------------------------------------------------------------
    def create_user(self, username: str, password_hash: str,
                    role: str = ROLE_USER) -> dict:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO users (username, password_hash, role, created_utc) "
                    "VALUES (?,?,?,?)",
                    (username, password_hash, role, stamp()))
        except sqlite3.IntegrityError as exc:
            raise UsernameTaken("username already exists: " + str(username)) from exc
        return self.user_by_id(cur.lastrowid)            # type: ignore[arg-type]

    def user_by_name(self, username: str) -> Optional[dict]:
        return _dict(self._conn().execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone())

    def user_by_id(self, user_id: int) -> Optional[dict]:
        return _dict(self._conn().execute(
            "SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def list_users(self) -> list[dict]:
        return [dict(r) for r in self._conn().execute(
            "SELECT * FROM users ORDER BY username").fetchall()]

    def count_admins(self, enabled_only: bool = True) -> int:
        sql = "SELECT COUNT(*) AS n FROM users WHERE role=?"
        if enabled_only:
            sql += " AND disabled=0"
        return int(self._conn().execute(sql, (ROLE_ADMIN,)).fetchone()["n"])

    def set_password(self, user_id: int, password_hash: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET password_hash=? WHERE id=?",
                      (password_hash, user_id))

    def set_role(self, user_id: int, role: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

    def set_disabled(self, user_id: int, disabled: bool) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET disabled=? WHERE id=?",
                      (1 if disabled else 0, user_id))

    def note_login_ok(self, user_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET last_login_utc=?, failed_count=0, "
                      "first_fail_utc=NULL, locked_until_utc=NULL WHERE id=?",
                      (stamp(), user_id))

    def note_login_fail(self, user_id: int, restart_window: bool) -> int:
        """Bump the failure counter. Returns the new count."""
        with self._conn() as c:
            if restart_window:
                c.execute("UPDATE users SET failed_count=1, first_fail_utc=? "
                          "WHERE id=?", (stamp(), user_id))
            else:
                c.execute("UPDATE users SET failed_count=failed_count+1, "
                          "first_fail_utc=COALESCE(first_fail_utc,?) WHERE id=?",
                          (stamp(), user_id))
            row = c.execute("SELECT failed_count FROM users WHERE id=?",
                            (user_id,)).fetchone()
        return int(row["failed_count"]) if row else 0

    def lock_user(self, user_id: int, until_utc: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET locked_until_utc=? WHERE id=?",
                      (until_utc, user_id))

    def clear_lock(self, user_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET locked_until_utc=NULL, failed_count=0, "
                      "first_fail_utc=NULL WHERE id=?", (user_id,))

    # -- requests ----------------------------------------------------------
    def create_request(self, public_id: str, user_id: int, created_utc: str,
                       request_expires_utc: str, remote_ip: str = "",
                       user_agent: str = "") -> dict:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO requests (public_id, user_id, status, created_utc,"
                    " request_expires_utc, remote_ip, user_agent) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (public_id, user_id, PENDING, created_utc,
                     request_expires_utc, remote_ip, user_agent[:400]))
        except sqlite3.IntegrityError as exc:
            raise PublicIdTaken(public_id) from exc
        return self.request_by_id(cur.lastrowid)         # type: ignore[arg-type]

    def request_by_id(self, request_id: int) -> Optional[dict]:
        return _dict(self._conn().execute(
            "SELECT * FROM requests WHERE id=?", (request_id,)).fetchone())

    def request_by_public_id(self, public_id: str) -> Optional[dict]:
        return _dict(self._conn().execute(
            "SELECT * FROM requests WHERE public_id=?", (public_id,)).fetchone())

    def list_requests(self, statuses: tuple = (), limit: int = 200,
                      user_id: Optional[int] = None) -> list[dict]:
        sql = ("SELECT r.*, u.username FROM requests r "
               "JOIN users u ON u.id = r.user_id")
        where: list[str] = []
        args: list[Any] = []
        if statuses:
            where.append("r.status IN (" + ",".join("?" * len(statuses)) + ")")
            args.extend(statuses)
        if user_id is not None:
            where.append("r.user_id = ?")
            args.append(user_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY r.id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self._conn().execute(sql, args).fetchall()]

    def live_request_for_user(self, user_id: int) -> Optional[dict]:
        """The newest request for this user that is pending or granting."""
        states = (PENDING, APPROVED, ACTIVE)
        return _dict(self._conn().execute(
            "SELECT * FROM requests WHERE user_id=? AND status IN ("
            + ",".join("?" * len(states))
            + ") ORDER BY id DESC LIMIT 1",
            (user_id,) + states).fetchone())

    def decide_request(self, request_id: int, status: str, decided_by: str,
                       decided_utc: str, access_expires_utc: Optional[str],
                       note: str = "") -> Optional[dict]:
        """Move a request out of PENDING. Only a pending request may be decided.

        The status check is part of the UPDATE rather than a read followed by a
        write, so two administrators clicking Approve and Reject at the same
        moment cannot both succeed: the second one updates zero rows and gets
        None back.
        """
        with self._conn() as c:
            cur = c.execute(
                "UPDATE requests SET status=?, decided_by=?, decided_utc=?, "
                "access_expires_utc=?, decision_note=? "
                "WHERE id=? AND status=?",
                (status, decided_by, decided_utc, access_expires_utc,
                 note[:500], request_id, PENDING))
            if cur.rowcount == 0:
                return None
        return self.request_by_id(request_id)

    def activate_request(self, request_id: int, when_utc: str) -> Optional[dict]:
        """APPROVED -> ACTIVE on the first authorised use. None if not pending."""
        with self._conn() as c:
            cur = c.execute(
                "UPDATE requests SET status=?, activated_utc=? "
                "WHERE id=? AND status=?",
                (ACTIVE, when_utc, request_id, APPROVED))
            if cur.rowcount == 0:
                return None
        return self.request_by_id(request_id)

    def close_request(self, request_id: int, status: str, when_utc: str,
                      by: str = "", note: str = "",
                      only_if: tuple = ()) -> Optional[dict]:
        """Move a request to a terminal state (expired / revoked)."""
        sql = ("UPDATE requests SET status=?, closed_utc=?, decision_note=? "
               "WHERE id=?")
        args: list[Any] = [status, when_utc, note[:500], request_id]
        if only_if:
            sql += " AND status IN (" + ",".join("?" * len(only_if)) + ")"
            args.extend(only_if)
        with self._conn() as c:
            cur = c.execute(sql, args)
            if cur.rowcount == 0:
                return None
            if by:
                c.execute("UPDATE requests SET decided_by=COALESCE(decided_by,?) "
                          "WHERE id=?", (by, request_id))
        return self.request_by_id(request_id)

    def due_requests(self, when_utc: str) -> list[dict]:
        """Requests whose clock has run out but whose status lags behind.

        Two different deadlines: a PENDING request dies at
        request_expires_utc, a granted one at access_expires_utc.
        """
        granting = GRANTING_STATES
        return [dict(r) for r in self._conn().execute(
            "SELECT * FROM requests WHERE "
            "  (status = ? AND request_expires_utc <= ?) "
            "  OR (status IN (" + ",".join("?" * len(granting)) + ") "
            "      AND access_expires_utc IS NOT NULL "
            "      AND access_expires_utc <= ?)",
            (PENDING, when_utc) + granting + (when_utc,)).fetchall()]

    # -- sessions ----------------------------------------------------------
    def create_session(self, token: str, user_id: int, kind: str,
                       expires_utc: str, request_id: Optional[int] = None,
                       remote_ip: str = "", user_agent: str = "") -> dict:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO sessions (token_hash, user_id, request_id, kind, "
                "created_utc, expires_utc, last_seen_utc, remote_ip, user_agent) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (token_hash(token), user_id, request_id, kind, stamp(),
                 expires_utc, stamp(), remote_ip, user_agent[:400]))
        return self.session_by_id(cur.lastrowid)         # type: ignore[arg-type]

    def session_by_id(self, session_id: int) -> Optional[dict]:
        return _dict(self._conn().execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone())

    def session_by_token(self, token: str) -> Optional[dict]:
        """Look a session up by raw token. Revoked rows are never returned."""
        return _dict(self._conn().execute(
            "SELECT * FROM sessions WHERE token_hash=? AND revoked_utc IS NULL",
            (token_hash(token),)).fetchone())

    def session_by_token_any(self, token: str) -> Optional[dict]:
        """Look a session up including revoked rows.

        Used only to explain a refusal - a user whose grant was withdrawn
        should be told that, not bounced to the login form with no reason.
        Never call this to decide whether to allow something: `revoked_utc`
        may be set, which is precisely what `session_by_token` filters out.
        """
        return _dict(self._conn().execute(
            "SELECT * FROM sessions WHERE token_hash=?",
            (token_hash(token),)).fetchone())

    def touch_session(self, session_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE sessions SET last_seen_utc=? WHERE id=?",
                      (stamp(), session_id))

    def rotate_session(self, session_id: int, new_token: str, kind: str,
                       expires_utc: str) -> Optional[dict]:
        """Give a session a new token when its privilege changes.

        Session fixation: the token the browser held while it was merely
        identified must not be the token that later carries eight hours of
        access.  Rotating in place keeps one row, so the request linkage and
        the device details recorded at login survive the upgrade.
        """
        with self._conn() as c:
            cur = c.execute(
                "UPDATE sessions SET token_hash=?, kind=?, expires_utc=?, "
                "last_seen_utc=? WHERE id=? AND revoked_utc IS NULL",
                (token_hash(new_token), kind, expires_utc, stamp(), session_id))
            if cur.rowcount == 0:
                return None
        return self.session_by_id(session_id)

    def revoke_session(self, session_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE sessions SET revoked_utc=? "
                      "WHERE id=? AND revoked_utc IS NULL", (stamp(), session_id))

    def revoke_sessions_for_request(self, request_id: int) -> int:
        with self._conn() as c:
            cur = c.execute("UPDATE sessions SET revoked_utc=? WHERE request_id=? "
                            "AND revoked_utc IS NULL", (stamp(), request_id))
        return cur.rowcount

    def revoke_sessions_for_user(self, user_id: int) -> int:
        with self._conn() as c:
            cur = c.execute("UPDATE sessions SET revoked_utc=? WHERE user_id=? "
                            "AND revoked_utc IS NULL", (stamp(), user_id))
        return cur.rowcount

    def sessions_for_user(self, user_id: int, live_only: bool = True) -> list[dict]:
        sql = "SELECT * FROM sessions WHERE user_id=?"
        args: tuple = (user_id,)
        if live_only:
            sql += " AND revoked_utc IS NULL AND expires_utc > ?"
            args = (user_id, stamp())
        sql += " ORDER BY id DESC"
        return [dict(r) for r in self._conn().execute(sql, args).fetchall()]

    def purge_sessions(self, before_utc: str) -> int:
        """Drop rows that are long dead. Nothing depends on them any more."""
        with self._conn() as c:
            cur = c.execute("DELETE FROM sessions WHERE expires_utc <= ?",
                            (before_utc,))
        return cur.rowcount

    # -- reporting ---------------------------------------------------------
    def stats(self) -> dict:
        c = self._conn()
        by_status = {r["status"]: r["n"] for r in c.execute(
            "SELECT status, COUNT(*) AS n FROM requests GROUP BY status")}
        return {
            "users": int(c.execute(
                "SELECT COUNT(*) AS n FROM users").fetchone()["n"]),
            "admins": self.count_admins(),
            "requests": by_status,
            "pending": int(by_status.get(PENDING, 0)),
            "live_sessions": int(c.execute(
                "SELECT COUNT(*) AS n FROM sessions WHERE revoked_utc IS NULL "
                "AND expires_utc > ?", (stamp(),)).fetchone()["n"]),
        }


def open_store(directory: str) -> Store:
    os.makedirs(directory, exist_ok=True)
    return Store(os.path.join(directory, FILENAME))

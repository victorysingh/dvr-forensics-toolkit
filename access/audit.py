"""Tamper-evident audit log for every access decision.

This does not reimplement the hash chain.  acquire/ledger.py already has one,
its construction is documented there, and the regression suite already proves
it detects edits, reorderings and deletions - so the access log is that same
ledger with a per-entry actor.

Why the actor has to move: CustodyLedger fixes `actor` at construction
because an acquisition has one operator.  Access events do not - a login is
by the user, the approval two minutes later is by an administrator - so the
actor is set per entry, under a lock, because ThreadingHTTPServer will call
this from several threads at once and the underlying append mutates both the
file and an in-memory list.

What is deliberately *not* written here: no password, no password hash, no
session token, and no 9-digit identifier of a request belonging to anyone
else.  An audit log that leaks credentials is a liability, not a control.
"""

from __future__ import annotations

import os
import threading
import time

from acquire.ledger import CustodyLedger

try:                                    # POSIX
    import fcntl
    _msvcrt = None
except ImportError:                     # Windows
    fcntl = None                        # type: ignore[assignment]
    import msvcrt as _msvcrt            # type: ignore[no-redef]

# Actions, named so a reader can grep one class of event.  Anything not in
# this tuple is still accepted - refusing to log an unexpected event would be
# the wrong failure - but a new action belongs here so the set stays readable.
LOGIN_OK = "access.login_ok"
LOGIN_FAIL = "access.login_fail"
LOGOUT = "access.logout"
LOCKOUT = "access.lockout"
SIGNUP = "access.signup"
USER_CREATED = "access.user_created"
USER_DISABLED = "access.user_disabled"
REQUEST_CREATED = "access.request_created"
REQUEST_APPROVED = "access.request_approved"
REQUEST_REJECTED = "access.request_rejected"
REQUEST_REVOKED = "access.request_revoked"
REQUEST_EXPIRED = "access.request_expired"
ACCESS_ACTIVATED = "access.activated"
ACCESS_DENIED = "access.denied"
SESSION_ROTATED = "access.session_rotated"
RATE_LIMITED = "access.rate_limited"
MAIL_SENT = "access.mail_sent"
MAIL_FAILED = "access.mail_failed"
MAIL_SKIPPED = "access.mail_skipped"

ACTIONS = (
    LOGIN_OK, LOGIN_FAIL, LOGOUT, LOCKOUT, SIGNUP, USER_CREATED,
    USER_DISABLED, REQUEST_CREATED, REQUEST_APPROVED, REQUEST_REJECTED,
    REQUEST_REVOKED, REQUEST_EXPIRED, ACCESS_ACTIVATED, ACCESS_DENIED,
    SESSION_ROTATED, RATE_LIMITED, MAIL_SENT, MAIL_FAILED, MAIL_SKIPPED,
)

#: The ledger's `case_id` column is not a case here; it says which log this is
#: so a file found on its own is self-describing.
LOG_SCOPE = "access-control"

#: Deliberately not "custody_ledger.jsonl": report.case.list_cases treats any
#: directory holding a file of that name as a case, and the access log would
#: then appear in the console's case list.
FILENAME = "access_audit.jsonl"


class _FileLock:
    """An advisory lock held across processes, for the length of one append.

    Needed because there is more than one writer: the running server has an
    AccessAudit open, and `cli.py access-request --action approve` opens a
    second one over the same file.  Each computes the next entry's prev_hash
    from its own view of the chain, so without this two appends interleave and
    the log on disk no longer verifies - the chain would report itself broken
    when nothing had actually been tampered with.

    A sidecar .lock file is used rather than the log itself, so the lock is
    never confused with the append and an abandoned lock cannot truncate data.
    """

    def __init__(self, path: str, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if fcntl is not None:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
                else:
                    self._fh.seek(0)
                    _msvcrt.locking(self._fh.fileno(), _msvcrt.LK_LOCK, 1)
                return self
            except OSError:
                # Windows LK_LOCK gives up after ~10 tries of its own; keep
                # trying until our own deadline, then give up rather than hang.
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            else:
                self._fh.seek(0)
                _msvcrt.locking(self._fh.fileno(), _msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            self._fh.close()
            self._fh = None
        return False


class AccessAudit(CustodyLedger):
    """The access log. Same chain rule as custody, one actor per entry."""

    def __init__(self, path: str):
        super().__init__(path, actor="system", case_id=LOG_SCOPE)
        self._lock = threading.Lock()
        self._lock_path = path + ".lock"

    def _reload(self) -> None:
        """Re-read the file so prev_hash commits to what is actually there."""
        self.entries = []
        if os.path.exists(self.path):
            self._load()

    def record(self, action: str, actor: str = "system",
               detail: dict | None = None) -> dict:
        """Append one event. Returns the entry, including its hash.

        The lock is taken, the file is re-read, and only then is the entry
        built: the head it links to is the head on disk at that moment, not
        the one this object happened to see when it was opened.
        """
        with self._lock:                       # this process's threads
            with _FileLock(self._lock_path):   # and every other process
                self._reload()
                self.actor = actor or "system"
                try:
                    return self.append(action, detail or {})
                finally:
                    self.actor = "system"

    def reread(self) -> "AccessAudit":
        """Pick up entries other writers have added. For the admin panel."""
        with self._lock:
            self._reload()
        return self

    def recent(self, limit: int = 200, action_prefix: str = "") -> list[dict]:
        """Newest first, for the admin panel."""
        rows = [e for e in self.entries
                if not action_prefix or str(e.get("action", "")).startswith(action_prefix)]
        return list(reversed(rows[-limit:]))

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            a = str(e.get("action", "?"))
            out[a] = out.get(a, 0) + 1
        return out


def open_audit(directory: str) -> AccessAudit:
    """Open (creating if needed) the access log inside `directory`."""
    os.makedirs(directory, exist_ok=True)
    return AccessAudit(os.path.join(directory, FILENAME))

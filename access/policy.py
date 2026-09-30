"""Access-control policy: the durations, the state names, and one clock.

Everything here is a decision about *how long* or *how many*, kept in one
file so the policy can be read without reading the implementation, and so a
deployment can argue with the numbers in one place rather than fifteen.

The clock helpers exist because the rest of the toolkit stores timestamps as
ISO-8601 Z strings (core.contract.utc_now) while expiry needs arithmetic.
Parsing is therefore done once, here, in a way that round-trips that exact
format - and every comparison in this package goes through `is_past` so a
naive/aware datetime mix-up cannot silently make an expired grant look live.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

# -- the eight hours ------------------------------------------------------
# The spec's headline number.  An approved request is good for this long from
# the moment of approval, not from the moment of the request: an examiner who
# waited forty minutes for a supervisor does not lose forty minutes of it.
ACCESS_WINDOW_HOURS = 8

# A request nobody has decided on stops being decidable.  Without this a
# waiting room left open overnight could be approved the next morning by an
# administrator who no longer remembers what they are approving.
REQUEST_TTL_MINUTES = 15

# How long the browser stays identified while it waits to be approved.  It is
# deliberately longer than REQUEST_TTL_MINUTES so that the user sees the
# honest "this request expired" page rather than being bounced to the login
# form with no explanation.
LOGIN_SESSION_MINUTES = 30

# -- brute force ----------------------------------------------------------
LOGIN_MAX_FAILS = 5                 # consecutive failures before a lockout
LOGIN_FAIL_WINDOW_MINUTES = 15      # ... counted only within this window
LOCKOUT_MINUTES = 15                # ... and then the account rests

# -- rate limiting --------------------------------------------------------
# Per minute.  The server binds loopback only, so this is not a defence
# against the internet; it is a defence against a script on this machine
# walking the 9-digit space or the password list.
#
# Keying matters more than the numbers here.  Everything arrives from
# 127.0.0.1, so a single per-address bucket is one bucket for the whole
# machine: one user fumbling their password would throttle a supervisor
# approving requests, and a supervisor working through a queue would throttle
# themselves.  So sign-in is limited per *account* - which is the granularity
# the lockout already uses, and the one an attacker cannot dodge for a
# password guess - with a looser per-address ceiling above it so a script
# still cannot spray a thousand usernames a minute.
RATE_AUTH_PER_MIN = 10              # per account: login and signup
RATE_AUTH_BURST_PER_MIN = 60        # per address, across all accounts
RATE_DECIDE_PER_MIN = 60            # an administrator clearing a real queue
RATE_GENERAL_PER_MIN = 300          # everything else, including status polls

# -- credentials ----------------------------------------------------------
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 256              # scrypt is not free; refuse a memory bomb
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")

ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLES = (ROLE_USER, ROLE_ADMIN)

# -- the state machine ----------------------------------------------------
#   PENDING ─┬─► REJECTED
#            ├─► EXPIRED          (nobody decided within REQUEST_TTL_MINUTES)
#            └─► APPROVED ─► ACTIVE ─┬─► EXPIRED   (8 hours ran out)
#                                    └─► REVOKED   (an admin cut it short)
#
# APPROVED and ACTIVE are kept apart on purpose: APPROVED means a supervisor
# said yes, ACTIVE means the browser actually came back and used it.  The
# difference is exactly what an audit reader wants to know.
PENDING = "pending"
APPROVED = "approved"
ACTIVE = "active"
REJECTED = "rejected"
EXPIRED = "expired"
REVOKED = "revoked"

STATES = (PENDING, APPROVED, ACTIVE, REJECTED, EXPIRED, REVOKED)

#: States in which a request could still become usable, or already is.
LIVE_STATES = (PENDING, APPROVED, ACTIVE)
#: States that authorise the protected application.
GRANTING_STATES = (APPROVED, ACTIVE)
#: States nothing can move out of.
TERMINAL_STATES = (REJECTED, EXPIRED, REVOKED)

#: Shown to the user verbatim, so the page never has to explain a code.
STATE_TEXT = {
    PENDING: "Waiting for administrator approval",
    APPROVED: "Approved - opening the console",
    ACTIVE: "Access granted",
    REJECTED: "Access denied by the administrator",
    EXPIRED: "This access request has expired",
    REVOKED: "Access was withdrawn by the administrator",
}


# -- one clock ------------------------------------------------------------
def now() -> datetime:
    """The only place this package reads the wall clock."""
    return datetime.now(timezone.utc)


def stamp(when: Optional[datetime] = None) -> str:
    """ISO-8601 with milliseconds and a Z, byte-identical to utc_now()."""
    dt = when or now()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse(text: str) -> Optional[datetime]:
    """Read a stamp back. None - never an exception - if it is not one."""
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    # A stamp without a zone is read as UTC: everything this package writes
    # is UTC, and guessing local time here would move expiry by hours.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def plus(when: datetime, **kw) -> datetime:
    return when + timedelta(**kw)


def is_past(text: str, ref: Optional[datetime] = None) -> bool:
    """True if `text` is a stamp at or before `ref` (default: now).

    An unparseable or empty stamp is *not* past.  That choice matters: it
    means a corrupted expiry never silently converts into "expired", which
    would log a user out, rather than into "valid", which would let one in.
    A missing expiry is caught by the caller as a missing grant instead.
    """
    dt = parse(text)
    return dt is not None and dt <= (ref or now())


def seconds_left(text: str, ref: Optional[datetime] = None) -> int:
    dt = parse(text)
    if dt is None:
        return 0
    return max(0, int((dt - (ref or now())).total_seconds()))

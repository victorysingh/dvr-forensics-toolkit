"""Live check of the access gate on a real Supabase project.

    python -m validate.access_supabase [--supabase-env FILE]

Drives the whole state machine (access/service.py) over access/supabase.py's
store against the project named by the credentials: sign-up, a correct
password that opens nothing, approval, the token rotating on first use,
revocation landing on the next request, rejection, expiry from the stored
deadline, lockout after five wrong passwords, and the sweep.

What it leaves behind: nothing.  Its accounts are named zzlive_<random>, and
every row it made - sessions, requests, users - is deleted at the end, pass or
fail.  Its audit entries go to a throwaway local file, not to the project's
audit table: that table refuses deletes by design, so a check run must never
write to it.  (The Supabase audit log itself is covered offline in
tests/test_pipeline.py and by the database's own refusals.)
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from access.audit import open_audit                       # noqa: E402
from access.policy import (ACTIVE, EXPIRED, PENDING, REJECTED,  # noqa: E402
                           REVOKED, now, plus, stamp)
from access.service import AccessControl                  # noqa: E402
from access.supabase import (REQUESTS, SESSIONS, USERS, Rest,  # noqa: E402
                             SupabaseStore, _where, load_config)

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}"
          f"{('  <- ' + detail) if detail and not cond else ''}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--supabase-env", default="")
    args = ap.parse_args()

    config = load_config(args.supabase_env)
    print(f"[access gate on Supabase: {config.url}]")
    rest = Rest(config)
    store = SupabaseStore(rest)
    tag = "zzlive_" + secrets.token_hex(3)
    tmp = tempfile.mkdtemp(prefix="access-live-")
    ac = AccessControl(tmp, store=store, audit=open_audit(tmp))   # type: ignore[arg-type]
    user_ids: list[int] = []

    try:
        t0 = time.monotonic()
        admin, user = tag + "a", tag + "u"
        check("an administrator is made (command-line path)",
              ac.create_user(admin, "adminpassword1", role="admin").ok)
        check("a self-made account is a plain user",
              ac.signup(user, "userpassword12").ok
              and store.user_by_name(user)["role"] == "user")
        user_ids += [store.user_by_name(admin)["id"], store.user_by_name(user)["id"]]
        check("the same username twice is refused",
              not ac.signup(user, "userpassword12").ok)
        check("administrators are counted", ac.has_admin)

        r = ac.login(user, "userpassword12", "10.0.0.1", "live-check")
        tok, req = r.data.get("token", ""), r.data.get("request") or {}
        check("a correct password opens a PENDING request, not the console",
              r.ok and req.get("status") == PENDING)
        d = ac.authorize(tok)
        check("pending: the console stays shut", not d.allowed and d.reason == PENDING)
        check("the waiting room shows the status and nothing personal",
              (ac.status_of(req["public_id"]) or {}).get("status") == PENDING
              and "username" not in (ac.status_of(req["public_id"]) or {}))
        again = ac.login(user, "userpassword12")
        check("signing in again reuses the live request",
              (again.data.get("request") or {}).get("id") == req["id"])

        check("approval works", ac.approve(req["public_id"], admin).ok)
        check("a request cannot be decided twice",
              not ac.approve(req["public_id"], admin).ok
              and not ac.reject(req["public_id"], admin).ok)
        d = ac.authorize(tok)
        check("first use of the grant: allowed, and the token is rotated",
              d.allowed and bool(d.new_token) and d.request["status"] == ACTIVE)
        new_tok = d.new_token or ""
        check("the pre-approval token is dead after rotation",
              not ac.authorize(tok).allowed)
        check("the rotated token carries the access", ac.authorize(new_tok).allowed)
        check("revocation works", ac.revoke(req["public_id"], admin, "live check").ok)
        d = ac.authorize(new_tok)
        check("revoked: denied on the very next request",
              not d.allowed and d.reason == REVOKED)

        r2 = ac.login(user, "userpassword12")
        req2 = r2.data.get("request") or {}
        check("after revocation a new sign-in opens a new request",
              r2.ok and req2.get("id") not in (None, req["id"]))
        check("rejection works", ac.reject(req2["public_id"], admin, "no").ok)
        check("rejected: denied, with the reason",
              ac.authorize(r2.data["token"]).reason == REJECTED)

        r3 = ac.login(user, "userpassword12")
        req3 = r3.data["request"]
        ac.approve(req3["public_id"], admin)
        live_tok = ac.authorize(r3.data["token"]).new_token or ""   # rotated on first use
        past = stamp(plus(now(), minutes=-1))
        store._update(REQUESTS, _where(id=("eq", req3["id"])), {"access_expires_utc": past})
        d = ac.authorize(live_tok)
        check("expiry is read from the stored deadline, not a timer",
              not d.allowed and d.reason == EXPIRED)

        r4 = ac.login(user, "userpassword12")
        req4 = r4.data["request"]
        store._update(REQUESTS, _where(id=("eq", req4["id"])),
                      {"request_expires_utc": past})
        check("the sweep closes an undecided request past its 15 minutes",
              ac.sweep(force=True) >= 1
              and store.request_by_id(req4["id"])["status"] == EXPIRED)

        ac.rate.reset()          # the flow above has used this minute's sign-ins
        for _ in range(5):
            ac.login(user, "wrong password here")
        locked = ac.login(user, "userpassword12")
        check("five wrong passwords lock the account, even to the right one",
              not locked.ok and "Too many failed attempts" in locked.message)
        check("the lockout is stored with the account",
              bool(store.user_by_name(user)["locked_until_utc"]))

        admin_login = ac.login(admin, "adminpassword1")
        check("an administrator does not queue",
              admin_login.ok and ac.authorize(admin_login.data["token"]).by_role)
        stats = store.stats()
        check("the overview counts what this run made",
              stats["users"] >= 2 and stats["admins"] >= 1
              and stats["requests"].get(REVOKED, 0) >= 1)
        check("requests list newest first, with the username",
              [x["username"] for x in store.list_requests((), 50, user_ids[1])][:1] == [user])
        check("disabling an account ends its sessions",
              ac.set_disabled(user, True, actor=admin).ok
              and not store.sessions_for_user(user_ids[1]))
        print(f"  ({time.monotonic() - t0:.1f} s for the whole flow)")
    finally:
        # Children first: sessions and requests point at users.
        for table in (SESSIONS, REQUESTS):
            for uid in user_ids:
                rest.call("DELETE", f"/{table}?{_where(user_id=('eq', uid))}")
        for uid in user_ids:
            rest.call("DELETE", f"/{USERS}?{_where(id=('eq', uid))}")
        left = [store.user_by_name(n) for n in (tag + "a", tag + "u")]
        check("clean-up: every row this run made is gone", left == [None, None])

    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n  {len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

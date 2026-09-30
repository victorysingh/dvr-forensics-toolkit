# Temporary access control

An authorisation layer between "this person proved who they are" and "this
person may see the evidence". Signing in does not open the console: it creates
an **access request** with a 9-digit identifier, and the browser waits at
`/<identifier>` until an administrator approves it. An approved request grants
**8 hours**, after which it lapses on its own.

Off unless asked for. `cli.py serve` behaves exactly as it always did; nothing
in `access/` is imported until `--require-access` is passed.

```
cli.py serve --out out                      # as before: no gate at all
cli.py serve --out out --require-access     # sign-in + approval + 8 hours
```

## Why a forensic tool has this

An examination workstation holds other people's evidence, and "who looked at
it, when, and who let them" is a question the case record has to be able to
answer. The approval step makes that a supervised decision; the hash-chained
audit log makes it a permanent one. It is the same argument as the custody
ledger, applied to the people reading the case rather than to the bytes.

## The flow

```
  sign in  ──►  PENDING  ──┬─►  REJECTED        (administrator said no)
  /access/login            │
        │                  ├─►  EXPIRED         (nobody decided in 15 min)
        ▼                  │
  /583921746  (waiting)    └─►  APPROVED ──► ACTIVE ──┬─► EXPIRED  (8 h up)
        │                            │         │      └─► REVOKED  (cut short)
        └── polls its own status ────┘         │
                                              ▼
                                      the case console
```

`APPROVED` and `ACTIVE` are kept apart deliberately: `APPROVED` means a
supervisor said yes, `ACTIVE` means the browser actually came back and used
it. The difference is exactly what an audit reader wants to know.

## What actually authorises a request

The 9-digit identifier is **not a credential**. It names a waiting room.
Knowing one lets you read that request's status and nothing else — no
username, no session, and no way to approve it.

The credential is a **256-bit session token** in an `HttpOnly`,
`SameSite=Strict` cookie. It is stored only as `sha256(token)`, so a copy of
the database — a backup, or a forensic image of the workstation itself — does
not hand over live sessions.

The token is **rotated** the first time a grant is used, so the token that
carried only an identity is never the token that carries eight hours of
access.

## Administrators do not queue

If an administrator had to be approved before they could approve anyone, the
first administrator on a fresh database could never get in, and a
single-administrator deployment would deadlock the moment their eight hours
ran out. So a user whose role is `admin` reaches the console without a
request. The bypass is written to the audit log every time it is used, and it
is the reason administrators are created from the command line only — an
attacker who can reach the sign-up form cannot mint one.

## Expiry is checked twice

`sweep()` moves timed-out rows to their terminal state for the benefit of the
admin panel. `authorize()` never trusts that the sweep has run: it re-reads
the deadline on every single request. A grant therefore stops working the
instant it is due even if no sweep has happened since — which matters because
there is no background thread here, by design. Nothing keeps running after
the server stops.

## Commands

```bash
# make the first administrator (prompts for the password; never in argv)
cli.py access-admin --username supervisor

# accounts
cli.py access-user                                   # list
cli.py access-user --action add     --username aakash
cli.py access-user --action passwd  --username aakash
cli.py access-user --action disable --username aakash

# decide without opening a browser
cli.py access-request --pending-only
cli.py access-request --action approve --id 583921746 --admin supervisor
cli.py access-request --action revoke  --id 583921746 --note "shift ended"

# the audit log, and its chain
cli.py access-audit
```

All of them take `--out` (the access store defaults to `<out>/.access`) or an
explicit `--access-dir`.

## Routes

| Route | Who | What |
|---|---|---|
| `/access/login` | anyone | sign in; creates or rejoins a request |
| `/access/signup` | anyone | make a plain user (`--no-signup` closes it) |
| `/access/logout` | POST only | ends the session |
| `/<9 digits>` | anyone with the id | the waiting room; polls itself |
| `/access/status/<id>` | anyone with the id | JSON: state only |
| `/admin` | `admin` role | approve, reject, revoke, read the audit log |
| `/admin/decide` | `admin` role, POST | the decision itself |
| everything else | an approved browser | the console, unchanged |

## Where things live

| File | What |
|---|---|
| `access/policy.py` | the durations, the states, and one clock |
| `access/passwords.py` | scrypt hashing, standard library only |
| `access/store.py` | sqlite3: users, requests, sessions |
| `access/audit.py` | the hash-chained log, reusing `acquire/ledger.py` |
| `access/service.py` | the state machine — all of the policy |
| `access/pages.py` | sign-in, the waiting room, the admin panel |
| `access/routes.py` | HTTP: cookies, forms, security headers, the gate |

`<out>/.access/` holds `access.db` and `access_audit.jsonl`. The log is
deliberately *not* named `custody_ledger.jsonl`: `report.case.list_cases`
treats any directory holding a file of that name as a case, and the access log
would otherwise appear in the console's own case list.

## Hosted deployments: the Supabase store

The workstation keeps everything above in `<out>/.access/`. A hosted
demonstration cannot: its machine's disk does not survive a restart. So the
same store and log also exist over a Supabase project (`access/supabase.py`),
method for method and row for row, and everything above the store is
unchanged.

```bash
# once, in the project's SQL editor: access/supabase_schema.sql
cli.py access-admin --access-store supabase --username supervisor
cli.py serve --require-access --access-store supabase     # + --cookie-secure --trust-proxy behind HTTPS
```

* **Never by accident.** SQLite stays the default; Supabase is used only with
  `--access-store supabase`, never picked up from the environment, so no test
  run or offline machine writes to a database whose log cannot be cleaned.
* **The key** is the project's secret key. It comes from `SUPABASE_URL` /
  `SUPABASE_SERVICE_KEY` or a `0600` file (`--supabase-env`, default
  `~/.config/anokhidrishti/supabase.env`), and it never appears in a message.
* **The database enforces the log as well.** Row-level security is on with
  no policies, and the public roles are revoked. Triggers refuse any UPDATE,
  DELETE or TRUNCATE on `access_audit`, even by the owner, and any row whose
  hash or link is wrong. The server's own key can only SELECT and INSERT
  there. The seal moves to `access_audit_seal`.
* **Behind a proxy**, `--cookie-secure` marks the cookie Secure and
  `--trust-proxy` keys the per-address limits on `X-Forwarded-For`. A client
  that reaches the origin directly can set that header, so only those limits
  lean on it; the per-account limit and the stored lockout do not.
* `deploy/` holds the hosted setup: Ubuntu, systemd and Caddy for HTTPS, with
  synthetic cases only, and Vercel forwarding to it.

## The policy numbers

| Setting | Value | Why |
|---|---|---|
| `ACCESS_WINDOW_HOURS` | 8 | the grant, timed from **approval**, not from the request |
| `REQUEST_TTL_MINUTES` | 15 | an undecided request dies, so a waiting room left open overnight cannot be approved next morning |
| `LOGIN_SESSION_MINUTES` | 30 | longer than the request TTL, so the user sees "expired" rather than being bounced to the login form |
| `LOGIN_MAX_FAILS` | 5 | then the account locks |
| `LOCKOUT_MINUTES` | 15 | how long it rests |
| `MIN_PASSWORD_LEN` | 10 | length, not character classes — those produce `Password1!` |
| `RATE_AUTH_PER_MIN` | 10 | sign-in attempts **per account** |
| `RATE_AUTH_BURST_PER_MIN` | 60 | sign-in attempts per client address, across all accounts |
| `RATE_DECIDE_PER_MIN` | 60 | an administrator's own budget for clearing a queue |

## What is deliberately not solved

* **Loopback only.** The server binds `127.0.0.1`, so the administrator
  approves from the same machine. That matches the SOP — a supervising
  officer signs off at the workstation — and it keeps the console's
  "offline · read-only" badge honest. That is the workstation. A hosted
  demonstration (above) still binds loopback, but a TLS proxy in front of it
  makes it reachable, and the console then reads "demo · synthetic data".
* **Rate limiting is in memory.** It is lost on restart. The account lockout,
  which is persisted, is the durable control; the limiter only stops a script
  on this machine walking the password list. Its *keying* matters more than
  its numbers: everything arrives from `127.0.0.1`, so sign-in is limited per
  account rather than per address — otherwise one person fumbling a password
  throttles everyone on the machine — with a looser per-address ceiling above
  it, and a separate budget for admin decisions.
* **The gate's pages are server-rendered**, not part of the React console.
  They have to work before anyone is authorised, so they cannot live behind
  the gate they are part of — and it means changing a word on the login form
  does not require rebuilding the committed bundle in `viewer/static/`.
* **No password reset.** `cli.py access-user --action passwd` is the reset,
  and it needs someone with a shell on the workstation. There is no email on
  an air-gapped machine to send a link to.

## Tests

`test_access` in `tests/test_pipeline.py` — 78 checks, no hardware, part of
the ordinary run. It covers the hashing, the clock, the identifier shape, the
full state machine, both expiry deadlines, the lockout, the admin bypass,
token rotation, CSRF, the rate limit, escaping, the audit chain under
concurrent writers, and the whole flow over real HTTP against the actual
server.

`test_access_supabase` covers the Supabase store offline: credentials, never
being chosen by accident, error mapping, and the audit chain, race, paging,
seal and tamper detection against a fake table that refuses what the triggers
refuse. `python -m validate.access_supabase` runs the whole flow live against
a real project. It writes no audit rows and deletes what it made.

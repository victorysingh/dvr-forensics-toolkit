"""Temporary, administrator-approved access to the case console.

An authorisation layer that sits between "this person proved who they are" and
"this person may see the evidence".  Signing in does not open the console: it
creates an access request with a 9-digit identifier, and the browser waits at
/<identifier> until an administrator on the same machine approves it.  An
approved request grants eight hours, after which it lapses on its own.

Why a forensic tool has this at all: an examination workstation holds other
people's evidence, and "who looked at it, when, and who let them" is a
question the case record has to be able to answer.  The approval step makes
that a supervised decision and the audit log makes it a permanent one.

    policy.py     the durations, the states, and one clock
    passwords.py  scrypt hashing, standard library only
    store.py      sqlite3: users, requests, sessions
    audit.py      the hash-chained log, reusing acquire/ledger.py
    service.py    the state machine - all of the policy lives here
    pages.py      sign-in, the waiting room, the admin panel
    routes.py     HTTP: cookies, forms, security headers, the gate

Off unless asked for: viewer/server.py builds a gate only when `serve()` is
called with require_access=True, which the CLI does only for
`cli.py serve --require-access`.  With the flag absent, none of this is
imported and the viewer behaves exactly as it did before.
"""

"""Email addresses encrypted at rest: AES-256-GCM, with a keyed hash for lookups.

The access store (SQLite here, Supabase when hosted) holds every account's
email address.  A copy of that database - a backup, a leaked service key, a
curious cloud operator - should not hand over a list of who uses the tool.  So
when a field key is configured, an address is stored only as:

* ``email``      ``enc:v1:`` + base64(nonce | AES-256-GCM ciphertext | tag), a fresh
                 12-byte nonce each time, so two equal addresses never look alike;
* ``email_hash`` HMAC-SHA256 of the address under a second key, so "is this
                 address already registered?" is answered without decrypting
                 anything.

Both keys are derived from one 32-byte field key that lives on the server (and
on the examiner's machine, for the command line) - never in the database.
Without the key a row shows only that an address is on file.

A store opened without a key keeps working as before, in plain text: the
air-gapped workstation, and the test suite, need no key.  Rows written before
encryption was switched on are read as they are and can be converted in place
(``cli.py access-user --action encrypt-emails``).

Needs the optional `cryptography` package, as signing does.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any, Optional

from access.store import StoreError

PREFIX = "enc:v1:"
_AAD = b"anokhidrishti/access_users.email/v1"


class FieldKeyError(StoreError):
    """No key, a bad key, or the cryptography package missing (reported like a store error)."""


def create_key(path: str) -> None:
    """Write a new random field key (refuses to overwrite: old rows need the old key)."""
    if os.path.exists(path):
        raise FieldKeyError(f"{path} already exists - a field key is never overwritten")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(os.urandom(32)).decode() + "\n")


def load_key(path: str) -> bytes:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            key = base64.b64decode(fh.read().strip())
    except FileNotFoundError:
        raise FieldKeyError(f"no field key at {path} - make one with: "
                            f"cli.py access-field-key --create {path}") from None
    except (OSError, ValueError):
        raise FieldKeyError(f"{path} is not a readable field key") from None
    if len(key) != 32:
        raise FieldKeyError(f"{path} does not hold a 32-byte key")
    return key


class EmailCrypt:
    def __init__(self, master: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise FieldKeyError("encrypting email addresses needs the optional "
                                "'cryptography' package") from None
        self._aes = AESGCM(hmac.new(master, b"anokhidrishti/email/aes-256-gcm",
                                    hashlib.sha256).digest())
        self._mac = hmac.new(master, b"anokhidrishti/email/lookup", hashlib.sha256).digest()

    def lookup(self, email: str) -> str:
        return hmac.new(self._mac, (email or "").strip().lower().encode(),
                        hashlib.sha256).hexdigest()

    def seal(self, email: str) -> tuple[str, str]:
        """(stored value, lookup hash) for an address."""
        email = (email or "").strip().lower()
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, email.encode(), _AAD)
        return PREFIX + base64.b64encode(nonce + ct).decode(), self.lookup(email)

    def open(self, stored: Optional[str]) -> Optional[str]:
        """The address, or the stored value untouched if it was never encrypted."""
        if not stored or not str(stored).startswith(PREFIX):
            return stored
        from cryptography.exceptions import InvalidTag
        raw = base64.b64decode(stored[len(PREFIX):])
        try:
            return self._aes.decrypt(raw[:12], raw[12:], _AAD).decode()
        except (InvalidTag, ValueError):
            return None                       # wrong key, or a damaged value


def is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


class EncryptedEmails:
    """A store (SQLite or Supabase) whose email column is encrypted at rest.

    Every method of the wrapped store is available unchanged; the few that
    write or read an address seal or open it on the way.
    """

    def __init__(self, store: Any, crypt: EmailCrypt):
        self._store = store
        self.crypt = crypt
        self.path = getattr(store, "path", "")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def _open_row(self, row: Optional[dict]) -> Optional[dict]:
        if row and row.get("email") is not None:
            row = dict(row, email=self.crypt.open(row["email"]))
        return row

    def create_user(self, username: str, password_hash: str, role: str = "user",
                    email: str = "") -> dict:
        stored, digest = self.crypt.seal(email) if email else ("", "")
        return self._open_row(self._store.create_user(username, password_hash, role,
                                                      email=stored, email_hash=digest))

    def set_email(self, user_id: int, email: str) -> None:
        stored, digest = self.crypt.seal(email) if email else ("", "")
        self._store.set_email(user_id, stored, email_hash=digest)

    def user_by_email(self, email: str) -> Optional[dict]:
        if not email:
            return None
        # Rows sealed under this key, then any written before encryption.
        return self._open_row(self._store.user_by_email_hash(self.crypt.lookup(email))
                              or self._store.user_by_email(email))

    def user_by_name(self, username: str) -> Optional[dict]:
        return self._open_row(self._store.user_by_name(username))

    def user_by_id(self, user_id: int) -> Optional[dict]:
        return self._open_row(self._store.user_by_id(user_id))

    def list_users(self) -> list[dict]:
        return [self._open_row(u) for u in self._store.list_users()]

    def admin_contacts(self) -> list[dict]:
        return [self._open_row(u) for u in self._store.admin_contacts()]

    def list_requests(self, *a, **kw) -> list[dict]:
        return [self._open_row(r) for r in self._store.list_requests(*a, **kw)]

    def encrypt_plaintext(self) -> int:
        """Seal every address still stored in clear. Returns how many."""
        n = 0
        for u in self._store.list_users():
            if u.get("email") and not is_encrypted(u["email"]):
                self.set_email(u["id"], u["email"])
                n += 1
        return n

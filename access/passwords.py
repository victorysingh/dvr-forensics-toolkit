"""Password hashing, standard library only.

scrypt is memory-hard: the cost of a guessing rig scales with RAM, not just
clock speed, which is what makes it a better answer than a fast hash with a
big iteration count.  It is in hashlib, so the zero-dependency rule
(requirements.txt) still holds.

hashlib.scrypt is only present when Python was linked against a version of
OpenSSL that provides it.  On a build where it is not, this module falls back
to PBKDF2-HMAC-SHA256 with a deliberately high iteration count rather than
refusing to run - an examiner's workstation is not the place to discover that
authentication is unavailable.  Which one produced a hash is recorded in the
hash string, so existing records keep verifying after an interpreter upgrade.

Stored form (one line, no ambiguity about field order):

    scrypt$<n>$<r>$<p>$<salt hex>$<key hex>
    pbkdf2_sha256$<iterations>$<salt hex>$<key hex>
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from access.policy import MAX_PASSWORD_LEN, MIN_PASSWORD_LEN

# 2**15 * 8 * 128 = 32 MiB per hash.  Chosen to stay inside OpenSSL's default
# maxmem while still being expensive enough that a wordlist run is unpleasant.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

PBKDF2_ROUNDS = 600_000          # OWASP's 2023 floor for SHA-256, doubled

SALT_BYTES = 16
KEY_BYTES = 32

HAVE_SCRYPT = hasattr(hashlib, "scrypt")


class PasswordError(ValueError):
    """A password that cannot be accepted, with a message fit to show a user."""


def check_strength(password: str) -> None:
    """Raise PasswordError if the password may not be used. Length only.

    No character-class rules: they push people towards 'Password1!' and the
    length floor buys more than they do.  The real defences against a weak
    password here are the lockout and the fact that a correct password still
    only reaches a waiting room.
    """
    if not isinstance(password, str) or not password:
        raise PasswordError("A password is required.")
    if len(password) < MIN_PASSWORD_LEN:
        raise PasswordError(
            f"Too short - at least {MIN_PASSWORD_LEN} characters.")
    if len(password) > MAX_PASSWORD_LEN:
        raise PasswordError(
            f"Too long - at most {MAX_PASSWORD_LEN} characters.")


def hash_password(password: str) -> str:
    """Hash with a fresh random salt. Returns the full stored form."""
    check_strength(password)
    salt = secrets.token_bytes(SALT_BYTES)
    if HAVE_SCRYPT:
        key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N,
                             r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES,
                             maxmem=SCRYPT_MAXMEM)
        return (f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}$"
                f"{salt.hex()}${key.hex()}")
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                              PBKDF2_ROUNDS, dklen=KEY_BYTES)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of `password` against a stored form.

    Returns False for anything malformed rather than raising: a corrupt row
    must read as "wrong password", never as an unhandled 500 that tells an
    attacker the row exists.
    """
    if not isinstance(password, str) or not stored:
        return False
    if len(password) > MAX_PASSWORD_LEN:
        return False                      # refuse to spend the memory
    parts = stored.split("$")
    try:
        if parts[0] == "scrypt" and len(parts) == 6:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt, expect = bytes.fromhex(parts[4]), bytes.fromhex(parts[5])
            if not HAVE_SCRYPT:
                return False
            # 128*n*r is scrypt's own memory formula; pass a maxmem that fits
            # the *stored* parameters, not today's, or an old hash made with a
            # larger n would fail to verify after a parameter change.
            got = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r,
                                 p=p, dklen=len(expect),
                                 maxmem=max(SCRYPT_MAXMEM, 128 * n * r * 2))
        elif parts[0] == "pbkdf2_sha256" and len(parts) == 4:
            rounds = int(parts[1])
            salt, expect = bytes.fromhex(parts[2]), bytes.fromhex(parts[3])
            got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                      rounds, dklen=len(expect))
        else:
            return False
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(got, expect)


def needs_rehash(stored: str) -> bool:
    """True if a stored hash was made with weaker parameters than today's.

    Called after a successful login, which is the only moment the plaintext
    is in hand and a silent upgrade is possible.
    """
    parts = (stored or "").split("$")
    if parts[0] == "scrypt" and len(parts) == 6:
        try:
            return (int(parts[1]) < SCRYPT_N or int(parts[2]) < SCRYPT_R
                    or int(parts[3]) < SCRYPT_P)
        except ValueError:
            return True
    if parts[0] == "pbkdf2_sha256" and len(parts) == 4:
        # Any pbkdf2 record is worth upgrading once scrypt is available.
        try:
            return HAVE_SCRYPT or int(parts[1]) < PBKDF2_ROUNDS
        except ValueError:
            return True
    return True

"""RSA signatures for the evidence trail - an examiner's key that anyone can check.

The custody ledger is a hash chain, and its seal is an HMAC: proof that the
log was not rewritten, but checkable only by whoever holds the seal key.  A
court, a defence expert or another agency has to take the examining machine's
word for it.  A digital signature removes that: the examiner signs with a
private key that never leaves their keeping, and anyone holding the matching
public key can check, offline and without any secret, that what was signed
has not changed since and was signed with that key.

The scheme is RSA-PSS with SHA-256 (MGF1-SHA256, maximum salt) over 3072-bit
keys: RSA because it is what Indian Class 3 signature tokens carry, so a
deployment can later move the private key onto the officer's own token; PSS
because it is the provably secure RSA signature padding.

Optional, like everything outside the standard library: it needs the
`cryptography` package (OpenSSL underneath).  Without it the tool runs exactly
as before - signing says it is unavailable, and nothing else changes.  The
cryptography is never written here: home-made RSA is the first thing a
defence expert would take apart.

Key files live outside any case folder, next to the ledger's seal key:

    ~/.ps26150/signing_key.pem       private key, readable by its owner only
    ~/.ps26150/signing_key.pub.pem   public key - hand this to whoever verifies
    ~/.ps26150/signing_key.json      who it belongs to, and its fingerprint

PS26150_SIGNING_KEY names another private key file.  A key may be protected
by a passphrase, read from PS26150_SIGNING_PASSPHRASE when it is set.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Optional

from core.contract import utc_now

KEY_ENV = "PS26150_SIGNING_KEY"
PASSPHRASE_ENV = "PS26150_SIGNING_PASSPHRASE"
ALGORITHM = "RSA-PSS-SHA256"            # MGF1-SHA256, maximum salt length
KEY_BITS = 3072


class SigningError(Exception):
    """No key, a wrong passphrase, or the cryptography package is missing."""


def available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _need() -> None:
    if not available():
        raise SigningError(
            "signing needs the optional 'cryptography' package "
            "(pip install cryptography; on Ubuntu: apt install python3-cryptography)")


# ---------------------------------------------------------------- key files
def key_path() -> str:
    return os.environ.get(KEY_ENV) or os.path.join(
        os.path.expanduser("~"), ".ps26150", "signing_key.pem")


def public_path(private_path: str) -> str:
    base = private_path[:-4] if private_path.endswith(".pem") else private_path
    return base + ".pub.pem"


def meta_path(private_path: str) -> str:
    base = private_path[:-4] if private_path.endswith(".pem") else private_path
    return base + ".json"


def fingerprint(public_pem: str) -> str:
    """SHA-256 of the key's DER SubjectPublicKeyInfo, in hex: the key's identity."""
    _need()
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(public_pem.encode())
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def key_id(fp: str) -> str:
    """The first 16 hex digits: short enough to read out, long enough to tell keys apart."""
    return fp[:16]


def generate(name: str, path: str = "", passphrase: str = "",
             bits: int = KEY_BITS) -> dict:
    """Make a key pair. Refuses to overwrite: a lost key cannot be re-made."""
    _need()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = path or key_path()
    if os.path.exists(path):
        raise SigningError(f"{path} already exists - a signing key is never overwritten")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = (serialization.BestAvailableEncryption(passphrase.encode()) if passphrase
           else serialization.NoEncryption())
    private_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8, enc)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    with open(public_path(path), "w", encoding="utf-8") as fh:
        fh.write(public_pem)
    fp = fingerprint(public_pem)
    meta = {"name": name, "key_id": key_id(fp), "fingerprint": fp,
            "algorithm": ALGORITHM, "bits": bits, "created_utc": utc_now(),
            "passphrase": bool(passphrase)}
    with open(meta_path(path), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return dict(meta, path=path, public_path=public_path(path), public_pem=public_pem)


class Signer:
    """An examiner's loaded private key, with who it belongs to."""

    def __init__(self, key: Any, public_pem: str, name: str):
        self._key = key
        self.public_pem = public_pem
        self.fingerprint = fingerprint(public_pem)
        self.key_id = key_id(self.fingerprint)
        self.name = name

    def sign(self, data: bytes) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = self._key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                               salt_length=padding.PSS.MAX_LENGTH),
                             hashes.SHA256())
        return base64.b64encode(sig).decode()


def load_signer(path: str = "", passphrase: Optional[str] = None) -> Signer:
    """The examiner's key. SigningError if there is none or it will not open."""
    _need()
    from cryptography.hazmat.primitives import serialization

    path = path or key_path()
    if not os.path.exists(path):
        raise SigningError(f"no signing key at {path} - make one with: "
                           f"cli.py keygen --name \"<examiner>\"")
    if passphrase is None:
        passphrase = os.environ.get(PASSPHRASE_ENV) or None
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        key = serialization.load_pem_private_key(
            data, password=passphrase.encode() if passphrase else None)
    except TypeError:
        raise SigningError("the signing key is protected by a passphrase - set "
                           f"{PASSPHRASE_ENV}, or sign with: cli.py sign") from None
    except ValueError:
        raise SigningError("the signing key did not open: wrong passphrase, "
                           "or not a private key") from None
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    name = ""
    try:
        with open(meta_path(path), "r", encoding="utf-8") as fh:
            name = json.load(fh).get("name", "")
    except (OSError, ValueError):
        pass
    return Signer(key, public_pem, name)


def verify(public_pem: str, data: bytes, signature_b64: str) -> bool:
    """True when the signature is the key's, over exactly these bytes."""
    _need()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        key = serialization.load_pem_public_key(public_pem.encode())
        key.verify(base64.b64decode(signature_b64), data,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=padding.PSS.MAX_LENGTH),
                   hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def trusted_fingerprints(paths: list[str]) -> dict[str, str]:
    """{fingerprint: file} for the public keys a verifier has chosen to trust."""
    out = {}
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as fh:
                out[fingerprint(fh.read())] = p
        except (OSError, ValueError):
            continue
    return out

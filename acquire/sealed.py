"""Sealed evidence packages: one recipient can open them, any change breaks them,
and the examiner's signature says who sealed them.

Handing evidence over - to a court, another agency, a defence expert - usually
means a pen drive or an attachment that anyone who handles it can read and
anyone can quietly alter.  A sealed package is the standard answer, hybrid
encryption:

* the files go into a tar that is encrypted as it is written, with a fresh
  random AES-256 key in GCM mode - so no plaintext copy ever touches the disk,
  and GCM's tag makes any changed byte fail decryption;
* that AES key is encrypted to the recipient's RSA public key (RSA-OAEP,
  SHA-256), so only the holder of the matching private key can open it;
* the header - recipient, sender, the list of files with their SHA-256 - is
  GCM's associated data, so it cannot be altered without failing either;
* the examiner signs the header, the ciphertext's hash and the tag with their
  key (core/signing.py), so anyone, before opening anything, can check who
  sealed it and that it is unchanged.

Opening is all-or-nothing: the signature is checked, the key unwrapped, the
whole package decrypted and authenticated, and every file's hash compared -
and only then is anything extracted.  A package that fails any step leaves
nothing behind.

File layout (.adseal):

    b"ADSEAL01" | u32 header length | header JSON (canonical)
    | ciphertext | u32 trailer length | trailer JSON (tag, ciphertext SHA-256, signature)

Optional, like signing: it needs the `cryptography` package.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tarfile
import tempfile
from typing import Optional

from core import signing
from core.contract import canonical_json, utc_now

MAGIC = b"ADSEAL01"
FORMAT = "anokhidrishti-sealed-v1"
CHUNK = 1 << 20

#: What a package carries by default: the record a recipient needs to check
#: the case, not the footage (add clips with --include).
DEFAULT_FILES = ["report.html", "report.json", "scan_report.json", "custody_ledger.jsonl",
                 "timeline.json", "carve/carve_report.json", "carve/extracted.json"]
DEFAULT_GLOBS = ["signatures/*.json", "certificate_s63_*", "parse_*.json", "*.jsonld"]


class SealError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _sha256_file(path: str) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def default_selection(case_dir: str) -> list[str]:
    import glob
    out = [p for p in DEFAULT_FILES if os.path.isfile(os.path.join(case_dir, p))]
    for pattern in DEFAULT_GLOBS:
        for p in sorted(glob.glob(os.path.join(case_dir, pattern))):
            rel = os.path.relpath(p, case_dir).replace(os.sep, "/")
            if os.path.isfile(p) and rel not in out:
                out.append(rel)
    return out


def _safe_rel(rel: str) -> bool:
    """A manifest path must stay inside the folder it is opened into."""
    parts = rel.replace("\\", "/").split("/")
    return bool(rel) and not rel.startswith(("/", "\\")) and ":" not in parts[0] \
        and ".." not in parts and "" not in parts


class _EncryptingWriter:
    """A file-like sink: encrypts whatever tarfile writes, hashing the ciphertext."""

    def __init__(self, encryptor, out):
        self.enc, self.out, self.sha, self.n = encryptor, out, hashlib.sha256(), 0

    def write(self, data: bytes) -> int:
        ct = self.enc.update(bytes(data))
        self.out.write(ct)
        self.sha.update(ct)
        self.n += len(ct)
        return len(data)

    def flush(self) -> None:
        pass


def _anonymous(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Strip who and where: a tar records the sealer's user and group names."""
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o644
    return info


def _sign_trailer_body(header_bytes: bytes, ct_sha: str, tag: bytes) -> bytes:
    return b"|".join([FORMAT.encode(), hashlib.sha256(header_bytes).hexdigest().encode(),
                      ct_sha.encode(), _b64(tag).encode()])


def seal(case_dir: str, files: list[str], recipient_pub_pem: str, dest: str,
         signer: Optional["signing.Signer"] = None, case_id: str = "",
         note: str = "") -> dict:
    """Write a sealed package of `files` (relative to case_dir) for one recipient."""
    signing._need()
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if not files:
        raise SealError("nothing to seal")
    manifest = []
    for rel in files:
        rel = rel.replace(os.sep, "/")
        if not _safe_rel(rel):
            raise SealError(f"not a path inside the case: {rel}")
        p = os.path.join(case_dir, rel)
        if not os.path.isfile(p):
            raise SealError(f"no such file in the case: {rel}")
        digest, size = _sha256_file(p)
        manifest.append({"path": rel, "sha256": digest, "bytes": size})

    recipient = serialization.load_pem_public_key(recipient_pub_pem.encode())
    rfp = signing.fingerprint(recipient_pub_pem)
    key, nonce = os.urandom(32), os.urandom(12)
    wrapped = recipient.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    header = {
        "format": FORMAT, "created_utc": utc_now(), "case_id": case_id, "note": note,
        "cipher": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256", "payload": "tar",
        "nonce": _b64(nonce), "wrapped_key": _b64(wrapped),
        "recipient": {"key_id": signing.key_id(rfp), "fingerprint": rfp},
        "sender": ({"name": signer.name, "key_id": signer.key_id,
                    "fingerprint": signer.fingerprint, "public_key_pem": signer.public_pem}
                   if signer else None),
        "manifest": manifest,
    }
    header_bytes = canonical_json(header)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(header_bytes)

    tmp = dest + ".part"
    try:
        with open(tmp, "wb") as out:
            out.write(MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes)
            w = _EncryptingWriter(enc, out)
            with tarfile.open(fileobj=w, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for m in manifest:
                    tar.add(os.path.join(case_dir, m["path"]), arcname=m["path"],
                            recursive=False, filter=_anonymous)
            tail = enc.finalize()
            out.write(tail)
            w.sha.update(tail)
            ct_sha = w.sha.hexdigest()
            trailer = {"tag": _b64(enc.tag), "ciphertext_sha256": ct_sha}
            if signer:
                trailer["signature_algorithm"] = signing.ALGORITHM
                trailer["signature"] = signer.sign(_sign_trailer_body(header_bytes, ct_sha, enc.tag))
            tb = canonical_json(trailer)
            out.write(tb + struct.pack(">I", len(tb)))
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return {"path": dest, "sha256": _sha256_file(dest)[0], "header": header,
            "recipient_key_id": signing.key_id(rfp), "signed": bool(signer)}


def _read(package: str) -> tuple[dict, bytes, int, int, dict]:
    """(header, header bytes, ciphertext start, ciphertext length, trailer)."""
    size = os.path.getsize(package)
    with open(package, "rb") as fh:
        if fh.read(8) != MAGIC:
            raise SealError("not a sealed AnokhiDrishti package")
        (hlen,) = struct.unpack(">I", fh.read(4))
        if hlen <= 0 or 12 + hlen > size:
            raise SealError("the package's header is damaged")
        hb = fh.read(hlen)
        fh.seek(size - 4)
        (tlen,) = struct.unpack(">I", fh.read(4))
        start, end = 12 + hlen, size - 4 - tlen
        if tlen <= 0 or end < start:
            raise SealError("the package's trailer is damaged")
        fh.seek(end)
        tb = fh.read(tlen)
    try:
        header, trailer = json.loads(hb), json.loads(tb)
    except ValueError:
        raise SealError("the package's header or trailer is not readable") from None
    if header.get("format") != FORMAT:
        raise SealError(f"unknown package format {header.get('format')!r}")
    return header, hb, start, end - start, trailer


def inspect(package: str, trusted_paths: Optional[list[str]] = None) -> dict:
    """What a package says about itself, and whether its sender's signature holds -
    without any private key, and before anything is decrypted."""
    signing._need()
    header, hb, start, length, trailer = _read(package)
    h = hashlib.sha256()
    with open(package, "rb") as fh:
        fh.seek(start)
        left = length
        while left:
            chunk = fh.read(min(CHUNK, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
    ct_ok = h.hexdigest() == trailer.get("ciphertext_sha256")
    sender = header.get("sender") or {}
    sig_ok = None
    if sender:
        pem = sender.get("public_key_pem", "")
        sig_ok = (signing.fingerprint(pem) == sender.get("fingerprint")
                  and signing.verify(pem, _sign_trailer_body(hb, trailer.get("ciphertext_sha256", ""),
                                                             _unb64(trailer.get("tag", ""))),
                                     trailer.get("signature", "")))
    from acquire.signatures import _default_trusted
    trusted = signing.trusted_fingerprints(list(trusted_paths or []) + _default_trusted())
    return {"header": header, "ciphertext_intact": ct_ok, "signed": bool(sender),
            "signature_valid": sig_ok,
            "sender_trusted": (sender.get("fingerprint") in trusted) if (sender and trusted) else None,
            "files": header.get("manifest", [])}


def unseal(package: str, recipient_key_path: str, dest_dir: str,
           passphrase: Optional[str] = None,
           trusted_paths: Optional[list[str]] = None,
           allow_unsigned: bool = False) -> dict:
    """Open a package into dest_dir - all of it, verified, or nothing at all."""
    signing._need()
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    info = inspect(package, trusted_paths)
    if info["signed"] and not info["signature_valid"]:
        raise SealError("the sender's signature does not hold: the package was altered, "
                        "or was not sealed by the key it names")
    if not info["signed"] and not allow_unsigned:
        raise SealError("the package is not signed, so who sealed it cannot be checked "
                        "(open it anyway with --allow-unsigned)")
    if not info["ciphertext_intact"]:
        raise SealError("the package's contents do not match their recorded hash")
    header, hb, start, length, trailer = _read(package)
    for m in header.get("manifest", []):
        if not _safe_rel(m.get("path", "")):
            raise SealError(f"refusing a path outside the destination: {m.get('path')!r}")

    try:
        signer = signing.load_signer(recipient_key_path, passphrase)
    except signing.SigningError as exc:
        raise SealError(f"the recipient key did not open: {exc}") from None
    fp = signer.fingerprint
    if fp != header["recipient"]["fingerprint"]:
        raise SealError(f"this package was sealed for key {header['recipient']['key_id']}, "
                        f"not {signing.key_id(fp)}")
    try:
        key = signer._key.decrypt(_unb64(header["wrapped_key"]),
                                  padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                               algorithm=hashes.SHA256(), label=None))
    except ValueError:
        raise SealError("the package key could not be unwrapped with this private key") from None

    if os.path.isdir(dest_dir) and os.listdir(dest_dir):
        raise SealError(f"{dest_dir} is not empty - open a package into a new folder, "
                        "so nothing already there is overwritten or mixed in")
    os.makedirs(dest_dir, exist_ok=True)
    fd, plain_tar = tempfile.mkstemp(prefix=".unseal-", suffix=".tar", dir=dest_dir)
    try:
        dec = Cipher(algorithms.AES(key), modes.GCM(_unb64(header["nonce"]),
                                                    _unb64(trailer["tag"]))).decryptor()
        dec.authenticate_additional_data(hb)
        with os.fdopen(fd, "wb") as out, open(package, "rb") as fh:
            fh.seek(start)
            left = length
            while left:
                chunk = fh.read(min(CHUNK, left))
                if not chunk:
                    raise SealError("the package ends early")
                out.write(dec.update(chunk))
                left -= len(chunk)
            try:
                out.write(dec.finalize())
            except InvalidTag:
                raise SealError("the package failed authentication: some byte of it, or of "
                                "its header, was changed after sealing") from None
        want = {m["path"]: m for m in header["manifest"]}
        with tarfile.open(plain_tar, mode="r") as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            if sorted(names) != sorted(want) or not all(m.isfile() for m in members):
                raise SealError("the package's contents do not match its manifest")
            # Hash every member before writing any of them out.
            for m in members:
                h = hashlib.sha256()
                src = tar.extractfile(m)
                for chunk in iter(lambda: src.read(CHUNK), b""):
                    h.update(chunk)
                if h.hexdigest() != want[m.name]["sha256"]:
                    raise SealError(f"{m.name} does not match its recorded SHA-256")
            for m in members:
                target = os.path.join(dest_dir, *m.name.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tar.extractfile(m)
                with open(target, "wb") as fh:
                    for chunk in iter(lambda: src.read(CHUNK), b""):
                        fh.write(chunk)
    finally:
        if os.path.exists(plain_tar):
            os.remove(plain_tar)
    return {"dest": dest_dir, "files": header["manifest"], "info": info}

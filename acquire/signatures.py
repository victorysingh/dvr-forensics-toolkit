"""Signed case statements: what an examiner vouches for, and the check anyone can run.

A statement names the case, the device (model, serial, size), the acquisition
hashes and Merkle root, the custody ledger's length and head, and the SHA-256
of every pipeline output the case holds.  It is signed with the examiner's
key (core/signing.py) and kept in <case>/signatures/, and the signing is
itself an entry in the custody ledger.

What a valid signature proves, and what it does not:

* the statement is exactly what the key's holder signed, so every hash it
  lists is the one they vouched for, and any file changed since no longer
  matches;
* the custody ledger up to the signed head is the ledger they saw - a hash
  chain cannot be edited behind a signed head without breaking it;
* *whose* key it is, only if the verifier trusts that public key - a key
  carried inside a statement proves integrity, not identity.  So the check
  says plainly whether the key is one the verifier chose to trust, and names
  its fingerprint for them to compare against the examiner's own.

The ledger is pinned by its count and head, not hashed as a file: it keeps
growing (this signing adds an entry), and an entry appended later must not
look like tampering.  The report, likewise, is regenerated on purpose, so only
the newest statement's files are compared with the folder; older statements
are checked for what never changes - the acquisition, the ledger prefix and
their signature.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
from typing import Optional

from acquire.ledger import CustodyLedger
from core import signing
from core.contract import canonical_json, utc_now

RULE = "anokhidrishti-case-statement-v1"
SIG_DIR = "signatures"
ACTION = "case_signed"

#: Outputs a statement covers when the case has them.
COVERED = ["scan_report.json", "blockmap.jsonl", "regions.json", "codec_profile.json",
           "oem_coverage.json", "timeline.json", "report.json", "report.html",
           "carve/carve_report.json", "carve/extracted.json",
           "analytics/analytics.json", "preserved/manifest.json"]
COVERED_GLOBS = ["parse_*.json", "certificate_s63_*.json", "certificate_s63_*.html",
                 "*.jsonld"]


def _sha256(path: str) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def covered_files(case_dir: str) -> list[str]:
    found = [p for p in COVERED if os.path.isfile(os.path.join(case_dir, p))]
    for pattern in COVERED_GLOBS:
        for p in sorted(glob.glob(os.path.join(case_dir, pattern))):
            rel = os.path.relpath(p, case_dir).replace(os.sep, "/")
            if rel not in found:
                found.append(rel)
    return found


def _ledger(case_dir: str) -> CustodyLedger:
    return CustodyLedger(os.path.join(case_dir, "custody_ledger.jsonl"))


def build_statement(case_dir: str, signer: "signing.Signer") -> dict:
    """What the examiner is about to vouch for. SigningError if it is not signable."""
    report_path = os.path.join(case_dir, "scan_report.json")
    if not os.path.exists(report_path):
        raise signing.SigningError("no completed acquisition (scan_report.json) to sign")
    ledger = _ledger(case_dir)
    chain = ledger.verify()
    if not chain["valid"]:
        # Signing a broken chain would put a signature behind the breakage.
        raise signing.SigningError(f"the custody ledger does not verify: {chain['message']}")
    with open(report_path, "r", encoding="utf-8") as fh:
        scan = json.load(fh)
    dev, case = scan.get("device") or {}, scan.get("case") or {}
    files = []
    for rel in covered_files(case_dir):
        digest, size = _sha256(os.path.join(case_dir, rel))
        files.append({"path": rel, "sha256": digest, "bytes": size})
    return {
        "rule": RULE,
        "case_id": case.get("case_id", ""),
        "case_folder": os.path.basename(os.path.abspath(case_dir)),
        "signer": {"name": signer.name, "key_id": signer.key_id,
                   "fingerprint": signer.fingerprint},
        "signed_utc": utc_now(),
        "tool_version": scan.get("tool_version", ""),
        "device": {k: dev.get(k) for k in ("model", "serial", "size_bytes", "sector_size",
                                           "write_block_method")},
        "acquisition": {
            "hashes": [{k: h.get(k) for k in ("algorithm", "value", "scope", "length")}
                       for h in scan.get("hashes", [])],
            "merkle_root": scan.get("merkle_root", ""),
            "completed_utc": scan.get("generated_utc", ""),
        },
        "ledger": {"entries": len(ledger.entries), "head": ledger.head},
        "files": files,
    }


def sign_case(case_dir: str, signer: "signing.Signer", reason: str = "") -> dict:
    """Sign the case as it stands; record the signing in the custody ledger."""
    statement = build_statement(case_dir, signer)
    if reason:
        statement["reason"] = reason
    body = canonical_json(statement)
    record = {"statement": statement, "algorithm": signing.ALGORITHM,
              "public_key_pem": signer.public_pem, "signature": signer.sign(body)}
    os.makedirs(os.path.join(case_dir, SIG_DIR), exist_ok=True)
    n = len(glob.glob(os.path.join(case_dir, SIG_DIR, "*.json")))
    rel = f"{SIG_DIR}/{n:03d}_{signer.key_id}.json"
    path = os.path.join(case_dir, rel)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1, sort_keys=True)
    ledger = _ledger(case_dir)
    first = ledger.entries[0] if ledger.entries else {}
    ledger.actor = signer.name or first.get("actor", "unknown")
    ledger.case_id = first.get("case_id", statement["case_id"])
    ledger.append(ACTION, {"file": rel, "key_id": signer.key_id,
                           "fingerprint": signer.fingerprint, "signer": signer.name,
                           "algorithm": signing.ALGORITHM, "covers_files": len(statement["files"]),
                           "ledger_entries": statement["ledger"]["entries"],
                           "reason": reason},
                  data_hash=_sha256(path)[0])
    return {"file": rel, "path": path, "statement": statement}


def _check_one(case_dir: str, record: dict, ledger: CustodyLedger, scan: dict,
               trusted: dict[str, str], newest: bool) -> dict:
    st = record.get("statement") or {}
    signer = st.get("signer") or {}
    pem = record.get("public_key_pem", "")
    out = {"signer": signer.get("name", ""), "key_id": signer.get("key_id", ""),
           "fingerprint": signer.get("fingerprint", ""), "signed_utc": st.get("signed_utc", ""),
           "files_checked": 0, "changed": [], "missing": [], "problems": []}
    try:
        fp = signing.fingerprint(pem)
    except Exception:                                      # noqa: BLE001
        fp = ""
    sig_ok = bool(fp) and fp == signer.get("fingerprint") and signing.verify(
        pem, canonical_json(st), record.get("signature", ""))
    out["signature_valid"] = sig_ok
    if not sig_ok:
        out["problems"].append("the signature does not match the statement and its key")
    out["trusted"] = fp in trusted if trusted else None
    out["trusted_as"] = trusted.get(fp, "")

    want = st.get("ledger") or {}
    count, head = want.get("entries", 0), want.get("head", "")
    ledger_ok = len(ledger.entries) >= count and (
        count == 0 or ledger.entries[count - 1].get("entry_hash") == head)
    out["ledger_ok"] = ledger_ok
    if not ledger_ok:
        out["problems"].append(f"the custody ledger no longer has the signed head at entry {count}")

    acq = st.get("acquisition") or {}
    now = [{k: h.get(k) for k in ("algorithm", "value", "scope", "length")}
           for h in scan.get("hashes", [])]
    acq_ok = acq.get("hashes") == now and acq.get("merkle_root") == scan.get("merkle_root", "")
    out["acquisition_ok"] = acq_ok
    if not acq_ok:
        out["problems"].append("the acquisition hashes or Merkle root differ from what was signed")

    if newest:
        for f in st.get("files", []):
            p = os.path.join(case_dir, f["path"])
            if not os.path.isfile(p):
                out["missing"].append(f["path"])
                continue
            out["files_checked"] += 1
            if _sha256(p)[0] != f["sha256"]:
                out["changed"].append(f["path"])
        if out["changed"]:
            out["problems"].append("changed since signing: " + ", ".join(out["changed"]))
        if out["missing"]:
            out["problems"].append("missing since signing: " + ", ".join(out["missing"]))
        listed = {f["path"] for f in st.get("files", [])}
        # Not a failure: an output made after the newest signing is simply not
        # vouched for yet. Named, so the examiner knows to sign again.
        out["unsigned_newer"] = [f for f in covered_files(case_dir) if f not in listed]
    out["valid"] = not out["problems"]
    return out


def verify_case(case_dir: str, trusted_paths: Optional[list[str]] = None) -> dict:
    """Check every statement in the case. Works without a private key."""
    paths = sorted(glob.glob(os.path.join(case_dir, SIG_DIR, "*.json")))
    if not paths:
        return {"signed": False, "valid": True, "signatures": [],
                "message": "not signed (no examiner key was used on this case)"}
    if not signing.available():
        return {"signed": True, "valid": True, "checked": False, "signatures": [],
                "message": f"{len(paths)} signature(s) present; checking them needs the "
                           "optional 'cryptography' package"}
    trusted = signing.trusted_fingerprints(list(trusted_paths or []) + _default_trusted())
    ledger = _ledger(case_dir)
    try:
        with open(os.path.join(case_dir, "scan_report.json"), "r", encoding="utf-8") as fh:
            scan = json.load(fh)
    except (OSError, ValueError):
        scan = {}
    results = []
    for i, p in enumerate(paths):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, ValueError):
            results.append({"file": os.path.relpath(p, case_dir), "valid": False,
                             "problems": ["unreadable signature file"]})
            continue
        r = _check_one(case_dir, record, ledger, scan, trusted, newest=(i == len(paths) - 1))
        r["file"] = os.path.relpath(p, case_dir).replace(os.sep, "/")
        results.append(r)
    ok = all(r["valid"] for r in results)
    newest = results[-1]
    who = newest.get("signer") or "an unnamed key"
    message = (f"{len(results)} signature(s), all valid; newest by {who} "
               f"(key {newest.get('key_id', '?')}), covering {newest.get('files_checked', 0)} files"
               if ok else "SIGNATURE CHECK FAILED: " + "; ".join(
                   f"{r['file']}: {', '.join(r.get('problems', []))}" for r in results if not r["valid"]))
    return {"signed": True, "checked": True, "valid": ok, "signatures": results,
            "message": message}


def _default_trusted() -> list[str]:
    """Your own public key, and any in ~/.ps26150/trusted/."""
    own = signing.public_path(signing.key_path())
    extra = glob.glob(os.path.join(os.path.dirname(signing.key_path()), "trusted", "*.pem"))
    return ([own] if os.path.exists(own) else []) + extra

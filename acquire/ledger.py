"""Hash-chained chain-of-custody ledger.

Every action the tool takes against evidence is appended here as one line of
JSON whose hash commits to the hash of the line before it.  Change any past
entry - a timestamp, an operator name, a hash value - and every entry after
it fails verification, and the tool can name the exact sequence number where
the chain breaks.

This is the honest reading of the "Blockchain & Cybersecurity" theme: a
tamper-evident append-only log with a verifiable linkage, not a distributed
ledger bolted onto a forensics tool for the sake of the word.  It is the
same construction a blockchain uses for its block headers, applied where it
actually buys something - proving the custody record was not edited after
the fact.

Chain rule, stated so a third party can re-verify independently:

    entry_hash = SHA-256( canonical_json(entry without entry_hash) )
    entry.prev_hash = previous entry_hash, or 64 zeros for the genesis entry

Canonical JSON = UTF-8, sorted keys, no insignificant whitespace.

What the chain cannot catch on its own: cutting entries off the end (what
remains is still a valid chain), or writing a whole new ledger from scratch.
So every append also seals the ledger: an HMAC-SHA256 of the number of
entries and the last entry hash, keyed with a secret kept OUTSIDE the case
folder (`~/.ps26150/ledger_seal.key`, or the path in PS26150_SEAL_KEY). The
seal sits beside the ledger in `custody_ledger.seal.json`. Anyone can still
read the ledger and re-check the chain; only the key holder can re-seal, so
a shortened or rewritten ledger no longer matches its seal. Each machine
seals with its own key, so on a case passed between examiners every key's
seal vouches for the entries that existed when it last sealed.

    seal = HMAC-SHA256(key, "ps26150-ledger-seal-v1|<entries>|<last entry_hash>")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Optional

from core.contract import canonical_json, utc_now

GENESIS_PREV = "0" * 64
SEAL_RULE = "ps26150-ledger-seal-v1"
SEAL_KEY_ENV = "PS26150_SEAL_KEY"


def seal_key_path() -> str:
    """Where this machine's seal key lives: never inside a case folder."""
    return os.environ.get(SEAL_KEY_ENV) or os.path.join(
        os.path.expanduser("~"), ".ps26150", "ledger_seal.key")


def load_seal_key(create: bool = False) -> Optional[bytes]:
    """This machine's seal key; with `create`, made on first use (32 random
    bytes, readable by this user only). None when there is none and it cannot
    be made - the ledger then stays unsealed, and verify says so."""
    path = seal_key_path()
    try:
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    except OSError:
        return None
    if not create:
        return None
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        key = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key
    except FileExistsError:          # made by another process a moment ago
        return load_seal_key(create=False)
    except OSError:
        return None


def seal_key_id(key: bytes) -> str:
    """A name for a key that gives nothing of it away."""
    return hashlib.sha256(key).hexdigest()[:16]


def _seal_mac(key: bytes, count: int, head: str) -> str:
    return hmac.new(key, f"{SEAL_RULE}|{count}|{head}".encode(), hashlib.sha256).hexdigest()


class LedgerError(Exception):
    pass


class CustodyLedger:
    """Append-only JSONL ledger. Opened for append; entries are never edited."""

    def __init__(self, path: str, actor: str = "unknown", case_id: str = ""):
        self.path = path
        self.actor = actor
        self.case_id = case_id
        self.entries: list[dict] = []
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        if os.path.exists(path):
            self._load()

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    self.entries.append(json.loads(line))

    @property
    def head(self) -> str:
        return self.entries[-1]["entry_hash"] if self.entries else GENESIS_PREV

    @property
    def seq(self) -> int:
        return len(self.entries)

    def append(self, action: str, detail: Optional[dict[str, Any]] = None,
               data_hash: str = "") -> dict:
        entry = {
            "seq": self.seq,
            "ts_utc": utc_now(),
            "case_id": self.case_id,
            "actor": self.actor,
            "action": action,
            "detail": detail or {},
            "data_hash": data_hash,
            "prev_hash": self.head,
        }
        entry["entry_hash"] = hashlib.sha256(canonical_json(entry)).hexdigest()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False) + "\n")
        self.entries.append(entry)
        self._seal()
        return entry

    # -- the seal ------------------------------------------------------------
    @property
    def seal_path(self) -> str:
        return os.path.splitext(self.path)[0] + ".seal.json"

    def _read_seals(self) -> dict:
        try:
            with open(self.seal_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, ValueError):
            data = {}
        data.setdefault("rule", SEAL_RULE)
        data.setdefault("seals", {})
        return data

    def _seal(self) -> None:
        """Re-seal under this machine's key; other keys' seals are kept."""
        key = load_seal_key(create=True)
        if key is None:
            return
        data = self._read_seals()
        data["seals"][seal_key_id(key)] = {"count": self.seq, "head": self.head,
                                          "hmac": _seal_mac(key, self.seq, self.head)}
        tmp = self.seal_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.seal_path)

    def verify_seal(self) -> dict:
        """Check the seal made with this machine's key, if the case has one.

        valid False: the seal no longer matches - entries were cut off the end,
        the ledger was rewritten, or the seal file itself was edited.
        checked False: the case is unsealed, or sealed only with keys that are
        not on this machine; that is reported, not counted as a failure."""
        if not os.path.exists(self.seal_path):
            return {"sealed": False, "checked": False, "valid": True,
                    "message": "not sealed (written before sealing, or no key could be kept)"}
        seals = self._read_seals()["seals"]
        key = load_seal_key(create=False)
        kid = seal_key_id(key) if key else None
        mine = seals.get(kid) if kid else None
        others = sorted(k for k in seals if k != kid)
        if mine is None:
            return {"sealed": True, "checked": False, "valid": True, "keys": others,
                    "message": f"sealed with key {', '.join(others)}; not on this machine, "
                               "so the seal cannot be checked here"}

        def broken(reason: str) -> dict:
            return {"sealed": True, "checked": True, "valid": False, "key": kid,
                    "message": f"SEAL BROKEN (key {kid}): {reason}"}

        count, head = mine.get("count", -1), mine.get("head", "")
        if not hmac.compare_digest(str(mine.get("hmac", "")), _seal_mac(key, count, head)):
            return broken("the seal file was edited")
        if len(self.entries) < count:
            return broken(f"entries were removed - the seal covers {count}, "
                          f"the ledger holds {len(self.entries)}")
        if count and self.entries[count - 1].get("entry_hash") != head:
            return broken(f"the ledger was rewritten - entry {count - 1} is not the one sealed")
        later = len(self.entries) - count
        return {"sealed": True, "checked": True, "valid": True, "key": kid, "count": count,
                "message": f"seal intact (key {kid}): all {count} entries it covers are there, "
                           "unchanged" + (f"; {later} later entries are outside this key's seal"
                                          if later else "")}

    # -- verification ------------------------------------------------------
    def verify(self) -> dict:
        """Walk the chain. Returns a result a report can quote verbatim."""
        prev = GENESIS_PREV
        for i, entry in enumerate(self.entries):
            if entry.get("seq") != i:
                return self._fail(i, "sequence number out of order",
                                  expected=i, found=entry.get("seq"))
            if entry.get("prev_hash") != prev:
                return self._fail(i, "broken link to previous entry",
                                  expected=prev, found=entry.get("prev_hash"))
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            recomputed = hashlib.sha256(canonical_json(body)).hexdigest()
            if recomputed != entry.get("entry_hash"):
                return self._fail(i, "entry content was modified after writing",
                                  expected=recomputed, found=entry.get("entry_hash"))
            prev = entry["entry_hash"]
        return {"valid": True, "entries": len(self.entries), "head": self.head,
                "message": f"chain intact across {len(self.entries)} entries"}

    @staticmethod
    def _fail(index: int, reason: str, expected: Any = None,
              found: Any = None) -> dict:
        return {"valid": False, "broken_at_seq": index, "reason": reason,
                "expected": expected, "found": found,
                "message": f"CHAIN BROKEN at entry {index}: {reason}"}

    def to_markdown(self) -> str:
        """Custody table for the report annexure."""
        lines = ["| # | UTC | Actor | Action | Entry hash (first 16) |",
                 "|---|---|---|---|---|"]
        for e in self.entries:
            lines.append(f"| {e['seq']} | {e['ts_utc']} | {e['actor']} | "
                         f"{e['action']} | `{e['entry_hash'][:16]}` |")
        return "\n".join(lines)

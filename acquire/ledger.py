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
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional

from core.contract import canonical_json, utc_now

GENESIS_PREV = "0" * 64


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
        return entry

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

"""Streaming hashes and the block Merkle tree.

Design note - why a block map and not just one linear hash:

A single SHA-256 over a 2 TB drive proves the whole image is unchanged, but
it cannot survive an interrupted scan and it cannot tell you WHICH region
changed.  So every pass also hashes each fixed-size block independently and
builds a Merkle tree over those block hashes.  That gives us:

  * resumable acquisition (re-hash only the blocks we have not done)
  * a tamper proof for any single clip - an inclusion path, not a re-read
  * the honest "blockchain" content the theme asks for

The linear MD5/SHA-256 are still computed in the same pass, because that is
what every court report and every other forensic tool expects to compare.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

DEFAULT_BLOCK_SIZE = 8 * 1024 * 1024        # 8 MiB


class MultiHasher:
    """Feed bytes once, get MD5 + SHA-256 (+ SHA-1 for legacy tool interop)."""

    def __init__(self, algorithms: Iterable[str] = ("md5", "sha256")):
        self.algorithms = list(algorithms)
        self._h = {a: hashlib.new(a) for a in self.algorithms}
        self.length = 0

    def update(self, data: bytes) -> None:
        for h in self._h.values():
            h.update(data)
        self.length += len(data)

    def digests(self) -> dict[str, str]:
        return {a: h.hexdigest() for a, h in self._h.items()}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Merkle tree over block hashes.
#
# Convention (documented because it must be reproducible by a third party
# verifying our report):
#   * leaf   = SHA-256 of the raw block bytes   (NOT double hashed)
#   * node   = SHA-256( left_digest_bytes || right_digest_bytes )
#   * an odd node at any level is promoted unchanged to the next level
#     (it is NOT duplicated - duplication enables the CVE-2012-2459 style
#     collision, and promotion is simpler to explain in court)
# --------------------------------------------------------------------------
def merkle_root(leaf_hexes: list[str]) -> str:
    if not leaf_hexes:
        return ""
    level = [bytes.fromhex(h) for h in leaf_hexes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])          # promote, do not duplicate
        level = nxt
    return level[0].hex()


def merkle_proof(leaf_hexes: list[str], index: int) -> list[dict]:
    """Inclusion path for one block: lets anyone prove a carved clip belongs
    to the acquired drive without re-reading the drive."""
    if index < 0 or index >= len(leaf_hexes):
        raise IndexError(f"leaf index {index} out of range ({len(leaf_hexes)})")
    path: list[dict] = []
    level = [bytes.fromhex(h) for h in leaf_hexes]
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            if i == idx:
                path.append({"side": "right", "hash": level[i + 1].hex()})
            elif i + 1 == idx:
                path.append({"side": "left", "hash": level[i].hex()})
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])
            if idx == len(level) - 1:
                idx = len(nxt) - 1
                level = nxt
                continue
        idx //= 2
        level = nxt
    return path


def verify_merkle_proof(leaf_hex: str, path: list[dict], root_hex: str) -> bool:
    cur = bytes.fromhex(leaf_hex)
    for step in path:
        sib = bytes.fromhex(step["hash"])
        cur = (hashlib.sha256(sib + cur).digest() if step["side"] == "left"
               else hashlib.sha256(cur + sib).digest())
    return cur.hex() == root_hex

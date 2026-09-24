"""Preserve a drive's metadata without imaging the drive.

A DVR drive is 1-4 TB of video and a few megabytes of filesystem: superblock,
partition table, volume headers, cluster index.  Those megabytes are what
every later finding rests on, so they are kept byte-exact - but the video is
not, because nobody on an air-gapped workstation has the space to hold it.

WHY WHOLE BLOCKS
----------------
The acquisition scan records a SHA-256 for every fixed-size block of the
drive and a Merkle root over all of them.  If we saved only the exact bytes
of each structure, nobody could check them against that root without
re-reading the original.  So we save the WHOLE scan blocks that cover each
structure: each saved block hashes to its leaf in `blockmap.jsonl`, and a
short Merkle path ties that leaf to the root recorded at acquisition.  A
reviewer can verify every preserved byte from the bundle alone.

The exact structure bytes are saved too (`regions/`), for convenience - they
are slices of the verified blocks, and the manifest says which.

This module only reads.  It is handed an open read-only `BlockDevice`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from core.hashing import (DEFAULT_BLOCK_SIZE, merkle_proof, merkle_root,
                          sha256_bytes)

# For a vendor with no parser we still keep the ends of the disk: boot
# sectors, partition tables and most vendors' superblocks live at the start,
# and backup structures commonly live at the end.
GENERIC_HEAD = 1 << 20
GENERIC_TAIL = 1 << 20


@dataclass
class Region:
    name: str
    start: int
    end: int
    why: str


def dahua_regions(dev) -> tuple[list[Region], list[str]]:
    """Every DHFS structure we know of: everything that is not video."""
    from parsers.dahua import (PTABLE_BACKUP_OFFSET, REC_SIZE, VHDR_BACKUP_OFFSET,
                               VHDR_OFFSET, DahuaParser)

    p = DahuaParser()
    notes: list[str] = []
    if not p.detect(dev):
        return [], ["no DHFS superblock at offset 0"]
    regions = [Region("superblock_and_partition_tables", 0,
                      PTABLE_BACKUP_OFFSET + 0x400,
                      "DHFS superblock, partition table and its backup")]
    vols, pnotes = p.read_partitions(dev)
    notes += pnotes
    for v in vols:
        p.read_volume(dev, v)
        notes += v.notes
        h = v.header
        if not h:
            regions.append(Region(f"volume{v.number}_header", v.start + VHDR_OFFSET,
                                  v.start + VHDR_BACKUP_OFFSET + 512,
                                  "volume header (not decodable)"))
            continue
        table = v.start + h["index_start_sector"] * 512
        table_end = table + h["cluster_capacity"] * REC_SIZE
        # Everything from the volume start to the first data cluster is
        # structure.  If calibration found the data base, that is the end;
        # otherwise the end of the cluster table is the most we can defend.
        end = v.data_base if v.data_base else table_end
        regions.append(Region(f"volume{v.number}_metadata", v.start, max(end, table_end),
                              f"volume {v.number}: header, header backup and "
                              f"cluster table ({h['cluster_capacity']} records)"))
    return regions, notes


def generic_regions(dev) -> list[Region]:
    size = dev.size_bytes
    return [Region("disk_head", 0, min(GENERIC_HEAD, size),
                   "first 1 MiB: boot sectors, partition tables, superblocks"),
            Region("disk_tail", max(0, size - GENERIC_TAIL), size,
                   "last 1 MiB: backup structures")]


def load_blockmap(out_dir: str) -> list[dict]:
    path = os.path.join(out_dir, "blockmap.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def preserve(dev, bundle_dir: str, vendor: str = "",
             blockmap: Optional[list[dict]] = None,
             extra: Optional[list[Region]] = None) -> dict:
    """Save the blocks covering every metadata region, and a manifest.

    `blockmap` is the acquisition scan's block list.  With it, each saved
    block is checked against the hash recorded at acquisition and gets a
    Merkle inclusion proof; a mismatch is reported, never hidden.  Without
    it, blocks are still hashed but cannot be tied to an acquisition.
    """
    blockmap = blockmap or []
    bs = blockmap[0]["length"] if blockmap else DEFAULT_BLOCK_SIZE
    notes: list[str] = []
    if vendor == "Dahua":
        regions, notes = dahua_regions(dev)
        if not regions:
            regions = generic_regions(dev)
    else:
        regions = generic_regions(dev)
    regions += extra or []

    complete = bool(blockmap) and blockmap[-1]["offset"] + blockmap[-1]["length"] \
        >= dev.size_bytes
    leaves = [b["sha256"] for b in blockmap]
    root = merkle_root(leaves) if complete else ""
    if blockmap and not complete:
        notes.append("block map does not cover the whole drive - blocks are "
                     "checked against it but no Merkle proofs are issued")

    os.makedirs(os.path.join(bundle_dir, "blocks"), exist_ok=True)
    os.makedirs(os.path.join(bundle_dir, "regions"), exist_ok=True)
    blocks: dict[int, dict] = {}
    out_regions = []
    for r in regions:
        r.end = min(r.end, dev.size_bytes)
        if r.end <= r.start:
            notes.append(f"{r.name}: empty or beyond the drive - skipped")
            continue
        idxs = list(range(r.start // bs, (r.end - 1) // bs + 1))
        for i in idxs:
            if i in blocks:
                continue
            off = i * bs
            data = dev.read_at(off, min(bs, dev.size_bytes - off))
            digest = sha256_bytes(data)
            name = f"blocks/block_{i:08d}.bin"
            with open(os.path.join(bundle_dir, name), "wb") as fh:
                fh.write(data)
            entry = {"index": i, "offset": off, "length": len(data),
                     "sha256": digest, "file": name}
            if i < len(blockmap):
                recorded = blockmap[i]["sha256"]
                entry["matches_acquisition"] = recorded == digest
                if recorded != digest:
                    notes.append(f"block {i} at 0x{off:X}: hash differs from the "
                                 f"acquisition scan - the drive or the read changed")
                elif complete:
                    entry["merkle_path"] = merkle_proof(leaves, i)
            blocks[i] = entry
        data = dev.read_at(r.start, r.end - r.start)
        rname = f"regions/{r.name}.bin"
        with open(os.path.join(bundle_dir, rname), "wb") as fh:
            fh.write(data)
        out_regions.append({"name": r.name, "start": r.start, "end": r.end,
                            "length": r.end - r.start, "why": r.why,
                            "sha256": sha256_bytes(data), "file": rname,
                            "blocks": idxs})

    manifest = {
        "kind": "metadata_preservation",
        "vendor": vendor or "generic",
        "drive_size_bytes": dev.size_bytes,
        "block_size": bs,
        "acquisition_merkle_root": root,
        "blockmap_complete": complete,
        "regions": out_regions,
        "blocks": [blocks[i] for i in sorted(blocks)],
        "bytes_saved": sum(b["length"] for b in blocks.values()),
        "all_blocks_match": all(b.get("matches_acquisition", False)
                                for b in blocks.values()) if blockmap else None,
        "notes": notes,
    }
    path = os.path.join(bundle_dir, "manifest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def verify_bundle(bundle_dir: str) -> dict:
    """Re-check a preserved bundle from its own files alone.

    Every saved block must still hash to what the manifest recorded, and -
    where the acquisition covered the whole drive - its Merkle path must lead
    to the acquisition root.  Every region file must still match its hash.
    """
    from core.hashing import verify_merkle_proof

    with open(os.path.join(bundle_dir, "manifest.json"), "r", encoding="utf-8") as fh:
        m = json.load(fh)
    problems: list[str] = []
    proven = 0
    for b in m["blocks"]:
        with open(os.path.join(bundle_dir, b["file"]), "rb") as fh:
            digest = sha256_bytes(fh.read())
        if digest != b["sha256"]:
            problems.append(f"{b['file']}: content changed since preservation")
            continue
        if "merkle_path" in b:
            if verify_merkle_proof(digest, b["merkle_path"], m["acquisition_merkle_root"]):
                proven += 1
            else:
                problems.append(f"{b['file']}: Merkle path does not reach the "
                                f"acquisition root")
    for r in m["regions"]:
        with open(os.path.join(bundle_dir, r["file"]), "rb") as fh:
            if sha256_bytes(fh.read()) != r["sha256"]:
                problems.append(f"{r['file']}: content changed since preservation")
    return {"ok": not problems, "blocks": len(m["blocks"]),
            "proven_to_root": proven, "regions": len(m["regions"]),
            "problems": problems}

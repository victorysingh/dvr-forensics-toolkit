"""Hikvision HIKBTREE index records, read off real media.

What the team's second drive showed (Seagate ST1000VX005 s/n Z9C2632A): a
Dahua-family recorder had reformatted it, overwriting the start of the disk
- including Hikvision's primary master sector - but two HIKBTREE copies near
the end of the disk survived, and with them the recording index.

OBSERVED LAYOUT (one real drive - `spec_only`)
----------------------------------------------
* HIKBTREE header: "HIKBTREE" then "HIK.2010.11.09"; followed by pointers to
  its pages. A master sector copy ("HIKVISION@HANGZHOU", "HIK.2011.03.08")
  sits just before the data area.
* Leaf records, 48 bytes:
      +0x00  8 x FF
      +0x11  u8   channel (1..N; 255 = a block reserved when the disk was
                  initialised - not a camera, and not always empty)
      +0x18  u32  start time  } seconds since 1970 on the RECORDER'S clock -
      +0x1C  u32  end time    } they equal the "HK" stream-map times of the
                                footage, so they are local time, zone unknown
      +0x20  u64  byte offset of the 1 GiB data block the segment is in
* Data blocks: 1 GiB each from a base; every record's offset lands exactly on
  base + N GiB (the base is found as the common residue, not assumed).

WHY THE LABELS CAN BE TRUSTED - AND WHERE THEY STOP
---------------------------------------------------
A carved stream is given a channel only when its data block has a record
AND the stream's own recorder times (from its "HK" descriptors) lie inside
that record's window. On the real drive this held for 2,021 of 2,516
streams, and the result is independently consistent: each channel keeps a
single resolution, and all eight hold ~760-790 h. A block reused by a newer
recording no longer describes older footage still in it - that footage is
"outside_index", exactly as for Dahua.
"""

from __future__ import annotations

import struct
from collections import Counter, defaultdict
from typing import Optional

HIKBTREE = b"HIKBTREE"
RECORD = 48
BLOCK = 1 << 30
UNUSED_CHANNEL = 255
TIME_LO, TIME_HI = 946_684_800, 2_147_483_647     # 2000-01-01 .. 2038
SLACK_S = 60
RULE = "hikvision.hikbtree.records.v1"


def find_records(buf: bytes, base_offset: int, disk_size: int) -> list[dict]:
    """Every 48-byte record in `buf` with the observed shape. Accepted only
    if its times are plausible and ordered, and its block offset is inside
    the disk. Residue (the data-area base) is checked by the caller."""
    out = []
    for r in range(0, len(buf) - RECORD + 1, 8):
        if buf[r:r + 8] != b"\xff" * 8:
            continue
        start, end = struct.unpack_from("<II", buf, r + 0x18)
        off = struct.unpack_from("<Q", buf, r + 0x20)[0]
        if not (TIME_LO <= start <= end <= TIME_HI) or not (0 < off < disk_size):
            continue
        out.append({"channel": buf[r + 0x11], "start": start, "end": end,
                    "block_offset": off, "at": base_offset + r})
    return out


def read_index(dev, header_offsets: list[int], window: int = 4 << 20) -> dict:
    """Read the region around each HIKBTREE header and return the index:
    de-duplicated records (the copies are identical), the data-area base,
    and a verdict on whether the records agree with a 1 GiB block grid."""
    raw: list[dict] = []
    for h in sorted(set(header_offsets)):
        start = max(0, h - 0x10000)
        raw += find_records(dev.read_at(start, window), start, dev.size_bytes)
    # overlapping read windows find the same physical record more than once
    raw = list({r["at"]: r for r in raw}.values())
    if not raw:
        return {"records": [], "base": None, "notes": ["no HIKBTREE records found"]}
    residue, votes = Counter(r["block_offset"] % BLOCK for r in raw).most_common(1)[0]
    on_grid = [r for r in raw if r["block_offset"] % BLOCK == residue]
    seen: dict[tuple, dict] = {}
    for r in on_grid:
        key = (r["channel"], r["start"], r["end"], r["block_offset"])
        if key in seen:
            seen[key]["copies"] += 1
        else:
            seen[key] = dict(r, copies=1, block=(r["block_offset"] - residue) // BLOCK)
    recs = sorted(seen.values(), key=lambda r: (r["block"], r["start"]))
    return {"rule": RULE, "records": recs, "base": residue,
            "block_bytes": BLOCK, "records_on_grid": len(on_grid),
            "records_off_grid": len(raw) - len(on_grid),
            "channels": dict(sorted(Counter(r["channel"] for r in recs).items())),
            "notes": [f"{len(raw) - len(on_grid)} candidate records off the 1 GiB grid "
                      f"were discarded"] if len(raw) != len(on_grid) else []}


def label_streams(index: dict, ps_rows: list[dict]) -> list[dict]:
    """Channel for each carved PS stream: its data block's record whose
    window contains the stream's own recorder times - else outside_index."""
    from datetime import datetime, timezone
    base = index.get("base")
    by_block: dict[int, list[dict]] = defaultdict(list)
    for r in index.get("records", []):
        if r["channel"] != UNUSED_CHANNEL:
            by_block[r["block"]].append(r)

    def secs(s: Optional[str]) -> Optional[float]:
        if not s:
            return None
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()

    out = []
    for row in ps_rows:
        a, z = secs(row.get("time_first_local")), secs(row.get("time_last_local"))
        block = (row["offset"] - base) // BLOCK if base is not None and row["offset"] >= base else None
        hit = None
        if a is not None and z is not None and block is not None:
            hit = next((r for r in by_block.get(block, [])
                        if r["start"] - SLACK_S <= a and z <= r["end"] + SLACK_S), None)
        out.append({"id": row["id"], "block": block,
                    "label": f"CH{hit['channel']:02d}" if hit else "outside_index",
                    "record_at": hit["at"] if hit else None})
    return out

"""Hikvision proprietary filesystem: the master sector and the HIKBTREE index.

A Hikvision recorder puts no conventional filesystem on the disk.  A master
sector describes the volume - where the system log is, where the data area
starts, how big its blocks are, where the two copies of the HIKBTREE index
lie - and the index maps each recording segment (camera, start, end) to the
data block that holds it.  This module reads both and turns the index into
`Recording` objects per the frozen contract.

WHERE THE LAYOUT COMES FROM
---------------------------
  * The magic `HIKVISION@HANGZHOU`, a master sector at 0x200 and a HIKBTREE
    index are published (Han, Jeong & Lee 2015).  SOURCE_PUBLISHED.
  * Every field offset used here was read off real media: the team's drive 2
    (ST1000VX005 s/n Z9C2632A), whose master sector survived as a backup copy
    and whose two HIKBTREE copies survived near the end of the disk.  The
    master's fields are read by `parsers/hiklog.py` and checked against each
    other and against the disk; the 48-byte leaf records by
    `parsers/hikbtree.py`.  SOURCE_OBSERVED.
  * The first version of this file decoded a layout invented for our own test
    fixture (the magic at 0x200 itself, capacity at 0x20, 24-byte index
    entries, the index searched for only in the first 16 MiB).  On a real disk
    it would have found the magic 0x10 further on, read garbage, and missed
    the index at the end of the disk.  Replaced on 28 Sep 2026.

WHAT A RECORDING IS HERE
------------------------
One index record: a camera, a start and an end on the recorder's clock, and
the data block its footage is in (the master's block size - 1 GiB on the real
drive).  The index does not say where inside the block the segment's bytes
lie, so a Recording's extent is the whole block; the exact streams, their
codec and their frames come from carving the block (`carve-ps`, then
`label-ps`, which matches each stream's own times to these records).  Index
times are recorder-local - on the real drive they equal the footage's `HK`
times - with the zone unknown, so they are reported as such and not converted.

Status `spec_only`: every field observed on one real drive.  The whole parse
has not yet been run on an intact Hikvision disk - drive 2's primary master
had been overwritten by a reformat.  Only a byte-match against the recorder's
own export reaches `validated`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from core.contract import STATE_ACTIVE, Provenance, Recording, TimestampClaim
from core.hashing import sha256_bytes
from parsers import hikbtree, hiklog
from parsers.base import (
    SOURCE_OBSERVED,
    SOURCE_PUBLISHED,
    FieldSpec,
    ParseResult,
    VendorParser,
    register,
    weakest_source,
)

VENDOR = "Hikvision"
MASTER_MAGIC = hiklog.MASTER_MAGIC
MAGIC_AT = hiklog.MAGIC_AT                      # the magic sits 0x10 into the sector
MASTER_EXPECTED_OFFSET = hiklog.PRIMARY_MASTER
BTREE_MAGIC = hikbtree.HIKBTREE
QUICK_SEARCH = 1 << 20                          # detection: the first 1 MiB
BTREE_FALLBACK_SEARCH = 16 << 20                # when the master's pointers are unusable
# A block size outside this range is not believed: the index would then be
# read on a grid the master does not really describe.
MIN_BLOCK, MAX_BLOCK = 64 << 10, 4 << 30
HASH_UP_TO = 8 << 20                            # hash an extent only when it is read whole

_CITE_PUB = "Han, Jeong & Lee 2015 (ICDF2C); published Hikvision FS write-ups"
_CITE_OBS = ("observed: drive ST1000VX005 s/n Z9C2632A - backup master sector at "
             "0x4C56000, two HIKBTREE copies near the end of the disk")

MASTER_FIELDS = [FieldSpec("magic", MAGIC_AT, "magic", "HIKVISION@HANGZHOU, 0x10 into the sector",
                           SOURCE_PUBLISHED, _CITE_PUB)] + [
    FieldSpec(name, off, fmt, name.replace("_", " "), SOURCE_OBSERVED, _CITE_OBS)
    for name, off, fmt in hiklog.MASTER_FIELDS]

BTREE_FIELDS = [
    FieldSpec("magic", 0x00, "magic", "HIKBTREE index header", SOURCE_PUBLISHED, _CITE_PUB),
    FieldSpec("record.marker", 0x00, "magic", "8 x FF opens each 48-byte leaf record",
              SOURCE_OBSERVED, _CITE_OBS),
    FieldSpec("record.channel", 0x11, "<B", "camera, 1..N; 255 = reserved at initialisation",
              SOURCE_OBSERVED, _CITE_OBS),
    FieldSpec("record.start", 0x18, "<I", "segment start, seconds since 1970, recorder clock",
              SOURCE_OBSERVED, _CITE_OBS),
    FieldSpec("record.end", 0x1C, "<I", "segment end, seconds since 1970, recorder clock",
              SOURCE_OBSERVED, _CITE_OBS),
    FieldSpec("record.block_offset", 0x20, "<Q", "byte offset of the data block",
              SOURCE_OBSERVED, _CITE_OBS),
]


def _local_time(t: int) -> Optional[str]:
    """A recorder-clock second as 'YYYY-MM-DD HH:MM:SS', or None for a value
    that is no plausible time (0 must never become 1970 presented as fact)."""
    if not hikbtree.TIME_LO <= t <= hikbtree.TIME_HI:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _find(dev, pattern: bytes, limit: int, start: int = 0, chunk: int = 1 << 20) -> int:
    """First offset of `pattern` in [start, start + limit), or -1.  Chunks
    overlap so a pattern straddling two reads is still found."""
    end = min(start + limit, getattr(dev, "size_bytes", 0) or start + limit)
    off, overlap = start, len(pattern) - 1
    while off < end:
        try:
            data = dev.read_at(off, min(chunk, end - off) + overlap)
        except Exception:                                # noqa: BLE001
            return -1
        if not data:
            return -1
        pos = data.find(pattern)
        if pos != -1:
            return off + pos
        off += chunk
    return -1


@register
class HikvisionParser(VendorParser):
    """The master sector and the HIKBTREE index, as observed on real media."""

    vendor = VENDOR
    parser_rule = "hikvision.master+hikbtree.observed.v2"

    # -- detection ---------------------------------------------------------
    def detect(self, dev, hint_offsets: Optional[list[int]] = None) -> bool:
        for off in hint_offsets or []:
            try:
                if dev.read_at(off, len(MASTER_MAGIC)) == MASTER_MAGIC:
                    return True
            except Exception:                            # noqa: BLE001
                continue
        return self.find_master(dev) != -1

    def find_master(self, dev) -> int:
        """Start of the master sector (its magic is 0x10 in), or -1.  The
        primary at 0x200 first, then the first 1 MiB; `parse` goes on to the
        backup copies further in."""
        try:
            if dev.read_at(MASTER_EXPECTED_OFFSET + MAGIC_AT,
                           len(MASTER_MAGIC)) == MASTER_MAGIC:
                return MASTER_EXPECTED_OFFSET
        except Exception:                                # noqa: BLE001
            pass
        at = _find(dev, MASTER_MAGIC, QUICK_SEARCH)
        return at - MAGIC_AT if at >= MAGIC_AT else -1

    # -- full parse --------------------------------------------------------
    def parse(self, dev, hint_offsets: Optional[list[int]] = None) -> ParseResult:
        result = ParseResult(vendor=VENDOR, parser_rule=self.parser_rule)
        result.field_provenance = [
            {"struct": struct_name, "field": f.name, "offset": f.offset, "source": f.source,
             "implies_status": f.status, "citation": f.citation}
            for struct_name, fields in (("master_sector", MASTER_FIELDS),
                                        ("hikbtree", BTREE_FIELDS))
            for f in fields]
        size = getattr(dev, "size_bytes", 0)

        starts = [off - MAGIC_AT for off in hint_offsets or []
                  if off >= MAGIC_AT and hiklog._read(dev, off, len(MASTER_MAGIC)) == MASTER_MAGIC]
        if not starts:
            first = self.find_master(dev)
            starts = [first] if first != -1 else hiklog.find_masters(dev)
        if not starts:
            result.errors.append(
                "no HIKVISION@HANGZHOU master sector in the first 256 MiB - not a "
                "Hikvision volume, or the volume does not start at the image origin")
            return result

        # Every copy is read; the first whose fields agree with each other is used.
        copies = [(m, hiklog.check_master(dev, m))
                  for m in (hiklog.read_master(dev, s) for s in sorted(set(starts)))]
        sound = [c for c in copies if all(x["ok"] is not False for x in c[1][:4])]
        master, checks = (sound or copies)[0]
        if not sound:
            result.notes.append(
                f"no master copy's fields agree with each other ({len(copies)} read) - the "
                "offsets may differ on this firmware; the index is looked for anyway")

        block = master["block_size"]
        if not MIN_BLOCK <= block <= MAX_BLOCK:
            result.notes.append(f"master block size {block} is implausible - the index is "
                                f"read on the 1 GiB grid observed on the real drive")
            block = hikbtree.BLOCK

        heads = [master[f"{k}_offset"] for k in ("hikbtree1", "hikbtree2")
                 if 0 < master[f"{k}_offset"] < size]
        if not heads:
            found = _find(dev, BTREE_MAGIC, BTREE_FALLBACK_SEARCH)
            if found != -1:
                heads = [found]
                result.notes.append(f"HIKBTREE found by search at 0x{found:X}, not where "
                                    "the master sector points")
        index = (hikbtree.read_index(dev, heads, block=block) if heads
                 else {"records": [], "base": None, "notes": []})
        result.notes.extend(index.get("notes", []))
        if index["base"] is not None:
            checks = checks + [{
                "check": "the index's data base = the master's data offset",
                "ok": index["base"] == master["data_offset"] % block}]

        records = [r for r in index["records"] if r["channel"] != hikbtree.UNUSED_CHANNEL]
        if not records:
            result.notes.append(
                "master sector present but no HIKBTREE records read - the index may be "
                "damaged or beyond this image; recordings cannot be listed from it, so the "
                "carver (carve-ps) is the remaining route")
        reserved = len(index["records"]) - len(records)
        for k, r in enumerate(records):
            result.recordings.append(self._to_recording(dev, k, r, block))
        result.indexed_extents = sorted({(r["block_offset"], block) for r in records})

        agree = sum(1 for c in checks if c["ok"])
        result.volume = {
            "vendor": VENDOR, "master": master,
            "master_copies": [m["offset"] for m, _ in copies],
            "master_checks": checks, "block_size": block, "btree_headers": heads,
            "index": {k: index.get(k) for k in ("base", "records_on_grid", "records_off_grid",
                                                 "channels")},
            "index_records": len(index["records"]), "reserved_records": reserved,
            "summary": [
                ("master", f"0x{master['offset']:X}  {master['fs_version'] or '(no version)'}"
                           f"  - copies at " + ", ".join(f"0x{m['offset']:X}" for m, _ in copies)),
                ("initialised", f"{_local_time(master['init_time']) or 'unreadable'} "
                                "(recorder clock)"),
                ("checks", f"{agree} of {len(checks)} agree"
                           + "".join(f"; {c['check']}: "
                                     + {True: "yes", False: "NO", None: "beyond image"}[c["ok"]]
                                     for c in checks if c["ok"] is not True)),
                ("data area", f"0x{master['data_offset']:X}, {master['block_count']} blocks of "
                              f"{block:,} bytes"),
                ("index", (f"{len(index['records'])} records at " +
                           ", ".join(f"0x{h:X}" for h in heads) +
                           f"; {reserved} reserved (channel 255); cameras "
                           + ", ".join(f"CH{c:02d}" for c in sorted(index.get("channels") or {})
                                       if c != hikbtree.UNUSED_CHANNEL))
                          if heads else "not found"),
                ("times", "recorder-local, zone unknown - not converted to UTC"),
            ],
        }
        result.validation_status = weakest_source(
            [f.source for f in MASTER_FIELDS] + [f.source for f in BTREE_FIELDS])
        result.notes.append(
            f"status {result.validation_status}: every field read off one real drive; "
            "only a byte-match against the recorder's own export justifies 'validated'.")
        return result

    # -- one recording -----------------------------------------------------
    def _to_recording(self, dev, k: int, r: dict, block: int) -> Recording:
        size = getattr(dev, "size_bytes", 0)
        off = r["block_offset"]
        in_image = bool(size) and off + block <= size

        def claim(value: int, field: str) -> TimestampClaim:
            local = _local_time(value)
            return TimestampClaim(
                source="index", raw_value=f"{value} = {local} recorder-local",
                decoded_utc=None, tz_offset_min=None,
                confidence=0.3 if local else 0.0,
                decode_rule=f"HIKBTREE leaf record {field} u32: seconds since 1970 on the "
                            "recorder's clock; zone unknown, not converted")

        sha = ""
        if in_image and block <= HASH_UP_TO:
            data = dev.read_at(off, block)
            sha = sha256_bytes(data) if len(data) == block else ""
        # The record is on the block grid and has plausible, ordered times;
        # a second identical copy of the index adds to that.  A block beyond
        # this image is known from the index only.
        confidence = 0.5 + (0.1 if r.get("copies", 1) > 1 else 0.0) - (0.0 if in_image else 0.2)
        sector = getattr(dev, "sector_size", 512) or 512
        return Recording(
            id=f"hik-b{r['block']:05d}-{k:05d}",
            camera_id=f"CH{r['channel']:02d}",
            state=STATE_ACTIVE,
            codec="",
            offset=off,
            length=block,
            start_utc=None,
            end_utc=None,
            duration_s=float(r["end"] - r["start"]),
            confidence=round(confidence, 4),
            frame_count=0,
            timestamps=[claim(r["start"], "+0x18"), claim(r["end"], "+0x1C")],
            provenance=Provenance(
                disk_offset=off, length=block,
                sector_start=off // sector,
                sector_end=(off + block + sector - 1) // sector,
                parser_rule=self.parser_rule, sha256=sha),
        )

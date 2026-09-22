# The frozen data contract

`core/contract.py` · `SCHEMA_VERSION = "1.0.0"` · frozen **2026-09-22**

Six people build against these shapes in parallel, against mock data, before
the real parsers exist. That only works while the shapes hold still.

- **Additive** change (new optional field) → bump the minor version.
- **Breaking** change (remove or retype a field) → raise it at the Saturday
  integration sync *before* committing. Someone else is already building
  against the old shape.

---

## Why canonical JSON matters

```python
canonical_json(obj)   # UTF-8, sorted keys, separators=(",", ":")
```

The custody ledger hashes these exact bytes. If key order or whitespace
differed between two machines, the same entry would hash differently and the
chain would appear broken on one machine and intact on the other. Always use
`canonical_json` for anything that gets hashed; `dump_json` (indented, for
humans) is for report artifacts only.

## Timestamps

`utc_now()` is the single source of truth: always UTC, always ISO-8601 with a
`Z` suffix and millisecond precision. Never write a local-time string into any
contract object. The whole point of the timeline stage is that a DVR's clock
lies — so our own timestamps must be beyond question.

---

## The objects

| Object | Purpose |
|---|---|
| `CaseInfo` | case id, investigator, organization |
| `DeviceInfo` | what was read; records **how** write-blocking was achieved |
| `HashRecord` | one hash, with its scope (`full_device` / `region` / `artifact`) |
| `BadRegion` | unreadable sectors — reported, never silently skipped |
| `Partition` | MBR/GPT entry, with a confidence |
| `SignatureHit` | one magic match at one absolute offset |
| `VendorDetection` | scored conclusion about an OEM, with its evidence |
| `Provenance` | disk offset, sector range, parser rule, hash — on every artifact |
| `TimestampClaim` | a time assertion from **one** source, never trusted alone |
| `Frame` | one NAL unit: offset, length, type, keyframe flag |
| `Recording` | a clip: state, codec, extent, timestamps, provenance |
| `ScanStats` | throughput, bad sectors, and `complete_pass` |
| `ScanReport` | top-level artifact of the acquire + detect stage |

## The fields that carry the project's principles

**`DeviceInfo.write_block_method`** — a string, not just a boolean. On Linux
with `blockdev --setro` it is the kernel flag; on Windows it is
`software:read-only-handle`. A forensic report that says "write-blocked" without
saying *how* is a misstatement waiting to be found by a defence expert.

**`VendorDetection.validation_status`** — `validated` / `spec_only` /
`detected_not_parsed` / `synthetic_only`, set by the **weakest** evidence
supporting that vendor (`detect/engine.py::_weakest`). Also
`parser_available: bool`, so detection can never be mistaken for parsing.

**`ScanStats.complete_pass`** — false for a triage scan (`--max-mb`) or a
resumed one. When it is false, the linear MD5/SHA-256 cover only the bytes
actually read in that run, and **must not be quoted as the drive hash**.

**`TimestampClaim.source`** — `container` / `index` / `osd_ocr` / `fs_meta`.
The clock-lie detector works by comparing claims from *different* sources
against each other. A single claim is never a conclusion, which is why the
source and the `decode_rule` are mandatory rather than informational.

**`Recording.confidence`** and **`Recording.state`** (`active` / `deleted` /
`fragment` / `overwritten`) — a carved clip stitched from fragments is a
probabilistic result. Say so numerically. Never emit certainty we do not have.

**`Provenance`** — attach it to every artifact. `disk_offset`, `sector_start`,
`sector_end`, `parser_rule`, `sha256`. This is what lets the UI jump from a
recovered clip straight to the hex, and what lets an investigator answer "where
exactly did this come from?" in court without re-deriving it.

---

## Output layout

A scan writes to `out/<case-id>/`:

| File | Contents |
|---|---|
| `scan_report.json` | the `ScanReport` — the primary artifact |
| `blockmap.jsonl` | one line per block: offset, SHA-256, codec counts, entropy |
| `custody_ledger.jsonl` | the hash-chained custody log |
| `codec_profile.json` | aggregate H.264/H.265 statistics |
| `oem_coverage.json` | explicit per-OEM position for every vendor the PS names |
| `scan_state.json` | resume state; refuses to resume onto a different device |

`blockmap.jsonl` doubles as the Merkle leaf list — the root recomputes from it
alone, which is what `cli.py verify` does.

`oem_coverage.json` exists to answer the question a judge or an investigator
actually asks: *what did you test?* It lists every OEM named in the PS, whether
it was detected on this disk, at what confidence, and whether a parser exists —
including the ones that were not found.

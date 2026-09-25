# DVR/NVR forensic image

PS26150 deliverable: *DVR/NVR forensic image*. What was imaged, what was
not, why, and how anyone can verify what we hold against the original drive.

---

## 1. The evidence item

| | |
|---|---|
| Source | CP Plus DVR |
| Drive | Seagate SkyHawk ST1000VX013, 1,000,204,884,992 bytes (931.5 GiB), 512-byte sectors |
| Serial | `WWD4A3NX` |
| Filesystem | Dahua DHFS 4.1, four volumes of ~250 GB |
| Custody | original drive retained sealed; every action on it is in `out/cpplus_WWD4A3NX/custody_ledger.jsonl` |

## 2. What exists, and why not a full image

A full raw image needs 931.5 GiB of free space; the workstation has 669 GB.
So, as `docs/SOP_EXAMINATION.md` §4.4 allows when documented, the image
deliverable is made of four parts that together let any byte of the drive
be verified without a second copy of it:

| Part | Size | What it proves |
|---|---|---|
| **Whole-drive hashes** — MD5 and SHA-256 over all 1,000,204,884,992 bytes, one continuous pass | two values | the identity of the drive's entire content, comparable with any other tool's hash |
| **Block map** — SHA-256 of every 8 MiB block, and a Merkle root over them | ~30 MB | that any 8 MiB block anyone reads later is exactly what was acquired |
| **Head image** — the first 20 GiB as a raw `.dd` | 20 GiB | a physical image of the region holding the superblock, partition tables, volume 1's header and index, and 20 GiB of footage |
| **Preserved metadata** — every filesystem structure on all four volumes, as whole scan blocks | 72 MB | the index and headers byte-exact, each block tied to the Merkle root by an inclusion proof |

The original drive stays sealed as the master copy. When disk space
allows, a full raw image can be made and checked against the whole-drive
SHA-256 in §3.

## 3. Hashes

**Whole drive** — acquisition attempt 4, 24 Sep 19:15 UTC to 25 Sep 06:34 UTC,
one complete pass over all 1,000,204,884,992 bytes:

| Algorithm | Value |
|---|---|
| MD5 | `f163d3517be26ca2a62a7fb2889364c2` |
| SHA-256 | `78eb8a4ac306691cacc1b3f0da911ded8edf1b9f9bf0819f483d95f467f8d909` |
| Block Merkle root (119,234 blocks of 8 MiB) | `8817ab49849140a66d941220515c60525154feb2b1d5735ca8621122bba9f4ae` |

**Preserved metadata** — superblock and partition tables, and each of the
four volumes' header, header backup and cluster table: 9 scan blocks, 72 MB,
every one matching its acquisition hash; manifest SHA-256
`ca73ae5b6e9deda656fc198a7f41a1a776f949863781a43a7a0f2e55d5e4f73e`.

**Head image**, `skyhawk_WWD4A3NX_first20GiB.dd`, bytes 0 – 21,474,836,479:

| Algorithm | Value |
|---|---|
| MD5 | `b1a7a6cfa8fc546e0bf4d21aa9a7d0bc` |
| SHA-256 | `c4098d59cff3973de9d281ba5613005ba52165743c36edfcf56f61aad8f4e610` |
| Merkle root over its 2,560 blocks | `51c9aa59404e17c2e986b94b86916154a1e0f77d28f1967e99d10c26ed77e014` |

The head image was made on 23 Sep 2026. Its 2,560 block hashes are
identical to the first 2,560 blocks of the independent full-drive pass
(`docs/VALIDATION_REPORT.md` §5), so it is verified against the drive
itself, not only against its own hash.

## 4. How to verify

```bash
# the head image against its recorded hash
sha256sum skyhawk_WWD4A3NX_first20GiB.dd

# the case: custody chain intact, Merkle root recomputes, preserved blocks match
python cli.py verify --out out/cpplus_WWD4A3NX

# any byte of the drive: the block that holds it, and its path to the root
python cli.py prove --out out/cpplus_WWD4A3NX --offset 4462075904

# against the original drive, later, with any tool
dd if=/dev/sdX bs=8M skip=N count=1 | sha256sum      # must equal blockmap line N
```

## 5. Acquisition record

| | |
|---|---|
| Tool | `dvr-forensics-toolkit`, `cli.py scan --carve`, stdlib-only core |
| Write block | software: kernel read-only flag verified before open, re-applied on every re-enumeration by a udev rule keyed on the drive serial; process opens read-only. No hardware blocker |
| Interface | USB 2.0 SATA bridge `14cd:6116`, ~24 MB/s |
| Duration | 11 h 19 min (40,741 s, 23.4 MB/s average, including the pause below) |
| Interruptions | one: the host disabled the USB port at 137.7 GB (02:23 IST); after a manual power-cycle and replug the drive returned write-blocked, blocks 0, 17620 and 17621 re-read identically, and the same hashes continued from the first unhashed byte (02:44 IST) |
| Unreadable sectors | none |
| Earlier attempts | three abandoned passes kept with their reasons (`out/cpplus_WWD4A3NX_attempt*`); their hashes are not quoted |

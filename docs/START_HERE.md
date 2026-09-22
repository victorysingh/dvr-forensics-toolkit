# START HERE

**Read this file completely before running anything or writing any code.**

You are working on **SIH 2026 Problem Statement 26150** — a multi-vendor
DVR/NVR forensic analysis tool for the National Technical Research
Organisation (NTRO). Theme: Blockchain & Cybersecurity.

This branch (`setup`) is a handoff. The acquisition and detection engine is
built and tested; the vendor parsers and the carver are not. Your job starts
where this document says it does.

---

## 1. The four rules that override everything else

### Rule 1 — Never write to the evidence drive

There is no write path in `acquire/device.py`. Do not add one. Do not add a
"repair" mode, a "mount" helper, or anything that opens a device for writing,
even behind a flag or a confirmation prompt.

A single byte written to the drive destroys two things at once: the deleted
footage we are trying to carve (the free space it lives in gets reused), and
the legal admissibility of everything else on the disk. There is no undo.

### Rule 2 — Write-block before the device node is touched

On Linux the kernel gives us a real read-only flag. Use it:

```bash
sudo blockdev --setro /dev/sdX
blockdev --getro /dev/sdX        # MUST print 1 before you go further
```

This resets when the device is unplugged and replugged. Re-apply every time.
See `docs/LINUX_ACQUISITION.md` for the full procedure, including the
auto-mount hazard, which is the realistic way this goes wrong on a desktop
Linux install.

### Rule 3 — Never claim support we have not demonstrated

Every vendor claim carries a status, and **the weakest piece of evidence sets
it**:

| status | means |
|---|---|
| `validated` | confirmed against real media we possess |
| `spec_only` | written from published research, never run on real media |
| `detected_not_parsed` | recognised on the platter, no parser exists |
| `synthetic_only` | only ever tested against our generated fixture |

The trap in this problem statement is claiming eight OEMs with no way to
validate any of them. We claim breadth through *detection plus a plugin SDK*
and depth only where we hold media. If you implement a Hikvision parser from
a paper, it is `spec_only` until it reads a real Hikvision disk — no matter
how well it passes tests against our synthetic fixture.

This is enforced in code (`detect/engine.py::_weakest`), not just in prose.
Do not weaken it to make a demo look better.

### Rule 4 — Confidence scores, never yes/no

CP Plus boards are frequently rebadged Dahua. A disk does not "have a vendor";
it has evidence that scores. Anything that returns a bare boolean vendor
answer is wrong.

---

## 2. What already works

Run this first — it needs no hardware and takes about ten seconds:

```bash
python tests/test_pipeline.py     # 46 tests, all should pass
python demo/tamper_demo.py        # the stage demo, end to end
```

If those pass, the engine below is intact:

| Component | File | State |
|---|---|---|
| Read-only device layer (Linux + Windows) | `acquire/device.py` | working |
| Bad-sector isolation, zero-fill in place | `acquire/device.py` | working |
| Single-pass acquisition scan | `acquire/scanner.py` | working |
| Linear MD5/SHA-256 + per-block Merkle map | `core/hashing.py` | working |
| Hash-chained custody ledger | `acquire/ledger.py` | working |
| Signature DB + confidence scoring | `detect/` | working |
| Partition parsing (MBR/GPT) | `detect/engine.py` | working |
| Synthetic DVR image generator | `tests/synth_dvr.py` | working |
| **Hikvision filesystem parser** | — | **not started** |
| **Dahua filesystem parser** | — | **not started** |
| **Deleted-footage carver** | — | **not started** |
| Clock-lie detector, camera timeline | — | not started |
| BSA s.63 certificate, CASE/UCO export | — | not started |

**Nothing has touched real DVR media yet.** Every result so far is against
the synthetic fixture, which tests the code, not our understanding of any
vendor's format.

---

## 3. Three design decisions you need to not undo

**Single pass.** Hashing, signature detection and codec profiling all happen
in one traversal of the device (`acquire/scanner.py`). Reading a 2 TB drive
over USB is hours, so a second pass is not an optimisation question — it is
another evening. If you need something from the bytes, add it to the existing
pass rather than introducing a new one.

**A hash per block plus a Merkle root, not one hash.** A linear SHA-256 proves
the whole image is unchanged but cannot survive an interrupted scan and cannot
say *which* region changed. Every pass also hashes each 8 MiB block and builds
a Merkle tree over those leaves. That buys three things: resumable acquisition
(a 4-hour USB scan *will* drop at some point), per-clip inclusion proofs, and
tamper *localisation* rather than a bare "something changed".

**Bad sectors are zero-filled in place, never skipped.** A dying DVR drive is
the normal case, not the exception. Skipping a bad sector shifts every
subsequent offset and silently corrupts the provenance record for everything
after it. `acquire/device.py::_read_degraded` drops to sector-by-sector reads
to isolate exactly which sectors failed. There is a regression test for this;
if you change the read path, keep it passing.

---

## 4. The data contract is frozen

`core/contract.py`, `SCHEMA_VERSION = "1.0.0"`, frozen 2026-09-22.

Six people build against these shapes in parallel. Additive changes bump the
minor version. Anything that removes or retypes a field is a **breaking change
that must be raised at the Saturday integration sync** before you commit it —
someone else is already building against the old shape.

Read `docs/DATA_CONTRACT.md` before you emit any JSON.

---

## 5. Where to start

The highest-value unblocked work, in order:

1. **Hikvision filesystem parser** (`parsers/hikvision.py`, new).
   The master sector magic is `HIKVISION@HANGZHOU` at offset `0x200`, and
   `HIKBTREE` marks the index header. The detection engine already finds both
   and reports their absolute offsets — start by running a scan and looking at
   `out/<case>/scan_report.json`. Emit `Recording` objects per the contract.
   Mark it `spec_only`.

2. **Deleted-footage carver** (`recover/carver.py`, new).
   Annex-B carving with SPS/PPS rebuild. Testable today: the synthetic fixture
   contains one clip that is present on the platter but absent from the index
   (that is exactly what a deleted recording looks like) — its offset is
   printed by `tests/synth_dvr.py`. Attach `Provenance` to every carved clip
   and an honest `confidence`, never a claim of certainty.

3. **Validate against real media.** The team owns a physical Hikvision DVR
   (board marked `DS-80xx P REV1.1`, 8-channel analog) and its Seagate SkyHawk
   drive. On Aakash's Windows laptop the USB-SATA bridge is not enumerating, so
   **if you can get that drive attached under Linux, you are unblocking the
   single most important thing in the project** — it is what moves Hikvision
   from `spec_only` to `validated`.

Before starting, run a scan against the fixture so you can see the shape of
the output you are extending:

```bash
python tests/synth_dvr.py /tmp/fixture.img --vendor mixed
python cli.py scan --device /tmp/fixture.img --case DEV-001 --investigator "Shrestha"
cat out/DEV-001/scan_report.json | head -60
```

---

## 6. Before you add a dependency or write a parser

Read `docs/TECH_STACK.md` first.
Two things in it bind you directly: the forensic core is **stdlib-only**, and
**parsers must be stateless per block** (a pure `(offset, bytes) -> findings`
shape). The second one exists because block detection will be moved to a
process pool once the parsers land — state carried across blocks turns that
from a drop-in change into a rewrite.

---

## 7. Memory

`docs/MEMORY_SEED.md` holds the project context worth persisting across
sessions — team roles, hardware state, dataset decisions (including which
datasets were rejected and why), and the standing constraints. If you keep
memory, write those in now, before starting work, so this does not have to be
re-derived every session.

---

## 8. Honest status of the problem statement itself

The PS text in `docs/PROBLEM_STATEMENT.md` is the official portal text.
Earlier planning used third-party listings, so if anything in older team docs
contradicts that file, the file wins.

Two things remain unverified and should not be stated as fact in any report
or slide until someone confirms them:

- the exact BSA 2023 Section 63 certificate format, against the Act's schedule
- the CFReDS Heimvision `.E01` download link and licence terms

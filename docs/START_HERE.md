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
python tests/test_pipeline.py     # 513 tests (515 with ffmpeg on PATH), all should pass
python demo/tamper_demo.py        # the stage demo, end to end
```

If those pass, the engine below is intact:

| Component | File | State |
|---|---|---|
| Read-only device layer (Linux + Windows) | `acquire/device.py` | working |
| E01 (EnCase) images, segments and compressed chunks, self-verified by their stored MD5 | `acquire/ewf.py`, `cli.py ewf-info` | working on generated E01 sets; not yet on a real E01 |
| Bad-sector isolation, zero-fill in place | `acquire/device.py` | working |
| Single-pass acquisition scan | `acquire/scanner.py` | working |
| Linear MD5/SHA-256 + per-block Merkle map | `core/hashing.py` | working |
| Hash-chained custody ledger | `acquire/ledger.py` | working |
| Signature DB + confidence scoring | `detect/` | working |
| Recorder model: platter strings outside the video, the examiner's reading with hashed photos, cross-checked | `detect/model.py`, `cli.py identify-model`, `cli.py record-device` | working; drive 2 `DS-7B08HUHI-K1` agrees with the unit and its serial; none found on drive 1's head image; drive 1's unit read off its label and System Info (`CP-UNR-104F1`), and `identify-model` now also searches for the unit's own serial, device ID and MAC |
| Partition parsing (MBR/GPT) | `detect/engine.py` | working |
| Synthetic DVR image generator | `tests/synth_dvr.py` | working |
| Vendor parser plugin SDK (field provenance) | `parsers/base.py` | working |
| Hikvision filesystem parser | `parsers/hikvision.py` | working, `spec_only`: the layout observed on drive 2; not yet run on an intact Hikvision disk |
| HeimVision DVR (drop-in plugin, read off the NIST CFReDS K9604-W image; E01 reader verified on it) | `plugins/heimvision.py` | working on real media, `spec_only` |
| Honeywell NVR (drop-in plugin, from Yoon & Hwang, DFRWS USA 2026 (arXiv:2605.07430)) | `plugins/honeywell.py` | working on a disk built to the paper, `spec_only` |
| **Dahua DHFS 4.1 parser + per-camera extract** | `parsers/dahua.py` | **working on real media, `spec_only`** — see `docs/DAHUA_DHFS.md` |
| Remnants of overwritten footage (Dahua) | `parsers/dahua.py` | working, `spec_only` |
| Indexless DHAV carver, index cross-reference | `recover/carver.py` | working on real media, `spec_only` |
| Raw H.264/H.265 carver for a vendor with no parser (anchored on parameter sets; no dates, no cameras) | `recover/annexb.py`, `cli.py carve-annexb`, `scan --carve-annexb` | working, `synthetic_only`; scored on the real HeimVision image (`validate/heimvision_carve.py`): every slice accounted for, cameras with identical settings not separable |
| MPEG-PS carver (Hikvision footage, dated from the `HK` descriptor; works on a reformatted drive) | `recover/pscarve.py` | working on real media, `spec_only` |
| Hikvision HIKBTREE index records → camera labels for carved footage | `parsers/hikbtree.py`, `cli.py label-ps` | working on real media, `spec_only` |
| Carve inside the acquisition pass (`scan --carve`) | `recover/carver.py`, `acquire/scanner.py` | working; identical to a standalone carve on real media |
| Survive a USB drop mid-pass, verified reconnect | `acquire/device.py`, `acquire/scanner.py` | working |
| Write block that survives reconnects (udev rule) | `cli.py writeblock-rule` | working |
| Filesystem metadata preserved, provable to the scan | `recover/preserve.py` | working |
| Timestamp normalization, gaps, cross-camera correlation | `analyse/timeline.py` | working |
| Several recorders in one view, on a shared axis only where every case states its timezone | `analyse/combined.py`, `cli.py combine` | working |
| Recovered footage byte-matched against the recorder's own export (the test for `validated`) | `validate/exportmatch.py`, `cli.py validate-export` | working on generated footage; not yet run on a real export |
| Forensic report (HTML + JSON) | `report/` | working |
| Dependency-free case viewer (all eight OEMs, pipeline, timeline) | `viewer/` | working; the planned FastAPI + React UI (`api/`, `ui/`) wraps the same `report/case.py` |
| Drop-in vendor plugins | `plugins/`, `parsers/__init__.py` | working |
| Unknown-vendor survey (headers, length/date fields, before/after diff) | `detect/survey.py` | working; rediscovered DHAV unaided |
| Motion activity from frame sizes (no decode; lead, not evidence) | `analyse/activity.py` | working |
| Burned-in OSD: camera titles and the clock, for footage no index names | `analytics/osd.py`, `analytics/osd_rules.py`, `cli.py read-osd` | rules and orchestration tested, `synthetic_only` — **never run on a rendered frame**; see `docs/OSD_OCR.md` §6 |
| Video decode (MP4), face/object detection | — | not started (optional layer: ffmpeg, ONNX Runtime — see TECH_STACK) |
| BSA s.63 certificate (draft, Part A/B, from the case's own hashes) | `report/s63.py`, `cli.py certificate` | working; wording matches the Gazette word for word (a test checks it) |
| CASE/UCO export: drive, recorder, ledger actions, every file with its hash and byte ranges | `report/case_uco.py`, `cli.py case-export` | working; a sample validates under `case_validate` 0.18.0 |

**Real media:** two DVR drives are held. The CP Plus unit's SkyHawk
(`WWD4A3NX`) carries Dahua-family DHFS 4.1 — the Dahua parser was built
against its first 20 GiB, and a full acquisition of the drive is under way.
The second drive (`Z9C2632A`) turned out to be reformatted by a Dahua-family
recorder (DHFS superblock, empty index) with **Hikvision MPEG-PS footage
underneath**, recovered by the MPEG-PS carver and dated from its `HK`
descriptors. Two copies of Hikvision's HIKBTREE index survived near the end
of the disk; decoded, they name the camera for 2,021 of the 2,516 recovered
streams. The full-filesystem parser now reads the same observed layout.

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

1. **Hikvision ground truth.** The parser (`parsers/hikvision.py`) reads the
   layout observed on drive 2, whose primary master a reformat had overwritten;
   it has never read a disk the Hikvision unit formatted itself. The team owns a
   Hikvision DVR (board `DS-80xx P REV1.1`, 8-channel analog). Put a spare small
   SATA disk in it, record known footage with the clock written down, delete one
   clip, export another, and image the whole disk
   (`docs/LINUX_ACQUISITION.md` section 6). That is the only route to
   `validated`. The SkyHawk is **not** this DVR's disk: it holds Dahua DHFS.

2. **Carving for other containers.** `recover/carver.py` carves DHAV (Dahua)
   without an index, splitting rather than mixing cameras it cannot tell apart.
   Hikvision streams are not DHAV. Their container needs the same treatment,
   and bare Annex-B carving is the last-resort fallback for unknown vendors.

3. **Finish the Dahua disk.** Image the first ~16 MiB of volumes 2–4 (their
   indexes) to list every recording on the SkyHawk, and find the recorder it came
   from to export a reference clip — see `docs/DAHUA_DHFS.md` section 7.

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

Two things that were unverified are now settled (29 Sep 2026):

- the BSA 2023 Section 63 certificate wording: it matches the Schedule word
  for word as printed in the Gazette of India Extraordinary, Part II Sec. 1, No. 55, 25 Dec 2023, pp. 46-47 (CG-DL-E-25122023-250882); `tests/test_pipeline.py` compares every word
- the CFReDS HeimVision `.E01`: downloaded, and FTK's own MD5 and SHA-1
  reproduced (VALIDATION_REPORT §8e). Licence: CC BY-ND 4.0, as stated on the
  creator's (Marshall University) archive.org upload
  (`docs/research/datasets_deep.md`); the CFReDS page states none

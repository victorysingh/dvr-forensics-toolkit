# PS26150 — Multi-Vendor DVR/NVR Forensic Analysis Tool

[![tests](https://github.com/victorysingh/dvr-forensics-toolkit/actions/workflows/tests.yml/badge.svg?branch=setup)](https://github.com/victorysingh/dvr-forensics-toolkit/actions/workflows/tests.yml)

SIH 2026 · Problem Statement **26150** · National Technical Research Organisation (NTRO)
Theme: Blockchain & Cybersecurity · Category: Software

Standardized acquisition, recovery and analysis of surveillance evidence across
DVR/NVR vendors that all use different proprietary filesystems.

---

## Safety rules (non-negotiable)

1. **The tool never writes to the evidence drive.** There is no write path in
   `acquire/device.py` — not behind a flag, not behind a confirmation.
2. **Software write-blocking is mandatory on Windows.** The enclosure has no
   hardware write-blocker, so the read-only handle *is* the write block, and the
   report says exactly that (`software:read-only-handle`) rather than claiming
   hardware blocking.
3. **If Windows offers to format the disk, always click Cancel.** A DVR platter
   has no filesystem Windows recognises; that prompt is normal and accepting it
   destroys the evidence.
4. **Raw device reads need Administrator.** Run the terminal elevated.

## The honesty rule

Every vendor claim carries a status, and the weakest piece of evidence sets it:

| status | meaning |
|---|---|
| `validated` | confirmed against a real disk or image we possess |
| `spec_only` | implemented from published research, untested on real media |
| `detected_not_parsed` | recognised on the platter, no parser implemented |
| `synthetic_only` | only ever tested against our generated fixture |

The trap in this problem statement is claiming support for eight OEMs with no
way to validate it. We claim depth only where we have real media: two recorder
drives the team acquired (a CP Plus unit, Dahua-family, and a reformatted
Hikvision drive) and NIST's real HeimVision image. The other vendors are
parsed from published research, their own firmware or their own documents,
and say so (`spec_only`, `detected_not_parsed`); any recorder's video can
still be recovered with no parser at all.

## On real media

- **Drive 1, CP Plus (Dahua DHFS 4.1):** 2,029 indexed recordings, and
  **2,246 streams (5.4 GB) recovered from outside every index**. ffmpeg's own
  `dhav` reader and ours agree on all 719,097 video frames it emits from them.
- **Drive 2, a reformatted Hikvision drive:** **2,516 streams (923 GiB,
  ~6,300 h) recovered and dated** from under the reformat; 2,021 put on a
  camera from surviving index records, which the carve covers 99.6-99.7% of;
  16 of 17 silences on every camera explained by power cuts in the recorder's
  own log.
- **NIST CFReDS HeimVision image (150 GB E01):** our E01 reader reproduces
  FTK Imager's stored MD5 and SHA-1; a recorder we had never seen, parsed
  from the image.
- **Real Dahua `.dav` files:** 726 of 726 and 104 of 104 frames identical to
  ffmpeg's reading.
- **Hostile input:** 12,800 damaged disks, streams and E01 sets fed to the 8
  vendor parsers, the 3 carvers and the E01 reader: no crash and no hang,
  after fixing what the first runs found (144 parser crashes, 1 hang, and a
  damaged E01 set that left the evidence file open).

Details and every number's source: `docs/VALIDATION_REPORT.md`,
`docs/STATUS.md`.

## Usage

```bash
python cli.py devices                       # list attached drives (read-only)
python cli.py writeblock-rule --device /dev/sdb --user "$USER"   # keep it RO across reconnects
python cli.py scan --device /dev/sdb --case CASE-001 --investigator "Shrestha" \
                   --carve --carve-ps --reconnect-wait 480   # one pass: hashes + both carvers
python cli.py scan --device image.img --case TEST --max-mb 512   # triage
python cli.py preserve --device /dev/sdb --out out/CASE-001      # filesystem metadata
python cli.py parse    --device /dev/sdb --vendor Dahua --out out/CASE-001
python cli.py extract-carved --device /dev/sdb --out out/CASE-001   # recovered footage out, hashed
python cli.py timeline --out out/CASE-001 --tz-offset 330
python cli.py analyse-video --out out/CASE-001                 # AI leads: people, faces, vehicles (optional layer)
python cli.py face-search --out out/CASE-001 --photo person.jpg  # faces ranked by likeness to a photo: candidates
python cli.py read-osd --out out/CASE-001 --unlabelled         # camera title and clock painted in the picture
python cli.py certificate --out out/CASE-001 --part A          # BSA 2023 s.63 certificate, drafted from the case
python cli.py case-export --out out/CASE-001                   # CASE/UCO JSON-LD for other forensic tools
python cli.py report   --out out/CASE-001    # HTML + JSON, hashed into the ledger
python cli.py serve                          # viewer on http://127.0.0.1:8150
python cli.py survey --device unknown.img    # draft the layout of an unknown vendor's disk
python cli.py carve-annexb --device unknown.img --out out/CASE-009   # its video, no parser needed
python cli.py identify-model --device /dev/sdb --out out/CASE-001    # model strings outside the video
python cli.py hik-log --device /dev/sdb --out out/CASE-001           # a Hikvision disk's own system log
python cli.py record-device --out out/CASE-001 --model CP-UNR-104F1 --photo label.jpg
python cli.py verify --out out/CASE-001      # re-verify custody, Merkle root, preserved blocks
python cli.py prove  --out out/CASE-001 --offset 8388608
python cli.py validate-export --export clip.dav --against out/REF-001/clips --out out/REF-001

python tests/test_pipeline.py               # 580 regression tests (582 with ffmpeg), no hardware
python cli.py ewf-info --image case.E01 --verify   # any command also takes an .E01
python -m validate.realmedia --case1 out/CASE-001 --image1 head.dd   # every real-media check
python demo/tamper_demo.py                  # tamper detection, end to end
python demo/stage_demo.py                   # every capability in eight steps, ~5 s (synthetic disks)
python demo/bench_single_pass.py            # one pass vs one read per task (docs/PERFORMANCE.md)
python tests/synth_dvr.py fixture.img --vendor mixed
```

Full Linux procedure: `docs/LINUX_ACQUISITION.md`. Windows: one packaged
`ps26150-dvr.exe` that needs no Python (`packaging/README.md`); the optional AI
layer runs from its own environment (`analytics/README.md`).

## Design

**Single pass.** Reading a 2 TB drive over USB is hours, so hashing, signature
detection and codec profiling all happen in one traversal (`acquire/scanner.py`).

**Block map + Merkle root, not one hash.** A linear SHA-256 proves the whole
image is unchanged but cannot survive an interrupted scan and cannot say *which*
region changed. Every pass also hashes each 8 MiB block and builds a Merkle tree
over those leaves. That buys resumable acquisition, per-clip inclusion proofs,
and tamper *localisation* — see `demo/tamper_demo.py`.

**Bad sectors are zero-filled in place, never skipped.** Skipping would shift
every downstream offset and silently corrupt the provenance record.

**Confidence, not yes/no.** CP Plus boards are frequently Dahua rebadges, so
vendor attribution is scored from weighted signatures, with a large bonus for a
magic found at its documented offset and sharply diminishing returns for repeats.

```
core/      contract.py   frozen JSON contract (v1.0.0, frozen 2026-09-22)
           hashing.py    streaming hashes, Merkle tree + inclusion proofs
acquire/   device.py     read-only raw block device (Windows ctypes / POSIX)
           ledger.py     hash-chained chain-of-custody ledger
           scanner.py    single-pass acquisition
detect/    signatures.py vendor + filesystem signature database
           engine.py     scoring, codec profiling, partition parsing
tests/     synth_dvr.py  synthetic DVR image generator
demo/      tamper_demo.py
```

## Status

| Component | State |
|---|---|
| Read-only device layer, bad-sector handling | working |
| Survives a USB drop mid-pass (verified reconnect) | working |
| Single-pass hash + block map + Merkle root | working |
| Custody ledger + verification | working |
| Signature detection + confidence scoring | working |
| Recorder model (platter strings + examiner's reading, cross-checked) | working; on real media: Hikvision `DS-7B08HUHI-K1`, platter and unit agree |
| Partition parsing (MBR/GPT) | working |
| Hikvision FS parser | working, `spec_only` (layout observed on drive 2; not yet run on an intact Hikvision disk) |
| Hikvision MPEG-PS carver + HIKBTREE index records → cameras | working on real media (drive 2), `spec_only` |
| Honeywell NVR (plugin, from Yoon & Hwang 2026) | working, `spec_only` (no Honeywell media) |
| HeimVision DVR (plugin, read off the NIST CFReDS image) | working on that real image, `spec_only` |
| Dahua / CP Plus DHFS 4.1 parser + extract | working on real media (drive 1), `spec_only` |
| Uniview (from its firmware's storage driver), Matrix (from its documents), Godrej (from Qualvision's firmware) | plugins working on generated disks, `spec_only` (no media) |
| TP-Link (index read from its firmware) | `detected_not_parsed` (footage not placed) |
| Indexless carver, inline in the scan | working on real media, `spec_only` |
| Raw H.264/H.265 carver for vendors with no parser | working, `synthetic_only` |
| Byte-match against the recorder's own export (`validate-export`) | working on generated footage; no real export yet |
| E01 images (read directly by every command) | working; reproduces FTK Imager's hashes on NIST's real image |
| Damaged or tampered disks (fuzzing) | 12,800 cases, no crash or hang |
| Metadata preservation | working |
| Timeline (normalization, gaps, correlation) | working |
| Report (HTML + JSON) and local UI | working |
| Drop-in vendor plugins | working |
| Unknown-vendor survey | working |
| Motion activity from frame sizes (lead, not evidence) | working |
| People, vehicles, faces in recovered footage (YOLOX-S + YuNet; optional layer, lead, not evidence) | working, measured on real footage (below) |
| Face search by a reference photo (SFace; candidates, never identification) | working, measured (below) |
| Camera title and clock read from the picture (OSD OCR) | working; weak on real files (5 of 36 clocks exact) |
| Export in NIST's CCTV profile (NISTIR 8161) | working |
| BSA s.63 certificate (draft from the case record) | working; wording matches the Gazette word for word |
| CASE/UCO export (JSON-LD; `Conforms: True` under the official `case_validate`) | working |

Nothing is `validated`: that needs a byte-match between recovered footage and
the recorder's own export (`validate-export`), not yet run on a real export.

## AI layer (optional): leads, measured

Everything here runs offline on footage the tool recovered from the disk,
including footage the recorder's own index no longer lists. Every model is
pinned by SHA-256 and recorded in the custody ledger, and every result is
labelled a lead for an examiner, not evidence.

| Task | Model | Measured (`docs/VALIDATION_REPORT.md`) |
|---|---|---|
| People, vehicles, bags | YOLOX-S on the whole frame and 2 x 2 tiles; fisheye pictures also turned round | a person in **44 of 57** labelled real recorder frames (the first version: 0); **810 of 1,089** people on CAVIAR footage never used for choosing (§8a) |
| Faces (where, not whose) | YuNet | **22 of 27** labelled faces; no face false alarm on drive 1 (§8a) |
| Parked vehicles | YOLOX-S, a car that stays put counted once per place | drive 1's night car reported in 26 of its 35 frames, none false (§8a) |
| **Face search by photo** | YuNet + SFace | LFW faces made recorder-sized: the same person passes in **97.8%** of pairs (4,519 of 4,619) with eyes 12 px or more apart, and **no** pair of different people passes at any size; strangers in 12 real surveillance clips: **1 false candidate** (an upside-down head at a fisheye's edge) (§8n) |
| Motion activity | compressed frame sizes, no decoding | per camera per minute, inside the acquisition pass |

Face search gives **candidates, not identifications**: faces for an examiner
to compare by eye with the photo. It runs only when an examiner supplies a
photo, and no candidate does not mean the person is absent.
(`analytics/README.md`)

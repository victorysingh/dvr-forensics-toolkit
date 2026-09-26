# Project status and handoff — 26 Sep 2026

Where SIH26150 stands two days before the deadline: what is done against
the problem statement, what the two real drives gave us, how to run it,
and — in §6 — what is left in JP's lane.

Everything below is on `setup` or in PR #4 (Hikvision index), except the
case outputs, which live under `out/` on Shrestha's machine (gitignored:
they are evidence).

---

## 1. The problem statement, item by item

`docs/PROBLEM_STATEMENT.md` is the official text; these are its asks.

| PS asks for | Status | Where |
|---|---|---|
| Identify the DVR / vendor | **done** — signatures for all eight OEMs, confidence scores; on-platter evidence found for CP Plus (`CPPlusIPCam`) and Hikvision (`HK` descriptors, surviving master/index) | `detect/` |
| Create forensic images | **done** — whole-drive MD5 + SHA-256 in one read-only pass, per-block Merkle map, preserved metadata, 20 GiB head image; see `FORENSIC_IMAGE.md` | `acquire/`, `recover/preserve.py` |
| MD5 and SHA-256 | **done** — both drives | `scan` |
| Parse proprietary file systems | **done on real media** — Dahua/CP Plus DHFS 4.1 (2 drives); Hikvision HIKBTREE index records (surviving copies) | `parsers/dahua.py`, `parsers/hikbtree.py` |
| Decode proprietary formats | **done on real media** — Dahua DHAV → H.265; Hikvision MPEG-PS + `HK` descriptors → H.264/H.265; ffmpeg decodes both | `recover/carver.py`, `recover/pscarve.py` |
| Extract video and metadata | **done** — `.dav`/`.h265` and `.ps`, per-file SHA-256 | `extract-carved`, `extract` |
| Recover deleted footage | **done on real media** — Dahua: 2,246 streams outside every index; Hikvision: a whole reformatted drive, 2,516 streams | carvers |
| Normalize timestamps | **partly** — recorder clock decoded and cross-checked against burned-in clocks on both vendors; conversion to UTC needs the recorder's zone and clock error, which we have not read from the units | `analyse/timeline.py` |
| Correlate events across cameras | **done** — gaps per camera, recorder-wide gaps, recurring patterns, multi-camera activity peaks | `analyse/timeline.py`, `analyse/activity.py` |
| Chain of custody | **done** — hash-chained ledger; every action recorded with the hash of what it produced | `acquire/ledger.py` |
| Reports | **done** — HTML + JSON, hashed into the ledger | `report/` |
| AI analytics (face, object, motion) | **done as leads** — motion from frame sizes (no dependencies); face and object detection in an optional layer (ffmpeg + ONNX); everything labelled "lead, not evidence" | `analyse/activity.py`, `analytics/` |
| Support 5–6 OEMs | **honest answer**: 3 decoded from real media (Dahua, CP Plus, Hikvision), 5 detected (Honeywell, TP-Link, Godrej, Uniview, Matrix) with a plugin route and a survey tool for onboarding | `plugins/`, `detect/survey.py` |

Named deliverables:

| Deliverable | File |
|---|---|
| Comparative analysis of OEMs | `OEM_COMPARISON.md` (draft — researchers to fill §5), `formats/*.ksy` |
| DVR/NVR forensic image | `FORENSIC_IMAGE.md` |
| System architecture | `ARCHITECTURE.md` |
| Functional prototype | the tool; `python cli.py serve` for the viewer |
| SOPs | `SOP_EXAMINATION.md`, `LINUX_ACQUISITION.md` |
| Validation reports | `VALIDATION_REPORT.md` |
| User manual | `USER_MANUAL.md` |
| Final project report | **not started** |

## 2. The two real drives

### Drive 1 — CP Plus DVR (Seagate ST1000VX013, s/n `WWD4A3NX`)

| | |
|---|---|
| Acquisition | complete single pass, 0 bad sectors; SHA-256 `78eb8a4ac306691cacc1b3f0da911ded8edf1b9f9bf0819f483d95f467f8d909` |
| Filesystem | Dahua DHFS 4.1, 4 volumes, **2,029 recordings**, 3 cameras, 27 Aug → 23 Sep 2026 (recorder clock), stored circularly |
| Recovered | 349.5 M frames carved without the index; **2,246 streams (5.4 GB) outside every index**, March → August 2026, all extracted |
| Timeline | 6 recorder-wide gaps (three on 23 Sep, the day the drive was pulled); a nightly 02:00–02:09 interruption pattern; 2 streams at the clock's default date (05:30 — hints at IST, not applied) |
| Analytics | motion activity (20 GiB head); people in 51 and cars in 63 sampled frames of recovered footage |
| Output | `out/cpplus_WWD4A3NX/report.html` |

### Drive 2 — Hikvision recorder, reformatted (Seagate ST1000VX005, s/n `Z9C2632A`)

| | |
|---|---|
| Acquisition | complete single pass, 0 bad sectors, two USB drops healed by verified reconnects; SHA-256 `04d7d4e05b14524b9f53b175ccc7e2b4156463b18e467e326da2a763405921d1` |
| Top layer | Dahua DHFS 4.1 with an **empty** index — a Dahua-family recorder formatted it and never recorded |
| Underneath | the Hikvision recorder's footage: **2,516 streams, 923 GiB, ~6,300 h**, every one dated, April 2021 (H.264) → 30 Aug 2024 (H.265 + audio) |
| Hikvision index | a master copy and two HIKBTREE copies survived at the end of the disk: **922 records, 8 channels**; 2,021 streams attributed to a camera; the carve recovered **99.6–99.7%** of the hours the index says each camera recorded |
| Analytics | on a 50-stream / 22 GB subset — see §5 |
| Output | `out/drive2_Z9C2632A/` (report pending the analytics run) |

Both drives: every block shared by independent reads is identical, apart
from two blocks corrupted by a since-fixed bug (`VALIDATION_REPORT.md` §5–6).

## 3. What the tool does now

```
scan --carve --carve-ps --activity   one read-only pass: hashes, block map, detection,
                                     Dahua carve, MPEG-PS carve, motion activity
                                     (survives USB drops: verified reconnect)
preserve                             filesystem structures kept byte-exact, provable
parse --vendor Dahua                 DHFS index -> recordings
label-ps                             HIKBTREE index -> cameras for carved PS footage
extract / extract-carved             footage out, hashed
timeline                             clock rule, gaps, recurring patterns, coverage
activity / analyse-video             leads: motion, faces, objects
report / verify / prove / serve      report, re-verification, Merkle proofs, viewer
survey                               draft the layout of an unknown vendor's disk
writeblock-rule                      udev rule keeping a drive read-only across resets
```

`python tests/test_pipeline.py` — 247 tests, no hardware, ~1 minute.

## 4. Things learned the hard way

- **The USB-SATA bridge (`14cd:6116`) dropped out five times across the two
  drives** (at 29.7, 48.6 and 137.7 GB on drive 1; 483 and 716 GB on drive 2).
  The scan now survives it by re-verifying the drive before continuing, but a
  USB 3 dock would cut 11 h passes to ~2 h and remove the risk.
- **A short read on a dying bridge was zero-padded into the hash** by the
  original device layer; fixed, and the fix is in the validation report.
- **A reconnected drive comes back writable.** The udev rules (serial- and
  adapter-keyed) re-apply the write block at enumeration; never reboot during
  a case (they live in `/run`).
- **A detector will call a steel pot a face.** Static detections are flagged
  and not counted.

## 5. Open items for everyone

| Item | Why it matters | Needs |
|---|---|---|
| Byte-match a recovered clip against a native DVR export | the only route to `validated` for any vendor | the physical CP Plus DVR |
| Recorder time zone + clock error | to state UTC; today every time is the recorder's own clock | read from the units' settings, or the seizure-time photo method in the SOP |
| Were the 23 Sep gaps on drive 1 the team's handling? | our own footprint must be stated | team memory |
| Final project report | named deliverable | everyone |
| Analytics on drive 2 | numbers for §2 | running at the time of writing |

## 6. For JP — your lane

Your lane was dataset collection, the deleted-footage carve, the camera
timeline and the Honeywell plugin. Two of those exist now, built against
real media; the rest is open, and there is new work that fits it.

**Already built — review rather than rebuild:**

- **Deleted-footage carve**: `recover/carver.py` (Dahua DHAV, splits rather
  than guesses at ambiguous boundaries) and `recover/pscarve.py` (MPEG-PS,
  dated from Hikvision `HK` descriptors). Both run inside the scan. Worth a
  second pair of eyes: `VALIDATION_REPORT.md` §7 has the numbers.
- **Camera timeline**: `analyse/timeline.py`. Indexed cameras, carved-footage
  lanes, resolution groups where no index survives, recorder-wide gaps,
  recurring patterns, recorded-vs-recovered coverage.

**Open, and yours if you want them:**

1. **Honeywell plugin.** No Honeywell media exists. The honest route is:
   `survey` on any Honeywell disk or image you can find → a plugin from
   `plugins/_template.py` → status `detected_not_parsed` until real media
   parses. Without media, stop at detection and say so.
2. **Datasets.** The CFReDS Heimvision `.E01` (link and licence still
   unconfirmed) or any other labelled DVR image. Each new image is a chance
   to validate a parser on a second recorder.
3. **Camera attribution from the burned-in text (OCR).** Footage outside every
   index has no camera — but the picture carries it: "Parking",
   "Road View 1/2" (CP Plus), "Camera 04" (Hikvision). Tesseract with a
   character whitelist on the title region (`TECH_STACK.md` already chose
   Tesseract) would label those streams. Same approach reads the burned-in
   clock for the seizure-time clock check.
4. **Frames that do not decode.** On drive 1, 2,087 video frames after a
   keyframe still fail to decode (4,980 more precede an overwritten keyframe,
   which is expected). Suspected: a reference frame lost mid-stream. Needs
   checking frame by frame.
5. **Timeline across the two drives.** Both recorders share nothing, but the
   timeline format is the same; a combined view for the demo is cheap.

**Prathyushree** (H.264 and timestamp research, output verification): the
`HK` time decoding (`formats/hikvision_ps.ksy`) and the DHAV packed date are
both cross-checked on one frame each against the burned-in clock; checking
more frames across more streams, and on H.265 footage, is exactly the output
verification the report needs.

**Before touching evidence:** read `START_HERE.md` rules 1–4 and
`LINUX_ACQUISITION.md` §2. Work on images, or on `out/` case folders, not on
the drives.

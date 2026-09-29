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
| Identify the DVR / vendor | **done** — signatures for all eight OEMs, confidence scores; on-platter evidence found for CP Plus (`CPPlusIPCam`) and Hikvision (`HK` descriptors, surviving master/index). **Model:** `identify-model` searches the non-video parts of the disk for model numbers; `record-device` records the model off the unit with hashed photos; the two are checked against the format on the disk. **Run 28 Sep:** drive 2 `DS-7B08HUHI-K1`, agreeing with the team's unit (label, serial `F29196515`, whose full device serial is on the platter 202 times); drive 1: no model string in its head image; its unit read on 28 Sep off the label and System Info - `CP-UNR-104F1` (a CP Plus NVR, Dahua-built, agreeing with the DHFS on the drive), firmware `V1.00.14.00.T`, SN, DevID and MAC; the whole-drive search for those identifiers is still to run | `detect/`, `detect/model.py` |
| Create forensic images | **done** — whole-drive MD5 + SHA-256 in one read-only pass, per-block Merkle map, preserved metadata, 20 GiB head image; see `FORENSIC_IMAGE.md` | `acquire/`, `recover/preserve.py` |
| MD5 and SHA-256 | **done** — both drives | `scan` |
| Parse proprietary file systems | **done on real media** — Dahua/CP Plus DHFS 4.1 (2 drives); Hikvision HIKBTREE index records (surviving copies); **HeimVision** FAT32 ring + `luo`/`liu` frames (a third real image, NIST CFReDS) | `parsers/dahua.py`, `parsers/hikbtree.py` |
| Decode proprietary formats | **done on real media** — Dahua DHAV → H.265; Hikvision MPEG-PS + `HK` descriptors → H.264/H.265; ffmpeg decodes both | `recover/carver.py`, `recover/pscarve.py` |
| Extract video and metadata | **done** — `.dav`/`.h265` and `.ps`, per-file SHA-256; the Hikvision recorder's own system log (43,108 events on drive 2: power cycles, a local `admin` session, disk events) | `extract-carved`, `extract`, `hik-log` |
| Recover deleted footage | **done on real media** — Dahua: 2,246 streams outside every index; Hikvision: a whole reformatted drive, 2,516 streams | carvers |
| Attribute recovered footage to a camera | **done where an index survived** — 2,021 of 2,516 Hikvision streams from HIKBTREE records. For the 2,741 streams no index covers, `read-osd` reads the title the recorder painted into the picture; built and tested, OCR accuracy not yet measured | `parsers/hikbtree.py`, `analytics/osd.py` |
| Normalize timestamps | **partly** — recorder clock decoded and cross-checked against burned-in clocks on both vendors (by eye on three frames; `read-osd` now does it per stream, untested against real pixels); conversion to UTC needs the recorder's zone and clock error, which we have not read from the units | `analyse/timeline.py`, `analytics/osd.py` |
| Correlate events across cameras | **done** — gaps per camera, recorder-wide gaps, recurring patterns, multi-camera activity peaks; on drive 2, **16 of 17 silences on every camera explained by power cuts in the recorder's own log** | `analyse/timeline.py`, `analyse/activity.py` |
| Chain of custody | **done** — hash-chained ledger; every action recorded with the hash of what it produced | `acquire/ledger.py` |
| Reduce analysis time (a PS success criterion) | **measured** - one read of the drive instead of five: a 1 TB drive over the team's USB 2 bridge takes ~11.3 h in one pass, ~56.6 h one read per task, ~21.9 h imaging first (and ~931 GiB free). taps now run in a process each - 2.24x the serial pass in the same run, fast enough that a slow laptop is again limited by the USB 2 drive, not the CPU (PERFORMANCE.md §5) | `docs/PERFORMANCE.md`, `demo/bench_single_pass.py` |
| Reports | **done** — HTML + JSON, hashed into the ledger; BSA 2023 s.63 certificate drafted from the case (Part A/B, hash report enclosed), wording to be checked against the Gazette | `report/`, `report/s63.py` |
| AI analytics (face, object, motion) | **done as leads** — motion from frame sizes (no dependencies); face and object detection in an optional layer (ffmpeg + ONNX); everything labelled "lead, not evidence" | `analyse/activity.py`, `analytics/` |
| Support 5–6 OEMs | **honest answer**: 3 of the eight decoded from real media (Dahua, CP Plus, Hikvision), plus **HeimVision** - an "other commonly used platform" - decoded from a real NIST image; **Honeywell parsed from published research** (Yoon & Hwang, DFRWS USA 2026 (arXiv:2605.07430)) as a drop-in plugin, `spec_only`, no media; 4 detected (TP-Link, Godrej, Uniview, Matrix) with a plugin route and a survey tool for onboarding. For those 4, their video can still be recovered with no parser: `carve-annexb` finds raw H.264/H.265 by its parameter sets (no dates or cameras; `synthetic_only`) | `plugins/`, `detect/survey.py`, `recover/annexb.py` |

Named deliverables:

| Deliverable | File |
|---|---|
| Comparative analysis of OEMs | `OEM_COMPARISON.md` — first-hand for Dahua/CP Plus/Hikvision, published research for Honeywell, sourced first answers for TP-Link, Godrej, Uniview, Matrix (§5.1); `formats/*.ksy` |
| DVR/NVR forensic image | `FORENSIC_IMAGE.md` |
| System architecture | `ARCHITECTURE.md` |
| Functional prototype | the tool; `python cli.py serve` for the viewer |
| SOPs | `SOP_EXAMINATION.md`, `LINUX_ACQUISITION.md` |
| Validation reports | `VALIDATION_REPORT.md` |
| User manual | `USER_MANUAL.md` |
| Final project report | `FINAL_REPORT.md` (with `RESEARCH_BASIS.md` for differentiators and references) |

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
| Camera labels checked against the picture | two decoded frames show "Camera 01" and "Camera 03" burned in, where the index gave CH01 and CH03; their on-screen clocks match the decoded times to within 2 s |
| Analytics | 50-stream / 22 GB subset, 68,639 sampled frames: person 517, face 73, bus 1 — each with its camera and recorder time. 64 more "faces" were boxes spanning most of the frame (a floor, buckets) and are flagged implausible |
| Output | `out/drive2_Z9C2632A/report.html` |

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
read-osd                             camera titles and the clock from the burned-in picture,
                                     for the streams no index accounts for
identify-model / record-device       the recorder's model: strings on the platter outside the
                                     video, and as read off the unit - checked against each other
hik-log                              a Hikvision disk's own system log: power cycles, logins,
                                     playback, disk events - on the recorder's clock
ewf-info --verify                    an E01 image's stored MD5/SHA-1 reproduced (every command
                                     also reads .E01 directly)
carve-annexb                         raw H.264/H.265 by parameter sets - footage from a vendor
                                     with no parser (no dates, no cameras)
case-export                          the case as CASE/UCO JSON-LD, for other forensic tools
certificate                          BSA 2023 s.63 certificate, Part A or B, drafted from the
                                     case's own hashes and device record
validate-export                      recovered footage byte-matched against the recorder's own
                                     export - the test for `validated`
combine                              several recorders in one view - on one axis only where
                                     every case states its recorder's timezone
report / verify / prove / serve      report, re-verification, Merkle proofs, viewer
survey                               draft the layout of an unknown vendor's disk
writeblock-rule                      udev rule keeping a drive read-only across resets
```

`python tests/test_pipeline.py` — 429 tests, no hardware, ~1 minute.

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
- **A detector will call a steel pot a face** — and a floor, and a stack of
  buckets, at 0.99 confidence. Static detections and face boxes spanning most
  of the frame are flagged and not counted; a score ranks what to watch, it
  does not measure truth.

## 5. Open items for everyone

| Item | Why it matters | Needs |
|---|---|---|
| Byte-match a recovered clip against a native DVR export | the only route to `validated` for any vendor | the comparison is built (`validate-export`); needs a reference disk recorded on and exported from each unit — never the evidence drive (`VALIDATION_REPORT.md` §9) |
| Recorder time zone + clock error | to state UTC; today every time is the recorder's own clock — and, since `combine` landed, the only thing keeping the two drives off one axis | read from the units' settings, or the seizure-time photo method in the SOP |
| Were the 23 Sep gaps on drive 1 the team's handling? (21 Sep's is a restart the unit's own log records, VALIDATION_REPORT §8) | our own footprint must be stated | the unit's log for 23 Sep (exported to USB, or photographed); team memory |
| Final project report | drafted in `FINAL_REPORT.md`; needs the team's review, and its limitations section updated after the field visit | everyone |

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

1. ~~**Honeywell plugin.**~~ **Built** as `plugins/honeywell.py` from
   Yoon & Hwang, DFRWS USA 2026 (arXiv:2605.07430), the first published analysis of Honeywell's surveillance
   filesystem: parse, recordings per camera, extract, and recovery after a
   format. `spec_only` — the next step is any real Honeywell disk or image,
   to move it on.
2. ~~**Datasets.**~~ **Done for CFReDS Heimvision:** the E01 reader
   reproduced its stored MD5 and SHA-1 over 150 GB, and its layout became
   `plugins/heimvision.py` - 24 h on 4 cameras recovered, attributed and
   dated, the recorder's zone (UTC-8) measured from its own disk
   (`VALIDATION_REPORT.md` §8e). Any other labelled DVR image is the next one.
3. ~~**Camera attribution from the burned-in text (OCR).**~~ **Built, and it
   needs the one thing this machine could not do.** `cli.py read-osd`
   (`analytics/osd.py`, rules in `analytics/osd_rules.py`, 22 tests) reads the
   channel title and the clock out of the picture, votes across sampled frames,
   and cross-checks the OSD clock against the date decoded from the container.
   It is wired into the report (section 6c), the viewer and the ledger.

   **It has never been run on a rendered frame** — neither ffmpeg nor Tesseract
   was installed where it was written, so the OCR accuracy is untested and the
   status is `synthetic_only`. The next step is small and is the whole of the
   remaining work: on a machine with `ffmpeg` and `tesseract-ocr`, run it over
   the streams whose frames §8a and §8b of `VALIDATION_REPORT.md` already
   record being read by eye (*Parking*, *Road View 1/2*; *Camera 01*,
   *Camera 03*) and compare. Matching what the eye read, on two vendors, makes
   it `spec_only`; disagreements belong in the validation report with the frame
   as the arbiter. `docs/OSD_OCR.md` §6 has the table to compare against.

   Read `docs/OSD_OCR.md` §3 before changing the rules: no OSD position is
   hardcoded (four bands are scored on the footage itself), a label needs
   frames to agree before it is claimed, and an ambiguous date stays ambiguous
   until the container's own date resolves it. §7 records the stronger route
   that was deliberately *not* taken — the channel title in Dahua `0xF1` aux
   frames, which is on-platter bytes rather than pixels, and what it would
   take.
4. ~~**Frames that do not decode.**~~ **Answered (Shrestha, #24, 28 Sep):**
   a reference frame missing from the disk. About 0.3-0.4% of CP Plus video
   frames are missing, and each breaks the rest of its ~8.6 s group of
   pictures, so only ~61% decode strictly. Streams with a complete frame
   counter lose 0.13% after their keyframe, streams with a gap 22.2%. Most
   missing frames have no intact copy on the disk; the 29 split across a
   chain boundary are now rejoined (62.1%). `VALIDATION_REPORT.md` §7.
   **Left:** `cli.py decode-check` classes every undecodable frame against
   the DHAV counter (before a keyframe / after a missing frame /
   unexplained) - the same answer, frame by frame. Run it — with everything else that needs only the case
   folders — as `python -m validate.realmedia --case1 out/cpplus_WWD4A3NX --image1 skyhawk_WWD4A3NX_first20GiB.dd --case2 out/drive2_Z9C2632A` (USER_MANUAL §3.4h).
5. ~~**Timeline across the two drives.**~~ **Built:** `cli.py combine --cases
   out/A out/B --out out/COMBINED` writes `combined.json` and a
   `combined.html` page, and records the view in each source case's ledger.

   The part worth reviewing is what it refuses to do. Both recorders share
   nothing — no common clock, no common zone — so a single axis has to be
   earned: the view draws one only when *every* case states its recorder's
   timezone, and otherwise shows the cases side by side on their own clocks,
   says on the page that they are not aligned, and makes **no** statement
   about what was recorded at the same time. On a shared axis, a recorder
   whose clock error was never measured is named as a caveat rather than
   absorbed. 11 tests cover this, including the one that matters: no
   simultaneity claim without a shared axis.

   For our two drives it will say "not aligned" until someone reads the zones
   off the units — which is the open item in §5 above, and this is now a
   second thing waiting on it.

**Prathyushree** (H.264 and timestamp research, output verification): the
`HK` time decoding (`formats/hikvision_ps.ksy`) and the DHAV packed date are
both cross-checked on one frame each against the burned-in clock; checking
more frames across more streams, and on H.265 footage, is exactly the output
verification the report needs.

**Before touching evidence:** read `START_HERE.md` rules 1–4 and
`LINUX_ACQUISITION.md` §2. Work on images, or on `out/` case folders, not on
the drives.

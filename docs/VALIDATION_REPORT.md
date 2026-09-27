# Validation report

PS26150 deliverable: *validation reports*. What has been tested, how, on
what, and with what result — including the failures, because two of the
most important results below are bugs that real hardware exposed.

Two different things are validated here, and they must not be confused:

- **the tool** — does it read without writing, hash correctly, recover what
  is there and nothing that is not, and fail safely? (§3–§8)
- **a vendor format** — does our understanding of a proprietary layout match
  what the recorder itself produces? That is the `validated` status, and it
  has **not** been reached for any vendor (§9).

---

## 1. Summary

| Area | Result |
|---|---|
| Automated tests | 307 pass, 0 fail: 299 on generated data with known ground truth, 8 on real media |
| Kernel write block | root writes refused, target unchanged (sacrificial loop device, kernel 7.1.5) |
| Write block across USB reconnects | re-applied automatically on 2 of 2 real reconnects (udev rule keyed on the drive serial) |
| Reproducibility of reads | every block shared by 5 independent reads over 3 days is identical, apart from two blocks — each the last block an old-code pass read as its adapter died, both zero-padded by the since-fixed bug |
| Analytics (optional) | runs on recovered clips; detections reviewed by eye as plausible leads; no accuracy claimed |
| OSD reader (optional) | rules and orchestration tested (§8c); **OCR accuracy not measured** — never yet run on a rendered frame |
| Export comparison (`validate-export`) | 17 tests on generated footage (§9); **not yet run on a real export** |
| Real-hardware failures found | 2 bugs that could have put wrong data into the evidence hash; both fixed with regression tests that fail on the old code |
| Recovery vs ground truth (generated data) | every surviving frame carved; no stream ever mixes two sources |
| Recovery on real media | inline carve identical to standalone carve; 49 unindexed streams extracted with matching frame counts |
| Full-drive acquisition | complete single pass of 931.5 GiB, 0 unreadable sectors, one USB drop survived by verified reconnect; SHA-256 `78eb8a4a…d909` |
| Vendor formats | none `validated`; Dahua/CP Plus `spec_only`; Hikvision container and index records `spec_only`, full-filesystem parser `synthetic_only` |

## 2. Environment

| | |
|---|---|
| Workstation | Kali Linux, kernel 7.1.5, Python 3.14.6, booting from a USB SSD (Realtek RTL9210, `0bda:9210`) |
| Tool | `dvr-forensics-toolkit`, commit `26fb542` or later (branch `shrestha/single-pass-recovery-report-ui`) |
| Evidence | Seagate SkyHawk ST1000VX013, 1 TB, s/n `WWD4A3NX`, from a CP Plus DVR |
| Adapter | generic USB 2.0 SATA bridge, Super Top M6116 (`14cd:6116`), 480 Mbit/s, own power supply |
| Image | first 20 GiB of the drive, SHA-256 `c4098d59cff3973de9d281ba5613005ba52165743c36edfcf56f61aad8f4e610` (23 Sep 2026) |

## 3. Automated tests

```bash
python tests/test_pipeline.py                                   # 226
DHFS_REAL_IMAGE=/path/to/first20GiB.dd python tests/test_pipeline.py   # + 8 real-media
```

Standard library only; runs on a bare Python install. Groups: Merkle trees;
custody ledger (edits and deletions detected); signatures across block
boundaries; bad-sector isolation; partitions; end-to-end scan; resume
safety; Hikvision parser (`synthetic_only`); parser robustness on
non-matching disks; DHAV frames; DHFS parser and carver against generated
disks with **known ground truth**, including a "twins" mode where two
cameras have identical counters and clocks; metadata preservation (tamper
caught); inline carve; drop-in plugins; device loss and reconnect; the
short-read failure; the survey tool; and the real-media checks:

| Real-media check (first 20 GiB) | Result |
|---|---|
| Recordings on volume 1 | 513 |
| Broken index chains | 0 |
| Data area base | 0x95E000 |
| CH01, first hour: stream breaks | none |
| CH01, first hour: video frames missing | under 0.5% |
| CH01, first hour: frames vs counter span | never more frames than the span |
| Indexless carve: streams with mixed camera evidence | none |
| Indexless carve: cameras recovered | all three, comparable volume |

### Full drive (all four volumes)

| Check | Result |
|---|---|
| Recordings indexed | 2,029 across three cameras (volume 1: 513, 2: 504, 3: 511, 4: 501) |
| Period held | 27 Aug 2026 19:00 → 23 Sep 2026 16:55 (recorder clock), continuous apart from the gaps below; ~642 h per camera |
| Recording order | circular across volumes 4 → 1 → 2 → 3; the oldest files (27 Aug 19:00–22:18) survive at the tail of volume 3, not yet overwritten |
| Broken index chains | volumes 1, 2, 4: 0; volume 3: 3 — the volume holding the last recordings, consistent with files open when recording stopped (not established) |
| Data-area calibration | volumes 1, 2: mean timing error 1.13 s and 1.17 s; volumes 3, 4: 2.56 s and 2.45 s — above the 2 s bar, so flagged "weak", though each is 3–5 s clear of the next candidate and chain continuity is 8/8 |
| Field provenance | 28 decoded fields, 0 resting only on the synthetic fixture |

## 4. Write blocking

**Mechanism test** (`LINUX_ACQUISITION §2`), 25 Sep 2026, on a sacrificial
loop device — never on evidence, where a failed block would overwrite
sector 0:

| Step | Result |
|---|---|
| `blockdev --setro`, `--getro` | 1 |
| `dd` as root, buffered, `conv=fsync` | refused: *Operation not permitted*, 0 bytes written |
| `dd` as root, `oflag=direct` | refused: *Operation not permitted*, 0 bytes written |
| SHA-256 of the backing file, before and after | identical |

**In practice**, across real USB drops:

| Event | Write block after reconnect |
|---|---|
| 24 Sep 23:53, before the udev rule existed | **came back writable** (`ro=0`) as `/dev/sdc`; re-applied by hand ~20 min later. Nothing mounted it (auto-mount and udisks off) |
| 25 Sep 00:41, with the rule | `ro=1` automatically, before any process opened it |
| 25 Sep 02:44 (after a manual replug) | `ro=1` automatically; the scan verified and resumed |

The first row is why the rule exists. The rule matches on the drive's own
serial (or on the evidence adapter's USB id); `udevadm test` confirms it
applies to the evidence drive and not to the workstation's own disk, and the
tool refuses to build an adapter rule for an adapter that holds a mounted
filesystem.

**Limitation:** this is a software write block at the kernel block layer.
No hardware write blocker was used.

## 5. Reproducibility of reads

The drive was read in whole or in part by five independent passes on 23–25
Sep. Their per-block SHA-256 values (8 MiB blocks) were compared wherever
they overlap:

| Comparison | Blocks compared | Differ |
|---|---|---|
| 20 GiB image (23 Sep) vs attempt 3 | 2,560 | 0 |
| attempt 1 vs attempt 3 | 3,078 | 0 |
| attempt 2 (before its failure) vs attempt 3 | 3,808 | 1 — block 3807, see §6.2 |
| attempt 4 (full pass) vs the 20 GiB image | 2,560 | 0 |
| attempt 4 vs attempt 1 | 3,078 | 0 |
| attempt 4 vs attempt 2 (before its failure) | 6,223 | 1 — block 6222 |
| attempt 4 vs attempt 3 | 3,808 | 1 — block 3807 |

Independent reads of the same drive through the same flaky adapter, days
apart, agree bit for bit. The two differences are the last block attempt 2
and attempt 3 each read as their adapter died, and both are the same bug
(§6.2): attempt 2's block 6222 equals the true block truncated at 400 KiB
plus zeros; attempt 3's block 3807, truncated at 6976 KiB plus zeros. The
drive re-read today matches attempt 4 for both.

## 6. Failures found on real hardware

Each attempt that failed is kept, with the reason recorded in its own
custody ledger (`out/cpplus_WWD4A3NX_attempt*`).

### 6.1 A lost device was recorded as bad sectors (attempt 2)

At 48.6 GiB the USB bridge reset and the drive re-enumerated under a new
name. The scanner kept reading the dead handle: every read failed, and the
bad-sector path zero-filled 22,035 blocks (180 GB) as "unreadable".

**Fix:** a read failure first checks whether the device still exists and is
the same device (node present, SCSI state `running`, same sysfs path, same
serial). If not, `DeviceLost` is raised — never zero-fill. Live devices get
three retries before any sector is declared bad.
**Regression tests:** "a vanished device raises DeviceLost instead of
zero-filling"; the reconnect suite.

### 6.2 A short read was zero-padded into the hash (attempt 3)

At 29.7 GiB the bridge failed mid-request. The kernel returned 7,143,424 of
8,388,608 bytes **without an error**, and the device layer padded the rest
with zeros and hashed it as data. This code predates the work on the
reconnect logic.

It was caught by the reconnect verification: after the drive returned, block
3807 re-read with a different SHA-256, and the scan refused to continue. The
same bug had struck attempt 2 at its own drop, unnoticed at the time: its
block 6222 is the true data truncated at 400 KiB plus zeros (found when the
full pass was compared against every earlier read, §5).
Diagnosis: the recorded hash equals the true block truncated at 6976 KiB
plus zeros (matched exactly); the true block re-reads identically three
times; neighbouring blocks match.

**Fix:** reads loop until the full length or end of device; a short read is
an error, never padding. The reconnect check re-verifies the last *two*
blocks hashed.
**Regression test:** the exact kernel behaviour — a short read with no
error, then EIO, device gone — through the real read loop. It **fails on the
previous code** (padded block, loss placed in the wrong block) and passes
now; a full pass through it yields the true MD5/SHA-256.

### 6.3 The port disabled the adapter (attempt 4)

At 137.7 GB the host disabled the USB port (`disabled by hub (EMI?)`) and
could not re-enumerate the adapter. The scan waited. After a manual
power-cycle of the adapter and a replug on another port, the drive returned
write-blocked; the scan re-read blocks 0, 17620 and 17621, all matched, and
the same hashes continued from the first unhashed byte. Recorded as
`device_lost` / `device_reconnected` in the ledger.

## 7. Recovery

| Test | Data | Result |
|---|---|---|
| Carver vs ground truth, 4 generated disks incl. twin cameras | synthetic | every surviving frame carved; no stream mixes sources; indistinguishable cameras split, never guessed |
| Index labels vs ground truth | synthetic | the older recording labelled `outside_index`, and nothing else |
| Inline carve (inside the scan) vs standalone carve | real, 20 GiB | identical: 152 streams, same extents, labels, statistics and Merkle root |
| Inline carve with a crashing tap | synthetic | hashes unchanged; tap switched off and recorded |
| Hashes with the carve tap on vs off | synthetic | identical |
| `extract-carved`, outside-index footage | real, 20 GiB | 49 streams, 42,638 frames, 209 MB; every frame count equals the carve's |
| Extracted H.265 structure | real | Annex-B; VPS/SPS/PPS and an IDR repeating, P-frames between |
| Extracted H.265 decode (ffmpeg 8.1.2) | real, 20 GiB | HEVC Main, 1920×1080. 13,706 of 20,773 video frames decode (66%). 4,980 precede their stream's first surviving keyframe — the keyframe was overwritten, so they cannot decode alone; the other 2,087 most likely follow a reference frame lost mid-stream (not yet verified). 4 streams have no keyframe at all |
| Full-drive carve, inside the acquisition pass | real, 931.5 GiB | 349,519,550 validated frames; 3,523 streams kept; 1,196 ambiguous boundaries split, never guessed. Labels: CH01 478, CH02 578, CH03 221 streams (~115.8 M frames each), **outside every index 2,246 streams, 1.99 M frames, 5.4 GiB**, first-frame dates from March to late August 2026 |

## 8. Timestamps

**Decoding checked against the picture itself.** Cameras burn their own
clock into the image. For carved stream `carve-00000` (footage no index
accounts for), decoded frame 100 shows **01/05/2026 01:20:26 PM** on screen.
That frame's own DHAV header (video frame 101; the decoder starts at the
first keyframe, frame 1) decodes to **2026-05-01 13:20:26**. Two independent
clocks — the one burned into the image and the one in the container — agree
to the second, which confirms the packed-date decoding (and that the
on-screen format is DD/MM/YYYY). It also dates this recovered footage to 1 May 2026 —
over four months before anything the index still describes.

Index start vs first-frame date for the 42 recordings with footage in the
first 20 GiB: within 2 s for 40, 3 s and 5 s for the other two. Both are the
recorder's own clock; the zone is unknown and no clock-error reading was
taken at seizure, so the timeline asserts no UTC.

The same frame carries the camera's title, **"Parking"**, burned into the
image. Reading it (on-screen text OCR, planned in `TECH_STACK.md`) is a route
to attributing carved footage to a camera, which the frame headers cannot.

### Timeline of the full drive

No UTC is asserted (zone unknown; no clock reading taken at seizure). On the
recorder's clock:

- **6 recorder-wide gaps** (every camera silent at once): 3 Sep 08:25 (1.3 min),
  21 Sep 18:59 (1 min), and on 23 Sep 13:03–14:08 (65 min), 14:54–16:48
  (114 min) and 16:50–16:51. Recording ends at 16:55:45 on 23 Sep, the day
  the drive was removed. Whether the 23 Sep gaps are the team's own handling
  of the unit is to be confirmed and recorded.
- **A recurring interruption**: 10 one-camera interruptions on 10 different
  nights, all between 02:00 and 02:09, across all three cameras; all 6
  index-vs-first-frame disagreements over 5 s are among them. The pattern of
  a scheduled task (a camera reboot, a time sync) — not established.
- **2 carved streams dated 2000-01-01 05:30** — the recorder's clock at its
  default at some point, e.g. after power loss with a flat clock battery.
  Their real time is unknown. The *05:30* is itself a clue: a clock reset to
  2000-01-01 00:00 UTC and displayed at UTC+05:30 shows exactly that, which
  suggests the recorder's zone is set to IST. An inference only — confirm it
  from the unit's settings before passing `--tz-offset 330`.
- **Footage outside every index** dates from March to 26 Aug 2026 — the
  previous recording cycle, surviving at the tails of reused clusters.

## 8a. Analytics (optional layer — leads, not evidence)

Run on the 45 decodable outside-index clips of the 20 GiB image at 1 frame
per second (UltraFace RFB-320 and SSD-MobileNet v1, hashes pinned):
frames with a person 5, with a car 3, faces 0. Two thumbnails reviewed by
eye: the strongest person detection (0.61) boxes a figure standing beside an
auto-rickshaw — plausibly correct; a car detection (0.50) marks a small
distant red object at the end of a road — possibly a vehicle, too small to
confirm. All scores sit near the thresholds, which is why the output is a
list of moments to watch and nothing more. These clips' on-screen clocks read
**9 August 2026** — a month before anything the index describes — and the
cameras' burned-in titles are *Parking*, *Road View 1* and *Road View 2*.

**Full drive:** the 2,025 decodable outside-index streams sampled at one frame
every 5 s — 4,802 frames: a person in 51, a car in 63, faces in none (4 more
car detections sat fixed in place through their clip — flagged static, e.g. a
parked car, and not counted). The two
strongest person detections, reviewed by eye: **0.84** is clearly a person
walking along the road (on-screen clock 13/08/2026 05:59 PM, *Road View 1*);
**0.83** is a small shape by a distant fence, too small to confirm. Nearly
equal scores, very different certainty — a score ranks what to watch first;
it is not a measure of truth.

No systematic accuracy measurement has been made; none is claimed.

## 8b. Second drive: Hikvision footage under a Dahua-family format

Drive `Z9C2632A` carries a DHFS 4.1 superblock whose index is empty on all
four volumes (every cluster record reserved or empty; no recordings) — a
Dahua-family recorder formatted it. Underneath: H.264 in MPEG-2 Program
Stream with Hikvision `HK` stream-map descriptors.

| Check | Result |
|---|---|
| Carve of a real 64 MiB sample | one stream: 7,260 packs, 15,680 video packets, 290 stream maps |
| ffprobe on the extracted `.ps` | MPEG-PS, H.264, 960×576, 25 fps, 290.40 s — the pack clock gave 290.36 s |
| Decode | frames decode; the first frames before the first keyframe do not (expected) |
| `HK` time vs burned-in clock | decoded frame 250 shows 23-04-2021 07:40:17; the `HK` time of the first stream map is 07:40:07 and frame 250 is 10 s later — equal to the second |
| `HK` time internally | 290 stream maps from 07:40:07 to 07:44:57: 288 steps of 1 s, one of 2 s |
| Full pipeline on the sample (scan with carve-ps, extract, timeline, analytics, report, verify) | runs end to end; custody chain intact |
| Analytics on the sample | 17 "face" detections at one fixed spot — a steel pot on a table. Now flagged **static** and not counted; the rule is tested |
| Full drive | one complete pass, 0 unreadable sectors, two USB drops healed by verified reconnects; MD5 `10496e7f842c020cbd47444cb270fbe2`, SHA-256 `04d7d4e05b14524b9f53b175ccc7e2b4156463b18e467e326da2a763405921d1` |
| MPEG-PS carve, full drive | 2,516 streams, 923 GiB, ~6,300 h, every one dated from its `HK` descriptors: April 2021 (H.264) to 30 Aug 2024 (H.265 + G.711) |
| Surviving Hikvision index | master sector copy + two identical HIKBTREE copies; 922 records on a 1 GiB block grid; 8 channels |
| Camera attribution | 2,021 of 2,516 streams inside their block's record window; 495 older streams outside the index |
| Independent checks of the attribution | every camera keeps one resolution (CH03/CH04 2560×1440, CH01/02/06 960×576, CH05/07/08 1280×720, apart from 3 streams each on CH03/CH04); all eight hold 761–788 h |
| Recorded vs recovered | per the index each camera recorded continuously (~27 Jul – 30 Aug 2024); the carve recovered **99.6–99.7%** of those hours on every camera |
| Time zone | index times equal `HK` times — both local; not derivable from these |
| Labels vs the picture | two decoded frames: burned-in "Camera 01" / "28-07-2024 08:19:42" where the index gave CH01 and the `HK` time 08:19:41; "Camera 03" / "22-07-2023 11:28:55" where it gave CH03 and 11:28:53 |
| Analytics (subset of 50 streams, 22 GB) | 68,639 frames: person 517, face 73, bus 1. The two strongest "faces" (0.997, 0.978) were a floor and buckets; the "person" beside the first looks like a dog. 64 face boxes spanning most of the frame are now flagged implausible and not counted |

## 8c. OSD reader (optional layer — never yet run on a rendered frame)

`cli.py read-osd` reads the burned-in channel title and clock, which is the
only camera attribution available for the 2,246 (drive 1) and 495 (drive 2)
streams no index accounts for.

| Check | Result |
|---|---|
| Rules under test | 22 checks in `tests/test_pipeline.py`: title normalisation, the agreement vote and its thresholds, band choice scored per stream, ambiguous-date handling, container-resolved dates, the clock comparison and its tolerance |
| Reader end to end | passes with `sample` and `ocr` replaced by a stubbed recorder painting a known title in one corner and a known clock in another: calibration finds both corners, each stream is named from its own picture, a 400 s offset is reported as a disagreement, a stream with no container date is `read, not compared` |
| OCR accuracy | **not measured.** Neither `ffmpeg` nor `tesseract` was installed on the machine this was written on, so the filter chain and the Tesseract call are unrun code paths |
| Status | `synthetic_only` |

**To reach `spec_only`:** run it over the same streams whose frames were
already read by eye in §8a and §8b and compare — *Parking*, *Road View 1*,
*Road View 2* on drive 1; *Camera 01*, *Camera 03* on drive 2; and the clocks
in those rows, where the picture ran 1–2 s ahead of the `HK` time and should
come back `agrees` inside the 3 s tolerance. A disagreement between the reader
and the eye belongs in this report, with the frame as the arbiter.
`docs/OSD_OCR.md` §6 has the full route.

## 8d. Combined view across recorders

`cli.py combine` places several cases in one view. The property under test is
what it refuses to assert: two recorders share no clock, so a single axis is
drawn only where every case states its recorder's timezone.

| Check | Result |
|---|---|
| Shared axis | granted only when every case states a timezone; a recorder whose clock error was never measured is granted the axis but named as a caveat |
| No shared axis | the cases are shown side by side on their own recorder clocks, the page says they are not aligned, and **no** overlap is computed — tested directly |
| Overlaps | reported once per pair with their duration; an overlap shorter than 60 s is not a finding |
| Provenance | each case's `timeline.json` cited by SHA-256; every source case's ledger records the view, and `verify` still passes afterwards |
| Status | 11 tests; no real media involved — the inputs are each case's own timeline, which is validated in §8 |

On the two drives held, this reports **not aligned**: neither recorder's
timezone has been read off the unit (§10).

## 9. Vendor format status

| Vendor | Status | Why not better |
|---|---|---|
| Dahua / CP Plus | `spec_only` | layout read off real media and consistent throughout (§3), but no footage has been byte-matched against the recorder's own export |
| Hikvision — video container | `spec_only` | MPEG-PS + `HK` descriptors decoded from real footage and cross-checked; not byte-matched to a Hikvision export |
| Hikvision — index records | `spec_only` | decoded from the surviving HIKBTREE copies on real media and cross-checked (resolution per camera, hours per camera, 99.6% recovered vs recorded); not byte-matched to an export |
| Hikvision — full-filesystem parser (`parsers/hikvision.py`) | `synthetic_only` | written before we held media; its master-sector layout is still fixture-only |
| Honeywell, TP-Link, Godrej, Uniview, Matrix | `detected_not_parsed` | brand-string detection only |

**To reach `validated`** — Dahua/CP Plus, and Hikvision the same way.

*The comparison is built:* `cli.py validate-export` (USER_MANUAL §3.4d,
`validate/exportmatch.py`). It compares every picture slice (VCL NAL unit) of
the recorder's export with the footage recovered from the disk, **in order**,
and reports `identical`, `partial` (naming the export frames not found), or
`none`. Slices are located by anchors — slices of at least 64 bytes that occur
once in the export — so the tiny identical slices a still scene produces can
never make a match on their own. Container differences (DHAV headers
rewritten, SEI added by the export) are measured and reported separately and
never decide the verdict. It writes both files' SHA-256 to
`validation/export_<clip>.json` and the custody ledger, and it does **not**
change a vendor's status: that stays a reviewed change.

Tested on generated footage only (17 tests): an export with new frame
counters and an added SEI is `identical`; one frame missing from the disk is
`partial` and names that frame; another camera at the same times is `none`;
two still scenes sharing identical tiny slices match nothing; an export
spanning two recovered files is found in both; a Hikvision `.mp4` (IMKH header
+ Program Stream) with its PES packets cut at different places is
`identical`, `HK` times equal.

*What is missing is the export.* It has to be of footage we can also
recover, and the evidence drives are out of their recorders — they must not
go back in, because a recorder writes to its disk the moment it runs. So the
route is a **reference disk**: a spare disk that the same recorder formats and
records on, a native export from it, the reference disk acquired and parsed
exactly like evidence, and the two compared. The same model and firmware is
what carries the result over to the evidence drive's format; both are
recorded with the result.

On the Hikvision unit the same reference disk does more: it would be the first
disk that recorder formatted *itself* that we hold, so it is also the check
for `parsers/hikvision.py`, which is still `synthetic_only`.

A match (or an explained difference) is recorded here with both files'
SHA-256.

## 10. Open items

- Why 2,087 frames after a keyframe still do not decode (suspected: a lost reference frame).
- OSD reader against the frames already read by eye (§8c), on a machine with ffmpeg and Tesseract.
- A native export and a reference disk for the validation in §9 — the comparison itself is built (`validate-export`).
- Recorder timezones, which are what keep the two drives on separate axes in §8d.
- The Hikvision full-filesystem parser against a disk the Hikvision unit formatted itself (the reference disk in §9).
- Kaitai `.ksy` compiled and checked against the image.

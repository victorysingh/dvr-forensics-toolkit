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
| Automated tests | 591 pass, 0 fail: 568 on generated data with known ground truth (2 need ffmpeg), 15 on real media (9 on the CP Plus drive's image, 6 on the HeimVision E01 and its FTK listing), 8 on vendor-made files: 6 from other recorders (§8g, §8l) and 2 on NIST's reference export (§8i) |
| BSA s.63 certificate | the draft's wording matches the Schedule **word for word** as printed in the Gazette of India Extraordinary (No. 55, 25 Dec 2023, pp. 46-47; the Government of India Press's digitally signed PDF): Part A 233 words, Part B likewise; a test compares every word and fails on any change |
| CASE/UCO export | a sample case (scan, carve, extraction, device record, report) exported and checked with the official validator `case_validate` (case-utils 0.18.0): **Conforms: True**; tests check every file's SHA-256 and byte ranges against the extraction manifest |
| E01 reader | **reproduces a real FTK Imager E01's own hashes**: the NIST CFReDS HeimVision image, 150 GB in 3 segments and 4,578,856 chunks - computed MD5 and SHA-1 equal the stored ones (§8e). On generated sets: byte-identical reads; scan and carve equal the raw image's; a damaged chunk is reported unreadable |
| Kernel write block | root writes refused, target unchanged (sacrificial loop device, kernel 7.1.5) |
| Write block across USB reconnects | re-applied automatically on 2 of 2 real reconnects (udev rule keyed on the drive serial) |
| Custody ledger seal | a ledger with entries cut off the end, or rewritten from scratch, still passes the hash-chain check and **fails its keyed seal** (an HMAC with a key kept outside the case folder); an edited seal is caught too; a case passed between examiners keeps each machine's seal (10 tests) |
| Outside programs | every ffmpeg / ffprobe / Tesseract call has a time limit, and a streaming decoder that goes silent is stopped: a hung decoder on damaged footage is reported, not left to freeze the tool (4 tests) |
| Reproducibility of reads | every block shared by 5 independent reads over 3 days is identical, apart from two blocks — each the last block an old-code pass read as its adapter died, both zero-padded by the since-fixed bug |
| Analytics (optional) | scored against 487 frames labelled by eye, and checked on CAVIAR footage never used for choosing (§8a). The first version found a person in **0 of the 57 frames** that had one. Now (YOLOX-S + YuNet, 2 x 2 tiles, people at 0.4, fisheye pictures also looked at turned round): a person in **44 of 57**, faces **22 of 27**, moving vehicles 7 of 12, and parked cars reported as a lead of their own (all 6 in the night car park; none false on CAVIAR); on CAVIAR **810 of 1,089** labelled people (the previous tiled models: 543), 837 with its overhead lobby camera turned round. False alarms: 6 person frames, all a hand in the picture, and 1 face frame, a head at the fisheye's edge. A lead is worth reviewing; an empty list still proves nothing |
| OSD reader (optional) | rules and orchestration tested; **measured** on six recorders' own files, 36 painted clocks: the clock found on 3 of 6 recorders, 5 frames read exactly, 9 wrong, 22 unread; no title right (§8c). A clock reading is a lead to check, not a time source |
| Analysis time | one pass over a 1 TB drive at the measured 23.4 MiB/s: ~11.3 h, against ~56.6 h one read per task; the pass itself runs at 26.7 MiB/s (CPU-bound on fast media) - `PERFORMANCE.md` |
| Export comparison (`validate-export`) | 17 tests on generated footage (§9); **not yet run on a real export** |
| Real-hardware failures found | 2 bugs that could have put wrong data into the evidence hash; both fixed with regression tests that fail on the old code |
| Parsers against damaged or tampered disks | **9,600 corrupted disks** fed to all 8 vendor parsers (§8m). Before the fixes: 144 crashes and 1 hang in 3,200. After, in all 9,600: **no crash and no hang**. The few cases the safety net caught were fixed at the parser too. A parser can no longer end in a traceback. The 3 carvers and the E01 reader were fuzzed too: one bug (a damaged E01 set left its evidence file open), fixed |
| Recovery vs ground truth (generated data) | every surviving frame carved; no stream ever mixes two sources |
| Recovery on real media | inline carve identical to standalone carve; 49 unindexed streams extracted with matching frame counts; the no-parser carver scored on the HeimVision image by its parser: every slice accounted for, 0.07% false, identically set cameras not separable (§8e) |
| Full-drive acquisition | complete single pass of 931.5 GiB, 0 unreadable sectors, one USB drop survived by verified reconnect; SHA-256 `78eb8a4a…d909` |
| Vendor formats | none `validated`; Dahua/CP Plus `spec_only`; Hikvision container, index records and full-filesystem parser `spec_only` (the parser not yet run on an intact Hikvision disk); HeimVision `spec_only`, observed on a third real image (§8e); Uniview `spec_only` and TP-Link's index, from the vendors' own firmware (§8f); Matrix `spec_only`, from Matrix's own documents (§8h) |

## 2. Environment

| | |
|---|---|
| Workstation | Kali Linux, kernel 7.1.5, Python 3.14.6, booting from a USB SSD (Realtek RTL9210, `0bda:9210`) |
| Tool | `dvr-forensics-toolkit`, commit `26fb542` or later (branch `shrestha/single-pass-recovery-report-ui`) |
| Evidence | Seagate SkyHawk ST1000VX013, 1 TB, s/n `WWD4A3NX`, from a CP Plus recorder |
| Recorder unit (read 28 Sep) | CP Plus **`CP-UNR-104F1`**, a 4-channel NVR, hardware V1.0; firmware (System Version) **`V1.00.14.00.T`**, built 16/08/2025; SN, DevID and MAC (recorded, not published here: a CP Plus serial can reach the unit through the vendor's cloud app) - from its label and its System Info screen (photos SHA-256 `2f873a693b6355d2...` and `bed79a8b0388affb...`; these are WhatsApp copies, which strip the time taken - the originals are to be hashed). A CP Plus NVR is Dahua-built, which agrees with the DHFS 4.1 on this drive. Recorded in the case with `record-device` on 29 Sep, from the values read off JP's photos (`--read-from other`: the photos are not on the examining machine; attach them with `--photo`). Whether this unit wrote the drive: **the disk does not say.** `identify-model` over the whole write-blocked drive (29 Sep, 12 worker processes, 42 MiB/s) searched all 9,814 non-video blocks, 76.67 GiB. It found none of the unit's serial, DevID or MAC (the MAC as text three ways and as its 6 raw bytes), and no model string. Its one candidate, `HRG745` at 0x6CFC3A4E2A, matches the Honeywell pattern by chance in binary data: the bytes around it are not text. The check first said "differ" because of it; the tool now lists a candidate that is short (8 characters or fewer) and seen once as a possible chance match, and keeps it out of the check, which reads "not determined" (29 Sep, §10). Result `model.json` SHA-256 `c56b3f8a…0f54741`, in the case ledger |
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
safety; Hikvision parser (`spec_only`, observed layout); parser robustness on
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
| 29 Sep 18:00, drive 1 connected for `identify-model`, before the rule was re-installed (it lives in `/run`, cleared by a reboot) | **came up writable** (`ro=0`); set by hand minutes later, before any tool opened it, and the rule re-installed. Nothing mounted it. The kernel's own counters for the drive showed **0 writes completed** for the whole session, while 85.6 GB were read. Before reading, its first block and a block at 500 GB were hashed and matched the full scan's block map |

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

### 6.4 A triage pass read as complete (found in review, 28 Sep)

Not a hardware failure: found while writing the s.63 certificate, which must
never certify a hash that does not cover the whole drive. A `--max-mb`
triage pass recorded `complete_pass: true` and scoped its MD5/SHA-256 as
`full_device` — complete relative to the range asked for, not the device —
although USER_MANUAL §3.3 says such a pass is marked incomplete. Neither
evidence drive is affected: both were acquired in full passes.

**Fix:** a pass is complete only if it covered the whole device, and only
then are its hashes scoped `full_device`; a triage hash is scoped `region`.
The certificate also checks each hash's length against the drive's size, so
reports written before the fix are caught.
**Regression test:** "a triage pass is not complete, its hash is a region's,
and no drive hash is certified".

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
| Extracted H.265 decode (ffmpeg 8.1.2) | real, 20 GiB | HEVC Main, 1920×1080. 13,706 of 20,773 video frames decode (66%). 4,980 precede their stream's first surviving keyframe — the keyframe was overwritten, so they cannot decode alone; the other 2,087 most likely follow a reference frame lost mid-stream (verified on the full drive, next row). 4 streams have no keyframe at all |
| Decode, all outside-index footage (ffprobe, 28 Sep) | real, 931.5 GiB | 2,246 streams, 989,792 video frames: **598,981 decode (60.5%)**. 245,538 precede their stream's first surviving keyframe; 25,148 sit in the 221 streams with no keyframe at all (P-frames only, 161 MB, never viewable alone); 120,125 follow a keyframe. Streams with complete frame counters lose 0.13% of frames after the keyframe, and streams with counter gaps lose 22.2%, so the lost-reference hypothesis holds. In the 49 streams inside the 20 GiB head image, 90% of the missing frames sit on a 2 MiB cluster boundary |
| Decode, indexed recordings via `extract` (ffprobe, 28 Sep) | real, 20 GiB, 4 one-hour recordings (CH01 ×2, CH02, CH03) | 386,119 video frames: **235,384 decode strictly (61.0%)**; each missing frame (0.29–0.38% by counter) breaks the rest of its ~8.6 s GOP. With error concealment, 99.8% of the frames in one recording display, with artifacts after each missing frame: a viewing aid, not intact evidence |
| Chain-boundary rejoin (`boundary_joined`) | synthetic + real, 20 GiB | Synthetic (`chain_splits=True`, 3 seeds): every intact split frame rejoined with both halves reported; split frames whose second half a later overflow overwrote are refused; 0 foreign, 0 missed, 0 duplicates. Real, CH01 12:53–14:00: 57 of the 371 missing frames are cut at a cluster end and finished in the next chain cluster; in 50 the physically previous cluster's overflow (header valid, trailer inside our second half) overwrote part of it, so they are refused; **7 rejoin intact**. Across the 4 recordings: 29 rejoined, and strict decode rises to 239,913 frames (**62.1%**) |
| Raw H.264/H.265 carver (`carve-annexb`), an undocumented container with stray start codes, noise, two codecs, a gap | synthetic | three cameras found at their exact first parameter set; split at a new SPS and at a gap; the container's stray 00 00 01 passed over; a 10-frame run not reported; 4 MiB of noise yields nothing; random bytes pass as an SPS 3 times in 20,000 (H.264), never for H.265; inline and standalone identical. On a real disk (HeimVision, §8e), scored by that recorder's parser: every slice in the written files accounted for; 0.07% of the slice-shaped start codes are container bytes; four cameras with one parameter set not separable. Status stays `synthetic_only` |
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
- **The 21 Sep gap is a restart, in the recorder's own log.** Its event log,
  photographed on the unit on 28 Sep (SHA-256 `f8dbf0efae073831...`), records
  `Shutdown [21/09/2026 06:59:24PM]` at 18:59:24, `Reboot with Flag [0x01]` at
  19:00:14, one disk in use (`Total Disk<1>, Operating Disk</dev/sda>`) at
  19:00:16, and channels 1, 2 and 3 logging in at 19:00:27 - the drive's
  recorder-wide gap at 18:59, to the minute. The unit's log and the drive's
  footage therefore keep the same clock. Around it: logins from 127.0.0.2 at
  18:41 and 19:09-19:15, one from the local console at 19:14:32, and a failed
  `admin` login at 19:13:58. What caused the shutdown is not in these lines,
  and the flag's meaning is not established. The log shows 68 entries for
  that day; 15 are in the photo. The 23 Sep log is still to be read.
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

**Full drive, first detector (26 Sep):** the 2,025 decodable outside-index streams sampled at one frame
every 5 s — 4,802 frames: a person in 51, a car in 63, faces in none (4 more
car detections sat fixed in place through their clip — flagged static, e.g. a
parked car, and not counted). The two
strongest person detections, reviewed by eye: **0.84** is clearly a person
walking along the road (on-screen clock 13/08/2026 05:59 PM, *Road View 1*);
**0.83** is a small shape by a distant fence, too small to confirm. Nearly
equal scores, very different certainty — a score ranks what to watch first;
it is not a measure of truth.

**Full drive, current detector (30 Sep):** the same 2,025 streams and 4,802
frames, re-run with YOLOX-S + YuNet (2 x 2 tiles; person 0.4, objects 0.5,
faces 0.7, parked vehicles 0.3; `analyse-video --fps 0.2`, about 0.7 s a
frame on the laptop's CPU). Frames with a person **191** (51 before), a car
**289** (63), a motorcycle 65, a face 23 (none), a bicycle 14, a truck 3; **49
parked-vehicle places**. Flagged static and not counted: car 756, truck 38,
motorcycle 19, person 4. These counts are leads, not a measure - the labelled
sample below gives the detector's rates. The strongest of three classes,
looked at by Claude (not yet by a person): person **0.93** is plainly a man
holding a hose (*Road View 2*); face **0.83** sits on the head of a rider
coming towards the camera on a two-wheeler (*Road View 1*), too small to
tell a face from a helmet; bicycle **0.81** is two small figures at the far
end of *Road View 2*, too small to confirm the bicycle. The first report is
kept in the case folder (`analytics_classic_26sep/`, SHA-256 `9afc450d…`, the
hash the custody ledger recorded for it); the re-run is the ledger's 23rd entry
(`1eef57d3…`), and the chain verifies.

### Measured against labels (29 Sep)

`python -m validate.analytics_eval` samples frames from real clips, runs both
detectors exactly as the tool does (the same thresholds and the same static
and implausible-box rules), and scores them frame by frame against labels a
person filled in by eye, looking at the plain frames with no boxes drawn.

**First run, HeimVision CH01 (NIST image), 200 keyframes over 24 h.** No real
person, face or vehicle is in any frame (a mannequin sits at a desk). The tool
reported nothing: 0 false alarms in 200 frames. With nobody in the footage,
this run could not measure recall.

**Second run: six public recorder clips with people and vehicles in them,
287 frames**, every one labelled by eye. The labels, with a note on each
borderline frame, are in `validate/analytics_labels.csv`:

| Clip (source; SHA-256) | Recorder, scene | Frames sampled | Person | Face | Vehicle |
|---|---|---|---|---|---|
| `19.25.00-19.25.50[R].dav` (FFmpeg trac #6144; `c17602dd…`) | Intelbras (Dahua OEM) fisheye, filmed while being mounted | 98 at 2/s | 39 | 12 | 0 |
| `dav-sample.dav` (HandBrake #1935; `9787cb4b…`) | Amcrest (Dahua OEM), two people in a studio | 15 at 4/s | 15 | 15 | 0 |
| `T1P3-Swan-CH01-20210814-191120-191154-….avi` (ForeSpeed; `ab9b8ce6…`) | Swann, empty street | 138 at 4/s | 0 | 0 | 0 |
| `T1P4-Lorex-D862A8_ch1_main_20210814191228_….mp4` (ForeSpeed; `2edd4c1a…`) | Lorex (Dahua OEM), a pickup truck passing | 13 at 10/s | 3 | 0 | 6 |
| `IMKH/00000001541000000.mp4` (VideoLAN; `79b1e557…`) | Hikvision, car park at night, infrared | 6 at 0.3/s | 0 | 0 | 6 |
| `20150327215559_ch01.mp4` (FFmpeg trac #4182; `20e31574…`) | Hikvision, a floor | 17 at 2/s | 0 | 0 | 0 |
| **Total** | | **287** | **57** | **27** | **12** |

Each clip was sampled at its own rate so that no one clip dominates. The
command is `sample CLIP@2 CLIP@4 ... --out DIR`. Scores, as the tool reports
them (static and implausible detections not counted):

| Class | Frames found (recall) | False alarms | Precision |
|---|---|---|---|
| Person | **0 of 57** | 0 of 230 | — (nothing reported) |
| Face | 3 of 27 (11%) | 0 of 260 | 3 of 3 |
| Vehicle | 4 of 12 (33%) | 0 of 275 | 4 of 4 |

What this shows:

- **When the tool names something, it has been right.** There was no false
  alarm in any class, across these 287 frames and the 200 HeimVision frames.
  The two rules do that work:
  - 122 frames in which the object model saw a "person" in a roadside shrub
    (Swann clip, scores 0.50–0.65) were flagged static;
  - 61 frames in which the face model saw a "face" in the bright centre of
    the fisheye picture were flagged implausible.
- **An empty result proves nothing.** The tool reported a person in none of
  the 57 frames that had one:
  - In the fisheye clip (39 frames: small, distorted, seen from above), the
    object model boxed the people in only 2 frames, at 0.35-0.38, below the
    tool's 0.5.
  - It never boxed the driver behind the truck's side window (3 frames). Its
    only "person" in those frames is the roadside shrub; the Swann and Lorex
    clips show the same street.
  - It did box the two people seated in the Amcrest studio (8 of 15 frames,
    0.54–0.67). **The static rule then removed them, because they sat still.**
    The rule cannot tell a fixed false detection from a person who does not
    move. At the thresholds where the model finds the parked cars in the
    night clip, the rule removes those too.
  - Faces: the 3 found are the Amcrest pair. The man looking up into the
    fisheye lens (11 frames) got no box on his face. At model level those
    frames did count as "found", but only because of the centre-of-picture
    box: the right frame, the wrong place.
  - Vehicles: the passing truck was found in 4 frames (0.51–0.98). It was
    missed in its first 2 frames, entering at the edge, and the parked cars
    at night were missed in all 6 frames.
- **A lower threshold does not fix it.** The `sweep` command ran both
  models again on the stored JPEG frames and scored every threshold. On 251
  of the 287 frames, the JPEGs give the same labels as the original decode,
  so the sweep's rows are indicative only.
  - At 0.2, the object model "finds" a person in 16 of 57 frames, with 147
    false-alarm frames. Three of the 16 are the shrub box in the truck
    frames. After the rules, it finds 2 of 57: the fisheye frames above.
  - A higher threshold can make things worse. At 0.6, only 20 shrub boxes
    remain, which is under the static rule's 25% share, so they are counted:
    20 false alarms.
  - Faces at 0.5: 8 of 27 found, with 2 false alarms (small boxes in the
    fisheye).
  - Vehicles at 0.3: 11 of 12 found before the rules, with no false alarm.
    After the rules, 5 of 12, because the parked cars are static.
- **How the frames were labelled.**
  - Person: a head or body can be recognised, even in part. A hand alone
    does not count: 9 frames show only a hand, 8 of them the hand holding a
    test board up to the Swann camera.
  - Face: turned towards the camera enough to be seen as one.
  - Vehicle: enough of it is in frame to recognise without context. The
    ~15-pixel edge of a parked car at the Swann and Lorex left border does
    not count.
- **Limits of this measurement.** It covers six clips, labelled by one
  person, and scores whole frames: a frame counts as found when any box of
  the class is reported, wherever that box is. A second labeller would move
  a few edge frames; that would not change 0 of 57.

**What changed:** the report's analytics section (§6b) and the notes in
`analytics.json` now state that an empty list does not mean nobody was there.
The static note no longer claims that static flags only objects.

### Small people found by tiling (29 Sep)

**Why the people were missed.** The object model shrinks every picture it is
given to 300 x 300. A person 60 pixels tall in a 1080p picture is then 17
pixels tall, and the fisheye clip's people are smaller still.

**The change** (`analytics/tiles.py`, `analytics/detect.py`):
- Each model runs on the whole frame, as before, and also on each tile of a
  3 x 3 grid of overlapping tiles. Each tile shares a fifth of its width or
  height with its neighbour.
- The boxes are mapped back to the whole frame. Where two tiles box the same
  object (same label, overlap 0.5 or more), the stronger box is kept.
- The object model reads a 1920 x 1080 decode (3 x 640 x 360). The face
  model reads the 640 x 360 frame, the mean of each 3 x 3 pixel block.
- The thresholds and both rules are unchanged.

**How it was chosen**, on the same 287 frames, labels, models, thresholds
and rules (native resolution is capped at 1920 wide). Each cell gives
frames found, then false alarms:

| Variant | Person (of 57) | Face (of 27) | Vehicle (of 12) |
|---|---|---|---|
| Untiled, 640 x 360 (above) | 0 · 0 | 3 · 0 | 4 · 0 |
| 3 x 3 tiles, 640 x 360 | 13 · 0 | 11 · 0 | 5 · 0 |
| 2 x 2 tiles, native resolution | 15 · 0 | 10 · **27** | 4 · 0 |
| 3 x 3 tiles, 1280 x 720 | 22 · 0 | 10 · 6 | 5 · 1 |
| 3 x 3 tiles, native resolution | 25 · 0 | 13 · 5 | 5 · 0 |
| **Chosen: objects 1920 x 1080, faces 640 x 360, 3 x 3** | **24 · 1** | **11 · 0** | **5 · 0** |

- Resolution helps the object model: 13 people at 640 x 360, 25 at native
  resolution.
- It hurts the face model: at higher resolution, tiled faces raised false
  alarms (5 to 27).
- The chosen row was measured with the tool itself (`sample`, then
  `score`). The others were measured with an experiment script using the same
  models, frames and rules.
- The grid and the two resolutions were picked on these labels, so the
  chosen row is somewhat optimistic. No threshold was changed.

**The score as the tool now reports it:**

| Class | Frames found (recall) | False alarms | Precision |
|---|---|---|---|
| Person | **24 of 57** (42%) | 1 of 230 | 24 of 25 |
| Face | 11 of 27 (41%) | 0 of 260 | 11 of 11 |
| Vehicle | 5 of 12 (42%) | 0 of 275 | 5 of 5 |

What was found, and what still is not:
- **Fisheye, people seen from above:** 20 of 39 frames, up from 0. Still
  missed: heads at the picture's edge, a head seen from directly above, and
  the people on the floor below, small and distorted.
- **Amcrest studio:** faces in 11 of 15 frames, up from 3; people in 4. The
  model boxes the seated pair in 4 more frames, and **the static rule still
  removes them because they sit still**.
- **Lorex, the driver behind the truck's side window:** still missed. The
  only "person" in those frames is the roadside shrub, flagged static.
- **Faces in the fisheye:** the man looking up into the lens still gets no
  box on his face.
- **Vehicles:** the passing truck is found in 5 of 6 frames, up from 4. The
  parked cars at night are still missed in all 6.
- **The one false alarm** is the same roadside shrub. The static rule
  removes it in the Swann clip's other frames, but in this frame (a
  whiteboard held up to the lens) its box sat in a different place.

**Lower thresholds.** `sweep` now scores the boxes that `sample` kept at low
scores. These are exactly the boxes the tool would report at each threshold:
a box is only ever dropped for a stronger one. The sweep no longer re-runs
the models on JPEG copies; the sweep above agreed with the original decode
on 251 of 287 frames. Tiled, as reported:

| Person threshold | Found | False alarms |
|---|---|---|
| 0.3 (the model returns nothing lower) | 42 of 57 | 6 |
| 0.4 | 35 of 57 | 0 |
| **0.5 (the tool's)** | **24 of 57** | **1** |
| 0.6 | 19 of 57 | 13 |

At 0.4 the tool would find 35 people with no false alarm. **The threshold
was left at 0.5.** Choosing 0.4 on the same labels it would be judged by is
fitting the test. It needs a second labelled set first.

Faces at 0.7 find 12 of 27 with 4 false alarms. Vehicles at 0.4 find 7 of
12 with 5 false alarms. Both keep their thresholds.

**Cost.** Tiling costs about 9 times the model time per frame: 2.2 s against
0.24 s on the team's laptop CPU, measured while other work was running.
`analyse-video --tiles 1` is the untiled tool, box for box. On these 287
frames it reproduces the earlier run's detections exactly (0 of 287 frames
differ), and scores 0 of 57 people again. For triage of long footage, use
`--tiles 1` or a lower `--fps`, then run tiled on the stretches that matter.

**Limits.** Six clips, labelled by one person, and only three of them
contain people. The 24 people found come from two clips. This measures
the direction and rough size of the gain; it does not predict recall on
other cameras.

### Better models, checked on footage never used for choosing (29 Sep)

**Why.** SSD-MobileNet v1 (2017) and UltraFace are small, old models. Even
tiled, the tool found a person in 24 of 57 frames. And every choice so far
(the tiling, the resolution) was made on the same 287 frames it was scored
on.

**What was tried**, with the same frames, labels and rules:
- For objects: YOLOX-S and YOLOX-Tiny (Megvii, Apache-2.0), on the whole
  frame and with 2 x 2 and 3 x 3 tiles.
- For faces: YuNet (OpenCV Zoo, MIT), on the 640 x 360 frame and on the
  1920 x 1080 frame.
- Every model file is pinned by SHA-256 (`analytics/models.py`), and
  `analytics/fetch_models.py` fetches and checks them.

**A second test set: CAVIAR.**
- Six clips of real CCTV from the EC-funded CAVIAR project (IST 2001 37540,
  CC BY-SA, https://homepages.inf.ed.ac.uk/rbf/CAVIAR/):
  - three from the INRIA lobby, a wide-angle camera looking down
  - three from a shopping-centre corridor
- Every person is boxed by hand in CAVIAR's own ground truth.
- One frame a second: 269 frames with 1,089 labelled people.
- **It played no part in any choice**; it only checks them.
- `python -m validate.caviar_eval DIR` reproduces it.

Results as the tool reports them (static and implausible rules applied),
threshold 0.5. Each set-A cell gives frames found, then false alarms:

| Model set | Set A: person (of 57) | face (of 27) | vehicle (of 12) | CAVIAR: people found (of 1,089) | by height: under 40 px / 40-80 / 80+ | CAVIAR: person in a frame with nobody labelled | Model time per frame |
|---|---|---|---|---|---|---|---|
| Classic, untiled (28 Sep) | 0 · 0 | 3 · 0 | 4 · 0 | 341 | 0 / 134 / 207 | 1 of 11 | 0.05 s |
| Classic, 3 x 3 tiles (above) | 24 · 1 | 11 · 0 | 5 · 0 | 543 | 19 / 297 / 227 | 4 of 11 | 0.40 s |
| YOLOX-S + YuNet, 2 x 2 tiles, all objects at 0.5 | 32 · 5 | 12 · 0 | 8 · 0 | 777 | 74 / 465 / 238 | 2 of 11 | 0.62 s |
| **The same, people at 0.4 (the default since 29 Sep evening)** | **39 · 5** | **12 · 0** | **8 · 0** | **810** | **83 / 487 / 240** | 2 of 11 | 0.62 s |
| YOLOX-S + YuNet, whole frame (`--tiles 1`) | 10 · 4 | 12 · 0 | 8 · 0 | 752 | 68 / 446 / 238 | 0 of 11 | 0.24 s |

(The height bins hold 297, 536 and 256 people.) The model times are from the
comparison run on the team's laptop CPU.

Variants tried and not adopted:
- YOLOX-S with 3 x 3 tiles: 22 of 57 people, with 37 vehicle false alarms.
- YOLOX-Tiny with 3 x 3 tiles: 31 of 57 people, with 6 person and 6
  vehicle false alarms; 745 people on CAVIAR.
- YuNet on 640 x 360: at most 11 of 27 faces, and none above 0.8.

What the numbers say:
- **On CAVIAR, YOLOX-S finds 777 of 1,089 people, against 543.** The gain
  is in small and mid-sized people: 74 against 19 under 40 px, and 465
  against 297 at 40-80 px. Even untiled it finds 752, in 0.24 s a frame.
- **On set A** it finds people in 32 of 57 frames (24 before), vehicles in
  8 of 12 (5) and faces in 12 of 27 (11).
  - The seated Amcrest pair is found in 14 of 15 frames (4 before). YOLOX's
    boxes on them vary enough from frame to frame that the static rule no
    longer removes them.
  - The fisheye: 18 of 39 (20 before).
- The roadside shrub is no longer taken for a person.
- **The 5 false alarms on set A are one moment:** a hand holding a test
  board up to the Swann lens (4.0-5.0 s). YOLOX boxes the arm as a person.
  By the labelling rule a hand alone is not a person, so these count
  against the tool, although a person is there.
- **A false alarm on CAVIAR:** the INRIA reception desk with its armchairs
  is boxed as a person in some frames, including 2 of the 11 frames with
  nobody labelled.
  - Its box changes size enough to escape the static rule.
  - Loosening the rule does not catch it, and it drops the seated pair on
    set A (32 found becomes 22). So the rule is unchanged.
- **Boxes that match no labelled person on CAVIAR:** 40, against 14 for the
  tiled classic set. Looked at by eye, most are real people:
  - a head boxed separately when a tile edge cuts a person
  - someone CAVIAR did not label, e.g. a head entering at the bottom edge

  The rest are the reception desk.
- **Faces:** YuNet finds about as many as tiled UltraFace (12 against 11 of
  27, with no false alarm), but it is cleaner before any rule.
  - At its threshold, YuNet said "face" in no frame without one. UltraFace
    did in 58 frames (the fisheye's bright centre), which the
    implausible-box rule then removes.
  - On the second drive UltraFace boxed floors and buckets as faces (§8a
    above). YuNet has not been run there.

**Thresholds.**
- Objects stay at 0.5, the tool's standing value.
- YuNet's 0.7 was chosen on set A, the only set with face labels (0.6: 13
  found and 1 false alarm; 0.8: 10 found).
- YOLOX's person false alarms do not rise as the threshold falls: 5 from
  0.2 to 0.5, the hand again. At 0.4 the tool would find 39 of 57 people on
  set A and 810 of 1,089 on CAVIAR, with no more frames falsely flagged on
  either.
- Vehicles at 0.4 raise 5 false alarms on set A, so the threshold is now
  per class (`class_min` in `analytics/models.py`). **People are at 0.4**;
  vehicles and bags stay at 0.5, faces at 0.7. Measured with the tool itself:
  - Set A: people 39 of 57 (32 at 0.5), still the same 5 false alarms (the
    hand). Faces and vehicles are unchanged.
  - CAVIAR: 810 of 1,089 people (777), and 209 of 258 frames with a person
    (202). A person is still reported in 2 of the 11 frames with nobody
    labelled.
  - 11 more CAVIAR boxes match no labelled person (51 against 40). Looked at
    by eye, 6 are real people: two heads entering at the corridor's bottom
    edge, a distant walker at its far end, and leg-only boxes of people who
    are also boxed whole. The other 5 are the reception desk again, all in
    frames that have a real person too.
  - 0.4 was first seen on set A's sweep; CAVIAR, which played no part in
    choosing, confirms it.

**Reproducing.**
- `python -m validate.analytics_eval sample ... --models yolox`, then
  `score`, gives set A.
- `--models classic --tiles 3` gives the tiled result above on 286 of 287
  frames identically. The 287th is the last frame of `dav-sample.dav`, which
  is damaged ("error while decoding MB 75 25"). ffmpeg conceals the damage
  differently on every decode (5 decodes gave 5 different pictures), so its
  boxes move slightly.
- `python -m validate.caviar_eval DIR` gives CAVIAR.

**Cost.** The whole 287-frame run took 138 s including decoding (the
tiled classic set: 71 s).

**Limits.**
- CAVIAR is 2004 footage at 384 x 288, upscaled, and its labels miss some
  people.
- Set A has people in only three clips.
- Neither set is from an Indian recorder, and these models have not been
  run on the team's drives.

### Cameras that look down: rotation (29 Sep)

**Why.** After the model change, the misses were concentrated in one camera:
16 of set A's 18 missed person frames and 11 of its 15 missed face frames
were the ceiling fisheye. Seen from above, people lie at every angle round
the picture, and the detectors were trained on upright people. The man
looking up into the lens is upside down in it.

**The change.**
- For a camera that looks down, both models also look at the whole frame
  turned a quarter, a half and three quarters of a turn. Each box is turned
  back (`analytics/tiles.py` `unrotate`) and merged with the rest.
- `analyse-video --rotate auto` (the default) does this for **round fisheye
  pictures**: a lit disc with nearly black corners (burned-in text in a
  corner is allowed). On the labelled clips it picked all 98 fisheye frames
  and none of the 458 frames from other cameras.
- `--rotate on` is for a ceiling camera that is not a round fisheye; the
  examiner knows how the camera was mounted. `--rotate off` turns it off.
- A rotated frame costs about 0.36 s more model time.
- The idea is established: RAPiD (Duan et al., CVPR Workshops 2020) detects
  people in overhead fisheye images by rotation-aware boxes. This is its
  simplest form, with the models the tool already has.

**Measured with the tool** (`analytics_eval sample`, then `score`; and
`caviar_eval`):

| | Before (people at 0.4) | Rotation `auto` |
|---|---|---|
| Set A: person | 39 of 57, 5 false alarms | **44 of 57**, 6 false alarms |
| Set A: face | 12 of 27, 0 false alarms | **22 of 27**, 1 false alarm |
| Set A: vehicle | 8 of 12 | 8 of 12 |
| The fisheye clip: person / face | 23 of 39 / **1 of 12** | 28 of 39 / **11 of 12** |
| CAVIAR (no round pictures) | 810 of 1,089 | 810 of 1,089 (unchanged) |
| CAVIAR, lobby turned (`--rotate on` for its 3 clips) | lobby 26 of 189 | **lobby 53 of 189**; all of CAVIAR **837**; under 40 px 109 of 297 (83) |

- **The new false alarms.**
  - The person one is a hand at the top of the fisheye picture, like the
    five before it.
  - The face is a head at the fisheye's top edge, labelled "no face"
    because it is not turned to the camera.
  - With the lobby turned, one more CAVIAR frame with nobody labelled has a
    person reported (3 of 11): the reception desk again, and a plant pot by
    the window. There are 58 unmatched boxes (51 before).
- **Why not rotate every camera.** Turning every frame of set A found
  nothing more on the upright cameras. It did add 6 false face frames on the
  Swann street camera: a fixed spot read as an upside-down face. Hence
  `auto` turns only round pictures.
- **Still missed on the fisheye:** 11 person frames (people on the floor
  below, small and bent by the lens) and 1 face (the installer upside down
  and blurred close to the lens).

### Parked vehicles (29 Sep)

**Why.** On our own drive, the car parked in full view in *Parking* at night
was boxed by YOLOX in all 35 frames, at 0.25-0.47. It was never reported,
for two reasons:
- its scores were under the 0.5 vehicle threshold;
- a parked car is static by definition, and the static rule (made for a
  steel pot scored as a face) removes it.

On set A the rule likewise dropped the parked cars in the night car park.

**The change** (`analytics/static.py` `parked_spots`).
- A car, bus or truck seen in the same place through much of a clip (the
  static rule's own test) is reported **once per place, as a parked
  vehicle**: a lead of its own, with its first and last time and the number
  of frames it was seen in.
- Its boxes are kept from 0.3 (`parked_min`). A box that comes back at the
  same place frame after frame is stronger evidence than one box at that
  score.
- A car box under 0.5 that is not part of a parked vehicle is marked
  "weak" and not counted.
- Moving vehicles are counted frame by frame as before, from 0.5.
- Bicycles and motorcycles are not parked leads. At low scores the model
  called chair legs in the studio clip "bicycle", in the same place.

**Measured with the tool:**

| | Result |
|---|---|
| Set A: parked vehicles | **8 places, all real cars**: the 6 cars in the night infrared car park, each seen in 5-6 of its 6 frames (0.37-0.84; before this, a vehicle was counted in only 2 of those frames), and the car parked at the Swann/Lorex street edge (0.87-0.88; set A's labels leave it out by their ~15-pixel rule) |
| CAVIAR (no vehicle in any scene) | **0 parked-vehicle places**, so none false |
| Set A: moving vehicles | 7 of 12 frames (8 before). One night-car-park frame's car is now recognised as parked and reported as such, not as a moving vehicle |
| People and faces | unchanged: 44 of 57, 22 of 27 |

**On our own drive (30 Sep), re-scored from the stored boxes.**
- `validate.analytics_eval apply` re-applies today's thresholds and rules to
  the boxes a sample stored. Its `detections.json` and `labels.csv` are
  enough, with no frames or video.
- On set A, `apply` then `score` on the earlier sample gives exactly the
  result of a fresh run of the current tool.
- For drive 1, Shrestha sent the two text files of the YOLOX set (210
  frames): `detections.json`, SHA-256 `b8680a61…2175cde`; Claude's
  `labels.csv`, `7295e5ef…`; and his reviewed labels, `d381a9f1…0db0ebba`.

| | Claude's labels | Shrestha's reviewed labels |
|---|---|---|
| **Parked vehicles** | **1: the car parked in *Parking* at night**, seen in 26 of its 35 frames (up to 0.47). All 33 frames in its span are labelled as holding a vehicle. No other parked vehicle, so none false. | the same |
| Person | 2 of 3 found | **2 of 2** |
| Person false alarms | 3 of 207 frames | 3 of 208 |
| Face | none to find; 0 false alarms | 0 of 1 (a ~5 px head in shadow); 0 false alarms |
| Moving vehicles | 0 of 100 | 0 of 92 |

- **The night car, missed until now, is reported.** It is boxed in all 35
  frames at 0.23-0.47, and 26 reach the parked threshold (0.3).
- **The person false alarms are two things.** One is a dog (0.71). The
  other is the tree trunk in front of the red car, in frames 54, 59 and 62:
  the static rule flags that spot in most frames, but its box shifts enough
  in these three to escape it. Both are the static rule's known gap.
- **The moving-vehicle misses are the far car** (~19 x 9 px, which the
  person's review reads as no vehicle at all) **and the red car half-hidden
  by a tree**, parked in daylight. Its boxes stay under 0.3, so it is not a
  parked vehicle either.

### On our own drive (29 Sep): 210 frames of the CP Plus cameras

The runs above are public clips. This is the same measurement on the team's
own cameras. `analytics_eval sample --frames 35` took six indexed drive-1
recordings - *Road View 1*, *Road View 2* and *Parking*, at 17:00 and at
22:00 on 3 Sep 2026 - with the tool's 3 x 3 tiling
(`out/realchecks/drive1_recall/`: `labels.csv` SHA-256 `7295e5ef…cab81f`,
`detections.json` `8505aeef…fb132cb`).

**Who labelled it: Claude, an AI model, at the user's request - not a
person.** Every frame was viewed at its stored size. Distant areas were
enlarged on every frame, and candidates at 4-6x. A change map against each
camera's median frame, independent of the detector, pointed at small
movers. The per-frame detections were not read until every label was
written (`LABELS.md` beside the labels). A person then checked the frames
the scores turn on (below); the other frames are the model's labels only.

What the 210 frames hold:
- a person in 3: one about 14 px tall beside a cow in a far field, and two
  walkers on *Road View 2*, one partly behind a tree;
- no face;
- a vehicle in 100:
  - the car parked in *Parking* at night, in full view (35 frames);
  - a small car at the far end of *Road View 1* (5);
  - a red car parked past the gate on *Road View 2*, partly hidden by a tree
    (60, marked borderline).

| Class | Found, as the tool reports | False alarms | Found, as the models said (before the rules) |
|---|---|---|---|
| Person | **0 of 3** (0 of 2 without the borderline frame) | **2 of 207** - the *dog* in frame 59 (0.75), and a smear in a corrupted frame (0.54) | 0 of 3 |
| Face | none to find | **7 of 210** - one patch of grass between branches on *Road View 1*, 0.81-0.95, in 7 of 35 frames | - |
| Vehicle | **1 of 100** (0 of 40 without the red car) | 0 of 110 | 15 of 100 (14 of 40) |

What this adds to the public-clip results:
- **The static rule has a gap.** The 7 "faces" sit on one fixed patch of grass.
  They recur in 7 of 35 frames, under the rule's 25% share (`STATIC_SHARE`),
  so every one is
  reported. On the public clips no false alarm got through; here 7 of 210
  frames carry one.
- **The one vehicle "found" is the right frame, the wrong place.** Frame 68
  holds the red car, but the box is on a small grey lump at the roadside,
  there in other frames too. By object, the tool found none of the vehicles.
- **Parked vehicles are removed by design.** The model sees the *Parking* car
  in 14 of 35 night frames after tiling (0 before it: it said *suitcase*).
  The static rule then removes every one, as on the public clips.
- **No person was found**, and one of the two person reports is a dog. The
  people here are small or partly hidden; the sweep finds none at any
  threshold down to 0.2, where the false alarms rise to 10.
- **The sweep:** vehicles as the models said rise to 50 of 100 at 0.2-0.3,
  with no false alarm, and 22 of 100 remain after the rules. These are
  frame-level: a box anywhere in the frame counts, so some may be boxes on
  something else, as in frame 68. Faces at 0.5 give 14 false alarms.

**Checked by a person (Shrestha, 29 Sep).** The review covered 22 frames:
the 20 the scores turn on, plus 2 controls. They were shuffled and shown plain,
with neither the labels nor the detector's boxes, and a 4x magnifier on hover
(`out/realchecks/drive1_recall_review/`, `review_labels.shrestha.csv`
SHA-256 `c90d8b3b…fb0`).

The person agreed on **12 of 22 frames**, and by class on:
- person, 21 of 22;
- face, 21 of 22;
- vehicle, 14 of 22.

| Confirmed by the person | Different reading |
|---|---|
| All 7 face false alarms: no face (11, 12, 13, 18, 19, 22, 26) | Frame 1: no person (the ~14 px figure beside a cow, marked borderline) |
| Both person false alarms: no person (6, the corrupted frame; 59, the dog) | Frame 48: **a face** - the walker faces the camera; the head is ~5 px and in shadow |
| Both walkers: a person (48, 51) | The far car (30, 32, 34): no vehicle - a ~19 x 9 px dark shape |
| The *Parking* car (control 190), the empty control (90), the infrared frame with no car visible (150), and the red car in 48 and 68 | The half-hidden red car in 35, 51, 59, 142, 162: no vehicle (marked borderline) |

Every difference is an object at the edge of what the frame shows at its
size: the person looked at 1.25x with a magnifier, the labels were made at
4-6x. On the person's reading - no far car, no borderline frames, and a face
in frame 48 - the tool reports:

| Class | Found, as the tool reports | False alarms |
|---|---|---|
| Person | **0 of 2** | 2 of 207 |
| Face | **0 of 1** | 7 of 209 |
| Vehicle | **0 of 35**, the parked *Parking* car; 14 of 35 before the static rule | 0 of 110 |

No conclusion above changes. The false alarms the findings rest on are
confirmed by a person, and the tool found none of the people or vehicles on
any of the three readings.

Before any label, re-sampling the same 210 keyframes before and after tiling
showed what tiling changes:

| Clip | Before tiling (models said) | With tiling (models said) | With tiling, reported |
|---|---|---|---|
| *Parking*, 22:00 (a car parked in full view in every frame) | *suitcase* 35 of 35, *car* 0 | *car* 14, *suitcase* 23, *backpack* 1 | *backpack* 1 - every *car* flagged static |
| *Road View 1*, 17:00 | *person* 1 | *person* 1, *face* 7 | the same |
| *Road View 2*, 17:00 | *person* 1 | *person* 2, *car* 1 | *person* 1, *car* 1 |
| the other three | nothing | *suitcase* 1 (*Road View 2*, 22:00) | the same |

### On our own drive, with the new detector (29 Sep, evening)

The same 210 frames were scored again with the tool's new default:
- YOLOX-S (`c5c2d13e…`) and YuNet (`ebafce4e…`);
- 2 x 2 tiles;
- people at 0.4, other objects at 0.5, faces at 0.7;
- rotation `auto`.

`analytics_eval sample --frames 35` over the same six recordings took **the same keyframes**. Every
row's clip and position match, and all 210 frame JPEGs are byte-identical
(`out/realchecks/drive1_recall_v3/`).

The frames were scored against two label sets:
- **Claude's** labels;
- **reviewed**: the same labels with the person's 22-frame review applied
  (`labels.reviewed.csv`). That changes 10 labels: 8 vehicles to *no*, frame 1's
  person to *no*, and frame 48's face to *yes*. Frames outside the review keep
  Claude's labels.

As the tool reports:

| Class | Labels | Old: SSD-MobileNet + UltraFace, 3 x 3 | New: YOLOX-S + YuNet, 2 x 2 |
|---|---|---|---|
| Person | Claude's | 0 of 3 found; 2 false alarms in 207 | **2 of 3** found; 3 false alarms in 207 |
| Person | reviewed | 0 of 2; 2 in 208 | **2 of 2**; 3 in 208 |
| Face | Claude's | none to find; **7 false alarms** in 210 | none to find; **0** false alarms |
| Face | reviewed | 0 of 1; 7 in 209 | 0 of 1; **0** in 209 |
| Vehicle | Claude's | 1 of 100 (wrong box); 0 in 110 | **0 of 100**; 0 in 110 |
| Vehicle | reviewed | 1 of 92; 0 in 118 | **0 of 92**; 0 in 118 |

Every false alarm and every miss, looked at by eye:

- **People found: both walkers.** Frame 48 at 0.79 and frame 51 at 0.43;
  the second is the one partly behind a tree. The ~14 px figure beside a
  cow (frame 1: Claude *yes*, the person *no*) gets a box on it only at 0.20.
- **The dog is still a person**: frame 59 at 0.71. **A new false alarm:**
  the tree trunk in front of the parked red car on *Road View 2*, at
  0.41-0.58, in frames 54 and 62 and as a second box in 48 and 59. The static
  rule flags that trunk in 22 other frames; these four slip through, the same
  gap as the grass patch below (`STATIC_SHARE`, and box sizes that vary).
  The old detector's person in the corrupted frame 6 is gone.
- **The grass-patch "face" is gone.** No face box lands on that patch at
  any score from 0.5, and there are no face reports at 0.7. Between 0.5 and
  0.7 YuNet gives 8 boxes in 7 frames, none on a face: five specks of ~3 px,
  two on a brown sack of coir on *Road View 2*'s parapet (0.51, 0.60), and
  one on the smear of the corrupted frame 6. The one face the person marked
  (frame 48, a ~5 px head in shadow) gets no box.
- **The parked car at night is still missed.** YOLOX boxes it in all 35
  night frames, but at 0.25-0.47, under the 0.5 object threshold, so it is
  never reported. At a lower threshold the static rule would remove it as
  parked. The red car half-hidden behind a tree, and the small far car, get
  no box at 0.5 either.

The sweep, on the reviewed labels:
- **Person:** 2 of 2 found at every threshold from 0.2 to 0.4, with 15, 4
  and 3 false alarms; 1 of 2 at 0.5 and above.
- **Vehicle, as the models said:** 42, 26 and 9 of 92 at 0.2, 0.3 and 0.4,
  with 8, 4 and 1 false alarms (at 0.24 a stack of paving blocks reads as a
  *truck*). After the rules, 15 of 92 at 0.2 and none above.
- **Face:** 7 false-alarm frames at 0.5 and 2 at 0.6 (the boxes above); the
  frame-48 face is found at no threshold.

**In short, on these cameras** the new detector:
- finds the people the old one missed;
- ends the face false alarms;
- still calls the dog a person, and adds a tree trunk;
- reports no vehicle at all. The one that matters, a car parked in full view,
  scores under its threshold.

The set, detections and both label files are in `out/realchecks/`
(`detections.json` SHA-256 `b8680a610497d004…`).

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
| Decode, the 50 extracted streams, first 10 min of each (ffprobe, 28 Sep) | 291,452 video frames: **291,035 decode (99.9%)**; 353 precede the first keyframe, 64 lost after it. H.264 and H.265, 960×576 to 2560×1440 |
| Surviving Hikvision index | master sector copy + two identical HIKBTREE copies; 922 records on a 1 GiB block grid; 8 channels |
| Recorder model and unit (28 Sep) | `identify-model` over the whole drive: **`DS-7B08HUHI-K1`**, 208 times from 0x11ECDD0. The team's Hikvision DVR is labelled `DS-7B08HUHI-K1`, serial `F29196515` (`record-device`, label photo hashed): model **agrees**. The platter also carries that unit's full device serial `DS-7B08HUHI-K1 0820201218CCWR F29196515 WCVU` 202 times, so this unit wrote this drive. The model check's "differ" (a Hikvision unit, Dahua-family structures on its disk) is the known reformat; which recorder did it is not established |
| Head image (28 Sep) | first 4 GiB with `ddrescue -d`, 0 read errors, drive write-blocked throughout; all 512 blocks equal the full-drive pass. MD5 `8500709651324ce36b25b548f068144f`, SHA-256 `401d5153c94b037e8e931474bdc157ac830d9460bf51d3048d748b5990acf460` |
| Camera attribution | 2,021 of 2,516 streams inside their block's record window. Of the other 495 (`label-ps` re-run on the write-blocked drive, 29 Sep, with the `stale_tail` rule of #41): **440 `stale_tail`**, 0.6 GiB / 1.8 h in 393 blocks - short remnants that end before their block's record starts, median 31.9 days older (10th-90th percentile 31.0-105.6 days, oldest 1,228.7), so the drive was overwriting a block about a month after last writing it; camera unknown. **55 `outside_index`**, 23.7 GiB / 96.8 h, each in a block with no record at all. The 922 index records read on 29 Sep are identical to those read on 26 Sep; the only label changes are these 440, from `outside_index` to `stale_tail`. Recorded in the case ledger; `verify`: chain intact, Merkle root matches |
| Independent checks of the attribution | every camera keeps one resolution (CH03/CH04 2560×1440, CH01/02/06 960×576, CH05/07/08 1280×720, apart from 3 streams each on CH03/CH04); all eight hold 761–788 h |
| Recorded vs recovered | per the index each camera recorded continuously (~27 Jul – 30 Aug 2024); the carve recovered **99.6–99.7%** of those hours on every camera |
| Time zone | index times equal `HK` times — both local; not derivable from these |
| Labels vs the picture | two decoded frames: burned-in "Camera 01" / "28-07-2024 08:19:42" where the index gave CH01 and the `HK` time 08:19:41; "Camera 03" / "22-07-2023 11:28:55" where it gave CH03 and 11:28:53 |
| Analytics (subset of 50 streams, 22 GB) | 68,639 frames: person 517, face 73, bus 1. The two strongest "faces" (0.997, 0.978) were a floor and buckets; the "person" beside the first looks like a dog. 64 face boxes spanning most of the frame are now flagged implausible and not counted |
| Master sector (surviving copy at 0x4C56000; `hik-log`, 28 Sep, from the 4 GiB head image) | `HIK.2011.03.08`, initialised 2021-04-27 13:17:48 (recorder clock). Six checks agree: log start + size = log end (0x8200 + 0x3D0B000 = 0x3D13200); 931 blocks × 1 GiB = data size; the data area ends inside the capacity; the log precedes the data area; both HIKBTREE offsets (+0x10) are where the scan found the copies; and the data offset 0x4C5E000 is the base the HIKBTREE index gave independently |
| System log (`hik-log`) | **43,108 `RATS` records, 2024-01-28 07:51 → 2024-08-25 13:53** (recorder clock), in the 61 MiB log area. Every record whose code the SDK lists is named by it (5,615); the rest carry three information codes and one exception code it does not list (0xAA: 37,464 periodic records). **188 power-on records, each after an "illegal shut down"** (no orderly power-off): power cuts. 174 network disconnects. **One local session by `admin`, 2024-03-23 03:28:18–03:52:44: configuration, two playbacks by time.** Two records name the Hik-Connect server `litedev.ind.hik-connect.com` and hold its verification code (not reproduced here) |
| Log clock vs footage clock | 75 of 188 power-ons are followed by a new stream within 120 s at no shift, 13 at the best other half-hour shift: the log keeps the recorder's clock, like the footage — so it cannot give the time zone either |
| Footage gaps vs the recorder's log (`timeline`, 28 Sep) | 17 periods, inside the log's period, in which every camera lane is silent for over a minute (1:01–3:47 min each). **16 have a logged power-on inside the silence or within 30 s of its end**: in each the "illegal shut down" is logged 4–60 s before the footage stops and the power-on within ~5 s of it resuming. One (2024-08-08 02:02, 1.2 min) has no power-on in the log — cause not established |
| Log end vs footage end | the newest surviving log record is 2024-08-25 13:53, the ring's next slot holds its oldest (28 Jan); the footage runs to 30 Aug 00:33. The last 4½ days of log are not on the disk — unexplained (not flushed, or overwritten) |
| 212-byte records in reserved blocks | ~355,000 records in two channel-255 blocks (27 Apr 2021 – 30 Aug 2024). An earlier reading of this region as "88 MiB of H.265 in an unknown container" was wrong: the scanner's start-code counts were false positives on these records. Meaning not established |

## 8e. Third real image: a recorder we had never seen (HeimVision K9604-W)

The NIST CFReDS *Heimvision DVR .E01 Forensic Image* (Brunty & Mock, Marshall University, 2021): a HeimVision K9604-W 4-channel DVR's 150 GB disk, FTK Imager 4.3.1.1, media MD5 `4895ea6d10b08c29fb1bb03591adc7b2`. Not one of the eight PS vendors - which is the point: the
add-a-vendor route (detect -> survey -> plugin) tried on a real disk.

**The image checks the reader.** `ewf-info --verify` read all 150,039,945,216
bytes (3 segments, 4,578,856 chunks, 4,546,985 compressed) through
`acquire/ewf.py`: computed MD5 `4895ea6d10b08c29fb1bb03591adc7b2` and SHA-1
`06f48890961187979ed4142ceab8a7144bd4dfea`, **both equal to what FTK Imager
recorded**. The E01 reader is therefore validated on a real third-party image.

**What the disk holds** (read off it, then implemented as
`plugins/heimvision.py`): GPT; partition 1 ext3 (`search.db`, `dvr_log.db`);
partition 2 FAT32 by `mkdosfs` with `ident.bin` ("ok1ormated"), `index.bin`,
and a pre-allocated ring of **17,152 files of 8 MiB** (`dirNNNNN/fileNNNN.dat`).
Each file opens with a 0x2080-byte header (magic `luo `, start and end on the display clock,
per-channel times); then a chain of frames, each with a 128-byte header
`liu ` ... ` uil` whose length field reaches the next header exactly on all
9,679 frames of the first file. The header names the **camera** (+0x2C), the
frame type (1 I, 2/3 P, 0 audio - G.711 A-law), a per-camera sequence, and a
**microsecond** time on the recorder's display clock (below). Unlike Dahua, footage is attributable per camera
with no index.

**What was recorded:** 806 of the 17,152 files - 6.30 GB, one continuous day
on all four cameras:

| Camera | Video frames | Keyframes | First -> last frame (recorder-local, frame clock) | Rate | Gaps > 2 s |
|---|---|---|---|---|---|
| CH01 | 1,296,146 | 8,609 | 2021-08-04 13:59:51.443 -> 2021-08-05 14:00:01.172 | 15.000 fps | 0 |
| CH02 | 1,296,105 | 8,619 | 2021-08-04 13:59:43.517 -> 2021-08-05 14:00:01.292 | 14.998 fps | 1 (8.0 s, at the start) |
| CH03 | 1,296,121 | 8,602 | 2021-08-04 13:59:43.604 -> 2021-08-05 14:00:01.208 | 14.998 fps | 1 (8.0 s, at the start) |
| CH04 | 1,295,950 | 8,449 | 2021-08-04 13:59:43.126 -> 2021-08-05 14:00:01.268 | 14.996 fps | 1 (7.6 s, at the start) |

- Frame counts check themselves: 86,410 s at 15 fps is 1,296,150 frames;
  CH01 has 1,296,146.
- **The recorder's clocks, measured on the disk (corrected 29 Sep 2026):** the
  frame times are the recorder's *display* clock, the one it paints on the
  picture. CH01's keyframes 0, 43 and 86 show 13:59:53, 14:07:03 and 14:14:13
  on screen, and their frame headers give the same seconds. So every time the
  recorder writes (frames, file headers, its log and index) is local
  wall-clock time written as if it were UTC. Its *system* clock, which stamps
  the FAT entries, is exactly 8 h behind on all 806 files: the display clock
  is the system clock plus a zone setting of **UTC+8**. This section first
  said "set to UTC-8", reading the frame times as true UTC; the painted clock
  shows that reading was wrong. Marshall University is at UTC-4 in August, so
  whether the display clock was right is not on the disk: the parse reports
  recorder-local times and states UTC only with the examiner's `--tz-offset`.
- **The recorder's own records, read and checked against the disk**
  (partition 1 is ext3, read by `parsers/ext3.py`; `index.bin` is on the FAT):
  - `dvr_log.db`, its event log (SQLite): 194 entries, ids 1-194 unbroken, so
    none deleted. "reload environment." twice, 48 s after the partition was
    made; "Rec begin" on all four cameras at 13:59:50-51 (recorder-local); a stop and begin
    per camera every hour; the last "Rec stop" at 14:00:01 the next day. No
    clock or zone change is logged.
  - `search.db`, its recording index (SQLite): all 806 files listed, **806 with
    exactly the start and end their own header gives**; 96 camera-hour
    segments, and every frame carries its segment's id (header +0x04). Its
    per-hour frame counts are within 0.04% per camera of the frames on disk
    but not equal, so they are reported, not used as ground truth.
  - `index.bin`: one byte per file slot - `x` on 805; the one written file
    not marked is the last, still open when recording stopped.
- **The zone, measured a second way:** the ext3 times of `dvr_log.db` and
  `search.db` (the recorder's system clock) are 8 h behind the last time
  each database holds - UTC+8 again, from a different file system. Both
  measurements come from the recorder's own clocks; its error against true
  time is still unmeasured.
- **Pre-record, now bounded:** the first video of CH02, CH03 and CH04 is 7.5,
  7.4 and 6.9 s before that camera's "Rec begin" in the log (CH01's is 0.4 s
  after). Footage from before the recorder logged the start is consistent
  with a pre-record buffer; that is still not established.
- **Frame header, decoded further:** +0x04 the camera-hour segment, +0x28 the
  camera number, +0x48 Unix seconds, +0x4C 0 on I-frames and 1 on P-frames.
  +0x50/+0x54 are file offsets of an earlier frame's video (the same camera's /
  any camera's, 0-2 s back); what they are for is not established. Audio is
  stamped up to ~1 s behind the video beside it.
- **Still not explained:** ~300 frames per camera (0.02%) carry a time earlier
  than the frame before them; the per-channel offsets and sizes in the file
  header; how `search.db` counts its frames and bytes.
- Camera 1 extracted: 403.26 MB of H.265, 1,296,146 frames, SHA-256
  `0afab158218c9bf0...` (full value in its manifest).

**The no-parser carver, scored on this disk.** Before the plugin existed,
the only way to get video off this recorder was `carve-annexb`, which knows
H.264/H.265 and nothing of the container. Here the plugin knows every frame,
so the carver can be scored on real data, which no generated test can do:
`python -m validate.heimvision_carve <E01>` carves every part of the image
that holds data (178 regions, 6.47 GiB, read off the E01's chunk table), then
places every `00 00 01` in the 806 written files by the parser.

| | Carver (no parser) | Parser (HeimVision plugin) |
|---|---|---|
| Codec, picture | H.265 1920x1080, one parameter set | H.265 1920x1080 on all four cameras |
| Video | 5,187,890 slices | 5,184,322 frames: 5,184,225 hold one slice each, 97 none |
| Keyframes | 35,163 | 34,279 (each with VPS, SPS, PPS: 102,837 NAL units) |
| Streams | 161, one per data region holding video | 4 cameras, 4 recordings |
| Camera, time | none | on every frame |

- **Every slice in the files is accounted for.** The carver's count equals every
  slice-shaped start code in the 806 files less one per stream (a stream
  leaves out its last NAL unit, whose end is unknown): 5,188,051 - 161 =
  5,187,890, exactly; keyframes 35,163 = 35,163.
- **3,826 of those slice-shaped start codes are not in any video frame**
  (0.07%): chance `00 00 01` in the 128-byte frame headers (3,345), the file
  headers (449), audio (19), and past the end of a file's frame chain (13).
  884 of them look like keyframes - 2.5% of the carver's keyframe count. The
  other 13.37 M chance start codes in the frame headers fail the NAL header
  check and are passed over, as designed.
- **The four cameras cannot be told apart.** They share one parameter set,
  so every carved stream interleaves all four - the limit the carver's own
  report states, now seen on a real disk. Only the container separates
  cameras, and only it carries time.
- `carve-annexb` therefore stays `synthetic_only`: its slice finding is
  measured on real media, but the streams it made here are not any one
  camera's footage.

**Named by a scan** (29 Sep). The disk carries no brand string, so until
now a scan reported no vendor for it although the parser read it. The plugin
now declares signatures for the recorder's own structures, all in the first
11 MB: its system partition's mount point `/root/rec/a1` (ext3 superblock)
and the schemas of its event log and recording index. A scan of the first
16 MiB names **HeimVision at 98-99.5%**, with its parser available.

**Checked against FTK Imager's own reading of the disk** (29 Sep,
`python -m validate.ftk_listing IMAGE.E01 LISTING.csv`). The image ships with
the file listing FTK Imager 4.3.1.1 made when it was acquired
(`HeimVision K9604-W File Listing.csv`, 17,418 entries). FTK's FAT32 and ext3
code is commercial and independent of ours:

| Check | Result |
|---|---|
| FAT32 files | **17,154 in both** (17,152 `.dat` plus `ident.bin` and `index.bin`), none only on one side |
| Sizes | **0 differ** |
| Write times | **0 differ**; both show the same 808 entries written and the rest never written (FTK "N/A") |
| ext3 system files | `dvr_log.db`, `search.db`, `pbversion`, `manual_rec_status.bin`: size, mtime and atime **identical** |
| Zone setting | FTK prints `dvr_log.db`'s mtime as 2021-08-05 06:00:00 UTC; the recorder's log ends at 14:00:01 on its display clock: **UTC+8**, the same as the plugin measures (and not the UTC-8 first reported) |
| Deleted entries | none, on either side |

This confirms the filesystem reading, not the video format: FTK does not
parse the `.dat` contents.

**Status:** `spec_only` - observed on real media, not byte-matched against a
HeimVision export. `tests/test_pipeline.py` pins these numbers when
`HEIMVISION_E01` points at the image.

## 8f. Two more vendors, from their own firmware (Uniview, TP-Link)

No disk from either is held, and nothing is published about either format
(OEM_COMPARISON §5.1). Both vendors publish their firmware, though, and the
code that writes the disk says what the disk holds. Two firmware images were
unpacked and their storage code read by **static disassembly** - nothing was
run (`docs/research/vendor_formats.md`). A new evidence level records this:
`vendor_firmware`, ranked with a paper - it says what the recorder is
programmed to write, not what a disk showed - so both stay at most
`spec_only`.

**Uniview** (NVR301-04LS3-W, B3612.1.21.220408; storage is the kernel module
`comm.ko`, whose symbol table survives, so each structure is tied to a named
function):

| Structure | From the driver | Checked in the plugin |
|---|---|---|
| Superblock, 64 KiB at LBA 0 and a copy at the end | magic 0x20131031, version 0x2000, CRC-16, device ID, UUID, capacity, block count, abstract/data zone positions (`UBS_RS_SuperInit`, `UBS_MT_PrintSuper`, `UBS_RS_OpenSuper`) | CRC-16 (the kernel's `crc16`); the copy used if the head fails |
| Abstract zone | one 128-byte entry per data block, 31 to a 4 KiB group, CRC-16 per group (`UBS_RS_SetupAbstNode2`, `UBS_RS_CrcCheck2`) | group CRCs |
| Data blocks | 256 MiB each, block *n* at DzPos + *n* × 256 MiB (`UBS_Open`) | |
| Block header, 8 KiB | 0x5050 v0x400: channel id, start/end time + ms, counts, write position, segments (`UBS_MT_DispDiskDbSuper`) | CRC-16 |
| GOP index at +0x2000 | 32 bytes per GOP: time, and start and length in 4 KiB pages (`UBS_DB_SetSubIndx4`) | |
| GOPs | header 0x2006; packets 0x1357 (DTS, PTS, flags, length); end 0x6002; the last 8 bytes of the GOP's last page hold its length and 0x6003 (`UBS_DB_RecoveryFromDataBlk`, `UBS_DB_ChkIGrpInfo`) | every GOP: the stated length must equal the bytes walked |

That trailer is what makes Uniview footage recoverable with no index: the
plugin walks GOPs by their own structure, as the recorder does when it
repairs a block. GOPs past a block's write position are reported separately,
as older footage (research gap G2, `docs/research/papers_usp.md`).

**TP-Link VIGI** (NVR1008H V2, 240119; `liblayouthddb.so` and TP's own
`libsqlite3.so`):

| Structure | From the firmware |
|---|---|
| Two layouts | V0: TP's partitioning, swap, ext4 with `sys.bin` and zone files; V1: raw disk |
| V1 format sector | at 512 MiB (retried up to 560 MiB past bad sectors): "TP-Link Corporation Limited, NVR FOR VERSION x.y.z", CRC-32 at +0x1FC (`rawDiskLayout_diskInfoFormatCheck`) |
| The index | SQLite behind a 512-byte "TpFile" header: magic "TP-Link format1", then key slots (big-endian type, encrypt, length, data) (`sqliteTpFileInit`, `getTpFileKey`) |
| Encryption | TP's SQLite build carries an AES codec (`CodecAES`, `sqlite3_key`); the layout library calls `db_encrypt()` with a key taken from the header's slots |
| Tables | `tEventInfo` (recording per camera), `tGopInfo` (each GOP's zone, offset, length), `tZoneInfo`, `tSlogInfo` (the system log, on the disk) - from the CREATE TABLE statements |
| Not recovered | the zone geometry (data-zone start, zone size): loaded at run time from an on-disk record whose layout was not read; the GOP header |

So the TP-Link plugin reads the index where it is plain SQLite, finds its
tables by their columns, and reports each camera's recordings and the system
log as the index states them. It places **no** footage on the disk; video is
recovered by `carve-annexb`. Where the index is encrypted it says so, and
stops.

**What is tested**: disks built to these readings (`tests/synth_uniview.py`,
`tests/synth_tplink.py`, 18 tests). They prove the code follows the firmware
as read. They cannot prove every model and firmware version writes the same,
and nothing here has met a real Uniview or VIGI disk. The first such disk
is the test: its superblock CRC, group CRCs and GOP trailers either check or
they do not.

## 8h. Matrix, from its own documents

Matrix publishes no firmware (its download server asks for a login) and no
format. Its support documents do describe the disk, though. "How to Backup
recording files from HDD in SATATYA Devices?" (Matrix Wiki, V1R1, 2018) says
the recorder keeps its recordings as ordinary files in a folder tree:

`<volume>/CameraNN/DD_Mon_YYYY/HH/HH_MM_SS~HH_MM_SS.stm1`

with `.evnt`, `.ifrm` and `.tmid` files beside each recording. The worked
example is `\\192.168.51.254\hvr\RAID0\Camera01\21_Apr_2018\14\14_47_19~14_59_59.stm1`.
The system manual (V8R7) adds that the NVR runs embedded Linux and formats
the disk itself, and that only Matrix's Device Player plays or converts a
`.stm` file.

`plugins/matrix.py` reads that tree:

| What | How | Tag |
|---|---|---|
| Filesystem | ext2/3/4 on the whole disk, in an MBR/GPT partition, or in one mirror of a Linux md RAID 1. **Which filesystem Matrix uses is not documented**; XFS or a striped RAID member is named in the report, not read | ext4: kernel documentation |
| Cameras | `CameraNN` folders, up to three levels below the root | Matrix document |
| Recordings | one per `.stm<N>` file: camera, date and hour from the folders, start and end from the file name - the recorder's clock, not converted; the file's inode time as a second statement | Matrix document |
| Where on the disk | every byte of each file located through the filesystem (extents or block maps) | ext4 |
| Codec | from the first NAL unit inside the file | measured |
| Extraction | the `.stm` and its sidecars **as stored**, each hashed - the container is not published, so it is not unwrapped; coded pictures counted from the slices inside | |

The ext reader (`parsers/ext3.py`) gained ext4 for this. It now reads
extent trees (in the inode and behind index blocks), allocated-but-unwritten
extents (as zeros) and 64-bit group descriptors, and still refuses what it
does not read (inline data, encryption, compression, meta_bg). It is tested
on an ext4 image built to the kernel's documented layout (4 tests).

**What is tested**: disks built to the documents (`tests/synth_matrix.py`, 8
tests). The disks have two cameras, H.264 and H.265 recordings split into
fragments, sidecars, and a stray file. They come in four layouts: plain,
RAID 1 member, RAID 0 member and XFS. As with Uniview, only a real Matrix
disk can show whether its filesystem is ext4 at all.

## 8i. Export in NIST's CCTV profile (NISTIR 8161 Rev. 1, Level 0)

NIST wrote an export profile for CCTV at the FBI's request (NISTIR 8161r1,
2019). It asks for:
- an MP4 holding one H.264 stream;
- in every frame, two SEI messages: a MISB ST 0604 precision time stamp
  (UTC, microseconds) and a "timesource" code saying how the recorder's clock
  was set;
- at the end of the file, an XMP packet with the **ClockOffset**: the
  recorder's clock and a reference clock, read at the same moment.

This is the "no UTC without a stated zone" rule (§8) in a standard,
machine-readable form. `cli.py export-nist` writes it from an extracted
H.264 stream (`report/nist_export.py`, USER_MANUAL §3.4m).

| Check | Result |
|---|---|
| Against **NIST's own reference file** (`WEB3.mp4`, biometrics.nist.gov/cs_links/DVR_Standards/) | its stream re-exported with its own times: **all 355 MISB time-stamp SEI messages byte-identical** to NIST's; the pictures unchanged |
| Decoded by ffmpeg | **the same 355 pictures** as NIST's file (MD5 per frame), and no decoder error. NIST's own file draws "SEI type 5 size 13 truncated": it declares 13 bytes for an 11-byte "timesource" record; ours declares 11 |
| ClockOffset XMP | well-formed, in NIST's two namespaces, codes and elements as in `ClockOffset.xsd` and `TimeValueset.xsd`. NIST's published example is not well-formed |
| Pictures untouched | proven on every export: the SHA-256 of the input's NAL units equals that of the MP4's video NAL units read back from the written file, less the added SEI |
| UTC | only with a stated zone; the recorder's measured clock error is applied and the rule recorded. Without a zone, no time stamp is written and the file is marked not Level 0 |
| H.265 | refused: Level 0 is H.264, and re-encoding would alter the evidence |

What it does not claim: the export is a derived copy for exchange and
playback, not the evidence. Its per-frame times come from the recorder's
clock, via the plugin's frame times or a start time and frame rate. The MISB
status bit 7 is set ("lock unknown"), because a recorder's clock is not
known to be locked to true time.

## 8c. OSD reader (optional layer — on six real recorders' files: clock found on 3 of 6, 5 of 36 clock frames exact, no title right)

`cli.py read-osd` reads the burned-in channel title and clock, which is the
only camera attribution available for the 2,246 (drive 1) and 495 (drive 2)
streams no index accounts for.

| Check | Result |
|---|---|
| Rules under test | 22 checks in `tests/test_pipeline.py`: title normalisation, the agreement vote and its thresholds, band choice scored per stream, ambiguous-date handling, container-resolved dates, the clock comparison and its tolerance |
| Reader end to end | passes with `sample` and `ocr` replaced by a stubbed recorder painting a known title in one corner and a known clock in another: calibration finds both corners, each stream is named from its own picture, a 400 s offset is reported as a disagreement, a stream with no container date is `read, not compared` |
| OCR accuracy, first real run (28 Sep, Tesseract 5.5.0, `validate.realmedia`) | Drive 2 `ps-00321` (CH01): **"Camera 01" — matches the eye.** Drive 2 `ps-03023` (CH03): no title read (white text on a light wall). Drive 1, 40 unlabelled streams: calibration found no title or clock band, though the frames carry *Parking* bottom-left and the clock top-right, inside the bands — thin white text on a bright wall and sky. **No clock read on either drive:** both recorders' clocks carry letters — Hikvision `28-07-2024 Sun 02:07:20` (weekday), CP Plus `01/05/2026 01:20:26 PM` (12-hour) — and `CLOCK_CHARS` holds digits and separators only |
| Found by the first run | the runbook picked drive 2's reference stream by time alone; eight cameras record at once, so it took CH07 (`ps-00257`, picture says "Camera 07") for "Camera 01" and called a near-correct reading ("Camera OF") a mismatch. Now chosen by time and the camera the title names |
| Fixed after the first run (29 Sep) | **the clocks:** the whitelist now allows the weekday and AM/PM letters; AM/PM turns the hour to 24-hour time; the weekday the recorder painted is checked against the date and, where `01/05/2026` is two dates, keeps only the one that falls on it (a weekday that fits neither is reported, not trusted). `28-07-2024 Sun 02:07:20` and `01/05/2026 Fri 01:20:26 PM` now parse. **Calibration:** a corner was scored across both polarities together, so text readable only inverted scored at most 0.5 - one misread frame put it under the bar and the corner was discarded; it is now scored per polarity (a test shows the old code finding no corner where the new one finds it). **Not fixed:** thin white text a few grey levels above a bright wall or sky. A morphological top-hat was tried on synthetic frames and did not separate text better (Otsu balanced error 24.1% vs 23.3% on a bright sky), so it was not added |
| Measured on six recorders' own files (29 Sep, Tesseract 5.5.3, `python -m validate.osd_eval`) | The six public clips of §8a (Intelbras/Dahua, Amcrest, Swann, Lorex, two Hikvision), each calibrated on its own as `read-osd` calibrates a case, 6 frames each; every painted clock and title read by eye on the same frames. **Clock found on 3 of 6 recorders; of 36 frames with a clock, 5 read exactly, 9 wrong, 22 unread. Titles: 0 of 5 right** ("amelek.net" read "ame leknet") |
| Why, clip by clip | Intelbras: 5 of 6 exact, one year read 2071. Hikvision 2018: the year read **2016** on all 6 frames (a pixel font's 8 as 6) and two seconds wrong. Swann: the clock is top-centre, across both top corners, and its "PM" is lost, so 7 PM reads 07:11 (2 frames). Hikvision 2015: the date reads, a Chinese weekday comes out as junk, and the time runs past the corner band. Amcrest: white text on a bright wall. Lorex: text about 8 px high. The wrong readings are years or 12 h off, which the comparison with a container's own date reports as a disagreement; a stream with no container date (an AVI export) has no such check |
| Changed after the measurement | `08/ 14/ 2021 07: 11: 22 PM` (a space after each separator) now parses; full-width top and bottom strips are tried beside the four corners (the Swann clock is found; exact reads did not rise); the reader opens containers (`.dav`, `.mp4`, `.avi`) as well as extracted streams. Rule `osd.tesseract_title_clock.v2`. The limit is Tesseract on small, compressed video text, not the rules |
| On our own drives (29 Sep, after the changes above) | Drive 2's reference streams (`read-osd --ids ps-00321,ps-03023`): *Camera 01* read on `ps-00321`, matching the eye; no title on `ps-03023` (white on a light wall); calibration found **no clock band**, so no clock was compared - the same as on 28 Sep. Drive 1's six clips (`validate.osd_eval sample`, 6 frames each, `out/realchecks/osd_drive1/`): calibration found **neither a title nor a clock band on any of the six**, though every frame carries *Road View 1/2* or *Parking* bottom-left and a 12-hour clock top-right - 0 of 6 titles, 0 of 6 clocks. The failure is in finding the band, before any reading: thin semi-transparent white text over bright road, sky and wall |
| Status | `synthetic_only` — measured on real frames and short of `spec_only`: a clock is a lead to be checked against the container and the eye, and a title is not reliable |

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

## 8g. Independent checks: vendor-made files and a second implementation

With no recorder or spare disk available for a native export, these checks
test our decoding on material we did not make: Hikvision's and Dahua's own
files, from other recorders, found in public sample archives. None of it is
a byte-match with an export of *our* drives, so no status changes from
`spec_only`. The samples are not committed; `VENDOR_SAMPLES` points the
tests at a folder of them.

| Sample | Source | SHA-256 |
|---|---|---|
| Hikvision `IMKH` player file, 2018, H.264 1920×1080, 5 MiB | `streams.videolan.org/samples/IMKH/00000001541000000.mp4` | `79b1e557…de69862` |
| Hikvision player file, 2015, H.264 1280×720 | `samples.ffmpeg.org/ffmpeg-bugs/trac/ticket4182/20150327215559_ch01.mp4` | `20e31574…d0f59a9` |
| Hikvision player file, 2014, "Control Room 1", 704×576, video type 0xB0 | `…/trac/ticket3566/Control Room 1…_20140314235910_20140314235939_164863298.mp4` | `80eaa112…3a4b3` |
| Dahua `.dav`, 2017, H.264, 25.8 MB | `…/trac/ticket6144/19.25.00-19.25.50[R].dav` | `c17602dd…b2da07` |
| Dahua `.dav`, 2019, H.264 1920×1080, cut to 2 MB | HandBrake issue 1935, `dav-sample.dav.zip` | `9787cb4b…f39c3bed` (unzipped) |

**Hikvision-made files** (`python -m validate.ps_sample FILE --out DIR`):

| File | Carve | Frames vs ffmpeg | `HK` time vs an independent clock |
|---|---|---|---|
| 2018 `IMKH` | one stream from 0x28, right after the 40-byte `IMKH` header; 463 packs; only the pack the 5 MiB cut truncated is left out | **463/463 identical** (MD5 per decoded frame) | painted clock on the keyframe after each of the 10 stream maps: **10/10 = `HK` − exactly 1 s** |
| 2015 | whole file, from 0x28 | **215/215 identical** | painted clock: **5/5 equal to the second** (with the weekday, 星期五 = Friday, right for 27 Mar 2015) |
| 2014 | whole file, from 0x28, 268 packs | not decodable by ffmpeg (0xB0) | the first `HK` time, 23:59:10, **equals the start time in the recorder's own file name** |

So the `HK` 0x40 layout (year, month, day, hour, minute, second) holds on
three more Hikvision recorders from 2014-2018. The offset from the painted
clock differs by recorder: 0 s on the 2015 file and on drive 2 (§8b), 1 s
on the 2018 file. A Hikvision `HK` time is good to about 1 s unless that
recorder's painted clock has been checked. One more thing the 2015 file
shows: its file name (21:55:59) is 12 s before its first frame, so a file
name is not a frame time.

**A second implementation of the DHAV frame walk**
(`python -m validate.dhav_crosscheck FILES_OR_DIRS`). It compares ffmpeg's
`dhav` demuxer with our walker frame by frame on the same `.dav`: payload
size, payload Adler-32, keyframe flag, and time (ffmpeg's `-copyts` time must
fall inside the frame's own DHAV second).
- **What it shows:** independent *code* agreeing. An implementation error would have to be repeated exactly by the other side.
- **What it doesn't:** our field layout was taken from ffmpeg's `dhav.c`, so a misreading both share is not tested. This is not independent knowledge of the format.
- **Expected differences, found on the real files, counted and reported rather than hidden:**
  - ffmpeg emits no video before the first keyframe (a file that opens mid-group);
  - ffmpeg keeps the bytes present of a last frame the file cuts short, which we reject;
  - ffmpeg skips 0xF1 aux frames.
- **A frame with a broken header checksum** is a real difference: ffmpeg keeps it and we don't. The tool reports it with where it is.

| File | Video frames compared | Audio | Times | Expected differences |
|---|---|---|---|---|
| Dahua 2017 (25.8 MB) | **726/726 identical** | 1,245/1,245 identical | 726/726 inside their own second | 21 of ours before the first keyframe |
| Dahua 2019 (2 MB cut) | **104/104 identical** | 60/60 identical | 104/104 | 12 before the first keyframe; a last frame declaring 15,100 bytes with 6,612 present |
| generated | 60/60 identical | 30/30 | 60/60 | none; a broken header checksum is reported as "ours 59, ffmpeg 60" |

The 2017 file's name says 19.25.00-19.25.50 and our decoded DHAV clock says
19:24:59-19:25:49: the recorder's export name and our time decoding agree
to 1 s.

**On the CP Plus drive's own `.dav` files (29 Sep).** All 2,246 streams
carved outside the index (`out/cpplus_WWD4A3NX/carve/streams`), ffmpeg
8.1.2. Result `out/realchecks/drive1_dhav_crosscheck.json`, SHA-256
`2abeced1…4dabe2`.

| | Result |
|---|---|
| Files identical frame for frame | **2,025 of 2,246** |
| Video frames ffmpeg emitted | **719,097, every one identical to ours** (payload size, Adler-32, keyframe flag) |
| Ours that ffmpeg did not emit | 270,686, all before the first keyframe of their file: 245,538 in files that open mid-group, 25,148 in the 221 files with no keyframe at all. These 221 are the only non-identical files, and ffmpeg emits no video from them by design. Both counts equal §7's independent ffprobe measurement |
| Audio | **995,224 frames, identical in all 2,246 files** |
| Other differences | 4,957 `0xF1` aux frames, ours only (expected); no truncated last frame; no header whose checksum we reject and ffmpeg keeps |
| Time | 717,599 of 719,097 inside their own DHAV second. 1,271 (in 620 files) at exactly +1.000 s: ffmpeg's millisecond-counter time reaches the next second one frame before the date field ticks. **227 frames in 6 files are 1.3-4.0 s apart - see below** |

**What the 227 frames show.** Each of the 6 files has a frame-counter gap of
6-67 missing frames. Across it the millisecond counter advances by about what
the gap implies (64 missing: +2,404 ms; 67: +2,621 ms; 31: +1,124 ms). The
date field moves by -1 to +2 s. ffmpeg times frames by the millisecond
counter, so after the gap it runs ahead, then holds until the date catches up.
This tool reports the date. The two clock fields of the recorder's own frame
header disagree by up to ~3 s there. The bytes alone cannot say which is
right, and two decoders that agree on every byte show that they are
interpreting the fields differently, not misreading them. **So after a
counter gap, a carved frame's time is good to about ±3 s, not ±1 s.** The
tool does not yet flag those frames (§10).

This makes the DHAV frame walk two independent implementations agreeing on
719,097 of this drive's own frames. The field layout both use still comes
from `dhav.c` (see above), so Dahua / CP Plus stays `spec_only`.

**On the drive's indexed recordings too (29 Sep).** The 301 hourly
recordings extracted for §8l (14-17 Sep, all three cameras, 131 GiB of
`.dav`, reassembled through the index) were run through the same check.
Results are in `out/realchecks/xcheck_indexed/`.

| | Result |
|---|---|
| Files identical frame for frame | **300 of 301** |
| Video frames ffmpeg emitted | **25,758,151, every one identical to ours** |
| Ours that ffmpeg did not emit | 34,579: 34,550 before a first keyframe, and the 29 of the one other file, a 59 KB recording with no keyframe (ffmpeg emits no video from it, by design) |
| Audio | **25,901,562 frames, identical in all 301 files** |
| Other | 129,704 `0xF1` aux frames, ours only; no truncated last frame |
| Time | 25,709,656 of 25,758,151 (99.8%) inside their own DHAV second; the largest offset is 1.96 s, in 50 files. Unlike the carved streams, no frame is missing there. **The recorder's own clock steps**: between consecutive frames, with the frame and millisecond counters running on, the date repeats a second (-1 s, 6 times) or skips one (+2 s, 3 times). Each step falls at about ten past the hour (01:10, 03:10, 05:10, 09:10, 12:10, 20:10 on 14-16 Sep) and is shared by the cameras. ffmpeg keeps its time monotonic and waits for the date to catch up (1.96 s). The other offsets in those files were not traced |

**What the steps suggest.** They are the signature of a periodic clock
synchronisation, corrected both ways by a second or two, for example NTP or
the recorder syncing with its cameras. The disk does not say which, so it
is not a result. If it is a network time server, the clock stays within a
couple of seconds of it between syncs; the unit's time settings screen
(NTP on or off, which server) settles it. Clock steps: `out/realchecks/xcheck_indexed/clock_steps.json`.

So on the reassembled recordings, the extraction path an examiner uses most,
the two implementations agree on every frame ffmpeg reads.

## 8j. Godrej, from Qualvision's firmware

Godrej publishes no format and no firmware. But its SeeThru cloud portal
drives Qualvision's `/tdkcgi` API, which Qualvision's firmware implements, so
a SeeThru recorder runs Qualvision's software (`docs/research/vendor_formats.md`).
Qualvision's application `Sofia` (NVR401L-4P4, 20240531, a public download)
was read by static disassembly - nothing run - with
`docs/research/fwread/sofia.py`, each structure from a named function:

- **Disk head** (`IDiskExt::CheckHead`): `QVEX` v1.0 at LBA 0, with two
  (start, size) regions bounded by the size field at +0x0C.
- **Frames** (`CheckFrameHead`, `LoadFrameHead`, `ReadPacket`): a 20-byte head
  - `00 00 01` + type E0-EB, a u32 payload length - and the next frame at
  head + 20 + length.
- **Frame time** (`CHOTUpload::OpenFile`): a DHTIME at +8 and milliseconds at
  +0x0C. The firmware's own debug print decodes it with exactly Dahua's
  packed-date shifts; the research notes had this as an assumption, and the
  disassembly makes it firmware evidence.

`plugins/godrej.py` finds footage by the frame chain alone: a head is believed
only when the next head follows exactly where its length says, several in a
row. It dates each run on the recorder's wall clock. Not decoded, so not
claimed:
- the VIDEO/PIC and HM index blocks, so no run is given a camera;
- what each frame type means;
- six bytes of the head;
- whether every Godrej model is Qualvision-made. A Godrej disk with no `QVEX`
  head stays `detected_not_parsed`.

| Check (a disk built to the reading) | Result |
|---|---|
| Head | read as the firmware checks it; region bounds hold; the size field is the disk in sectors |
| Runs | both at their offsets, every frame, first and last times to the millisecond |
| A lone fake frame head in random bytes | passed over: it chains to nothing |
| Video | extracted exactly (payloads with a start code); audio left out |
| A head failing the firmware's own bounds check | refused |
| Other plugins | none claims the QVFS disk; Godrej claims no other vendor's |

With this, all eight named OEMs have a plugin. Three are read from real media
(Dahua, CP Plus, Hikvision) and one comes from published research (Honeywell).
Three come from the vendors' own firmware (Uniview; TP-Link's index; Godrej
via Qualvision) and one from the vendor's own documents (Matrix). Only the
first three are observed; none is `validated`.

## 8k. Dress rehearsal from the packaged executable (29 Sep)

The whole workflow, run as an examiner would run it: from `ps26150-dvr.exe`
(built from this branch; no Python on the path), on two real inputs.

**A. NIST HeimVision image (E01, 139.74 GB)**

| Step | Result |
|---|---|
| `scan --max-mb 4096` (triage) | MD5/SHA-256 of the range, Merkle map; vendor **HeimVision 99.5%, parser available**; no high-entropy region without video |
| `parse --vendor HeimVision` | 806 files, 4 cameras, 24 h recorder-local; zone setting UTC+8 measured, not applied |
| `extract` (camera 2) | 1,296,105 frames, 615 MB, SHA-256 in its manifest, 58 s |
| `timeline` | 4 camera lanes, 24.0 h each, 0 gaps; "recorder-local, not converted" |
| `report`, `case-export` | HTML/JSON report and CASE/UCO JSON-LD, each hash in the custody ledger |
| `certificate --part B --records both` | drafted, Gazette wording; refuses to certify a whole-drive hash from a triage pass, as it should |
| `verify` | custody chain intact; Merkle root **MATCH** |

**B. A real Dahua recording (`.dav`, 2017, H.264; samples.ffmpeg.org, §8g)**

| Step | Result |
|---|---|
| `scan --carve` | Dahua 95.5%; the DHAV carver, in its own process, found 2,042 frames, 1 stream |
| `extract-carved` | `.dav` and `.h264`, hashed |
| `export-nist` | a valid MP4 (ffmpeg: H.264 High, 2592x1520, 15 fps, 49.8 s); Level 0 declared **not** met, because no zone was stated |
| `report`, `certificate`, `verify` | drive and footage hashes in the draft; Merkle MATCH |

**What the rehearsal found, now fixed:**
- **A scan never named HeimVision.** Its only signature was a brand string
  that is not on the disk, spelled `Heimvision`. The plugin now carries
  structural signatures (§8e).
- **`scan --carve` did nothing in the executable.** The carver runs in a
  worker process, and a packaged Windows build starts that process by
  re-running the executable, whose command-line parser rejected the
  worker's arguments. The scan reported it ("inline carve disabled ...
  hashing continues unaffected") and carried on without carving. `cli.py`
  now calls `multiprocessing.freeze_support()` first. The packaging check of
  28 Sep ran `scan` without `--carve`, so it missed this.
- **The certificate missed footage extracted into a subfolder.** USER_MANUAL
  §3.4 extracts to `--out clips/`, and the certificate looked only at the
  case folder's top level. It now looks one folder down, and it leaves out
  (and says so) any footage whose manifest names another device.

**Re-run on 29 Sep evening, from `staging` (`e9a7527`).** The executable was
rebuilt with the permanent build environment. It ran with no Python on the
path, into fresh folders; the demo copies were not touched.

| | Result |
|---|---|
| A. NIST image: scan (triage), parse, extract camera 2, timeline, report, CASE/UCO, certificate | every step exits 0; `verify`: custody chain intact across 8 entries, Merkle root **MATCH** over 512 blocks |
| B. Dahua `.dav`: scan with carving, extract-carved, NIST export, report, certificate | 2,042 frames, 1 stream; the export decodes with no error (H.264 High, 2592x1520, 15 fps, 49.8 s, as before); `verify`: chain intact across 13 entries, **MATCH** |
| `analyse-video` from the executable | **not available**: "the optional analytics layer is not installed". The build leaves out numpy, onnxruntime and the detectors by design (`packaging/ps26150.spec`) |
| `analyse-video` with the analytics environment (`python cli.py analyse-video`, numpy + onnxruntime) on the same case | runs: 48 frames in 37 s, person in 14, face in 7 (YOLOX-S + YuNet, tiles and rotation) |

So for the demo, the executable does everything except the AI, and the AI
runs from the analytics Python on the case folder the executable made. An
AI-capable executable would need a second build that bundles onnxruntime,
numpy and the models (hundreds of MB).

Two small faults found, both fixed with a test:
- **`--label unlabelled` selected nothing.** On a source with no filesystem
  index (a single `.dav`), the scan names the carved stream "unlabelled",
  but `extract-carved --label unlabelled` matched nothing: only `all` or
  `--ids` worked. It now selects what the scan calls unlabelled.
- **`export-nist` with a missing input** ended in a Python traceback. It
  now says what is missing and exits 1.

## 8l. The recorder's clock from daylight (`analyse/daylight.py`)

Converting recorder time to UTC needs the recorder's zone and its clock
error, normally read at the unit (SOP 1.2). With the unit out of reach, an
outdoor camera holds a clock nobody can set: most CCTV cameras switch to a
black-and-white infrared picture at dusk and back to colour at dawn, at a
fixed light level - to first order, a fixed sun elevation.

The tool finds each switch in footage sampled over days, stamped with the
recorder's clock, and searches for the offset T (recorder = UTC + T) at
which every dusk and every dawn switch sits at the same sun elevation (NOAA's
solar equations). A wrong T moves dusk elevations one way and dawn ones the
other, so only the right one makes them agree. The camera's threshold is
not needed, and it comes out of the fit. The sun must be setting at every
dusk switch and rising at every dawn one, which also rules out the 12-hour
alias.

| Check | Result |
|---|---|
| The sun | Bengaluru's 18:16 IST sunset on 23 Sep 2026 at the horizon (-0.8 deg); noon 76.9 deg |
| 10 days of generated footage: IST, a clock 7 min fast, switch at -2 deg, +-0.6 deg of weather per switch, headlight flashes | 10 dusk + 10 dawn switches; **UTC +337 min = IST + 7 min**, found exactly; per-switch offsets 334-340; switch elevation -2.0 deg recovered |
| Only dusks | refused: every offset fits them equally |
| Real recorder footage (§8g samples) | a Hikvision infrared night picture measures chroma 0.0, a daylight one 49.5, evening Dahua colour 5.8-17.7 (threshold 4.0); a `.dav`'s samples carry the recorder's own frame times |

**Limits, stated with each result:**
- Weather moves the light threshold, and the spread of the per-switch offsets
  shows by how much.
- A street-lit scene or a camera without infrared has no switch.
- The result settles a zone and a clock error of minutes, not seconds.
- Estimating clocks from daylight is not new (Sundial, EWSN 2009); reading it
  from a DVR's infrared switches is the application here.

**Run on drive 1 (29 Sep): no infrared switch, so no estimate.**

What was run:
- Site: Bengaluru, 12.97 N 77.59 E.
- Footage: four whole days, 14-17 Sep 2026 (recorder clock), of all three
  cameras, *Road View 1*, *Road View 2* and *Parking*: 301 hourly recordings.
- Extracted from the write-blocked drive with one `extract` call (the disk
  parsed once), each recording with its manifest.
- Sampled every 120 s: 8,632 samples, one series per camera.
- `switches()` sorts everything it is given into one timeline, so two cameras
  in one series would make switches of their own. Each camera was estimated
  separately.

| Camera | Samples | At or below the infrared threshold (chroma 4.0) | Switches | `estimate` |
|---|---|---|---|---|
| *Road View 1* | 2,878 | 1: a single grey decode at 11:54 on a sunny noon, not infrared | 0 dusk, 0 dawn | refused: needs a dusk and a dawn |
| *Road View 2* | 2,878 | 0 (lowest 6.2) | 0 | refused |
| *Parking* | 2,876 | 0 (lowest 5.3) | 0 | refused |

**Why.** The cameras do have infrared: on 3 Sep at 22:08 both road cameras
turned black and white for about 14 minutes (the AI sample frames, §8a),
when the lighting went off. But the scene is lit all night, so at dusk the
light never falls to the camera's threshold. Night chroma sits around
7-9 (*Road View*) and 16 (*Parking*); daylight is 18-22. This is the limit
stated above: a street-lit scene gives no switch.

**Exploratory, not the method: the colour crossing.** The picture's
colourfulness still follows the daylight: it rises near 06:00 and falls near
18:30. `out/realchecks/daylight/lightlevel.py` takes each camera's first
sustained crossing of the level midway between its night and day chroma:
- a dawn after 03:00;
- a dusk after 15:00, before the evening lights lift the chroma again.

The tool's own `estimate()` then fits the offset.

Five of the 24 crossings were looked at in the frame and flagged:
- on 14 Sep evening the sky is grey (overcast), so all three dusks came early
  (17:33-18:23);
- on *Road View 2* a light switched on at 03:57 on 16 Sep and at 05:31 on 17
  Sep, well before dawn.

| | Crossings | Offset | Against IST | Level reached at sun elevation | Per-crossing offsets |
|---|---|---|---|---|---|
| All 24, as found | 12 dusk, 12 dawn | UTC +317 min | -13 min | -4.2 deg (spread 6.6) | median +328, range +212 to +334 |
| 19, the flagged 5 left out | 9 dusk, 10 dawn | **UTC +328 min** | **-2 min** | -4.0 deg (spread 0.85) | median +328, middle half +327 to +329, range +321 to +334 |
| per camera, flagged left out | 7, 5, 7 | +329, +330, +325 | -1, 0, -5 | -4.1, -4.5, -3.4 | ranges 327-333, 326-332, 321-327 |

**What it shows:** the recorder's clock keeps **IST**, and, read this way,
is within a few minutes of it. It excludes a clock set to UTC or to any other
zone.

**What it does not:** a colour crossing is not the infrared switch the
method rests on. Street lights, exposure and white balance move it, and 5
crossings were left out after looking at their frames. So the clock error is
**not measured**. Stating UTC to the minute still needs the unit's clock set
beside network time (SOP 1.2).

Series SHA-256: CH01 `ed6f260d2362cc7a…`, CH02 `25f255e37832853c…`, CH03 `7cc5c65313d09780…`
(`out/realchecks/daylight/`).

## 8m. Other tools on the same data (research gap G5, 29 Sep)

Five free tools were run beside ours, read-only, on the same inputs. Two
more are other SIH26150 teams' tools; for those, their own published
results on the NIST image are set beside ours. Each tool is named at the
commit that was run.

| Tool (commit) | Input | Their result | Ours |
|---|---|---|---|
| OpenDHFS (`af5b6d0`, Aug 2026), DHAV carving | the real Dahua `.dav` of §8g (FFmpeg #6144) | 2,042 DHAV candidates | 2,042 frames (Kaitai agrees, §9a) |
| OpenDHFS | the real Dahua `.dav` cut to 2 MB (HandBrake #1935) | 191 candidates | 190 complete frames; the extra one is most likely the frame the cut truncated |
| OpenDHFS | a generated DHFS 4.1 disk with known contents: 3 cameras recording at once (462, 459 and 457 frames surviving) over an older recording | 6,601 candidates; the recording under test is **one group of 1,379**, "camera/channel assertion: No" | 6,597 frames; the recording under test is **three streams of 462, 459 and 457**, one per camera, as written |
| dhfs_extractor (`166bd56`, IFRN, DHFS 4.1) | the same generated disk | **does not finish**: its partition-table loop reads 64-byte entries until it meets `AA 55 AA 55`, with no bound, and our disk has no such marker there | 3 recordings, cameras 0-2, 12 s each |
| hikextractor (`d73755a`) | a generated disk in drive 2's observed Hikvision layout (8 recordings on 4 cameras, one deleted) | reads the master sector (signature, capacity, block size); lists no recordings | 8 recordings |
| hikvision-nvr-recovery (A22Z4, `813eeab`) | the same disk | reads the master sector; one empty index page. **Every stored time is converted in the examiner's computer's own zone** (`datetime.fromtimestamp`): the same field reads 05:30 on an IST laptop and 00:00 under UTC | recorder times stay recorder-local; UTC only from a stated zone and clock error |
| Trace (`Hardik-droid/sih_x`, their `docs/real-corpus-validation.md`) | the NIST HeimVision E01 | hashes equal NIST's; **3 of the 806 recording files sampled**, 12 excerpts, 13,186 frames (881 s); the 24 h labelled **UTC** | all 806 files, 24 h on each of 4 cameras (1,296,105 frames on camera 2 alone); times labelled recorder-local, the zone setting measured as UTC+8 (§8e) |
| CCTVault (`VinayBU14`, their README and status report) | the NIST HeimVision E01 | parses the `luo` header's epoch times "into UTC ISO-8601 strings" | as above: those times are the recorder's display time, not UTC |
| DVRExtractor (`41581c2`) | - | not run: a Windows GUI that bundles Dahua's closed `dhplay.dll`; nothing to script | - |

What this does and does not show:

- **On real Dahua files, OpenDHFS and our parser find the same frames.**
  That is independent agreement on the DHAV format, from a second
  implementation.
- **Separating cameras is where the tools differ.** OpenDHFS declines to do
  it, by design. We separate the cameras by stream continuity and match the
  written ground truth exactly (USP claim 5, `FINAL_REPORT.md` §8).
- **The generated disks carry our reading of each format.** On the Hikvision
  disk, and where dhfs_extractor stalls, the difference may be the disk's
  and not the tool's. Neither disk proves a rival wrong: the Hikvision tools
  follow the 2015 paper's older layout (`HIK.2011.03.08`); dhfs_extractor was
  built on Brazilian recorders' disks, and our notes on drive 1 never
  recorded the bytes after the last partition entry, which it relies on. A
  fair head-to-head needs the real images: `dhfs41.DHFS41().load_image()` on
  drive 1's head image, and the two Hikvision tools on drive 2.
- **Two findings stand on their own.** A loop with no bound turns a disk
  without the expected marker into a hang, not an error. And a tool that
  converts recorder times in the host's zone gives different answers on
  different examiners' machines.
- **The SIH comparison is on the same public image.** It uses the other
  teams' own published figures. They were not re-run here, because both need
  the 150 GB E01 streamed through their own readers.

## 8m. Parsers against corrupted disks (fuzzing, 30 Sep)

Evidence arrives damaged: bad sectors, a half-overwritten index, a disk cut
short, or bytes changed on purpose. A parser that crashes on such a disk
shows the examiner a Python traceback and reads nothing more. Worse, a
parser that hangs stops the case.

`python -m validate.fuzz_parsers` builds each vendor's synthetic disk (the
tests' `tests/synth_*.py`) and parses it once cleanly. While it does, it
records every byte range the parser reads: its structures, not the video.
It then makes corrupted copies, mostly damaging those ranges:
- bit flips;
- a field set to a poison value (0, all ones, the sign bit, just past the
  disk's end);
- runs of bytes zeroed, set to 0xFF or randomised;
- one structure copied over another;
- the disk cut short inside a structure.

Each case runs `detect()` and `parse()` in a worker process, killed after
30 s. The test is the contract `cli.py` relies on: `detect()` answers true
or false, and `parse()` returns a result with any problem in its `errors`.
Anything else raised, bar a device error, is a crash. Cases are
reproducible (`--repro VENDOR:CASE` reruns one and, for a hang, shows where
it is stuck).

**Found: 145 failures in 3,200 cases (400 per parser), in 22 places.**

| Parser | Crashes | Hangs |
|---|---|---|
| Dahua | 0 | 0 |
| Godrej | 0 | 0 |
| Matrix | 76 | 1 |
| Hikvision | 22 | 0 |
| HeimVision | 20 | 0 |
| Honeywell | 20 | 0 |
| Uniview | 5 | 0 |
| TP-Link | 1 | 0 |

What they were:
- **Structures read past the end of a cut or damaged disk, unpacked without
  checking the length.** The Hikvision system log's master block,
  Honeywell's partition header, HeimVision's FAT and recording heads,
  Uniview's GOP trailer, and the ext2/3/4 reader's inodes, group
  descriptors and blocks.
- **A corrupted file size taken at its word.** One ext inode claimed about
  a terabyte. Reading by it exhausted memory, or, in the "hang", listed
  about a billion blocks one by one.
- **The ext reader's own refusal was not caught.** It raises "not read" for
  what it will not guess at, but Matrix did not catch that for a single
  damaged file or folder, so one bad file stopped the whole parse.
- **TP-Link:** SQLite's own error message quoted the damaged bytes, and
  Python could not decode the message.

**Fixed.**
- Each place now reads exactly or refuses. A structure past the end of the
  image is "beyond the image - not read", and a file larger than the whole
  disk is refused.
- Matrix skips an unreadable file or folder and lists it in the result's
  errors, then reads the rest.
- TP-Link reports such an index as not readable.
- **A safety net for every parser**, including a drop-in plugin
  (`parsers/base.py` `_guard`). If a parser still raises on the data,
  `detect()` answers False and `parse()` returns a result that says where it
  stopped (`detected_not_parsed`). A device error still propagates: the
  device, not the data, failed. The fuzzer counts these stops apart, so the
  net does not hide a bug.

**After the fixes:**
- The same 3,200 cases: no crash, no hang.
- 3,200 new ones (another seed): no crash, no hang.
- 7 stops across both runs, all fixed at the parser (a FAT entry past the
  image, Matrix's `detect()`, TP-Link's error text). Each of the 7 cases now
  returns a clean result.
- A third, fresh 3,200: no crash, no hang. 3 stops (a directory entry cut short, a damaged database header that made SQLite ask for more memory than there is, and a frame header cut short), each fixed at the parser and now a clean result.
- The test suite runs 12 corrupted disks per parser on a fixed seed, and
  tests the safety net itself.

**Limits.**
- The disks are the synthetic ones, built to each vendor's layout, not real
  damaged recorder disks.
- The damage is random, aimed at what the parser reads. It is not a proof
  that no input can crash a parser.
- The scan engine itself was not fuzzed here.

### The carvers and the E01 reader, fuzzed the same way (30 Sep)

The three carvers recover footage the recorder's index no longer lists:
DHAV (Dahua family), MPEG-PS (Hikvision) and raw H.264/H.265 (any recorder).
They read every byte, so their damage was aimed at what they recognise:
- DHAV frame headers;
- PS pack and stream-map headers;
- Annex B start codes and the container around them.

Each carve was followed by what the tool does with its result: report rows,
recordings, and a stream written out. The E01 reader was given damaged
segment files. Opening may refuse (a device error), and a damaged chunk may
be refused on read (the reader's own error, which the scan records as
unreadable). Anything else is a crash.

**Found: one bug, in the E01 reader.** When `BlockDevice` refused a damaged
E01 set, it left the set's first segment file open. On Windows that file (the
evidence) stayed locked until Python happened to free it. The fuzzer found it
because it could not delete the set afterwards (16 of the first 20 cases).
Only the reader's own error became a clean device error; any other failure
in a damaged set would have escaped as a raw exception. Fixed
(`acquire/device.py`): the file is closed, and any failure to open a set is a
device error that names it.

**Result:** 3,200 damaged inputs (400 per target, two seeds), after the fix: no crash and no hang. The carvers handled all 2,400 cleanly. The damage did change what they recovered (for example 2-6 DHAV streams where the clean input gives 5), so it reached them; they split or dropped what was damaged, as designed. Of 800 damaged E01 sets, 605 were refused cleanly and 195 read. The test suite runs 8 damaged inputs per target on a fixed seed, and checks that a refused E01 set leaves no file open (that test fails on the old code).

## 9. Vendor format status

| Vendor | Status | Why not better |
|---|---|---|
| Dahua / CP Plus | `spec_only` | layout read off real media and consistent throughout (§3), but no footage has been byte-matched against the recorder's own export. The frame walk agrees with ffmpeg's `dhav` demuxer, a second implementation, frame for frame on two real Dahua recordings from other units and on all 719,097 video frames ffmpeg emits from this drive's 2,246 carved streams (§8g, 29 Sep). It shares ffmpeg's field layout, so this is independent code, not independent knowledge |
| Hikvision — video container | `spec_only` | MPEG-PS + `HK` descriptors decoded from real footage and cross-checked; also checked on three Hikvision-made files from other recorders, 2014-2018 (§8g): `HK` times equal the painted clock (0 s, 5/5) or trail it by a constant 1 s (10/10), or equal the recorder's file-name start; 463/463 and 215/215 frames identical to ffmpeg's decode of the vendor files. Not byte-matched to an export of our drive |
| Hikvision — index records | `spec_only` | decoded from the surviving HIKBTREE copies on real media and cross-checked (resolution per camera, hours per camera, 99.6% recovered vs recorded); not byte-matched to an export |
| Hikvision — system log and master sector (`parsers/hiklog.py`) | `spec_only` | read off real media, six master-sector cross-checks, log clock checked against the footage; not matched against the log the recorder shows or exports |
| Hikvision — full-filesystem parser (`parsers/hikvision.py`) | `spec_only` | rewritten on 28 Sep on the layout observed on drive 2 - the master sector as `hiklog.py` reads it, the HIKBTREE copies where the master points, the 48-byte records `hikbtree.py` reads - and tested on a disk built to that layout, including a primary master overwritten and read from its backup; not yet run on an intact Hikvision disk. The first version decoded offsets invented for our fixture and would have found nothing on a real disk |
| HeimVision (K9604-W) | `spec_only` | `plugins/heimvision.py`, read off the NIST CFReDS image (§8e); every field observed on real media; not byte-matched to a HeimVision export |
| Honeywell | `spec_only` | `plugins/honeywell.py`, written from Yoon & Hwang, DFRWS USA 2026 (arXiv:2605.07430); tested on a disk built to the paper's description (10 tests, including recovery after a format); no Honeywell disk read |
| Uniview | `spec_only` | `plugins/uniview.py`, from the storage driver in Uniview's own firmware (§8f); tested on a disk built to it (11 tests, including footage found with the index wiped); no Uniview disk read |
| TP-Link | `detected_not_parsed` (index: `spec_only`) | `plugins/tplink.py`, from the VIGI firmware (§8f): the format sector and the index are detected, and a plain index is read (recordings per camera, GOP rows, system log); footage is not placed on the disk, because the zone geometry was not recovered - `carve-annexb` recovers it; an encrypted index is reported as encrypted |
| Matrix | `spec_only` | `plugins/matrix.py`, from Matrix's own documents (§8h): the recording tree on ext2/3/4, incl. one RAID 1 mirror; the .stm container is not published and is extracted as stored; tested on disks built to the documents (8 tests); no Matrix disk read, and the recorder's filesystem type is not documented |
| Godrej (Qualvision QVFS) | `spec_only` | `plugins/godrej.py`, from Qualvision's own firmware (§8j); tested on a disk built to it; no Godrej or Qualvision disk read; cameras and the index not decoded |

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
for `parsers/hikvision.py`, now written on the layout observed on drive 2 but never run on an intact Hikvision disk.

A match (or an explained difference) is recorded here with both files'
SHA-256.

## 9a. Format definitions (Kaitai), compiled and checked

`formats/*.ksy` publish each observed layout for others to reuse; the tool
runs hand-written parsers. Until 28 Sep neither `.ksy` had been through a
compiler. Now both are compiled by the official kaitai-struct-compiler
(0.11.0; the Python it generates is in `formats/generated/`), and
`python -m validate.ksy_check` compares what each reads with what the
tool's own parser reads, field by field.

| Check | Data | Result |
|---|---|---|
| Compile | - | both compile |
| `hikvision_ps.ksy`, first version | synthetic PS stream | **failed on the first stream it was given**: it read a pack's packets to the end of the stream, not to the next pack header. Rewritten as a flat run of start-code units |
| `hikvision_ps.ksy` against `recover/pscarve.py` | synthetic, 2 streams between noise | the `.ksy` reads each carved stream whole; packs (123 in all), stream maps, video and audio packets, and the HK times at the first and last stream map equal the carver's |
| `dahua_dhfs41.ksy` against `parsers/dahua.py` | synthetic DHFS disk | superblock; the volume's extent and cluster size; all 64 cluster records, every field (the channel as the byte stored); 328 DHAV frames (type, number, length, date, ms, extension length, trailer) - all equal |
| The check itself | the same disk, a `.ksy` with `next` and `prev` swapped | 18 records flagged: the check is not vacuous |
| A test-fixture fault it found | the MPEG-PS test streams | their HK descriptor declared 14 bytes (0x0E, the value the carver matches on real footage) but held 13. The carver reads fixed offsets and never noticed; the compiled `.ksy` did. Fixed to 14; every MPEG-PS test passes |
| Vendor-made files (29 Sep) | 5 | **agree on every record**: every DHAV frame of the two Dahua `.dav` files of §8g (2,042 + 190 frames: type, number, length, date, ms, extension, trailer) and all 946 packs of the three Hikvision player files (packs, stream maps, video and audio packets, first and last `HK` time): `python -m validate.ksy_check --ps FILE --dav FILE` |
| Real media (29 Sep, kaitaistruct 0.11) | drive 1's 20 GiB head image; drive 2's 4 GiB head image, region 0x4C5E000 + 1 GiB (the data area's first block) | **agree, no mismatches.** Dahua: superblock 4.1, 4 volumes, 119,229 cluster records and 3,000 DHAV frames, field for field (volumes 2-4 lie beyond the image). Hikvision MPEG-PS: 2 streams carved, 115,004 packs read identically by the `.ksy` and the carver. Result `out/realchecks/ksy_check.json`, SHA-256 `4562b05d…6eef66a4` |

## 10. Open items

- ~~Why 2,087 frames after a keyframe still do not decode.~~ **Answered on 28 Sep (§7):** a reference frame missing from the disk. Streams with a complete frame counter lose 0.13% of their frames after the keyframe, streams with a gap 22.2%; 90% of the missing frames sit on a 2 MiB cluster boundary, and most have no intact copy anywhere on the disk. Still to run: `decode-check`, which makes the same test frame by frame (it is in `validate.realmedia`).
- ~~All of the checks that need only the case folders (`validate.realmedia`).~~ **Run on 28 Sep.** Drive 1 `identify-model` (head image, 4 GiB of non-video blocks): no model string. Drive 2: `DS-7B08HUHI-K1`, agreeing with the unit's label and serial (§8b). `decode-check`: 365,654 of 964,635 video frames do not decode — 245,538 before the first keyframe, 119,822 after a counter gap, 294 unexplained; **a missing frame explains 99.8% of the failures after a keyframe**, the same count as the independent measurement in §7. `carve-annexb`: the default first 2 GiB of drive 1 holds no footage, so the range now extends to the first known footage; over the first 8 GiB it covers **100%** of the DHAV carve's bytes plus 48.7 MiB it did not, as **one** stream — the three cameras share identical parameter sets and the carver cannot tell them apart. OCR: §8c.
- OSD reader: weekday and AM/PM clocks now parse, but measured on six recorders (§8c) the OCR is weak: small, compressed text, white text on bright walls. Still to run on our drives' reference frames.
- A native export and a reference disk for the validation in §9 — the comparison itself is built (`validate-export`).
- Recorder timezones, which are what keep the two drives on separate axes in §8d. Daylight (§8l, 29 Sep): drive 1's cameras never switch to infrared (street-lit), so no estimate; the exploratory colour crossing says drive 1's clock keeps IST, within a few minutes - not a measured error.
- The CP Plus unit's own log for 23 Sep - and, better than photos of it, the log exported
  to a USB stick from the recorder's menu (one file, hashed). ~~Then `identify-model` over
  the whole of drive 1 for the unit's serial, DevID and MAC.~~ **Run 29 Sep: none of them
  on the platter, and no model string** (drive 1 row, §2).
- ~~`identify-model` counts any match of a model pattern as a candidate, even one in binary
  data: on drive 1, `HRG745` (6 characters, Honeywell's pattern) turned up by chance in
  76.67 GiB and made the check say "differ".~~ **Fixed 29 Sep:** a candidate seen once and
  8 characters or fewer is listed as a possible chance match and kept out of the check.
  "HRG" and three digits has about a 1-in-3e11 chance at any byte of random data, and the
  search covered 8.2e10 bytes. Real recorder models are longer: `CP-UNR-104F1` has 12
  characters and `DS-7B08HUHI-K1` 14. Drive 1's case report was regenerated and reads
  "not determined".
- The Hikvision full-filesystem parser against a disk the Hikvision unit formatted itself (the reference disk in §9).
- ~~Kaitai `.ksy` compiled~~ **Compiled, and checked against the parsers on synthetic data (§9a).** ~~Still to run on the real images.~~ **Run 29 Sep: agree on both drives' images and on five vendor-made files (§9a).**
- ~~The ffmpeg cross-check on drive 1's own `.dav` files.~~ **Run 29 Sep (§8g):** 719,097 of 719,097 emitted frames identical. It found one thing to fix: after a frame-counter gap the DHAV date and millisecond counter can disagree by up to ~3 s (6 files, 227 frames). Frames after such a gap should carry that wider time uncertainty in the timeline and report; today they do not.
- Analytics recall on our own cameras: 210 drive-1 frames, labelled by Claude, the 20 deciding frames checked by a person, scored with both detectors (§8a). New detector: people 2 of 2 (was 0), no face false alarms (was 7), but the dog is still a person, a tree trunk is a new one, and no vehicle is reported - the parked car scores 0.25-0.47 against a 0.5 threshold. Open: the static rule's 25% share lets an intermittent fixed false alarm through.
- ~~Drive 2 `label-ps` re-run on the drive.~~ **Run 29 Sep (§8b):** 440 `stale_tail`, 55 `outside_index`; index unchanged since 26 Sep.

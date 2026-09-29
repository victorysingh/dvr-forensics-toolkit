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
| Automated tests | 441 pass, 0 fail: 429 on generated data with known ground truth, 12 on real media (9 on the CP Plus drive's image, 3 on the HeimVision E01) |
| CASE/UCO export | a sample case (scan, carve, extraction, device record, report) exported and checked with the official validator `case_validate` (case-utils 0.18.0): **Conforms: True**; tests check every file's SHA-256 and byte ranges against the extraction manifest |
| E01 reader | **reproduces a real FTK Imager E01's own hashes**: the NIST CFReDS HeimVision image, 150 GB in 3 segments and 4,578,856 chunks - computed MD5 and SHA-1 equal the stored ones (§8e). On generated sets: byte-identical reads; scan and carve equal the raw image's; a damaged chunk is reported unreadable |
| Kernel write block | root writes refused, target unchanged (sacrificial loop device, kernel 7.1.5) |
| Write block across USB reconnects | re-applied automatically on 2 of 2 real reconnects (udev rule keyed on the drive serial) |
| Reproducibility of reads | every block shared by 5 independent reads over 3 days is identical, apart from two blocks — each the last block an old-code pass read as its adapter died, both zero-padded by the since-fixed bug |
| Analytics (optional) | runs on recovered clips; detections reviewed by eye as plausible leads; no accuracy claimed |
| OSD reader (optional) | rules and orchestration tested (§8c); **OCR accuracy not measured** — never yet run on a rendered frame |
| Analysis time | one pass over a 1 TB drive at the measured 23.4 MiB/s: ~11.3 h, against ~56.6 h one read per task; the pass itself runs at 26.7 MiB/s (CPU-bound on fast media) - `PERFORMANCE.md` |
| Export comparison (`validate-export`) | 17 tests on generated footage (§9); **not yet run on a real export** |
| Real-hardware failures found | 2 bugs that could have put wrong data into the evidence hash; both fixed with regression tests that fail on the old code |
| Recovery vs ground truth (generated data) | every surviving frame carved; no stream ever mixes two sources |
| Recovery on real media | inline carve identical to standalone carve; 49 unindexed streams extracted with matching frame counts; the no-parser carver scored on the HeimVision image by its parser: every slice accounted for, 0.07% false, identically set cameras not separable (§8e) |
| Full-drive acquisition | complete single pass of 931.5 GiB, 0 unreadable sectors, one USB drop survived by verified reconnect; SHA-256 `78eb8a4a…d909` |
| Vendor formats | none `validated`; Dahua/CP Plus `spec_only`; Hikvision container, index records and full-filesystem parser `spec_only` (the parser not yet run on an intact Hikvision disk); HeimVision `spec_only`, observed on a third real image (§8e) |

## 2. Environment

| | |
|---|---|
| Workstation | Kali Linux, kernel 7.1.5, Python 3.14.6, booting from a USB SSD (Realtek RTL9210, `0bda:9210`) |
| Tool | `dvr-forensics-toolkit`, commit `26fb542` or later (branch `shrestha/single-pass-recovery-report-ui`) |
| Evidence | Seagate SkyHawk ST1000VX013, 1 TB, s/n `WWD4A3NX`, from a CP Plus recorder |
| Recorder unit (read 28 Sep) | CP Plus **`CP-UNR-104F1`**, a 4-channel NVR, hardware V1.0; firmware (System Version) **`V1.00.14.00.T`**, built 16/08/2025; SN `WJQYRMDNPB06GIVC`, DevID `1155004A`, MAC `F8:20:97:10:12:B7` - from its label and its System Info screen (photos SHA-256 `2f873a693b6355d2...` and `bed79a8b0388affb...`; these are WhatsApp copies, which strip the time taken - the originals are to be hashed). A CP Plus NVR is Dahua-built, which agrees with the DHFS 4.1 on this drive. Whether this unit wrote the drive: its serial, DevID or MAC on the platter is still to be searched (`identify-model` over the whole drive) |
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
| Decode, the 50 extracted streams, first 10 min of each (ffprobe, 28 Sep) | 291,452 video frames: **291,035 decode (99.9%)**; 353 precede the first keyframe, 64 lost after it. H.264 and H.265, 960×576 to 2560×1440 |
| Surviving Hikvision index | master sector copy + two identical HIKBTREE copies; 922 records on a 1 GiB block grid; 8 channels |
| Recorder model and unit (28 Sep) | `identify-model` over the whole drive: **`DS-7B08HUHI-K1`**, 208 times from 0x11ECDD0. The team's Hikvision DVR is labelled `DS-7B08HUHI-K1`, serial `F29196515` (`record-device`, label photo hashed): model **agrees**. The platter also carries that unit's full device serial `DS-7B08HUHI-K1 0820201218CCWR F29196515 WCVU` 202 times, so this unit wrote this drive. The model check's "differ" (a Hikvision unit, Dahua-family structures on its disk) is the known reformat; which recorder did it is not established |
| Head image (28 Sep) | first 4 GiB with `ddrescue -d`, 0 read errors, drive write-blocked throughout; all 512 blocks equal the full-drive pass. MD5 `8500709651324ce36b25b548f068144f`, SHA-256 `401d5153c94b037e8e931474bdc157ac830d9460bf51d3048d748b5990acf460` |
| Camera attribution | 2,021 of 2,516 streams inside their block's record window; 495 older streams outside the index |
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

**Status:** `spec_only` - observed on real media, not byte-matched against a
HeimVision export. `tests/test_pipeline.py` pins these numbers when
`HEIMVISION_E01` points at the image.

## 8c. OSD reader (optional layer — first real run 28 Sep: 1 of 5 reference titles, no clock)

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
| Status | `synthetic_only` — run on real frames, but 1 of 5 reference titles and no clock is short of `spec_only`; the clock fix is to be re-run on the same reference frames |

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
| Hikvision — system log and master sector (`parsers/hiklog.py`) | `spec_only` | read off real media, six master-sector cross-checks, log clock checked against the footage; not matched against the log the recorder shows or exports |
| Hikvision — full-filesystem parser (`parsers/hikvision.py`) | `spec_only` | rewritten on 28 Sep on the layout observed on drive 2 - the master sector as `hiklog.py` reads it, the HIKBTREE copies where the master points, the 48-byte records `hikbtree.py` reads - and tested on a disk built to that layout, including a primary master overwritten and read from its backup; not yet run on an intact Hikvision disk. The first version decoded offsets invented for our fixture and would have found nothing on a real disk |
| HeimVision (K9604-W) | `spec_only` | `plugins/heimvision.py`, read off the NIST CFReDS image (§8e); every field observed on real media; not byte-matched to a HeimVision export |
| Honeywell | `spec_only` | `plugins/honeywell.py`, written from Yoon & Hwang, DFRWS USA 2026 (arXiv:2605.07430); tested on a disk built to the paper's description (10 tests, including recovery after a format); no Honeywell disk read |
| TP-Link, Godrej, Uniview, Matrix | `detected_not_parsed` | brand-string detection only; their video is recoverable by `carve-annexb` without a parser |

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
| Real media | - | **not yet run** - on the machine that holds the images: `python -m validate.ksy_check --dahua <drive 1 head image> --ps <drive 2> --ps-region <offset> <length>` (USER_MANUAL §3.4h) |

## 10. Open items

- ~~Why 2,087 frames after a keyframe still do not decode.~~ **Answered on 28 Sep (§7):** a reference frame missing from the disk. Streams with a complete frame counter lose 0.13% of their frames after the keyframe, streams with a gap 22.2%; 90% of the missing frames sit on a 2 MiB cluster boundary, and most have no intact copy anywhere on the disk. Still to run: `decode-check`, which makes the same test frame by frame (it is in `validate.realmedia`).
- ~~All of the checks that need only the case folders (`validate.realmedia`).~~ **Run on 28 Sep.** Drive 1 `identify-model` (head image, 4 GiB of non-video blocks): no model string. Drive 2: `DS-7B08HUHI-K1`, agreeing with the unit's label and serial (§8b). `decode-check`: 365,654 of 964,635 video frames do not decode — 245,538 before the first keyframe, 119,822 after a counter gap, 294 unexplained; **a missing frame explains 99.8% of the failures after a keyframe**, the same count as the independent measurement in §7. `carve-annexb`: the default first 2 GiB of drive 1 holds no footage, so the range now extends to the first known footage; over the first 8 GiB it covers **100%** of the DHAV carve's bytes plus 48.7 MiB it did not, as **one** stream — the three cameras share identical parameter sets and the carver cannot tell them apart. OCR: §8c.
- OSD reader: read clocks that carry a weekday or AM/PM (both of our recorders), and white text on bright backgrounds (§8c).
- A native export and a reference disk for the validation in §9 — the comparison itself is built (`validate-export`).
- Recorder timezones, which are what keep the two drives on separate axes in §8d.
- The CP Plus unit's own log for 23 Sep - and, better than photos of it, the log exported
  to a USB stick from the recorder's menu (one file, hashed). Then `identify-model` over
  the whole of drive 1 for the unit's serial, DevID and MAC.
- The Hikvision full-filesystem parser against a disk the Hikvision unit formatted itself (the reference disk in §9).
- ~~Kaitai `.ksy` compiled~~ **Compiled, and checked against the parsers on synthetic data (§9a).** Still to run: `validate.ksy_check` on the real images.

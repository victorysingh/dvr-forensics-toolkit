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

> Sections marked **PENDING** are filled in when the full acquisition of the
> CP Plus drive (attempt 4) completes.

---

## 1. Summary

| Area | Result |
|---|---|
| Automated tests | 234 pass, 0 fail: 226 on generated data with known ground truth, 8 on real media |
| Kernel write block | root writes refused, target unchanged (sacrificial loop device, kernel 7.1.5) |
| Write block across USB reconnects | re-applied automatically on 2 of 2 real reconnects (udev rule keyed on the drive serial) |
| Reproducibility of reads | every block shared by 4 independent reads over 2 days is identical, apart from one block corrupted by a since-fixed bug |
| Analytics (optional) | runs on recovered clips; detections reviewed by eye as plausible leads; no accuracy claimed |
| Real-hardware failures found | 2 bugs that could have put wrong data into the evidence hash; both fixed with regression tests that fail on the old code |
| Recovery vs ground truth (generated data) | every surviving frame carved; no stream ever mixes two sources |
| Recovery on real media | inline carve identical to standalone carve; 49 unindexed streams extracted with matching frame counts |
| Full-drive acquisition | **PENDING** |
| Vendor formats | none `validated`; Dahua/CP Plus `spec_only`, Hikvision `synthetic_only` |

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
| attempt 4 vs all earlier reads | **PENDING** | |

Independent reads of the same drive through the same flaky adapter, days
apart, agree bit for bit. The single difference is explained, reproduced and
fixed.

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
3807 re-read with a different SHA-256, and the scan refused to continue.
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
| Full drive: carve labels, extraction | real, 1 TB | **PENDING** |

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

No systematic accuracy measurement has been made; none is claimed.

## 9. Vendor format status

| Vendor | Status | Why not better |
|---|---|---|
| Dahua / CP Plus | `spec_only` | layout read off real media and consistent throughout (§3), but no footage has been byte-matched against the recorder's own export |
| Hikvision | `synthetic_only` | field offsets beyond the magic strings rest only on our fixture; the team's drive has not been read |
| Honeywell, TP-Link, Godrej, Uniview, Matrix | `detected_not_parsed` | brand-string detection only |

**To reach `validated` for Dahua/CP Plus:** export one clip with the DVR's
own export function for a known camera and period, locate the same period in
the parsed recordings, extract it, and byte-compare the video payload. A
match (or an explained difference, e.g. container rewrapping) is recorded
here with both files' SHA-256.

## 10. Open items

- Full-drive results (§1, §5, §7) — PENDING.
- Why 2,087 frames after a keyframe still do not decode (suspected: a lost reference frame).
- A native export for the validation in §9.
- Hikvision drive acquisition and parser check.
- Kaitai `.ksy` compiled and checked against the image.

# Final project report

**SIH 2026, Problem Statement 26150 (NTRO):** *Development of a Multi-Vendor
DVR/NVR Forensic Analysis Tool for Standardized Acquisition, Recovery, and
Analysis of Surveillance Evidence.* Theme: Blockchain & Cybersecurity.
Category: Software.

Repository `dvr-forensics-toolkit`. Report as of 28 Sep 2026. Every figure
below is taken from the document named beside it, which holds the evidence.

---

## Abstract

Surveillance recorders store video in proprietary filesystems that general
forensic tools cannot read, and each vendor's own software reads only its own
format. We built a vendor-agnostic tool that:

- acquires a DVR/NVR drive **read-only, in one pass**, with MD5, SHA-256 and a
  per-block Merkle map;
- identifies the vendor by scored evidence and the recorder model from the
  disk and the unit;
- parses Dahua/CP Plus and Hikvision structures, HeimVision's (read off a
  public NIST image), and Honeywell's from published research;
- recovers deleted footage without an index, including from a drive that
  another recorder had reformatted;
- builds a timeline that refuses to invent a time zone;
- keeps a hash-chained custody record of every action;
- reports in HTML and JSON, with a draft BSA 2023 s.63 certificate.

It was run on two real 1 TB surveillance drives:

- **Drive 1 (CP Plus):** 2,029 indexed recordings, and **2,246 streams of
  deleted footage outside every index**.
- **Drive 2 (reformatted by a Dahua-family recorder):** **2,516 streams,
  about 6,300 hours of Hikvision footage**, attributed to cameras from a
  surviving index. The carve recovered **99.6–99.7%** of what that index says
  each camera recorded.

- **A third, public image (NIST CFReDS HeimVision K9604-W, 150 GB E01):** our
  E01 reader reproduced FTK Imager's MD5 and SHA-1; a new plugin, built from
  the disk itself, recovered **24 hours on 4 cameras**, each frame naming its
  camera and time on the recorder's display clock (the clock painted on the
  picture), and measured its zone setting, UTC+8, from its own system clock.

No vendor format is yet `validated`. That status needs a byte-match against
the recorder's own export; the tool to make it is built, and the export is
not yet taken.

---

## 1. The problem

The problem statement (`PROBLEM_STATEMENT.md`) names eight OEMs (Dahua, CP
Plus, Honeywell, Hikvision, TP-Link, Godrej, Uniview, Matrix) and asks for at
least five to six. Its required modules are Device Identification,
Acquisition, File System & Format Parsing, Recovery, Timeline Analysis,
Reporting and Machine Learning. It closes with its success criteria: parse
proprietary filesystems, decode video formats, recover deleted recordings,
verify integrity by hashing, produce standardized reports, reduce analysis
time, and give reliable and legally defensible results.

Its trap is breadth. Eight vendors cannot be supported honestly by a team
that holds media for two or three. So the project was built around one rule:
**claim only what has been demonstrated, and say how strongly.**

## 2. Design principles

| Principle | Why | Where |
|---|---|---|
| **Never write to the evidence** | a single write destroys deleted footage and admissibility | no write path exists in `acquire/device.py`; kernel read-only flag and udev rules survive reconnects |
| **One pass** | a 1 TB drive over USB 2 is an 11-hour read; a second read is another 11 hours and another chance of failure | `acquire/scanner.py`; carvers and analyses run as taps inside it |
| **A hash per block plus a Merkle root** | a single linear hash cannot survive an interruption or say which region changed | `core/hashing.py`; inclusion proofs per clip (`prove`) |
| **The weakest evidence sets the status** | `validated` / `spec_only` / `synthetic_only` / `detected_not_parsed`; nothing is `validated` without an export byte-match | `detect/engine.py::_weakest`, `parsers/base.py::weakest_source` |
| **Confidence, never yes/no** | CP Plus units are commonly Dahua-built; a disk has evidence that scores, not a vendor | `detect/engine.py` |
| **Split, never guess** | carved footage whose camera cannot be told apart is split, never merged | `recover/carver.py`, `recover/annexb.py` |
| **No UTC without stated inputs** | recorders keep local time on unaudited clocks | `analyse/timeline.py::ClockModel`, `analyse/combined.py` |
| **Analytics are leads, not evidence** | a detector scored a steel pot as a face at 0.99; scored against 287 labelled real frames it first found a person in 0 of 57; now in 44 of 57 (faces 22 of 27), and 810 of 1,089 people on CAVIAR footage never used for choosing | `analytics/`, `analyse/activity.py` |
| **Stdlib-only forensic core** | auditable, and runs air-gapped on a bare Python install | `TECH_STACK.md` |

## 3. Architecture

The full description is in `ARCHITECTURE.md`. In short, a read-only device
layer feeds one acquisition pass. During that pass, "taps" (carvers, motion
activity) see every block the hasher sees, but none of them can alter a
hash. Parsers are plugins on one SDK that records where each decoded field's
layout came from. Everything the pipeline produces is bound into a
hash-chained custody ledger. The report and the local viewer are built from
one case view.

| PS module | Implementation |
|---|---|
| Device Identification | `detect/` signatures for all eight OEMs, confidence-scored; `detect/model.py` model numbers from the disk and the unit, cross-checked |
| Acquisition | `acquire/`: read-only device, single pass, bad-sector zero-fill in place, verified reconnect after USB drops, write-block rules |
| File System & Format Parsing | `parsers/dahua.py` (DHFS 4.1), `parsers/hikbtree.py` (Hikvision index), `parsers/hikvision.py` (full FS, observed layout), `plugins/honeywell.py` (from Yoon & Hwang 2026) |
| Recovery | `recover/carver.py` (DHAV), `recover/pscarve.py` (MPEG-PS, Hikvision), `recover/annexb.py` (raw H.264/H.265 for vendors with no parser), `recover/preserve.py` (metadata) |
| Timeline Analysis | `analyse/timeline.py` (clock rule, gaps, recurring patterns, coverage), `analyse/combined.py` (several recorders) |
| Reporting | `report/` (HTML + JSON, hashed into the ledger), `report/s63.py` (certificate draft), `viewer/` |
| Machine Learning | `analyse/activity.py` (motion from frame sizes); `analytics/` (faces, objects, on-screen text), all labelled leads |
| Validation | `validate/exportmatch.py` (recovered footage against the recorder's export) |

## 4. Results on real media

### 4.1 Drive 1: CP Plus unit (Seagate ST1000VX013, s/n `WWD4A3NX`)

Sources: `STATUS.md` §2, `VALIDATION_REPORT.md` §3, §7, §8, `FORENSIC_IMAGE.md`.

| | |
|---|---|
| Acquisition | one complete read-only pass of 931.5 GiB; 0 unreadable sectors; one USB drop survived by verified reconnect. SHA-256 `78eb8a4ac306691cacc1b3f0da911ded8edf1b9f9bf0819f483d95f467f8d909` |
| Filesystem | Dahua DHFS 4.1, four volumes; **2,029 recordings**, three cameras, 27 Aug to 23 Sep 2026 (recorder clock), written circularly |
| Deleted footage | 349.5 M frames carved without the index; **2,246 streams (5.4 GB) outside every index**, March to August 2026, all extracted |
| Timeline | 6 recorder-wide gaps (three on 23 Sep, the day the drive was pulled); a nightly 02:00–02:09 interruption across all three cameras; 2 streams dated 2000-01-01 05:30, a reset clock whose 05:30 suggests the zone is IST (an inference, not applied) |
| Checked against the picture | decoded frame's burned-in clock `01/05/2026 01:20:26 PM` equals its DHAV date `2026-05-01 13:20:26` to the second |
| Analytics (leads) | 4,802 sampled frames of recovered footage: a person in 51, a car in 63 |

### 4.2 Drive 2: Hikvision footage under a Dahua-family format (Seagate ST1000VX005, s/n `Z9C2632A`)

Sources: `STATUS.md` §2, `VALIDATION_REPORT.md` §8b.

| | |
|---|---|
| Acquisition | one complete pass; 0 unreadable sectors; two USB drops healed by verified reconnects. SHA-256 `04d7d4e05b14524b9f53b175ccc7e2b4156463b18e467e326da2a763405921d1` |
| Top layer | Dahua DHFS 4.1 with an **empty** index: a Dahua-family recorder formatted it and never recorded |
| Underneath | Hikvision MPEG-PS footage, recovered by structure alone: **2,516 streams, 923 GiB, about 6,300 h**, every one dated from its `HK` descriptors, April 2021 (H.264) to 30 Aug 2024 (H.265 + audio) |
| Surviving index | a master-sector copy and two HIKBTREE copies near the end of the disk: **922 records, 8 channels**; **2,021 of 2,516 streams** attributed to a camera |
| The recorder | `DS-7B08HUHI-K1` on the platter, matching the team's unit (label, serial `F29196515`); the unit's full device serial is on the platter 202 times, so this unit wrote this drive |
| Measured against that index | the carve recovered **99.6–99.7%** of the hours each camera recorded |
| Checked against the picture | burned-in "Camera 01" / "Camera 03" where the index gave CH01 / CH03; on-screen clocks within 2 s of the decoded times |
| Analytics (leads) | 68,639 frames of a 22 GB subset: person 517, face 73, bus 1; 64 implausible face boxes (a floor, buckets) flagged and not counted |
| The recorder's own log | 43,108 system-log records, 28 Jan – 25 Aug 2024, read from the surviving master sector's log area: **188 power cuts** (power-on after an "illegal shut down"), which explain **16 of the 17 times every camera went silent** for over a minute, and **one local session by `admin` on 23 Mar 2024, 03:28–03:52**, with a configuration change and two playbacks. Its clock is the footage's clock, checked against the streams that restart after each power-on |

### 4.3 A public image of a recorder we had never seen (HeimVision K9604-W)

Source: `VALIDATION_REPORT.md` §8e. The NIST CFReDS *Heimvision DVR .E01 Forensic Image* (Brunty & Mock, Marshall University, 2021): a HeimVision K9604-W 4-channel DVR's 150 GB disk, FTK Imager 4.3.1.1, media MD5 `4895ea6d10b08c29fb1bb03591adc7b2`.

| | |
|---|---|
| E01 | read by our own reader; computed MD5 and SHA-1 **equal FTK Imager's** over all 150 GB |
| Layout | GPT; ext3 system partition; FAT32 ring of 17,152 files of 8 MiB; frames `liu ` ... ` uil` naming camera and microsecond time - decoded from the disk, now `plugins/heimvision.py` |
| Recorded | 806 files, 6.30 GB: **24 h continuous on 4 cameras**, 1.296 M frames each at 15 fps, no gap over 2 s after the start |
| Time | frame, log and index times are the recorder's display clock - equal to the clock painted on the picture: local time written as if UTC. Its system clock (FAT times on all 806 files, ext3 times of both databases) runs 8 h behind: a zone setting of UTC+8, measured twice, not applied. Made at Marshall University (UTC-4 in August), so true UTC needs the clock's error, which the disk does not hold |
| Recorder's own records | its event log and recording index (SQLite on the ext3 partition) read and **checked, not trusted**: 194 log entries, none deleted; the index gives all 806 files exactly the times their headers do; recording began at 13:59:50-51 UTC on all four cameras, and CH02-CH04 hold ~7 s of video from before it |
| No-parser carver | `carve-annexb`, scored frame by frame by the plugin: 5,187,890 slices, every one in the files accounted for, 0.07% of them container bytes; the four cameras share one parameter set, so its streams mix them - only the container separates cameras and gives time |

## 5. Validation

Full account: `VALIDATION_REPORT.md`.

- **Automated tests:** 551 in all: 528 on generated data with known ground
  truth (2 need ffmpeg), 15 on real media (9 on the CP Plus drive's image, 6 on the
  HeimVision E01 and its FTK listing), and 8 on vendor-made files: 6 from
  other recorders and 2 on NIST's reference export (`VALIDATION_REPORT.md` §1).
  They cover the Merkle tree, the custody chain, bad sectors, device loss,
  every parser and carver, the timeline, the model check, the export
  comparison, the Honeywell and HeimVision plugins, the E01 reader, the
  CASE/UCO export and the certificate.
- **Write blocking:** root writes refused on a sacrificial loop device, and
  the block re-applied automatically after 2 of 2 real reconnects.
- **Reproducibility:** five independent reads over three days agree bit for
  bit, apart from two blocks that the bug below corrupted.
- **Bugs found and fixed, each with a regression test that fails on the old
  code:**
  - a lost device was recorded as 180 GB of bad sectors (real hardware);
  - a short read was zero-padded into the evidence hash (real hardware);
  - a triage pass was reported as complete (found in review, §6.4).
- **Vendor formats:** none `validated`.
  - Dahua/CP Plus: `spec_only`.
  - Hikvision container and index: `spec_only`.
  - Hikvision full-filesystem parser: `spec_only` (the layout observed on drive 2;
    not yet run on an intact Hikvision disk).
  - Honeywell: `spec_only`.
  - Uniview: `spec_only`, from the storage driver in Uniview's own firmware.
  - TP-Link: `detected_not_parsed`; its index is read when plain (from the VIGI firmware), but no footage is placed.
  - Matrix: `spec_only`, from Matrix's own documents (its recording tree).
  - Godrej: `spec_only`, from Qualvision's firmware (Godrej's SeeThru
    recorders run Qualvision's software): footage found and dated, no camera.
- **Checked without an export** (`VALIDATION_REPORT.md` §8g), as SWGDE
  18-Q-001 and ISO/IEC 17025 allow when no reference export exists:
  - ffmpeg's `dhav` demuxer, a second implementation, agrees with ours frame
    for frame on two real Dahua recordings (726 and 104 video frames);
  - on three Hikvision-made files, our carve decodes identically to the
    vendor's file (463/463, 215/215 frames), and the `HK` time equals the
    painted clock, trails it by a constant 1 s, or equals the recorder's own
    file-name start.
  - on NIST's HeimVision image, FTK Imager's own file listing and our
    reading agree on all 17,154 FAT32 files (size, write time) and the
    recorder's 4 ext3 files, and FTK's times give the same UTC+8 zone
    setting (§8e).
  None of it raises a status.
- **The route to `validated`** is built (`validate-export`, USER_MANUAL
  §3.4d). The evidence drives must not go back into their recorders, so the
  export comes from a **reference disk**: a spare disk that the same recorder
  formats, records on and exports from, then acquired like evidence.

## 6. Analysis time

Source: `PERFORMANCE.md`. Over the USB 2 bridge actually used, which gave a
measured 23.4 MiB/s on drive 1, a 1 TB drive takes:

- **about 11.3 h in one pass**;
- about 56.6 h with one read of the drive per task;
- about 21.9 h if the drive is imaged first, and that also needs ~931 GiB
  free. The workstation had 669 GB.

The saving is fewer reads of the evidence. On fast media the pass is
CPU-bound (26.7 MiB/s measured), and `TECH_STACK.md` records the planned fix.

## 7. Legal defensibility

- **Integrity:**
  - MD5 and SHA-256 of the whole drive;
  - SHA-256 per 8 MiB block with a Merkle root, so any clip can be proven
    later without re-reading the drive;
  - preserved filesystem metadata provable block by block.
- **Custody:** an append-only ledger in which each entry carries the SHA-256
  of the one before. Every action is bound in with the hash of what it
  produced: acquisition, carving, extraction, timeline, analytics, OCR,
  validation, model record, certificate.
- **India:** *Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal* (2020)
  made the certificate mandatory where the original is not produced, and BSA
  2023 s.63 carries it forward. `cli.py certificate` drafts Part A or Part B
  from the case's own hashes and device record, with the hash report
  enclosed. It never ticks ownership, never makes the "working properly"
  statement, and never signs. Its wording matches the Schedule word for
  word as printed in the Gazette (No. 55 of 25 Dec 2023, pp. 46-47), and a
  test holds it there.
- **What the courts now ask for.**
  - *Pune Bar Association v. Union of India* (SC, 22 May 2026) upheld
    s.63(4): the hash is "an electronic fingerprint", and Part B may come
    from a s.79A Examiner or, "on the basis of unimpeachable material", from
    another skilled person. The tool is built to give that expert the
    material; it is not admissible in itself.
  - *Randeep Singh @ Rana v. State of Haryana* (SC, 2024 INSC 887) threw out
    CCTV on a CD that nobody could tie to the recorder: no hash, no marking,
    copied by people who had not seen it, no certificate. Here every clip
    carries a hash bound to the drive's Merkle root and the byte offsets it
    came from, and the ledger records who did what.
  - s.63(2) asks whether the device was working properly. The recorder's
    own log answers from the device: 188 power cuts in drive 2's log; the
    CP Plus unit's log, read on its screen, matching drive 1's recorder-wide
    gap to the minute. Puducherry's G.O.Ms.No.27 (2025) names
    the DVR/NVR itself as primary evidence and asks for the hash at seizure.
- **Police procedure.** Kerala Police's CCTV seizure SOP asks for make and
  model, a clock check against a reference, and native export. The tool
  turns those into recorded, hashed steps (`record-device`,
  `identify-model`, SOP 1.2, `validate-export`). MeitY's s.79A scheme (v2.0,
  2025) lists "CCTV Forensics" and asks labs for ISO/IEC 17025 and a list of
  every tool used.
- **Exchange:** `export-nist` writes recovered H.264 in NIST's CCTV export
  profile (NISTIR 8161r1 Level 0), written for the FBI. Every frame carries
  its UTC time, and the file carries the recorder's clock offset. Its time
  stamps are byte-identical to NIST's own reference file, and the pictures
  are proven unchanged (VALIDATION_REPORT §8i).
- **Procedure:** `SOP_EXAMINATION.md` and `LINUX_ACQUISITION.md` follow SWGDE
  DVR acquisition practice, ISO/IEC 27037 and NIST SP 800-86. Step 1.2 reads
  the recorder's clock against true time before anything else.

## 8. What sets it apart

Source: `RESEARCH_BASIS.md`. Published DVR forensics is mostly one vendor per
paper: Hikvision in Han, Jeong & Lee 2015; DHFS in Rzayeva et al. 2025;
Honeywell in Yoon & Hwang 2026; or carving without a filesystem in Ariffin,
Slay & Choo 2013. This tool puts those ideas into one read-only pass over
real drives, and adds:

- per-block proofs;
- a custody chain over every derived artefact;
- a status for every vendor claim that only an export byte-match can raise;
- measurement on two real drives, including the failures they exposed.

Five claims survived a second round of checking against the literature
and 30+ rival repositories (`RESEARCH_BASIS.md` §5, `docs/research/`):

- **Footage recovered from under another vendor's reformat, and measured:**
  about 6,300 h, 99.6% of what the drive's own surviving index says was
  recorded. No paper or rival tests a cross-vendor reformat.
- **Times checked, not trusted:** the recorder's log matched a video gap to
  the minute; on NIST's HeimVision image the painted, frame and system
  clocks are reconciled (zone setting UTC+8), where another team's
  published timeline is ~11 h off the painted clock.
- **Status earned, and checked without an export:** nothing is `validated`
  before a byte-match; meanwhile each format shows its independent checks.
- **Real media from three recorder families,** failures published; no paper
  or rival has more than two.
- **Cameras separated by stream continuity where the frames carry no camera
  number.** On our CP Plus unit the DHAV channel byte is 0 for every camera,
  where identifier-based demultiplexing, as in Information 2026, cannot help.
  (The continuity principle is Park & Lee 2014's; the field evidence is ours.)
  Run beside OpenDHFS, the newest open DHFS tool, on a disk with known
  contents: both find the same frames, and only ours splits the three
  cameras, exactly as written (`VALIDATION_REPORT.md` §8m).

Hashing, the Merkle map, the custody ledger, the s.63 draft, "AI as a lead"
and offline use are engineering other teams also have, and are not pitched
as unique.

## 9. Coverage of the eight OEMs

| OEM | Status | Basis |
|---|---|---|
| Dahua | `spec_only` | DHFS 4.1 and DHAV read off real media (the CP Plus drive) |
| CP Plus | `spec_only` | the same format on our unit; CP Plus listed as a current Dahua OEM (IPVM, May 2024) |
| Hikvision | container, index and full-FS parser `spec_only` (the parser not yet run on an intact Hikvision disk) | real footage and a surviving index on drive 2 |
| HeimVision (beyond the eight) | `spec_only` | read off a real public NIST image; drop-in plugin |
| Honeywell | `spec_only` | drop-in plugin from Yoon & Hwang (DFRWS USA 2026); older units were Dahua-built until April 2022, so the Dahua parser may apply |
| Uniview | `spec_only` | drop-in plugin from the storage driver in Uniview's own firmware (static disassembly); footage found with or without its index (VALIDATION_REPORT §8f) |
| TP-Link | `detected_not_parsed` | drop-in plugin from the VIGI firmware: format sector and index detected, a plain index read (recordings, system log); footage not placed - `carve-annexb`; an encrypted index is reported as such |
| Matrix | `spec_only` | drop-in plugin from Matrix's own documents: the CameraNN/date/hour tree of .stm files, read on ext2/3/4 (incl. one RAID 1 mirror); .stm extracted as stored (VALIDATION_REPORT §8h) |
| Godrej | `spec_only` | drop-in plugin from Qualvision's own firmware (Godrej SeeThru runs Qualvision's software): disk head, frame chain, dated runs; cameras and the index not decoded (VALIDATION_REPORT §8j) |

**Four platforms are read from real media (three of the eight, plus
HeimVision from a public NIST image), one more from published research, and
two (Uniview, and Godrej via Qualvision, plus TP-Link's index) from the
vendors' own firmware, and one (Matrix) from the vendor's own documents -
all eight named OEMs parsed or their index read; and footage can be recovered from any vendor that
stores standard H.264/H.265.** That is our honest answer to "five to six".

## 10. Limitations

- **Nothing is `validated`.** It needs a native export and a reference disk.
- **No UTC.** The time zone and clock error of neither recorder have been
  read, so every time is the recorder's own clock. The combined two-recorder
  view says "not aligned" for this reason. A route that needs no unit is
  built: the offset from the cameras' infrared switches at dusk and dawn
  (`VALIDATION_REPORT.md` §8l). It is tested on generated days and real
  night and day footage, and not yet run on our drives' outdoor cameras.
- **The on-screen text reader (OCR) is weak.** Measured on six real
  recorders' files (36 painted clocks), it found the clock on 3 of the 6,
  read 5 frames exactly and 9 wrongly (a year off, or 12 hours off when "PM"
  is lost), and read no title right. The wrong readings are years or hours
  off, so the comparison with the container's own date flags them. On our
  drives it read "Camera 01" correctly and nothing on drive 1's bright
  scenes. It remains `synthetic_only`: a lead to check, not a time source.
- **About 38% of CP Plus video frames do not decode strictly.** The cause
  is measured: 0.3-0.4% of the frames are missing from the disk, and each
  breaks the rest of its ~8.6 s group of pictures. Most have no intact copy
  anywhere on the disk; the 29 split across a chain boundary are rejoined
  (62.1% decode). With error concealment 99.8% of one recording displays,
  with visible damage:
  a viewing aid, not intact evidence (`VALIDATION_REPORT.md` §7).
- **No real disk has been read for** the Honeywell plugin, and the Hikvision
  full-filesystem parser has not read an intact Hikvision disk (it is written on
  drive 2's observed layout, whose primary master a reformat had overwritten). The raw H.264/H.265 carver has run on one (the
  HeimVision image): it finds the video, but cannot separate cameras that
  share the same settings. That is this tool's limit, not the field's:
  CARVE (DFRWS APAC 2026) does it by OCR of the painted camera label or by
  PRNU sensor noise.
- **The analytics still miss people.** Scored against 287 frames of real
  recorder footage labelled by eye, the first version reported a person in 0
  of the 57 frames that had one.
  - It now runs YOLOX-S on the whole frame and a 2 x 2 grid of tiles, and
    YuNet for faces, and looks at a fisheye picture turned round as well.
    It finds a person in 44 of 57, faces in 22 of 27 and vehicles in 8 of
    12.
  - On CAVIAR CCTV footage that played no part in any choice, it finds 810
    of 1,089 labelled people, against 543 for the previous tiled models.
  - Its false alarms: 6 person frames, each a hand in the picture, and 1
    face frame, a head at the fisheye's edge.
  - It still misses distorted and distant people.
  - A lead is worth reviewing; an empty list proves nothing
    (`VALIDATION_REPORT.md` §8a).
- **On fast media the single pass is CPU-bound.**
- **The 23 Sep gaps on drive 1** may be the team's own handling of the unit
  (the 21 Sep gap is a restart the unit's own log records).
  This is to be confirmed and recorded.

## 11. Future work

1. **The field visit** (USER_MANUAL §3.4d–e, SOP 1.2–1.4):
   - photograph each recorder's clock against true time, and its time-zone
     setting;
   - record its model, serial and firmware (done for the CP Plus unit on 28 Sep:
     `CP-UNR-104F1`, firmware `V1.00.14.00.T`);
   - take a native export from a reference disk.

   These make the first vendor `validated`, give UTC, and put both drives on
   one axis.
2. **Date drive 2's reformat.** The Hikvision log survives but ends on
   25 Aug 2024, 4½ days before the footage does, and holds no format record;
   the Dahua-family recorder that reformatted the disk kept its own log, which
   records hard-drive formatting (Dragonas et al. 2024) - on that recorder's
   disk or flash, not this one.
3. **Make the OCR read what the eye read:** clocks with a weekday or AM/PM
   are now read (28 Sep) and need a re-run on the reference frames. White
   text on bright backgrounds remains open: a top-hat filter was tried and
   did not help (VALIDATION_REPORT §8c).
4. **Speed:** done in the main - the taps run in a process pool, and the NAL
   searches are one pass; threaded hashes did not matter (PERFORMANCE.md §5).
   What is left, folding the signature search into that pass, is small.
5. **Any real disk** from Honeywell, Uniview or TP-Link: run the plugin
   (`parse --vendor ...`) - the first real disk is its test. The same for
   Matrix and Godrej. From anyone else: run `survey` and `carve-annexb`, then
   write a plugin.

## 12. Deliverables named in the PS

| Deliverable | Where |
|---|---|
| Comparative analysis of major OEMs | `OEM_COMPARISON.md`, `formats/*.ksy` |
| DVR/NVR forensic image | `FORENSIC_IMAGE.md` (whole-drive hashes, block map, 20 GiB head image, preserved metadata) |
| System architecture documentation | `ARCHITECTURE.md`, `TECH_STACK.md`, `DATA_CONTRACT.md` |
| Functional prototype | `cli.py` and the viewer (`python cli.py serve`); `python demo/stage_demo.py` shows every capability in eight steps |
| Standard Operating Procedures | `SOP_EXAMINATION.md`, `LINUX_ACQUISITION.md` |
| Validation reports | `VALIDATION_REPORT.md`, `PERFORMANCE.md` |
| User manuals | `USER_MANUAL.md` |
| Final project report | this document; `RESEARCH_BASIS.md` for differentiators and references |

## 13. Team

Six members, working as coder + researcher pairs (`MEMORY_SEED.md`). The
code contributions below are taken from the repository history.

- **Aakash** (coder; UI and presentation):
  - the acquisition and detection engine: read-only scan, block Merkle map,
    custody ledger;
  - Linux device enumeration and the tech-stack decisions;
  - the burned-in OSD reader and the combined multi-recorder view.
- **Shrestha** (coder):
  - the vendor parser SDK and the Dahua DHFS 4.1 and Hikvision parsers;
  - the DHAV and MPEG-PS carvers and the HIKBTREE index;
  - the single pass with USB-drop recovery, the timeline, the report and
    viewer, the analytics layer and the survey tool;
  - both drive acquisitions and most of the documentation.
- **JP** (coder):
  - the export comparison, model identification, the raw H.264/H.265 carver,
    the Honeywell plugin and the s.63 certificate;
  - the triage-pass fix, the performance measurement, the OEM research
    answers, the research basis, and this report.
- **Researchers**, as planned in `MEMORY_SEED.md`:
  - **Shrini** (specifications, hex inspection, test cases), paired with
    Shrestha;
  - **Prathyushree** (H.264 and timestamp research, output verification),
    paired with JP;
  - **Hriday** (BSA 2023 s.63, ISO 27037 and NIST SP 800-86, QA), paired with
    Aakash. Hriday is to make the s.63 wording check (§7).

## References

Full list with links in `RESEARCH_BASIS.md`. The principal ones are:

- Han, Jeong & Lee, ICDF2C 2015 (Hikvision FS)
- Rzayeva et al., *Information* 16:983, 2025 (Hikvision/Dahua recovery)
- *Information* 17(5):493, 2026 (DHAV demultiplexing)
- Yoon & Hwang, DFRWS USA 2026 (Honeywell FS)
- Ariffin, Slay & Choo, IFIP 2013 (proprietary CCTV carving)
- Dragonas, Lambrinoudakis & Kotsis, J. Forensic Sci. 2024 (Dahua logs)
- Garfinkel, DFRWS 2007 (carving with object validation)
- Merkle, CRYPTO '87
- Schneier & Kelsey, ACM TISSEC 1999 (secure audit logs)
- Boyd & Forster, Digital Investigation 2004 (time in forensics)
- Poppe et al., JVCIR 2009 (compressed-domain motion)
- SWGDE *Best Practices for Data Acquisition from DVRs* (2025)
- ISO/IEC 27037:2012; NIST SP 800-86
- *Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal* (SC, 2020)
- Bharatiya Sakshya Adhiniyam 2023, s.63 and Schedule
- IPVM *Dahua OEM Directory* (May 2024)
- Park & Lee, Digital Investigation 2014 (DVR fragment forensics)
- Giri, Yoon & Hwang, CARVE, DFRWS APAC 2026
- *Pune Bar Association v. Union of India* (SC, 22 May 2026)
- *Randeep Singh @ Rana v. State of Haryana* (SC, 2024 INSC 887)
- Puducherry G.O.Ms.No.27 (2025); Kerala Police CCTV SOP; MeitY s.79A scheme v2.0 (2025)
- SWGDE 18-Q-001 v2.1 and 12-Q-001; UK FSR-G-218 Issue 2; ISO/IEC 17025:2017
- Hargreaves et al., DFPulse 2024; Dstl, *Recovery and Acquisition of Video Evidence* (2022)

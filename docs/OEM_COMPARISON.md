# Comparative analysis of DVR/NVR OEMs

PS26150 deliverable: *comparative analysis of major DVR/NVR OEMs (Dahua
Technology, CP Plus, Honeywell Security, TP-Link, Godrej, Uniview, Matrix)*;
Hikvision is included because the PS names it among the supported OEMs.

**Status: draft.** The Dahua / CP Plus column is first-hand; Hikvision is
first-hand for the container and index; Honeywell is from published research
(§4); the research questions for the rest have first answers with sources
(§5.1). What is still unknown says so. Filling the unknowns, with citations, is the
researchers' work (§5 lists the questions). Nothing here may be quoted as
more certain than its tag.

| Tag | Meaning |
|---|---|
| **O** | observed by us on real media (CP Plus unit's drive, SkyHawk `WWD4A3NX`) |
| **P** | published research or open-source code — citation to be attached |
| **S** | only in our synthetic fixture |
| **?** | unknown to us |

The machine-readable companion for each format is a Kaitai `.ksy` file in
`formats/` (`dahua_dhfs41.ksy`, `hikvision_ps.ksy`), per `docs/TECH_STACK.md` - both
compiled and checked against the tool's own parsers (`VALIDATION_REPORT.md` §9a).

---

## 1. Summary

| | Dahua | CP Plus | Hikvision | Honeywell | TP-Link | Godrej | Uniview | Matrix |
|---|---|---|---|---|---|---|---|---|
| Filesystem | DHFS 4.1 **O** | DHFS 4.1 on our unit **O** (Dahua OEM) | `HIKVISION@HANGZHOU` master sector + `HIKBTREE` index **P**; index records decoded from surviving copies on our drive **O** | GPT; Partition 1 proprietary (header, block list, channel list, record state, video area), Partition 2 ext4 **P** | ? | ? | ? | ? |
| Video container | DHAV frames **O P** | DHAV **O** | MPEG-2 Program Stream with `HK` stream-map descriptors **O** | 20-byte Custom Header before each NAL unit **P** | ? | ? | ? | ? |
| Codec seen | H.265 **O** | H.265 **O** | H.264, 960×576, 25 fps **O** | H.264 (unit supports H.265) **P** | ? | ? | ? | ? |
| Camera id in frames | none — every camera writes channel 0; aux frames carry the channel title **O** | same **O** | none in the stream; the index names the channel per 1 GiB block **O** | none in the frame header; the channel list names it per chunk **P** | ? | ? | ? | ? |
| Time encoding | packed local date, no zone, + ms counter **O P** | same **O** | `HK` descriptor 0x40: year byte + packed M/D/h/m/s, local, no zone **O** | Unix seconds (lists), Unix microseconds per frame; zone not stated **P** | ? | ? | ? | ? |
| Detection in this tool | superblock magic + DHAV frames | Dahua-family structures + `CPPlusIPCam` channel title **O** | master magic + index header; `HK` stream-map descriptor **O** | `HONEYWELL` string | `TP-LINK` string | `GODREJ` string | `UNIVIEW` string | `MATRIX` string (weak: a common word) |
| Parser | yes | yes (Dahua parser) | index records (real media) + MPEG-PS carver; full-FS parser fixture only | yes, drop-in plugin from the paper | no | no | no | no |
| Our status | `spec_only` | `spec_only` | container and index `spec_only`; full-FS parser `synthetic_only` | `spec_only` | `detected_not_parsed` | `detected_not_parsed` | `detected_not_parsed` | `detected_not_parsed` |
| Real media held | via the CP Plus drive | yes | footage on the second drive, under a Dahua-family format | no | no | no | no | no |

---

## 2. Dahua DHFS 4.1 — and CP Plus

First-hand, from the CP Plus unit's 1 TB drive. Full detail and evidence:
`docs/DAHUA_DHFS.md`; layout: `formats/dahua_dhfs41.ksy`.

| Aspect | Finding | Tag |
|---|---|---|
| Layout | superblock at 0; partition table at 0x3C00 with a byte-identical backup at 0x7C00; 1 TB split into four ~250 GB volumes | O |
| Index | per volume, one 32-byte record per 2 MiB cluster: kind, camera, start/end date, next/prev/head cluster. A recording is a head record and a chain of continuations. Volume 1: 513 files, 115,063 clusters, 0 broken links | O |
| Data area | its base offset is not a header field; calibrated from the frames (0x95E000 on volume 1, 1.13 s mean timing error vs 2.98 s for the runner-up) | O |
| Files | one file per camera per hour; three cameras recording continuously 3–10 Sep 2026 in the first 20 GiB | O |
| Frames | DHAV header (24 B) + extension + H.265 payload + `dhav` trailer repeating the length; header checksum = byte sum of 0x00–0x16 (not in ffmpeg) | O P |
| Camera attribution | only through the index: frames carry no camera number, and cameras started together keep near-identical counters and clocks | O |
| Auxiliary frames | DHAV type 0xF1 frames carry a `TEXT` block with the channel title — `CPPlusIPCam` on every camera of this unit (17,557 occurrences in the first 20 GiB). Where titles differ between cameras this could attribute carved footage; here they do not. Found by `survey` | O |
| Recording behaviour | circular: clusters are reused, a newer recording overwriting an older one from the cluster start | O |
| Where old footage survives | at the tail of reused clusters (70 remnant runs in the first 20 GiB) and in clusters no index record accounts for (49 carved streams, ~14 min) | O |
| Timestamps | recorder wall clock, no zone. Index start vs first frame (42 recordings with footage in the first 20 GiB): within 2 s for 40, 3 s and 5 s for the other two | O |
| CP Plus vs Dahua on disk | the filesystem is identical. On this unit the platter itself names CP Plus: the default channel title `CPPlusIPCam` in the auxiliary frames (signature `cpplus.osd_title`). A user can rename channels, so its absence proves nothing | O |
| Forensic consequences | a Dahua parser covers CP Plus units built on Dahua boards; carved footage outside the index cannot be attributed to a camera; the index must be read *before* carving to label frames in one pass | O |

Open: whether every CP Plus model is a Dahua OEM (some may not be), and the
meaning of the undecoded header and record fields (listed in the `.ksy`).

## 3. Hikvision

The team's second drive (Seagate ST1000VX005, s/n `Z9C2632A`) was believed
to come from the Hikvision unit. Its platter now carries a **Dahua DHFS 4.1
superblock with an empty index** — a Dahua-family recorder formatted it — and,
underneath, **Hikvision footage** that the format did not overwrite. Layout:
`formats/hikvision_ps.ksy`.

| Aspect | Finding | Tag |
|---|---|---|
| Filesystem | master sector carrying `HIKVISION@HANGZHOU`; a `HIKBTREE` index mapping recordings to fixed-size data blocks | P (Han / Jeong / Lee DVR filesystem analysis; hikextractor — citations to attach) |
| What survived on our drive | the primary master sector was overwritten by the later format; a master sector copy (`HIK.2011.03.08`, just before the data area) and **two identical `HIKBTREE` copies** (`HIK.2010.11.09`) near the end of the disk survived | O |
| Index records | 48 bytes: 8×FF, channel at +0x11 (255 = initialised, never used), start/end at +0x18/+0x1C (seconds since 1970 on the recorder's own clock), data-block offset at +0x20 | O — 922 records |
| Data blocks | 1 GiB each from a base (0x4C5E000 here); every record lands exactly on the grid; 931 blocks, as the master copy states | O |
| Camera attribution | carved stream → its data block → the record whose window contains the stream's own times. 8 channels; each keeps one resolution; each holds 761–788 h | O |
| Time zone | the index times equal the `HK` stream-map times: both are the recorder's local clock, and neither stores a zone | O |
| Field offsets beyond the magic strings | as implemented in `parsers/hikvision.py` | **S** — our fixture only |
| Container | MPEG-2 Program Stream: one pack per frame, a stream map before each keyframe, H.264 video | O (ISO/IEC 13818-1 container) |
| `HK` descriptors | private descriptors in the stream map starting "HK": tag 0x40 carries the recorder's clock; 0x41 and the per-stream 0x42/0x44 are partly decoded (0x42 holds 960×576) | O |
| Time | 0x40: year byte + month 4 bits / day 5 / hour 5 / minute 6 / second 6. Matches the burned-in clock to the second, +1 s per stream map, spans the pack clock's interval | O |
| On-screen text | "23-04-2021 Fri 07:40:17", "Camera 04" | O |
| Camera attribution (stream alone) | nothing in the stream names the camera; the index does (above) | O |
| Forensic consequence | a reformatted drive still yields its old footage, dated, by carving the container by structure — no filesystem needed | O |

Status: Hikvision's **video container and index records are decoded from
real media** (`spec_only`: observed and cross-checked, not byte-matched to a
Hikvision export). The full-filesystem parser in `parsers/hikvision.py`,
written before we held media, stays `synthetic_only`.

## 4. Honeywell

From Yoon & Hwang, DFRWS USA 2026 (arXiv:2605.07430), section 5, which studied a Honeywell HN35080200 NVR with eight
HN40E-2030I cameras (H.264) on 160 GB and 250 GB disks. Implemented as the
drop-in plugin `plugins/honeywell.py`; status `spec_only` — no Honeywell
disk has been read by the team.

| Aspect | Finding | Tag |
|---|---|---|
| Which Honeywell units | Honeywell was a Dahua OEM until April 2022 (IPVM, §5.2 [1]): older units may carry DHFS and are read by the Dahua parser; this layout is the newer units' | P |
| Layout | GPT; sector 34 holds Machine Data (device ID, model name); Partition 1 proprietary, Partition 2 a 10 GB ext4 | P (5.1–5.2) |
| Partition 1 | header 0x0–0x3FFF; block list 0x40000; channel list 0x400000; record state 0x40000000; video from 0x80000000 | P (5.4) |
| Header | video start, next write, available and total space, each ×0x1000 ("rounded at the third digit"), little-endian; block group start time at 0x44 | P (5.4.1) |
| Channel list | 16-byte entries: channel, stream (0x00 main, 0x20 sub), length ×0x1000, start time (Unix s), offset ×0x1000 | P (5.4.3) |
| Frame header | 20 bytes before each NAL unit: type (0x82 IDR, 0x02 other), 80 01 00, width, height, NAL length, Unix µs | P (5.4.6) |
| Deletion | formatting resets the header and removes the indexes but leaves the video until overwritten from the start of the video area; expiry and overwrite rewrite metadata the same way | P (6) |
| Ambiguities, not guessed | byte order of the frame header's size and length; whether "the 12th byte" of a block index counts from 0 or 1; the origin of channel offsets; 4 bytes of each channel entry | — |

The plugin measures what the paper leaves open (the channel-offset origin,
whether a NAL length counts the start code) instead of assuming it, and
recovers timestamped footage from a formatted disk by walking the frame
headers.

## 4b. Beyond the eight: HeimVision (K9604-W), from a real public image

The PS asks for "other commonly used platforms" as well. From the NIST CFReDS *Heimvision DVR .E01 Forensic Image* (Brunty & Mock, Marshall University, 2021): a HeimVision K9604-W 4-channel DVR's 150 GB disk, FTK Imager 4.3.1.1, media MD5 `4895ea6d10b08c29fb1bb03591adc7b2` -
first-hand (**O**), in `plugins/heimvision.py`:

| Aspect | Finding | Tag |
|---|---|---|
| Disk | GPT; ext3 system partition (`search.db`, `dvr_log.db`); FAT32 video partition made by `mkdosfs` (the recorder runs Linux) | O |
| Storage | a pre-allocated ring of 8 MiB `.dat` files in `dirNNNNN/` (17,152 on 150 GB); `ident.bin` "ok1ormated"; `index.bin` | O |
| File header | 0x2080 bytes, `luo `, Unix start/end, per-channel start/end | O |
| Frames | 128-byte header `liu ` ... ` uil`, then the payload; the length field chains frames exactly | O |
| Camera id in frames | **yes** - channel at +0x2C, with a per-camera sequence; no index needed to attribute | O |
| Time | Unix microseconds per frame; FAT times in the recorder's local zone (UTC-8 on this unit) | O |
| Codec | H.265 1920x1080 15 fps, GOP ~10 s; audio G.711 A-law | O |
| System records | ext3: `dvr_log.db` (event log) and `search.db` (index per file and per camera-hour), SQLite, read and checked against the disk; `index.bin` one byte per file slot; each frame carries its `search.db` segment id | O |
| Status | `spec_only` | |

## 4a. TP-Link, Godrej, Uniview, Matrix

What the tool does today for each: recognise a brand string (`HONEYWELL`,
`TP-LINK`, `GODREJ`, `UNIVIEW`, `MATRIX`) wherever it appears on the
platter, score it, and report the vendor as `detected_not_parsed`. Brand
strings typically come from firmware, configuration or log areas; they
suggest who made the recorder but say nothing about how the video is stored.
`MATRIX` is also an ordinary word and is weighted as a candidate only.

Beyond that, their on-disk formats are **unknown to us**. Two routes to
footage exist regardless:

- **Carving** — if the recorder stores a raw H.264/H.265 stream or a known
  container, a codec-level carve recovers footage with no filesystem parser
  (`carve-annexb`: raw H.264/H.265 anchored on parameter sets — no dates, no
  cameras, and the unknown container's bytes left between frames; see
  USER_MANUAL §3.4f).
- **The plugin route** — one file in `plugins/` once the layout is known
  (`plugins/_template.py`).

## 5. Research questions (for the researchers)

For each of Honeywell, TP-Link, Godrej, Uniview, Matrix — and for CP Plus
models not built on Dahua boards:

1. Who manufactures the recorder board (own design, or OEM of Dahua,
   Hikvision, XM/Xiongmai, or another)? Cite the source.
2. Filesystem: proprietary or standard (ext, FAT)? Any published analysis or
   open-source parser?
3. Container and codec on disk; camera number in the frame headers or only
   in an index?
4. Time encoding: local or UTC, zone stored or not, where the index keeps
   start/end times.
5. Overwrite behaviour: circular? Is anything retained after "delete" from
   the recorder's menu?
6. Native export format and player; does the export carry a hash or
   signature?
7. Magic strings or structures strong enough for a signature better than a
   brand name.

Answers go into this file with a tag and a citation, and into a `.ksy` in
`formats/` once a layout is established.

### 5.1 Answers so far (28 Sep 2026)

Public sources for these vendors are thin, and that is itself a finding: none
of TP-Link, Godrej, Uniview or Matrix has a published analysis of its
on-disk format. Everything below is sourced; a blank question is marked **?**,
not filled from forum talk. Sources are listed in §5.2.

| Question | CP Plus | Honeywell | TP-Link (VIGI) | Godrej | Uniview | Matrix (SATATYA) |
|---|---|---|---|---|---|---|
| 1. Who builds the board | Dahua OEM: "CP Plus (Orange Line)" is a current entry in IPVM's Dahua OEM directory [1]; the brand's trademarks belong to Aditya Infotech [2]. On our unit, DHFS 4.1 **O** | A **former** Dahua OEM that "stopped purchasing these models in April 2022" [1]; the HN35080200 studied by Yoon & Hwang uses its own filesystem [3] | ? — not in the Dahua OEM directory [1]; no public statement found | ? — not in the Dahua OEM directory [1]; no public statement found | Its own design, and itself an OEM source: IPVM keeps separate Uniview OEM directories [1] | Indian manufacturer (Vadodara, Gujarat), own SATATYA line [4]; not in the Dahua OEM directory [1] |
| 2. Filesystem | DHFS 4.1 **O** (Dahua-built units) | newer units: GPT + proprietary video partition **P** [3]; older Dahua-built units: presumably DHFS — **not established** | ? | ? | proprietary; commercial recovery tools support it [5] but no layout is published | ? |
| 3. Container, codec, camera id | DHAV, H.265, channel byte 0 on every camera **O** | 20-byte header per H.264 NAL unit; camera only in the channel list **P** [3] | ? | ? | ? | ? |
| 4. Time encoding | packed local date, no zone **O** | Unix s / µs, zone not stated **P** [3] | ? | ? | ? | ? |
| 5. Overwrite | circular; old footage survives at cluster tails **O** | expiry and overwrite rewrite metadata; a format leaves video until overwritten **P** [3] | loop recording; "Locked" files are protected from overwrite [6] | ? | ? | ? |
| 6. Native export, player, integrity | `.dav` (Dahua) — not yet exported by us | ? | exported to USB from the NVR's GUI; format not stated; "the audio format in exported videos may not be compatible with some playback software"; no hash or signature mentioned [6] | ? | ? | native `.avs` (MATRIX DVR Backup Manager), `.stm` (Device Player), `.mxs` (Device/Web/DVR Client, SATATYA CORE) [7]; export to AVI over USB/FTP [8] |
| 7. Signature better than a brand name | DHFS superblock, DHAV frames, `CPPlusIPCam` **O** | GPT + partition header + frame header `82/02 80 01 00` **P** [3] (too short to scan the whole disk for; checked structurally) | model numbering `VIGI NVRxxxx` (`identify-model`) | ? | model numbering `NVR3xx-xx…` (`identify-model`) | model numbering `SATATYA …`; the magic bytes of `.avs`/`.mxs`/`.stm` are not published |

**What follows for the tool:**

- **CP Plus.** The Dahua parser is the right parser for Dahua-built CP Plus
  units, now from a second, independent source [1] as well as our drive. For
  a CP Plus unit that is not Dahua-built, `record-device` + `identify-model`
  will show the mismatch.
- **Honeywell.** A Honeywell disk may carry either format: DHFS on units
  bought from Dahua before April 2022, the Yoon & Hwang layout on the newer
  ones. The tool already tries both (the Dahua parser and the Honeywell
  plugin detect independently). On a Honeywell unit with a DHFS disk, the
  model check reads "differ", which is explained by [1] and should be
  written up as such, not as tampering.
- **TP-Link, Godrej, Uniview, Matrix.** Nothing published to parse from. Their
  video is recoverable by `carve-annexb`. Their exports (TP-Link to USB,
  Matrix to AVI) are what `validate-export` would compare against, once a
  unit is available to record on.

### 5.2 Sources

1. IPVM, *Dahua OEM Directory (Public Report)*, 3 May 2024 — https://ipvm.com/reports/dahua-oem
2. Trademark note "CP Plus, KVMS Pro, … CP-UNC, CP-USC, CP-VNR, and CP-UVR are trademarks of Aditya Infotech Ltd.", on an integrator's page (Tentosoft) — https://tentosoft.com/works-with/cp-plus.html. A primary CP Plus source is still to be found.
3. J. Yoon, S. Hwang, DFRWS USA 2026, arXiv:2605.07430 (§4 of this file).
4. Matrix Comsec, *SATATYA Network Video Recorders* product pages — https://www.matrixcomsec.com/product/satatya-network-video-recorders/
5. 512 BYTE, *Uniview NVR Recovery* (commercial recovery software; states support, publishes no layout) — https://soft.512byte.ua/knowledge-base/uniview-nvr-recovery/
6. TP-Link, *How to Search and Export Recordings from VIGI NVR GUI* (FAQ 4615) — https://www.tp-link.com/us/support/faq/4615/
7. Matrix Wiki, *How to play .avs, .mxs and .stm file?* — https://wiki.matrixcomsec.com/index.php?title=How_to_play_.avs%2C_.mxs_and_.stm_file%3F
8. Matrix Wiki, *FAQs – SATATYA HVR* / *FAQs – SATATYA SAMAS* (export to AVI) — https://wiki.matrixcomsec.com/index.php?title=FAQs_-_SATATYA_HVR

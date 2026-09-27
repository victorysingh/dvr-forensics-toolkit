# Comparative analysis of DVR/NVR OEMs

PS26150 deliverable: *comparative analysis of major DVR/NVR OEMs (Dahua
Technology, CP Plus, Honeywell Security, TP-Link, Godrej, Uniview, Matrix)*;
Hikvision is included because the PS names it among the supported OEMs.

**Status: draft.** The Dahua / CP Plus column is first-hand. Everything else
is either published research whose citation still has to be attached, or
unknown — and says so. Filling the unknowns, with citations, is the
researchers' work (§5 lists the questions). Nothing here may be quoted as
more certain than its tag.

| Tag | Meaning |
|---|---|
| **O** | observed by us on real media (CP Plus unit's drive, SkyHawk `WWD4A3NX`) |
| **P** | published research or open-source code — citation to be attached |
| **S** | only in our synthetic fixture |
| **?** | unknown to us |

The machine-readable companion for each format is a Kaitai `.ksy` file in
`formats/` (`dahua_dhfs41.ksy` so far), per `docs/TECH_STACK.md`.

---

## 1. Summary

| | Dahua | CP Plus | Hikvision | Honeywell | TP-Link | Godrej | Uniview | Matrix |
|---|---|---|---|---|---|---|---|---|
| Filesystem | DHFS 4.1 **O** | DHFS 4.1 on our unit **O** (Dahua OEM) | `HIKVISION@HANGZHOU` master sector + `HIKBTREE` index **P**; index records decoded from surviving copies on our drive **O** | ? | ? | ? | ? | ? |
| Video container | DHAV frames **O P** | DHAV **O** | MPEG-2 Program Stream with `HK` stream-map descriptors **O** | ? | ? | ? | ? | ? |
| Codec seen | H.265 **O** | H.265 **O** | H.264, 960×576, 25 fps **O** | ? | ? | ? | ? | ? |
| Camera id in frames | none — every camera writes channel 0; aux frames carry the channel title **O** | same **O** | none in the stream; the index names the channel per 1 GiB block **O** | ? | ? | ? | ? | ? |
| Time encoding | packed local date, no zone, + ms counter **O P** | same **O** | `HK` descriptor 0x40: year byte + packed M/D/h/m/s, local, no zone **O** | ? | ? | ? | ? | ? |
| Detection in this tool | superblock magic + DHAV frames | Dahua-family structures + `CPPlusIPCam` channel title **O** | master magic + index header; `HK` stream-map descriptor **O** | `HONEYWELL` string | `TP-LINK` string | `GODREJ` string | `UNIVIEW` string | `MATRIX` string (weak: a common word) |
| Parser | yes | yes (Dahua parser) | index records (real media) + MPEG-PS carver; full-FS parser fixture only | no | no | no | no | no |
| Our status | `spec_only` | `spec_only` | `synthetic_only` | `detected_not_parsed` | `detected_not_parsed` | `detected_not_parsed` | `detected_not_parsed` | `detected_not_parsed` |
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

## 4. Honeywell, TP-Link, Godrej, Uniview, Matrix

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

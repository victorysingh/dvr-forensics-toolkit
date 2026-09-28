# Dahua DHFS 4.1 — what we know, and how we know it

The on-disk format of Dahua-family DVRs, as reverse-engineered from real media,
and the rules `parsers/dahua.py` follows because of it. Read this before
changing the parser: most of the rules exist because a simpler version
produced wrong output against the real disk.

**Status: `spec_only`.** The structure was read off real media, but nothing has
been byte-matched against the recorder's own export. Only that moves Dahua to
`validated` (see START_HERE Rule 3).

---

## 1. The evidence this is based on

| | |
|---|---|
| Drive | Seagate SkyHawk `ST1000VX013-3CV10C`, serial `WWD4A3NX`, 1 TB |
| Bridge | Super Top M6116 (`14cd:6116`), USB 2.0, ~34 MB/s |
| Write block | software — `blockdev --setro`, verified `getro = 1` |
| Image | first 20 GiB only, `ddrescue -d -s 20Gi`, 0 bad areas, 2026-09-23 |
| SHA-256 | `c4098d59cff3973de9d281ba5613005ba52165743c36edfcf56f61aad8f4e610` |
| MD5 | `b1a7a6cfa8fc546e0bf4d21aa9a7d0bc` |
| Cross-check | first 184 × 8 MiB blocks match an earlier independent read of the drive |

This is a **partial image**, and its hashes are not the drive's. Volume 1's
whole index is inside it; volumes 2–4 are not.

**Where the drive came from is unconfirmed.** It holds DHFS, so it did not
record in the Hikvision `DS-80xx` it was believed to belong to. Nothing on the
platter tells Dahua from CP Plus (CP Plus boards are usually rebadged Dahua),
so the tool says "Dahua-family" and nothing more specific.

---

## 2. Disk layout

```
0x000000   superblock        "DHFS4.1", then "uuid:{...}" at +0x20
0x003C00   partition table   4 entries; byte-identical backup at 0x7C00
volume + 0x004400   volume header     backup at +0x8400 (matched on volume 1)
volume + 0x017600   cluster table     32-byte records, one per 2 MiB cluster
volume + 0x95E000   data area         cluster N at base + N * 2 MiB
```

On this 1 TB disk the partition table splits the platter into four volumes of
250.1 GB, starting at sectors `0`, `0x1D1C2000`, `0x3A383800`, `0x57545800`.

### Superblock (offset 0)

| Offset | Field | Evidence |
|---|---|---|
| `0x00` | `DHFS4.1` magic + version | observed; also in dvrdecode |
| `0x20` | `uuid:{b7656fca-9c42-ebce-bf64-f44c71a8c1b0}` | observed |
| `0x1F4` | `AA 55 AA 55` marker | observed |

A 4-byte `DHFS` also turns up at random inside video (9 times in 20 GiB, as
chance predicts). Only the one at offset 0 is a superblock.

### Partition entry (0x40 bytes, from 0x3C40)

| Offset | Field | Evidence |
|---|---|---|
| `+0x24` | start, 512 B sectors (u32) | the four starts tile the disk with no gaps |
| `+0x2C` | length, sectors (u32) | start + length < next start |

The dword after each is zero on this disk. If it isn't on a larger disk, these
may be 64-bit, and the parser says so in its notes.

### Volume header (volume + 0x4400)

| Offset | Field | Value on volume 1 | Evidence |
|---|---|---|---|
| `0x10` | earliest recording (packed date) | 2026-09-03 12:53:53 | equals the earliest head record |
| `0x14` | latest recording (packed date) | 2026-09-10 07:56:27 | within 2 s of the latest head record |
| `0x2C` | bytes per sector | 512 | |
| `0x30` | sectors per cluster | 0x1000 (2 MiB) | matches frame layout |
| `0x38` | first data cluster | 2120 | equals the count of leading `FE` records |
| `0x44` | cluster table start, sectors | 0xBB → 0x17600 | table found there |
| `0x4C` | cluster slots | 119,229 | volume size / 2 MiB |

**Seen but not decoded:** `0x08`=10, `0x0C`=85, `0x18`=117,182, `0x3C`=0x4900,
`0x40`=0x22, `0x48`=0x4B00, `0x54`=5, `0x58`=0x4B00, `0x5C`=0x10. The data base
0x95E000 is 0x4AF0 sectors, which is `0x48 − 0x5C`. That might be the rule, but
one disk is not enough to say, so the parser does not rely on it (section 5).

### Cluster record (32 bytes)

| Offset | Field | Evidence |
|---|---|---|
| `0x00` | kind: `01` head of file, `02` continuation, `FE` reserved, `00` empty | 513 heads + 114,550 continuations; all chains close |
| `0x01` | camera as an ASCII digit, `'0'` = first camera | `'0'`/`'1'`/`'2'`, 171 files each |
| `0x02` | head: number of continuations; continuation: sequence number | head value = chain length for all 513 |
| `0x04` | start (packed date) | frame dates in each cluster match it |
| `0x08` | end (packed date) | head end = file end, on the hour |
| `0x0C` | next cluster, `0` ends the chain | 0 broken links across 115,063 clusters |
| `0x14` | previous cluster | |
| `0x18` | head cluster of this file | |

**Not decoded:** `0x10` (512–4096 on heads), `0x1C`, `0x1E`.

A **recording** is one head record plus its chain of continuations: one file
per camera per hour, rolling over on the hour.

---

## 3. DHAV frames

Video, audio and metadata inside clusters are DHAV frames. The layout is
**published** (ffmpeg `libavformat/dhav.c`):

| Offset | Size | Field |
|---|---|---|
| `0x00` | 4 | `DHAV` |
| `0x04` | 1 | type: `FD` I-frame, `FC` P-frame, `F0` audio, `F1` aux |
| `0x08` | 4 | frame counter |
| `0x0C` | 4 | whole frame length, including header and trailer |
| `0x10` | 4 | packed date |
| `0x14` | 2 | millisecond clock, wraps at 65536 |
| `0x16` | 1 | extension length |
| `0x17` | 1 | checksum |
| … | | extension tags, payload, then `dhav` + length |

**Packed date:** `sec[0:6] min[6:12] hour[12:17] day[17:22] month[22:26]
(year−2000)[26:32]`. The DHFS index uses the same encoding. It is the
recorder's wall clock, **with no timezone**.

**Checksum (observed, not in ffmpeg):** byte `0x17` = sum of bytes `0x00–0x16`,
mod 256. It held for every frame tested. The parser accepts a frame only if
the checksum holds *and* the trailer repeats the length.

**Extension tags:** `0x80` → width/8, height/8; `0x81` → codec, fps
(`0x0C` = H.265, `0x02`/`0x08` = H.264); `0x83` → audio. On this disk every
camera is 1920×1080 H.265 at 25 fps, with 8 kHz A-law audio.

**Payload** is Annex-B. I-frames open with a VPS NAL (`00 00 00 01 40 01`), so
the extracted elementary stream should play directly. Its structure is
checked (parameter sets and an IDR repeating, P-frames between); playback has
not yet been verified with a decoder on the team's workstation.

**Auxiliary frames (type `0xF1`)** carry a `TEXT` block holding the channel
title. On this unit every camera's title is the default `CPPlusIPCam` —
17,557 occurrences in the first 20 GiB — which puts the CP Plus name on the
platter itself (signature `cpplus.osd_title`). It does not separate cameras
here, because the titles are identical; on a recorder whose channels are
named, it could attribute carved footage. Found by `cli.py survey`, which
flagged `TEXT` as a candidate header.

---

## 4. How the recorder writes — the traps

These are why a naive carve produces wrong evidence.

1. **Every camera is "channel 0".** The DHAV channel byte is 0 for all three
   cameras. The camera exists only in the cluster index. Carving DHAV frames by
   magic alone interleaves every camera into one stream.

2. **Overflow lands in someone else's cluster.** When a write runs past the end
   of a 2 MiB cluster, the rest — the frame that crossed the boundary, plus the
   remainder of that write, typically an audio frame — goes into the
   **physically next** cluster, usually another camera's, overwriting its first
   bytes. Confirmed 6 of 6 cases tested. So:
   - the start of a cluster can hold the tail of another camera's stream;
   - frames are destroyed where writes collide at a cluster start. This is the
     ~0.37% of frames with **no intact copy on the disk**, about one per
     cluster. In CH01's first hour, 314 of the 371 are overflow frames whose
     header survives in the next physical cluster while their body does not.

   **Less often, the cut goes to the chain instead.** A frame can be cut at the
   cluster end and finished at the start of the recording's **next chain
   cluster**, so its two halves are not adjacent on disk (57 of the 371). That
   next cluster's start is also where the physically previous cluster's
   overflow lands, and in 50 of the 57 such an overflow later overwrote part
   of the second half: its trailer lies inside it. Only 7 rejoin intact.

3. **Cameras are near-twins.** Cameras started together keep near-identical
   frame counters and millisecond clocks: at one instant they are 20–60 frames
   and about a second apart, and over an hour they drift through each other.
   Anything that separates streams by "does this frame continue that one?"
   will jump from one camera to another. Taking the closest match helps but is
   not enough on its own: without an index it still mixed two cameras (section
   6a). Byte contiguity, plus refusing to guess, is what holds.

4. **Counters are per frame type, and they drift.** Video, audio and aux frames
   each keep their own counter. They start in near-lockstep, which hides this,
   but on this disk audio was 78 ahead of video six hours in.

5. **Clusters are reused without being cleared.** Past where the current
   recording stopped writing, a cluster still holds older footage. That older
   footage is the recoverable remnant of overwritten recordings.

6. **Head clusters are not understood.** A head cluster holds less than a
   second of data, sometimes a partial I-frame whose counter belongs to a
   *different* camera's stream, then older footage. The parser lists heads but
   does not extract from them.

---

## 5. What the parser does about it

**Data-area base: calibrated, not assumed.** Candidate bases come from
I-frames that sit exactly on a cluster boundary. Each one is dated inside some
index record's window, so it proposes `offset − record × 2 MiB`. Voting alone
is not enough, and neither is stream continuity. The cameras are allocated
clusters in rotation, so a base that is whole clusters off lands on another
camera's clusters from nearly the same seconds, and those chains are just as
continuous. **Timing** separates them. Clusters are allocated in time order,
so at a wrong base the frames found are consistently early or late against the
index. On volume 1:

| Base shift (clusters) | −2 | −1 | **0** | +1 | +2 |
|---|---|---|---|---|---|
| mean start/end error, s | 2.9 / 8.4 | 2.1 / 4.9 | **1.2 / 1.2** | 2.7 / 3.5 | 5.8 / 6.2 |

The chosen base, 0x95E000, has 1.13 s mean error against 2.98 s for the
runner-up, with 8/8 chain pairs continuous. If no candidate finds footage, the
base stays unknown and **extraction refuses** to run rather than guess.

**Frame assignment: by stream, never by position.** Walking a recording's
chain in order, each frame is classified:
- **own**: continues this recording's stream;
- **spill-in**: continues the stream of the *physically previous* cluster;
  when both could claim a frame, the closer match wins;
- **overflow out**: after a cluster's own run reaches its end, frames in the
  next physical cluster are taken only while they are **byte-contiguous** —
  each starting exactly where the last ended — *and* continuous. Continuity
  alone once walked straight on into the next camera's data (trap 3);
- **rejoined**: when the own run ends in a frame that crosses the cluster end
  but does not continue in the next physical cluster, its first half is joined
  to the start of the **next chain cluster**. The frame is taken only if it
  starts exactly where the last own frame ended, passes the header checksum
  and the trailer-length check as one piece, and continues the stream. It is
  refused if its second half holds any `DHAV` or `dhav` marker: another
  camera's overflow that overwrote part of it always leaves one, while the
  header and trailer, the only bytes the other checks see, stay intact. Both
  halves' offsets go into the extraction manifest (`joined_frames`);
- **remnant**: anything else, dated outside the cluster's window.

Continuity compares the millisecond clock and date with the previous frame of
any type, and the counter only with the previous frame **of the same type**
(trap 4).

**Remnants: only when clearly older.** A run counts as a remnant of an
overwritten recording only when it is at least 1 h outside its cluster's
window. Closer runs are counted and reported, but not presented as recovered
footage. A remnant's camera is **unknown**: the DHAV header does not carry it,
and the index now points to the cluster's new owner.

---

## 6. Results on volume 1

| | |
|---|---|
| Recordings | 513 (171 per camera × 3), 2026-09-03 12:53:53 → 2026-09-10 07:56:29 |
| Chains broken | 0 |
| Footage inside the 20 GiB image | 8,073 of 114,550 continuation clusters |
| CH01 12:53–14:00 | 98,801 video frames, 0.37% missing by counter, 0 duplicates, 0 stream breaks, all 198,451 adjacent frame pairs continuous |
| Remnants of older footage | 70 runs, 38,407 frames, ~13 min, 99 MB — 68 from Aug 2026, 1 May, 1 June |
| Not explained | 7 runs, 613 frames dated inside the current recording period |

With chain-boundary rejoin, the same hour gives 98,808 video frames and 364
missing (7 rejoined, 50 refused as overwritten).

The synthetic fixture (`tests/synth_dahua.py`) reproduces traps 1–5, and the
chain-boundary cut with `chain_splits=True`, including second halves that a
later overflow overwrote. Against
its known ground truth, reassembly gets every camera exactly right — no foreign,
missed or duplicate frames — across the seeds tested.

---

## 6a. Carving without the index

`recover/carver.py` (`cli.py carve`) recovers the same footage **from raw
bytes alone**, for when an index is damaged, wiped or missing, and for footage
no index describes. It validates every DHAV frame in a region and assigns each
one to a stream:

1. **Byte contiguity first.** A frame that starts exactly where the previous
   frame ended, and continues its stream, is that stream's. This settles
   99.9% of frames on the real disk (6,996,492 of 7,004,515).
2. **At a discontinuity** (cluster start, overflow, stale data), the closest
   continuing stream, **but only if it beats the runner-up by 4×**. Otherwise
   the frame starts a new stream.

Rule 2's refusal is the point. The first version took the plain closest match,
and on the real disk **146 of 152 streams mixed two cameras**: CH02 and CH03
drift to within tens of frames and seconds of each other (trap 3). Splitting
one camera into several pure fragments is an inconvenience. Mixing two cameras
into one output is a false statement.

A carved stream is **not a camera**: it is labelled `UNKNOWN`, one camera can
span several streams, and carving alone says nothing about deletion. Where a
DHFS index is readable, `cross_reference` uses it **only afterwards** to label
each stream with the camera whose clusters hold it, or `outside_index` when no
index record accounts for those frames at their dates.

**Results, whole 20 GiB, no index used to carve:**

| | |
|---|---|
| Time | 50 s carve + 40 s labelling |
| Streams kept | 152; 104 ambiguous boundaries split; **0 with mixed evidence** |
| CH01 / CH02 / CH03 | 2.32 M frames each, in 22 / 46 / 35 streams |
| Outside every index window | 49 streams, ~14 min of video — 47 from Aug 2026, 1 May, 1 June |

Over hour one, the carve holds 100% of the frames index-guided extraction
recovers for each camera, with no stream mixing them. The outside-index
footage agrees with the independent remnant scan (section 6) in both amount
and dates. On the synthetic fixture, including a mode where two cameras have
identical counters and clocks, every surviving frame is carved and no stream
mixes sources.

```bash
python cli.py carve --device image.dd --out out/CASE/carve                   # report only
python cli.py carve --device image.dd --out out/CASE/carve --extract outside # + write unindexed footage
```

---

## 7. Open questions

- **Validation.** Needs a clip exported by the recorder this disk came from,
  byte-matched against our extraction. Without the recorder, Dahua stays
  `spec_only`.
- **Volumes 2–4.** Each keeps its index in its first ~16 MiB. Imaging just
  those regions would list every recording on the disk without a 1 TB image.
- **Undecoded fields** in the volume header and cluster record (section 2).
- **The head cluster's role** (trap 6).
- **Timezone.** Unknown until someone reads the recorder's settings; pass
  `--tz-offset` in minutes (e.g. 330 for IST). Until then `start_utc` is empty
  and every time is labelled recorder-local.
- **Generality.** One disk, one firmware, three cameras. Other DHFS versions or
  larger disks may differ. The parser reports what doesn't fit rather than
  forcing it.

---

## 8. Using it

```bash
# list recordings (and optionally older remnants)
python cli.py parse --device image.dd --vendor Dahua --out out/CASE
python cli.py parse --device image.dd --vendor Dahua --remnants --out out/CASE

# reassemble one recording: .dav, .h265, and a hashed manifest
python cli.py extract --device image.dd --recording dhfs-v1-c002120 --out out/CASE/clips
ffplay out/CASE/clips/dhfs-v1-c002120.h265

# regression tests; the real-media checks need the image
DHFS_REAL_IMAGE=~/evidence/skyhawk_WWD4A3NX_first20GiB.dd python tests/test_pipeline.py
```

The manifest records every cluster read and its hash, what was left out, and
how many frames are missing.

**For the timeline and report stages:** recordings carry `TimestampClaim`s from
the index (`source="index"`) and from the first DHAV frame
(`source="container"`). `decoded_utc` and `start_utc` are empty unless a
timezone was supplied. That is deliberate: a recorder-local time presented as
UTC would be a false statement in a court report.

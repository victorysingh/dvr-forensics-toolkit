# User manual

PS26150 deliverable: *user manuals*. For the examiner running the tool. The
full evidence-handling procedure is `docs/SOP_EXAMINATION.md`; the Linux
acquisition steps are `docs/LINUX_ACQUISITION.md`; how the system is built is
`docs/ARCHITECTURE.md`.

---

## 1. What it does, and what it does not

It takes a DVR/NVR hard drive (or an image of one) and, without ever writing
to it:

- hashes the whole drive (MD5, SHA-256) and every 8 MiB block;
- identifies the vendor by signature, as a confidence score, for all eight
  OEMs in the problem statement;
- parses the filesystem where a parser exists (Dahua DHFS 4.1, which CP Plus
  units also use; Hikvision, tested on synthetic data only);
- recovers footage without the filesystem index, including footage the index
  no longer accounts for;
- builds a camera timeline, converting the recorder's clock to UTC only on
  inputs you state;
- writes a report and keeps a hash-chained chain of custody.

It measures motion activity from compressed frame sizes (§3.4a) as a lead for
review. It does **not** yet: decode video to MP4, run face/object detection, read the
on-screen clock, or sign reports; the BSA s.63 certificate is produced as a draft (§3.4g). Nothing
it produces is labelled `validated` — see §6.

## 2. Requirements

- Python 3.11 or newer. No packages to install. **Or** the packaged
  `ps26150-dvr.exe`: one file, no Python. It takes the same commands as
  `python cli.py`, and loads new vendors from a `plugins\` folder next to it
  (`packaging/README.md`).
- Linux for live acquisition (the tested path); Windows works with an
  Administrator shell and `\\.\PhysicalDriveN` paths.
- Free space for the outputs, not the drive: about 50 MB per drive for the
  scan, plus whatever footage you choose to extract.

Check the installation (no hardware needed, about 10 seconds):

```bash
python tests/test_pipeline.py      # all tests must pass
python demo/tamper_demo.py         # the two-minute integrity demo
```

## 3. The workflow for one drive

Replace `/dev/sdX` and `CASE-001` throughout. **Do §3.1 before the drive is
plugged in.**

### 3.1 Before attaching (once per session)

```bash
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false
sudo systemctl stop udisks2 && sudo systemctl mask --runtime udisks2
sudo sh -c 'echo -1 > /sys/module/usbcore/parameters/autosuspend'
```

If you know the USB id of your evidence adapter (`lsusb`), install a rule
that write-blocks every disk behind it the moment it appears:

```bash
python cli.py writeblock-rule --usb-id 14cd:6116 --user "$USER" \
  | sudo tee /run/udev/rules.d/70-ps26150-writeblock-adapter.rules
sudo udevadm control --reload
```

### 3.2 Attach, identify, write-block

```bash
python cli.py devices                  # find the drive; wblock column shows RO(kernel) or RW !!
sudo blockdev --setro /dev/sdX
blockdev --getro /dev/sdX              # MUST print 1
python cli.py writeblock-rule --device /dev/sdX --user "$USER" \
  | sudo tee /run/udev/rules.d/70-ps26150-writeblock.rules
sudo udevadm control --reload
```

The second rule is keyed on the drive's own serial, so the drive stays
write-blocked even if the USB bridge resets and the drive comes back under a
new name. With `--user`, you get **read** permission, and the scan runs
without root.

### 3.3 Acquire — one pass

```bash
systemd-inhibit --what=sleep:idle python cli.py scan --device /dev/sdX \
    --case CASE-001 --investigator "Name" --organization "Unit" \
    --notes "drive make/model/serial, enclosure, seal numbers" \
    --carve --reconnect-wait 480
```

| Option | Meaning |
|---|---|
| `--carve` | also recover footage in the same pass (Dahua-family disks). Costs CPU, not time |
| `--carve-ps` | also recover MPEG Program Stream footage (Hikvision and others), dated from Hikvision's `HK` stream maps — including footage under a drive another recorder reformatted |
| `--carve-annexb` | also recover raw H.264/H.265 by its parameter sets — the last resort for a recorder we have no parser for (§3.4f) |
| `--no-parallel` | run the carvers and the activity count inside the scanning process instead of one process each. Same output, slower; for a machine with one CPU |
| `--reconnect-wait N` | if the drive drops off USB, wait up to N minutes for it to come back write-blocked and verified, then continue the same hashes. `0` fails at once |
| `--max-mb N` | triage: stop after N MiB. The pass is marked incomplete and its hashes must not be quoted |
| `--resume` | continue an interrupted scan. The Merkle root is valid; the linear MD5/SHA-256 are not |
| `--tz-offset M` | the recorder's zone in minutes east of UTC, if known |

Plan the time: USB 2 reads about 25 MB/s (1 TB ≈ 11 h); USB 3 about 100–150 MB/s.
Outputs go to `out/CASE-001/`.

### 3.4 After the pass

```bash
python cli.py verify   --out out/CASE-001                          # custody chain + Merkle root
python cli.py preserve --device /dev/sdX --out out/CASE-001        # filesystem metadata, ~100 MB
python cli.py parse    --device /dev/sdX --vendor Dahua --out out/CASE-001
python cli.py extract-carved --device /dev/sdX --out out/CASE-001  # footage outside every index
python cli.py timeline --out out/CASE-001 --tz-offset 330 \
    --clock-observed "2026-09-25 10:02:13" --clock-reference "2026-09-25 10:00:00"
python cli.py report   --out out/CASE-001 --notes "..."
python cli.py verify   --out out/CASE-001                          # again, now covering preserved blocks
```

- `label-ps --device /dev/sdX --out out/CASE` names the camera of each carved
  MPEG-PS stream from a surviving Hikvision HIKBTREE index, where the scan found
  one; the timeline then shows camera lanes and recorded-vs-recovered hours.
- `extract-carved --format ps` saves MPEG-PS streams unmodified as playable `.ps` files
  (the default `auto` picks PS when the DHAV carve found nothing).
- `extract-carved` defaults to `--label outside_index`. Use `--label CH02` for
  one camera's carved footage, `--label all`, or `--ids carve-00012,carve-00019`.
- `timeline --clock-observed/--clock-reference`: at seizure, write down what
  the DVR's screen shows and a trusted clock at the same instant. Without
  them, the timeline states that the clock error was not measured.
  Without `--tz-offset`, no UTC is asserted at all.
- To reassemble one indexed recording rather than carved footage:
  `python cli.py extract --device /dev/sdX --vendor Dahua --recording dhfs-v1-c002120 --out clips/`.

### 3.4a Motion activity (a lead, not evidence)

```bash
python cli.py activity --device image.dd --out out/CASE-001    # over an image
# or, on a live drive, in the acquisition pass itself:  scan ... --carve --activity
```

P-frame bytes per camera per minute, from the frame headers — no video is
decoded. A peak is a minute at 3x or more the median of the 30 minutes either
side on that camera; minutes where several cameras peak together are listed
separately. Low-light noise, lighting or infrared changes, rain and camera
shake also produce peaks: on the CP Plus drive the strongest cluster is every
camera at once around dusk. Use it to decide what footage to watch first,
never as a finding.

### 3.4b Camera names from the burned-in picture (a lead, not evidence)

Optional, and it needs two binaries the forensic core does not:
`sudo apt install ffmpeg tesseract-ocr`.

```bash
python cli.py read-osd --out out/CASE-001 --unlabelled
```

Footage no index accounts for carries no camera in its bytes — but the recorder
painted the channel title into the picture. This samples frames from each
stream, reads the title and the displayed clock, and claims a label only when
enough frames agree; the share that agreed is reported with it. `--unlabelled`
restricts the run to exactly those streams, which is what you normally want.

It also compares the clock in the picture with the date decoded from the
container: two routes to the recorder's own clock, which should agree. A
disagreement is reported and is not resolved for you — the frame is the
arbiter. Nothing here converts a time to UTC.

A title is what the installer typed ("Parking"), not a channel number, and it
is OCR of pixels: confirm it in the frame before it goes near a finding. The
OCR's accuracy has not yet been measured on real footage — `docs/OSD_OCR.md`
§6 says exactly what that means and how to settle it.

### 3.4c More than one recorder in the same case

```bash
python cli.py combine --cases out/CASE-001 out/CASE-002 --out out/COMBINED     --title "Premises X: two recorders"
```

Writes `combined.json` and `combined.html`, and records the view in each
source case's custody ledger.

**Two recorders share no clock.** Each has its own crystal, its own timezone
setting and no knowledge of the other, so the command will only draw them on
one axis when *every* case states its recorder's timezone (`timeline
--tz-offset`). Where one does not, the cases are shown side by side, each on
its own recorder clock, the page says plainly that they are not aligned, and
section 3 makes no statement about what was recorded at the same time. The
command prints exactly which case is missing what.

Even on a shared axis, a recorder whose clock error was never measured
(`--clock-observed/--clock-reference`) carries an unknown offset, and that is
listed as a caveat rather than absorbed.

### 3.4d Validate against the recorder's own export

This is the only way a vendor's status can become `validated`: the recorder
exports a clip with its own export function, and the same footage recovered
from the disk is compared with it byte for byte.

**Never put an evidence drive back into its recorder to do this.** A recorder
writes to its disk as soon as it runs — it records, rotates, may re-format —
which changes the evidence and its hash. Use a **reference disk**:

1. Put a spare SATA disk in the recorder and let the recorder format it. That
   is the point: the layout is then the recorder's own.
2. Photograph the recorder's clock next to a trusted clock, then let it
   record 10–15 minutes.
3. Export 1–2 minutes of one camera with the recorder's own export function —
   in its native format if it offers one (`.dav` on Dahua and CP Plus). Note
   the camera and the period. Photograph the recorder's label and its System
   Info screen (model, firmware).
4. Acquire the reference disk like any evidence (`scan --carve` or
   `--carve-ps`), `parse` it, and `extract` the recording that covers the
   exported period.
5. Compare:

```bash
python cli.py validate-export --export /media/usb/ch1_1100.dav \
    --against out/REF-001/clips --out out/REF-001 \
    --recorder "CP Plus CP-UNR-104F1, firmware <from System Info>"
```

It compares the pictures themselves — every H.264/H.265 slice, in order —
not the container around them, because an export may legitimately rewrite
frame headers or add data. The verdict is `identical`, `partial` (with the
export frames it could not find, each of which needs an explanation), or
`none`. Container differences are printed separately. `--against` takes files
or directories; a stream extracted both as `.dav` and as bare video is
searched once. MP4, AVI and ASF exports need `ffmpeg`, which copies the video
out without re-encoding it; Hikvision's `.mp4` files are Program Streams and
are read directly.

The result goes to `validation/export_<clip>.json` with both files' SHA-256,
and into the custody ledger. The vendor's status is **not** changed for you:
record an `identical` result in `VALIDATION_REPORT.md` §9, and the status
moves in review.

### 3.4e The recorder's model

The disk says whose *format* it carries; it rarely says which *model* wrote
it — that lives in the recorder's flash. Two sources, kept apart:

```bash
# what the examiner read off the unit, with the photos that show it (hashed, not copied)
python cli.py record-device --out out/CASE-001 --model CP-UNR-104F1 \
    --serial <label> --mac <label> --device-id <label> --firmware <System Info> \
    --read-from label --photo label.jpg sysinfo.jpg

# model-numbered strings on the platter, outside the video (uses the scan's block map)
python cli.py identify-model --device /dev/sdb --out out/CASE-001
```

Once the unit is recorded, `identify-model` also searches for **its own** serial,
device ID and MAC (the MAC as text in the usual forms and as its 6 raw bytes). A
model string can come from any unit of that model; this unit's serial on the
disk shows this unit wrote to it. Finding none shows nothing - many recorders
never write their identity to the disk. It searches the non-video blocks up to
`--max-gb` (4 GiB by default); raise it to cover a whole drive.

`identify-model` reads only blocks the scan did not classify as video, plus
both ends of the disk — minutes, not another full pass — and lists every
model-shaped string (`CP-UNR-…`, `DS-7…`, `DH-XVR…`, `VIGI NVR…`, `SATATYA…`)
with its offsets. A string on the platter shows the text is on this disk, not
that the disk was seized from that model; a camera's model on an NVR's disk
names the camera.

Both commands print, and the report shows (section 3), the checks between the
sources: the model's vendor against the format found on the disk (a CP Plus
unit on a Dahua-format disk agrees — CP Plus units are commonly Dahua-built),
and the platter's model strings against the unit. A disagreement is a finding
to explain, not an error: a Hikvision unit whose disk carries Dahua
structures is a disk that another recorder formatted.

### 3.4f Footage from a recorder we have no parser for

When detection names nobody, or TP-Link (whose plugin reads the index but
places no footage), or a Godrej disk with no `QVEX` head (a model not made
by Qualvision) — recover the video anyway:

```bash
python cli.py carve-annexb --device /dev/sdb --out out/CASE-001     # or scan --carve-annexb
python cli.py extract-carved --device /dev/sdb --out out/CASE-001 --format annexb
```

Almost every recorder stores standard H.264 or H.265. A stream is started
only at a sequence parameter set that parses within the standard's limits to
a real picture size (random bytes pass as one about 3 times in 20,000), and is
split at a new parameter set or a gap, never merged. Files come out as
`carve/es_streams/es-NNNNN.h264|.h265`, hashed.

Know what they are not: **no date and no camera** (a bare stream carries
neither), and the unknown container's own bytes sit between frames — the
footage plays, decoders conceal the rest, but it is not the recorder's
bitstream byte for byte. Two cameras with identical settings interleaved on
the disk may share a stream. The next step for that vendor is `survey`, then
a plugin (§8).

### 3.4g Section 63 certificate (BSA 2023) — a draft

Footage extracted anywhere in the case folder, or one folder down (e.g.
`clips/`), is found by its manifest; footage whose manifest names another
device is left out, and the draft says so.

```bash
python cli.py certificate --out out/CASE-001 --part B --records both \
    --name "A. Examiner" --designation "Forensic examiner"
python cli.py certificate --out out/CASE-001 --part A          # for the party producing it
```

Writes `certificate_s63_partA|B.html` (print it) and `.json`, and records
both in the custody ledger. The form is the Schedule's: Part A for the party
producing the record, Part B for the expert, each stating the hash value(s)
and the algorithm, with a hash report enclosed.

The tool fills only what it recorded: DVR ticked; the recorder's make, model
and serial from `record-device`, the drive's from the scan; the whole-drive
SHA-256 and MD5 (only if the acquisition pass covered the whole drive) and
the SHA-256 of every extracted file; the case, Merkle root and ledger head.
It **never** ticks Owned / Maintained / Managed / Operated, never makes the
"working properly" statement, and leaves name, relation, residence,
signature, date, time and place blank unless you pass them.

It is a **draft** for the party or the expert to complete and sign. The
wording and layout follow the Schedule as printed in the Gazette of India Extraordinary, Part II Sec. 1, No. 55, 25 Dec 2023, pp. 46-47 (CG-DL-E-25122023-250882):
a test compares the draft with the Gazette's text word for word. Who signs
Part B, and when a s.79A Examiner is needed, are legal questions for the
team's legal lead (see *Pune Bar Association v. UoI*, SC 2026, in
FINAL_REPORT §7).

### 3.4h Real-media checks in one command

Several tools have run only on generated data. On the machine that holds the
case folders (and, if possible, the drives), one command runs every check
that needs no recorder and writes `out/realchecks/SUMMARY.md` for the
validation report:

```bash
sudo apt install ffmpeg tesseract-ocr        # for steps 3 and 4
python -m validate.realmedia --case1 out/cpplus_WWD4A3NX --image1 skyhawk_WWD4A3NX_first20GiB.dd --case2 out/drive2_Z9C2632A
```

1. `identify-model` on each drive — also on a head image, once its first
   block's hash proves it is the same drive;
2. `carve-annexb` over the first 2 GiB, scored by how much of the footage
   the DHAV / MPEG-PS carver found there it also covers;
3. `decode-check` on drive 1: every extracted frame that does not decode,
   classed as before the first keyframe (expected), after a gap in the DHAV
   counter (a frame missing from the disk), or unexplained;
4. `read-osd` on the streams whose titles and clocks were read by eye
   (VALIDATION_REPORT §8a–8b), compared with what the eye read.

Anything its inputs do not allow is skipped, with the reason in the summary.

The published format definitions (`formats/*.ksy`) are checked the same way,
against the parsers the tool runs - field by field on drive 1's volumes,
cluster records and DHAV frames, and on every MPEG-PS stream carved in a
region of drive 2 (one 1 GiB data block is enough):

```bash
pip install kaitaistruct
python -m validate.ksy_check --dahua skyhawk_WWD4A3NX_first20GiB.dd \
    --ps /dev/sdX --ps-region 0x4C5E000 0x40000000 --out out/realchecks/ksy_check.json
```

It exits 0 only if every compared field agrees; each disagreement is listed.

### 3.4i E01 (EnCase) images

Every command that takes `--device` also takes an `.E01` image: pass the
first segment and the rest (`.E02`, `.E03`, ...) are found beside it.
Compressed and stored chunks are both read, read-only, with no extra
software. Before relying on a reader for an image, let the image check it:

```bash
python cli.py ewf-info --image case.E01 --verify
```

An E01 stores the MD5 (and often the SHA-1) of the media it holds; `--verify`
reads every chunk and compares. A match proves the bytes the tool sees are
the bytes that were acquired. A chunk whose data fails its checksum is
reported by `scan` as an unreadable region, never read as good data.

### 3.4j Export to other forensic tools (CASE/UCO)

```bash
python cli.py case-export --out out/CASE-001        # writes out/CASE-001/case.jsonld
```

CASE (caseontology.org) is the standard JSON-LD format for exchanging digital
forensic results. The export holds the evidence drive with its whole-drive
hashes, the recorder as the examiner recorded it, every custody-ledger action
as an `InvestigativeAction` with its tool, examiner and time, and every
extracted file with its SHA-256 and - through `DataRangeFacet` - the exact
byte ranges of the drive it came from. Identifiers are derived from the case,
so exporting twice gives the same graph. Check a file with the official
validator: `pip install case-utils`, then `case_validate case.jsonld`.

### 3.4k The recorder's own log (Hikvision)

A Hikvision disk keeps the recorder's system log next to its master sector:
power-on and abnormal shutdown, logins, configuration, playback, disk format,
recording starts - each with the recorder's time and, for operations, the
user.

```bash
python cli.py hik-log --device /dev/sdb --out out/CASE-001     # or a head image of the drive
```

It finds the master sector (at 0x200, or a surviving copy - a reformat often
destroys the primary), checks its fields against each other and against the
HIKBTREE copies the scan found, reads every record in the log area it names,
and writes `hik_log.json`: the records, counts by event type, power cycles and
the actions a named user took. Event names are Hikvision's SDK codes; a code
that SDK version does not list is reported as undefined, never guessed.

Times are the recorder's clock, like the footage's. When the case holds
carved footage, `hik-log` checks that: power-on records should be followed by
a new stream once the recorder has booted. It reports which clock the log
keeps, or "not determined" - it never converts to UTC. Given a head image,
the image's first block must hash to the scan's, or it refuses.

Then rebuild the timeline and the report. When the log keeps the footage's
clock, `timeline` sets it against the footage: a period in which every camera
is silent for over a minute, with a logged power-on inside it or within 30 s
of its end, is reported as a power cut, with the abnormal shutdown logged
before it; a silence the log says nothing about is reported as such. The
report's section 6d lists them, with the log's power, disk and user records.

```bash
python cli.py timeline --out out/CASE-001 && python cli.py report --out out/CASE-001
```

### 3.4l Uniview, TP-Link and Matrix (plugins)

All three are `plugins/` files, loaded like Honeywell's. Uniview and TP-Link
rest on the vendors' firmware (VALIDATION_REPORT §8f), Matrix on its own
documents (§8h). No real disk from any of them has been read yet.

```bash
# Uniview: recordings per block, with camera and recorder-clock times
python cli.py parse --vendor Uniview --device /dev/sdb --out out/CASE-001
python cli.py extract --vendor Uniview --device /dev/sdb --out out/CASE-001 \
    --recording unv-b00012                     # the block's video, GOPs checked
python cli.py parse --vendor Uniview --device /dev/sdb --remnants   # GOPs with no index

# TP-Link: scan first, so the index header's offset is passed as a hint
python cli.py parse --vendor TP-Link --device /dev/sdb --out out/CASE-001

# Matrix: the recording tree on the disk's ext filesystem
python cli.py parse --vendor Matrix --device /dev/sdb --out out/CASE-001
python cli.py extract --vendor Matrix --device /dev/sdb --out out/CASE-001 \
    --recording mtx-camera01-20180421-144719-s1  # the .stm and sidecars as stored
```

- **Uniview.** Each recording is one 256 MiB block of one camera. `--remnants`
  walks every block for GOPs by their own trailers, index or not; runs past
  a block's write position are named `unv-stale-*` (older footage).
- **TP-Link.** The summary says whether the index was read, or found and not
  readable (encrypted). When read: recordings per camera and the recorder's
  system log, as the index states them. No footage is placed on the disk -
  use `carve-annexb` (§3.4f).
- **Matrix** (from Matrix's documents, VALIDATION_REPORT §8h). One recording
  per `.stm` file, with camera, date and times from the recorder's own folder
  and file names. The `.stm` is extracted as stored - its format is not
  published; Matrix's Device Player converts it. The summary names any
  filesystem it could not read (XFS, a striped RAID member).

### 3.4m Export in NIST's CCTV profile (NISTIR 8161 Level 0)

For exchange with other agencies and tools: an extracted H.264 stream as an
MP4 with UTC time stamps in every frame and the clock offset in the file
(VALIDATION_REPORT §8i). Nothing is re-encoded.

```bash
python cli.py export-nist --es out/CASE-001/hw-ch00-main-0000.h264 --out out/CASE-001 \
    --start "2024-09-21 18:58:00" --fps 25 \
    --tz-offset 330 --clock-observed "2024-09-21 19:00:27" \
    --clock-reference "2024-09-21 19:01:05" --clock-set manual-unknown
```

- `--start` is the first picture's time on the recorder's clock (from the
  parse or extract manifest); `--times FILE` gives one time per picture
  instead of `--fps`.
- `--tz-offset` and the two clock readings come from the field visit (SOP
  1.2). Without `--tz-offset`, no UTC time stamp is written and the file is
  marked **not Level 0**: the tool does not guess a zone.
- `--clock-set` is how the recorder's clock was set, from its time settings
  screen: `auto-network` if it uses NTP, otherwise `manual-*`.
- The manifest beside the MP4 records the input's hash, the clock rule, and
  proof that every picture is unchanged. The export is logged in the
  custody ledger.

### 3.4n The recorder's clock from daylight (no unit needed)

When the recorder can't be reached to read its clock against true time
(SOP 1.2), use an outdoor camera that switches to black-and-white infrared at
night. Sample days of its footage, then fit:

```bash
python -m analyse.daylight sample out/CASE-001/carve/streams/*.dav --out series.jsonl --every 120
python -m analyse.daylight estimate series.jsonl --lat 12.97 --lon 77.59 --zone 330
```

A `.dav` keeps the recorder's own frame times; any other clip needs `--start`
(and `--fps` for a raw stream). The result is the recorder's offset from UTC,
the camera's switch elevation, and each switch's own offset, whose spread is
the uncertainty. With `--zone` it also states the clock error. It needs at
least one dusk and one dawn switch.

### 3.5 Look at the results

```bash
python cli.py serve            # then open http://127.0.0.1:8150
```

| Tab | Shows |
|---|---|
| Overview | evidence, write block, custody status, vendor, counts; live progress during a scan |
| Vendors | all eight PS OEMs with status, parser, real media held; the add-a-vendor pipeline; plugins |
| Acquisition & custody | device, hashes, preserved regions, every ledger entry |
| Filesystem | parser status, volumes, recordings, field provenance |
| Recovered | carve labels, footage outside every index, remnants, camera names read from the picture |
| Timeline | camera lanes, gaps, other footage; correlations and anomalies |
| Report | the report, printable |

The viewer only reads `out/`; it never opens a drive. `#case=<id>&tab=tl` in
the URL opens a case and tab directly.

## 4. Proving a piece of evidence later

```bash
python cli.py prove --out out/CASE-001 --offset 8388608
```

prints the block holding that byte, its SHA-256, and the Merkle path to the
root recorded at acquisition — enough for anyone to check that a clip or a
preserved structure came from this drive, without the drive.

## 5. Reading the results

| You see | It means |
|---|---|
| `CH01`, `CH02`… on a carved stream | ≥90% of its frames sit in clusters the index assigns to that camera, at dates inside that record's window |
| `outside_index` | no index record accounts for those frames at their dates: overwritten, deleted, or from an earlier period. **Camera unknown** |
| `mixed-evidence` | no clear majority; reported, not guessed |
| `remnant` | older footage at the tail of a cluster since reused by a newer recording |
| confidence | how strongly the evidence supports a claim, 0–1; never a certainty |
| a gap in the timeline | no indexed footage for that period — not "deleted" |
| `system_wide_gap` | every camera is silent at once: a property of the recorder (power, restart, clock change) |
| `recorder-local` time | the DVR's own wall clock, not converted |

## 6. Status labels

| Label | Meaning |
|---|---|
| `validated` | footage byte-matched against the recorder's own export. **Not yet reached for any vendor** |
| `spec_only` | built from published research and observation of real media |
| `synthetic_only` | tested only against generated data |
| `detected_not_parsed` | recognised by signature; no parser |

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Permission denied` opening the device | add the read-only ACL (`writeblock-rule --user`) or run with `sudo` |
| `RW !!` in `devices` | the drive is writable: `sudo blockdev --setro` before anything else |
| `[!] device lost … waiting` | the USB bridge reset. If it comes back by itself the scan continues. If `dmesg` shows `disabled by hub (EMI?)` / `unable to enumerate`: unplug USB **and** the drive's power, let the adapter cool 10–15 min, power first, then USB in another port |
| `refusing to continue the pass` | the returning drive did not re-read the blocks already hashed identically. The pass stops rather than risk a wrong hash; start a new pass (compare block maps across attempts to confirm the drive is unchanged) |
| 20–30 MB/s on a hard disk | the bridge negotiated USB 2 (`lsusb -t` shows 480M). Use a USB 3 dock |
| `no DHFS superblock` | not a Dahua-family disk: use `--vendor Hikvision`, or write a plugin (§8) |
| `not enough free space` from `extract-carved` | narrow the selection with `--ids` or `--label` |

## 8. Adding a vendor

`plugins/honeywell.py` is the worked example: one file, written from a
published paper, registered by dropping it into `plugins/`. It uses
`parse`, `extract --vendor Honeywell --recording <id>`, and
`parse --vendor Honeywell --remnants` (footage by frame headers after a
format) with no change to the core.

Start with a survey of the unknown disk (write-blocked, or an image):

```bash
python cli.py survey --device /dev/sdX --json out/survey.json
python cli.py survey --diff out/BEFORE out/AFTER     # what changed between two scans
```

It lists candidate headers (tokens recurring far more than chance, across
many samples), whether a field inside each header gives the distance to the
next one (a length field), which fields decode as dates and in what encoding,
the codec, and printable strings. These are leads, not a format: check them
in a hex editor. The before/after diff is the core of a ground-truth
experiment — record, delete a clip on the recorder, scan again — the changed
blocks are where the index and logs live.

Then copy `plugins/_template.py` to `plugins/<vendor>.py`, add signatures and a
parser, remove the leading underscore. It loads at the next start; a plugin
that fails to load is reported and skipped. Follow the rules in the template:
never open a device, record where each field's layout came from, never claim
`validated`.

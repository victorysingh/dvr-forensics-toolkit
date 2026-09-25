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

It does **not** yet: decode video to MP4, run face/object detection, read the
on-screen clock, sign reports, or generate the BSA s.63 certificate. Nothing
it produces is labelled `validated` — see §6.

## 2. Requirements

- Python 3.11 or newer. No packages to install.
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

- `extract-carved` defaults to `--label outside_index`. Use `--label CH02` for
  one camera's carved footage, `--label all`, or `--ids carve-00012,carve-00019`.
- `timeline --clock-observed/--clock-reference`: at seizure, write down what
  the DVR's screen shows and a trusted clock at the same instant. Without
  them, the timeline states that the clock error was not measured.
  Without `--tz-offset`, no UTC is asserted at all.
- To reassemble one indexed recording rather than carved footage:
  `python cli.py extract --device /dev/sdX --vendor Dahua --recording dhfs-v1-c002120 --out clips/`.

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
| Recovered | carve labels, footage outside every index, remnants |
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

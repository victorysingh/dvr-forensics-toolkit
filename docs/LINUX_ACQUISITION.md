# Linux acquisition procedure

The procedure for attaching a DVR drive and acquiring it without writing to
it. Follow it in order, every time. It maps onto ISO/IEC 27037 (identification,
collection, acquisition, preservation) and NIST SP 800-86.

---

## 0. Before you plug anything in

**Disable auto-mount.** This is the realistic way a Linux desktop destroys
evidence: GNOME/KDE see a partition, mount it read-write, and the filesystem
driver writes journal recovery data before you have typed a single command.

```bash
# GNOME/KDE session - disable for the current session
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false

# udisks-based auto-mounting, belt and braces
systemctl stop udisks2.service      # re-enable later with `start`
```

A DVR platter usually has no filesystem Linux recognises, so nothing mounts
and the risk looks theoretical. It is not: DVR disks often carry a small
ext or FAT partition for firmware, config and logs alongside the proprietary
video area — and that one *will* mount.

Record the starting state of the machine before you attach anything: date,
operator, machine, kernel version. It goes in the custody record.

---

## 1. Attach and identify

```bash
sudo dmesg -w          # leave running in one terminal, then plug the drive in
```

You are looking for lines like `sd 6:0:0:0: [sdb] 5860533168 512-byte logical
blocks`. **Write down the device node** (`/dev/sdb` here) and be certain of
it — every later command targets it, and targeting the wrong node is how
people wipe their own system disk.

```bash
lsblk -o NAME,SIZE,TYPE,TRAN,MODEL,SERIAL,RO,MOUNTPOINT
```

Confirm the size and model match the physical label on the drive. For our
unit that is a **Seagate SkyHawk** (surveillance-grade, `ST…VX…`), pulled from
a Hikvision DVR whose board is marked `DS-80xx P REV1.1`.

If a partition auto-mounted despite step 0, unmount it *before* anything else:

```bash
findmnt -n -o TARGET --source /dev/sdb1 && sudo umount /dev/sdb1
```

---

## 2. Write-block — before any tool reads the device

```bash
sudo blockdev --setro /dev/sdb
blockdev --getro /dev/sdb          # MUST print 1
```

Prove it actually blocks writes. Do this once, on the first acquisition, so
you can state in the validation report that it was tested rather than assumed:

```bash
sudo dd if=/dev/zero of=/dev/sdb bs=512 count=1
# expected: dd: failed to open '/dev/sdb': Read-only file system
```

Three caveats that have burned people:

- `--setro` applies to the **whole device**, but is reset by a replug. Any
  time the drive is disconnected and reconnected, re-apply and re-verify.
- It blocks writes through the block layer, not the USB bridge. It is a
  *software* write block, and the report must say so — our enclosure has no
  hardware blocker, and claiming otherwise in a forensic report is a
  misstatement a defence expert will find.
- `--setro` on the parent device does not automatically mark partitions RO
  in every kernel version. Check `blockdev --getro /dev/sdb1` too.

### Keep it write-blocked across reconnects

A cheap USB-SATA bridge can reset itself mid-read. On 24 Sep 2026 ours (a
generic `14cd:6116` USB 2.0 bridge) dropped 48.6 GiB into a pass and came
back three seconds later as **`/dev/sdc` — with the read-only flag gone**.
Nothing mounted it only because automount and udisks were already off.

So before a long pass, install a **runtime** udev rule keyed on the drive's
own serial. It re-applies `--setro` (and, optionally, a read-only ACL for the
examiner) the moment the drive appears, under whatever name it gets:

```bash
python cli.py writeblock-rule --device /dev/sdb --user "$USER"   # prints the rule
python cli.py writeblock-rule --device /dev/sdb --user "$USER" \
  | sudo tee /run/udev/rules.d/70-ps26150-writeblock.rules
sudo udevadm control --reload
sudo udevadm test /sys/block/sdb 2>&1 | grep setro     # confirm the rule matches
```

- `/run/udev/rules.d` is cleared at reboot, so the rule never outlives the
  case. It is keyed on the serial, **never on "all USB disks"** — the
  workstation itself may boot from a USB SSD.
- The serial comes from udev's database (`ID_SERIAL_SHORT`), which most
  bridges fill from the drive's own ATA IDENTIFY. If it is empty for your
  bridge, you cannot rely on the rule: stay with the drive and re-apply
  `--setro` by hand after any reconnect.
- With the ACL (`--user`), the scan runs as your user with **read** permission
  only — no root process ever holds the evidence open.

Our tool surfaces the kernel's own flag, so you can confirm it independently:

```bash
python cli.py devices
# the wblock column shows RO(kernel) when blockdev --setro is in effect,
# and RW !! when it is not
```

---

## 3. Acquire

Raw device reads need root:

```bash
sudo python cli.py scan \
    --device /dev/sdb \
    --case HIK-001 \
    --investigator "Shrestha" \
    --organization "SIH26150 Team"
```

Start with a triage pass. It tells you the vendor and roughly where the video
lives in about a minute, before you commit to a multi-hour full pass:

```bash
sudo python cli.py scan --device /dev/sdb --case HIK-001-TRIAGE --max-mb 512
```

A triage scan is explicitly marked `complete_pass: false` in the report, and
its linear hashes cover only the bytes actually read. Never quote a partial
scan's hash as the drive hash.

For a Dahua-family disk, carve in the same pass. Carving costs CPU, not a
second multi-hour read, and every frame is labelled against the DHFS index as
it is carved:

```bash
systemd-inhibit --what=sleep:idle python cli.py scan --device /dev/sdb \
    --case CPPLUS-001 --investigator "Shrestha" --carve --reconnect-wait 480
```

**If the drive drops off the bus mid-pass,** the scan does not treat the
vanished device as bad sectors. It waits (`--reconnect-wait`, minutes) for a
device with the same serial and size that **is write-blocked** — it never
opens one that is not — re-reads block 0 and the last block it hashed, and
continues only if both match the SHA-256 already recorded. The running
MD5/SHA-256 then continue from the first unhashed byte, so they equal one
uninterrupted read. Every step (`device_lost`, `device_reconnected`, or
`reconnect_refused`) goes into the custody ledger and the report.

**The full pass on a multi-TB drive takes hours over USB.** It is resumable:

```bash
sudo python cli.py scan --device /dev/sdb --case HIK-001 --resume
```

Resume re-reads only the blocks not yet hashed. Note the honest trade-off: a
resumed scan cannot produce a valid *linear* MD5/SHA-256, because those
require one continuous pass — so a resumed run reports the Merkle root over
the block map and marks `complete_pass: false`. If you need the linear hashes
for court, the scan has to complete in one run. Plan for that: use a powered
enclosure, disable USB autosuspend, and do not let the machine sleep.

```bash
# stop USB autosuspend killing a 4-hour read halfway through
sudo sh -c 'echo -1 > /sys/module/usbcore/parameters/autosuspend'
systemd-inhibit --what=sleep:idle sudo python cli.py scan ...
```

The module parameter only applies to devices enumerated *after* it is set.
For a drive already attached, check its port directly:
`cat /sys/bus/usb/devices/<port>/power/control` must print `on`.

Check the speed the bridge actually negotiated before planning the run
(`lsusb -t`): a USB 2.0 bridge (`480M`) caps a hard disk at about 30 MB/s, so
1 TB takes roughly nine hours; a USB 3 dock takes under two.

After the pass, everything else works from what the scan wrote, plus small
targeted reads:

```bash
python cli.py preserve --device /dev/sdb --out out/CPPLUS-001   # filesystem metadata, ~100 MB
python cli.py parse    --device /dev/sdb --vendor Dahua --out out/CPPLUS-001
python cli.py timeline --out out/CPPLUS-001 --tz-offset 330 \
    --clock-observed "2026-09-25 10:02:13" --clock-reference "2026-09-25 10:00:00"
python cli.py report   --out out/CPPLUS-001
python cli.py serve                                            # UI on http://127.0.0.1:8150
```

---

## 4. Verify

```bash
python cli.py verify --out out/HIK-001
```

Re-walks the custody chain and recomputes the Merkle root from the block map.
Both must pass. If either fails, stop and investigate before doing anything
else with that acquisition — do not "re-run it and see".

For any individual clip or region, produce an inclusion proof rather than
re-reading the drive:

```bash
python cli.py prove --out out/HIK-001 --offset 8388608
```

---

## 5. Record everything

Log to the shared manifest, not just to the tool's output:

- drive model, capacity, serial (from the physical label **and** from `lsblk`)
- DVR model and firmware version
- the exact `blockdev --getro` output proving write-blocking was in effect
- start and end timestamps, operator name
- the linear MD5 + SHA-256 and the Merkle root
- any bad sectors reported, with their offsets

The custody ledger (`out/<case>/custody_ledger.jsonl`) captures most of this
automatically and is tamper-evident, but the physical observations — what the
label said, who was present, what the DVR board was marked — only exist if a
human writes them down.

---

## 6. Ground-truth experiment (do this once the drive is imaged)

This is the step that converts a spec-based parser into a validated one, and
it is the strongest slide in the deck. The team owns the DVR unit, so it can
be done at no cost:

1. Set the DVR clock to a known, written-down time.
2. Record known footage (something visually identifiable and timestamped).
3. Delete one clip through the DVR's own menu.
4. Export another clip using the DVR's native export function — **this is the
   known-good reference.** Keep it.
5. Re-image the drive.
6. Diff the two images: the differences reveal the index tables, allocation
   maps and logs. That is how the filesystem gets reverse-engineered.
7. Byte-match our carved output against the DVR's own export. If they match,
   the parser is correct — and that is what `validated` means.

Nothing short of step 7 justifies moving Hikvision out of `spec_only`.

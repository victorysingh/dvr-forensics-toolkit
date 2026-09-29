# Standard Operating Procedure — DVR/NVR drive examination

PS26150 deliverable: *Standard Operating Procedures*. This SOP covers one
DVR/NVR hard drive from seizure to report. Command details are in
`docs/USER_MANUAL.md`; Linux write blocking and acquisition in depth are in
`docs/LINUX_ACQUISITION.md`.

The phases follow ISO/IEC 27037 (identification, collection, acquisition,
preservation) and NIST SP 800-86 (collection, examination, analysis,
reporting). Clause-level citations are to be confirmed against the standards'
text before they appear in a report; they are not asserted here.

**Two rules override every step below:**

1. Nothing is ever written to the evidence drive — not by the examiner, the
   workstation, or the tool.
2. Nothing is claimed that has not been demonstrated. Every finding carries
   its status and confidence; limitations go in the report with the findings.

---

## Phase 1 — At the scene (identification, collection)

| # | Step | Record |
|---|---|---|
| 1.1 | Photograph the DVR in place: front, rear, labels, cabling, cameras connected | photo log |
| 1.2 | **If the DVR is running, read its clock before anything else.** Photograph the DVR's on-screen time next to a trusted clock (phone on network time) in the same frame. Note the DVR's time-zone setting from its menu if it can be read without changing anything | DVR time, reference time, zone — used by `timeline --clock-observed/--clock-reference/--tz-offset` |
| 1.3 | Note make, model and serial of the unit, number of channels, number of drives. Photograph the label and, if the unit is running, its System Info screen (model, serial, MAC, device ID, firmware). Keep the photos as the camera wrote them: a messaging app recompresses them and strips the time they were taken - send them as files, or copy them by cable | unit record; entered later with `record-device --photo`, which hashes each photo into the ledger |
| 1.4 | Decide on a native export. If footage for a known period is needed *and* the unit is running, export one clip with the DVR's own export function before power-down. Record exactly what was done — it is interaction with a live system | export log; the clip is the only thing that can later move a parser to `validated` |
| 1.5 | Power down. A DVR overwrites its oldest footage continuously; every minute it runs is recoverable footage lost | time of power-down |
| 1.6 | Remove the drive(s). Photograph each drive's label; record make, model, serial, capacity, and which bay it came from | drive record |
| 1.7 | Bag, seal, label; start the chain-of-custody form | seal numbers |

## Phase 2 — Workstation preparation (before the drive is attached)

| # | Step | Check |
|---|---|---|
| 2.1 | Disable auto-mount and stop udisks (`USER_MANUAL §3.1`) | `gsettings get … automount` is `false`; `systemctl is-active udisks2` is `inactive` |
| 2.2 | Disable USB autosuspend | `/sys/module/usbcore/parameters/autosuspend` is `-1` |
| 2.3 | Install the adapter write-block rule for the evidence adapter (`writeblock-rule --usb-id`) | the tool refuses an adapter that holds the workstation's own disk |
| 2.4 | Run `python tests/test_pipeline.py` | all pass; record the count and the tool's git commit |
| 2.5 | Check free space: about 50 MB per drive for the scan, plus footage to extract | `df -h` |

## Phase 3 — Acquisition

| # | Step | Check |
|---|---|---|
| 3.0 | **Every session, including a re-examination days later:** a reboot clears `/run/udev/rules.d`, so re-install the write-block rule *before* connecting. `writeblock-rule --serial SERIAL` needs no drive attached. On 29 Sep drive 1 came up writable (`ro=0`) for this reason; it was blocked by hand before any read, and the kernel counted 0 writes | `ls /run/udev/rules.d` shows the rule before the drive is plugged in; `lsblk -o NAME,SERIAL,RO` shows `RO 1` once it is |
| 3.1 | Connect the drive through the evidence adapter, with its own power supply for a 3.5" drive | — |
| 3.2 | `python cli.py devices` — identify the drive by size, model and serial | serial matches the drive label (1.6) |
| 3.3 | `sudo blockdev --setro /dev/sdX`; `blockdev --getro /dev/sdX` | **must print 1**. If the adapter rule (2.3) is installed, it already does |
| 3.4 | Install the serial write-block rule (`writeblock-rule --device /dev/sdX --user $USER`) | `udevadm test` shows the `--setro` command for the drive |
| 3.5 | Once per workstation and kernel: prove the write block on a **sacrificial loop device**, never the evidence (`LINUX_ACQUISITION §2`) | `dd` fails (`Operation not permitted` or `Read-only file system`); the backing file hash is unchanged |
| 3.6 | Check the negotiated USB speed (`lsusb -t`) and plan the time | 480M = USB 2, about 11 h per TB |
| 3.7 | `scan --carve --reconnect-wait 480` with case id, examiner, organisation, and notes naming the drive, adapter and seals | — |
| 3.8 | During the pass: if the drive drops and does not return, follow `USER_MANUAL §7`. Do not reboot (runtime write-block rules are cleared by a reboot) | ledger shows `device_reconnected` with verified blocks |

**If a pass is abandoned,** keep its directory, rename it
(`…_attemptN_<reason>`), and record the reason as a `scan_aborted` ledger
entry in it. Its hashes are never quoted. Its block map is still useful: the
block hashes of independent passes over the same drive should agree, and
comparing them is evidence that the reads are reproducible (see
`docs/VALIDATION_REPORT.md`).

## Phase 4 — Preservation

| # | Step | Check |
|---|---|---|
| 4.1 | `verify --out out/CASE` | custody chain intact; Merkle root recomputes |
| 4.2 | Record the whole-drive MD5 and SHA-256 on the custody form | from `scan_report.json`, `complete_pass: true` only |
| 4.3 | `preserve --device … --out out/CASE` | every preserved block matches the acquisition hash |
| 4.4 | Decide on imaging. A full image is the textbook order when space allows. When it does not, document the decision: the drive is retained sealed as the original; the whole-drive hashes, the block map and the preserved metadata allow any extracted range to be verified against it | decision recorded in the case notes and the report |
| 4.5 | Disconnect; re-seal the drive; update the custody form | seal numbers |

## Phase 5 — Examination

| # | Step | Check |
|---|---|---|
| 5.1 | `parse --vendor <vendor> --out out/CASE` (drive re-attached and write-blocked as in 3.3, or an image) | parser status printed; notes read |
| 5.2 | `extract-carved --out out/CASE` for footage outside every index; `--label CHnn` or `--ids` for more | every stream's frame count matches the carve |
| 5.3 | `extract --recording <id>` for specific indexed recordings of interest | per-file SHA-256 in the manifest |

## Phase 6 — Analysis

| # | Step | Check |
|---|---|---|
| 6.1 | `timeline --out out/CASE` with `--tz-offset` and the clock readings from 1.2 **only if they were recorded** | the clock rule is printed and names its inputs |
| 6.2 | Review gaps, system-wide gaps, unindexed footage inside gaps, and anomalies in the viewer | — |
| 6.3 | Any analytic output (when the AI layer exists) is a lead for review, never a finding | — |

## Phase 7 — Reporting

| # | Step | Check |
|---|---|---|
| 7.1 | `report --out out/CASE --notes "…"` | report hash recorded in the ledger |
| 7.2 | `verify --out out/CASE` once more | chain intact, preserved blocks OK |
| 7.3 | Read the report's limitations section before signing anything that quotes it | — |
| 7.4 | Archive the case directory with the drive's custody record | — |

---

## What must never be done

- Attach the drive to any machine where auto-mount is on, or before a write
  block is in place and verified.
- Power the evidence drive in the DVR again, or in any device that might
  "repair" or initialise it. If the OS offers to format the disk, cancel.
- Quote a hash from a pass that is incomplete, resumed, triage, or abandoned.
- Describe footage outside the index as "deleted", a gap as "tampering", a
  high-entropy region as "encrypted", or a software write block as hardware.
- Report any parser output as `validated` without a byte-match against the
  recorder's own export.

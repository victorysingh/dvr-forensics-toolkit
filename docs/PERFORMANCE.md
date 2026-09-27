# Analysis time

The problem statement lists "reduce analysis time" among what the tool must
achieve. This document gives the measured answer and states where it stops
holding.

Measured 28 Sep 2026. Reproduce it with
`python demo/bench_single_pass.py --size-mb 1024`.

---

## 1. The claim, in one line

**One read of the drive does what would otherwise take five.** For a 1 TB
surveillance drive over the USB 2 bridge the team actually used:

| Approach | Time | Free disk space needed |
|---|---|---|
| **This tool: one pass** (hashes, Merkle map, detection, three carvers, motion activity) | **~11.3 h** | none beyond the outputs |
| The same work, one read of the drive per task | ~56.6 h | none |
| Image the drive first, then run each task on the image | ~21.9 h | **~931 GiB** |

## 2. Where the numbers come from

**The drive speed is measured, not assumed.** Drive 1's acquisition (attempt 4)
read all 1,000,204,884,992 bytes in 11 h 19 min (24 Sep 19:15 to 25 Sep
06:34 UTC). That period includes one USB drop and a manual replug. It works
out to **23.4 MiB/s**: the Super Top USB 2.0 bridge (`14cd:6116`) is the
limit, not the disk and not the software.

**The CPU cost of each task is measured on a synthetic image.** The image
holds Dahua DHAV, Program Stream and raw H.264 footage (not evidence). It was
1 GiB, on an Intel Core (Family 6 Model 186), 16 logical CPUs, Python 3.13.9,
Windows 11:

| Work | Seconds | MiB/s |
|---|---|---|
| read only (from the OS cache) | 0.87 | 1,178 |
| **one pass: all of the below** | **38.33** | **26.7** |
| separately: scan (MD5 + SHA-256, Merkle map, detection) | 9.86 | 103.9 |
| separately: DHAV carve | 18.09 | 56.6 |
| separately: MPEG-PS carve | 3.30 | 310.7 |
| separately: raw H.264/H.265 carve | 6.08 | 168.4 |
| separately: motion activity | 3.62 | 282.6 |
| one read a task: sum | 40.94 | 25.0 |

**How the projection works.** Each pass takes whichever is slower: the drive
at 23.4 MiB/s, or the CPU at the rate above. Every task here runs faster than
the drive, so over USB 2 each pass costs a full read of the drive:

- one pass is 1 read, **~11.3 h**;
- one read per task is 5 reads, **~56.6 h**;
- imaging first is 1 read (~11.3 h) plus each task on the local image at CPU
  speed (~10.6 h), **~21.9 h**, and it needs the drive's full size free.
  Shrestha's workstation had 669 GB free against a 931.5 GiB drive
  (`FORENSIC_IMAGE.md` §2). That is why the case holds hashes, a Merkle map, a
  20 GiB head image and preserved metadata rather than a full image.

## 3. What the saving is, and what it is not

- **It is fewer reads of the evidence.** On data already in memory, doing
  everything in one pass saves only about 6% of the CPU time (38.3 s against
  40.9 s). The saving comes from the drive: every pass not taken is another
  11 hours on this bridge.
- **Fewer reads also means less risk.** The bridge dropped out five times
  across the two drives (`STATUS.md` §4). A second full read is a second
  chance of that happening, and a second chance for a mistake to write to
  the evidence.
- **It is not "faster than a commercial tool."** We have not timed one, and
  make no claim about one.

## 4. Where it stops holding: fast media

In one pass the tool runs at **26.7 MiB/s on this machine: it is CPU-bound.**
Over USB 2 (23.4 MiB/s) that does not matter; the drive is slower. Over USB 3
(assumed ~120 MiB/s, not measured by the team), the pass would take about
**9.9 h, set by the CPU and not the drive**, although the drive alone could be
read in about 2.2 h.

That is the known cost of a pure-Python, stdlib-only core. `TECH_STACK.md`
sets out the fix, deferred on purpose until the parsers landed:
1. one regex pass instead of six;
2. MD5 and SHA-256 on separate threads;
3. block detection across a process pool.

The DHAV carve (56.6 MiB/s alone) is now the slowest single task and the next
candidate.

## 5. Update, 28 Sep: taps in parallel, a faster carve

Section 4's limit - a pass that is CPU-bound - is now largely lifted, with
no change to any output.

**What changed**

- **Each tap runs in its own process** (`acquire/parallel.py`; the default
  for `scan`, `--no-parallel` to switch it off). The main process still
  hashes and detects; the carvers and the activity count stop waiting for
  each other. Blocks reach the workers through shared memory, not pipes:
  pickling 8 MiB blocks into four queues had cut the main process from 69 to
  25 MiB/s on its own, with the workers doing nothing (measured).
- **The DHAV carver** no longer recomputes the oldest stream's position on
  every frame, and no longer finds a stream in its list by comparing
  dataclasses field by field. Its output is identical to the previous
  carver's on every test image, including with stream retirement forced
  (1, 4 and 32 MiB) so that path was exercised.
- **Detection** counts the four kinds of NAL header in one regex pass
  instead of four. The counts are provably the same (no two such matches can
  overlap), and the block summaries, codec profile and signature hits were
  compared block by block, old code against new.

**Measured, same run, same machine** (1 GiB synthetic image):

| | MiB/s |
|---|---|
| one pass, taps in the scanning process | 12.5 |
| **one pass, taps in parallel** | **28.0 (2.24x)** |
| scan alone (hashes, Merkle map, detection) - now the ceiling | 35.4 |
| DHAV carve alone | 51.0 |

**Why only same-run ratios are quoted.** This laptop's speed moved by about
3x between runs on the same day - the scan alone measured 104 MiB/s in the
morning and 32-35 MiB/s later (Windows Defender scanning the freshly written
test images, and power/thermal state). A ratio inside one run is sound; an
absolute figure from one run is a statement about the laptop's mood.

**What it means for a 1 TB drive.** Even in the slow state, the parallel
pass (28.0 MiB/s) is faster than the USB 2 bridge (23.4 MiB/s), so the drive
is the limit again: **~11.3 h**, where the serial pass in the same state would
take ~21 h. On USB 3 the main process - hashing and detection, 104 MiB/s in
the fast state - is now what sets the pace; measure it on the acquisition
workstation before planning around a USB 3 dock.

## 6. Recommendation for the next acquisition

- Use a **USB 3 dock**. Over USB 2 the drive is the limit, and nothing in
  software shortens an 11-hour read.
- Before relying on a USB 3 dock to cut the time, run the benchmark on the
  acquisition workstation. The CPU figure above is for this laptop, and the
  pass cannot go faster than the CPU rate measured there.

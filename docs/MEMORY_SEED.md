# Memory seed

Context worth persisting across sessions. If you keep a memory store, write
these in **before starting work** so they do not have to be re-derived every
session. One file per fact; the headings below are the suggested names.

Everything here was true on **23 Sep 2026**. Verify anything time-sensitive
before relying on it.

---

## sih26150-project

Building SIH26150 for SIH 2026: a multi-vendor DVR/NVR forensic analysis tool
for NTRO, theme Blockchain & Cybersecurity, category Software. Ingests a raw
DVR/NVR disk image, auto-detects the OEM, parses the proprietary filesystem,
recovers active and deleted footage, normalizes timestamps across cameras, and
emits a court-ready report with chain of custody.

Five-stage pipeline: acquire & secure → detect & parse → recover → analyse →
report & export. Runs fully offline / air-gapped.

Repo: `dvr-forensics-toolkit`, branch `setup`. Stages 1–2 are built and
tested (read-only device layer, single-pass hash + block Merkle map, custody
ledger, confidence-scored vendor detection). No vendor filesystem parser and
no carver exist yet.

## sih26150-evidence-honesty-rule

Standing rule: never claim more than can be demonstrated.

**Why:** the identified trap in this PS is claiming support for all eight named
OEMs with no way to validate it. A forensics tool that overclaims is worse than
one with narrow, honest scope, and NTRO will probe exactly there. Only
Hikvision can become `validated` (we own the hardware); everything else is
`spec_only` or `detected_not_parsed`.

**How to apply:** label every vendor validated vs spec-only in UI, report and
pitch; report unparsed or high-entropy regions as "detected, not parsed" and
never assert "encrypted" from entropy alone; attach honest confidence
percentages to fragment stitching and timestamp normalization; label any AI
triage output "lead, not evidence". Enforced in code at
`detect/engine.py::_weakest` — do not weaken it for a demo.

## sih26150-team-roles

Six people, paired coder + researcher so no pair blocks another:

- **Shrestha** (coder, heaviest load) + **Shrini** (researcher: spec sheets,
  hex inspection, test cases) — imaging, hashing, Hikvision + Dahua plugins,
  fallback carver. Shrestha works on **Linux**.
- **JP** (coder) + **Prathyushree** (researcher: H.264/timestamp research,
  author outreach, output verification) — dataset collection, deleted-footage
  carve, camera timeline, Honeywell plugin.
- **Aakash** (coder, UI/presenting) + **Hriday** (researcher: BSA 2023 s.63
  legal, ISO 27037 / NIST SP 800-86 standards, threat model, QA) — custody
  ledger, Merkle + signing, report engine, backend API, CASE export, UI, PPT,
  demo. Aakash works on **Windows**.

A shared JSON data contract (`core/contract.py`, v1.0.0, frozen 2026-09-22)
lets each engine be built and tested against mock data before real parsers
exist. Contract changes are a Saturday integration-sync topic. If Week 1 slips,
the Dahua plugin moves from Shrestha to JP.

## sih26150-hikvision-hardware

The team physically owns a DVR, opened up: a **Seagate SkyHawk** 3.5" SATA HDD
(surveillance-grade) and the DVR unit itself, motherboard marked **`DS-80xx P
REV1.1`**, 8 BNC video-in ports (8-channel analog), HDMI out. The `DS-xxxx`
naming confirms **Hikvision**; the exact model digits are still unread.

**Why it matters:** no real labelled Hikvision/Dahua/Honeywell disk images were
publicly available, so parsers could be written from specs but not validated.
Because the DVR unit is intact, the team can generate its own ground truth —
set the clock, record known footage, delete a clip, re-image, diff — and can
use the DVR's native export as a known-good reference to byte-match carved
output against. Hikvision is therefore the one vendor that can reach
`validated`.

**Status 23 Sep 2026:** the drive is wired to a bare USB-SATA bridge board (LED
lit) but **Windows does not enumerate it at all** — no USB mass-storage device,
no Kernel-PnP events. Diagnosis: the fault is in the USB data path, not the
drive — likely a charge-only cable, a cable plugged into a charger rather than
the laptop, or no 12 V reaching the drive (a 3.5" drive cannot spin up on USB
5 V bus power; the LED only proves the bridge chip has 5 V). Unresolved.

## sih26150-acquisition-constraints

Aakash's Windows laptop has a single 476 GB NVMe with **~25 GB free**, against a
DVR drive expected to be 500 GB – 4 TB. A full forensic image does not fit.

**Decision (Aakash, 23 Sep 2026):** acquire by *live read-only scan first*
rather than imaging. The scanner streams the device once, computing the
full-device MD5/SHA-256 and a per-block SHA-256 map, writing only the sector
map, metadata regions, carved clips and custody ledger — a few GB, not
terabytes. A full E01 is deferred until a large external drive exists.

**Standing prerequisites before any acquisition run:** the enclosure must be
connected *and externally powered*; the tool must run as root/Administrator for
raw device reads; and if the OS offers to format the disk, always Cancel — a
DVR platter has no filesystem the OS recognises, so that prompt is expected.

On Linux this constraint is much weaker — if Shrestha's machine has the free
space, a full image is the textbook-correct order and should be preferred.

## sih26150-datasets

**Usable:** NIST CFReDS "Heimvision DVR .E01" (best public ground truth;
download link/licence still unverified — confirm on the portal or email
cftt@nist.gov). Amrita TIFAC-CORE UMAM-DF (Indian academic corpus, GPL-2.0; not
DVR-specific, useful as an integrity-manifest template). Hikvision/Dahua/
Honeywell academic papers (MDPI, arXiv, Wiley) for byte-level specs — HIKBTREE,
DHFS/DHAV, Honeywell FS — spec only, no images. Open-source reference parsers
(hikextractor, dvrdecode, HikvisionLogAnalyzer, Honeywell-NVR-Filesystem-Tools)
show exact byte offsets; licences vary, so **study and re-implement, never copy
verbatim**.

**Rejected — do not re-suggest:** DukeMTMC-ReID (taken down by Duke in 2019 over
consent/privacy — do not cite; use Market-1501 or MSMT17 if Re-ID is ever
pursued). VIRAT, UCF-Crime, SCface, OTCBVS thermal, MIVIA audio — real, but
CV/AI-layer material, off the PS core and a time sink. The Stratosphere IoT
Mirai "on Dahua/Hikvision cameras" claim is unconfirmed — frame only as generic
IoT-malware indicators. Digital Corpora — PC/phone images, not DVR.

## sih26150-open-questions

Unresolved as of 23 Sep 2026; do not state any of these as fact:

- exact BSA 2023 Section 63 certificate format, against the Act's schedule
  (Hriday to confirm) — this is the India-specific differentiator, so getting
  it wrong is expensive
- CFReDS Heimvision `.E01` download link and licence terms
- full model number on the `DS-80xx` DVR board — needs a clearer photo
- no real Dahua or Honeywell media exists; if none materialises, pitch those
  as "detected, not parsed" rather than implying support

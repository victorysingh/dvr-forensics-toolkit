# PS26150 — Multi-Vendor DVR/NVR Forensic Analysis Tool

SIH 2026 · Problem Statement **26150** · National Technical Research Organisation (NTRO)
Theme: Blockchain & Cybersecurity · Category: Software

Standardized acquisition, recovery and analysis of surveillance evidence across
DVR/NVR vendors that all use different proprietary filesystems.

---

## Safety rules (non-negotiable)

1. **The tool never writes to the evidence drive.** There is no write path in
   `acquire/device.py` — not behind a flag, not behind a confirmation.
2. **Software write-blocking is mandatory on Windows.** The enclosure has no
   hardware write-blocker, so the read-only handle *is* the write block, and the
   report says exactly that (`software:read-only-handle`) rather than claiming
   hardware blocking.
3. **If Windows offers to format the disk, always click Cancel.** A DVR platter
   has no filesystem Windows recognises; that prompt is normal and accepting it
   destroys the evidence.
4. **Raw device reads need Administrator.** Run the terminal elevated.

## The honesty rule

Every vendor claim carries a status, and the weakest piece of evidence sets it:

| status | meaning |
|---|---|
| `validated` | confirmed against a real disk or image we possess |
| `spec_only` | implemented from published research, untested on real media |
| `detected_not_parsed` | recognised on the platter, no parser implemented |
| `synthetic_only` | only ever tested against our generated fixture |

The trap in this problem statement is claiming support for eight OEMs with no
way to validate it. We claim breadth through **detection plus a plugin SDK**,
and depth only where we have media. Today that is Hikvision (physical DS-80xx
unit) and nothing else.

## Usage

```bash
python cli.py devices                       # list attached drives (read-only)
python cli.py writeblock-rule --device /dev/sdb --user "$USER"   # keep it RO across reconnects
python cli.py scan --device /dev/sdb --case CASE-001 --investigator "Shrestha" \
                   --carve --carve-ps --reconnect-wait 480   # one pass: hashes + both carvers
python cli.py scan --device image.img --case TEST --max-mb 512   # triage
python cli.py preserve --device /dev/sdb --out out/CASE-001      # filesystem metadata
python cli.py parse    --device /dev/sdb --vendor Dahua --out out/CASE-001
python cli.py timeline --out out/CASE-001 --tz-offset 330
python cli.py report   --out out/CASE-001    # HTML + JSON, hashed into the ledger
python cli.py serve                          # viewer on http://127.0.0.1:8150
python cli.py survey --device unknown.img    # draft the layout of an unknown vendor's disk
python cli.py carve-annexb --device unknown.img --out out/CASE-009   # its video, no parser needed
python cli.py identify-model --device /dev/sdb --out out/CASE-001    # model strings outside the video
python cli.py hik-log --device /dev/sdb --out out/CASE-001           # a Hikvision disk's own system log
python cli.py record-device --out out/CASE-001 --model CP-UNR-104F1 --photo label.jpg
python cli.py verify --out out/CASE-001      # re-verify custody, Merkle root, preserved blocks
python cli.py prove  --out out/CASE-001 --offset 8388608
python cli.py validate-export --export clip.dav --against out/REF-001/clips --out out/REF-001

python tests/test_pipeline.py               # 522 regression tests (524 with ffmpeg), no hardware
python cli.py ewf-info --image case.E01 --verify   # any command also takes an .E01
python -m validate.realmedia --case1 out/CASE-001 --image1 head.dd   # every real-media check
python demo/tamper_demo.py                  # tamper detection, end to end
python demo/stage_demo.py                   # every capability in eight steps, ~5 s (synthetic disks)
python demo/bench_single_pass.py            # one pass vs one read per task (docs/PERFORMANCE.md)
python tests/synth_dvr.py fixture.img --vendor mixed
```

Full Linux procedure: `docs/LINUX_ACQUISITION.md`.

## Design

**Single pass.** Reading a 2 TB drive over USB is hours, so hashing, signature
detection and codec profiling all happen in one traversal (`acquire/scanner.py`).

**Block map + Merkle root, not one hash.** A linear SHA-256 proves the whole
image is unchanged but cannot survive an interrupted scan and cannot say *which*
region changed. Every pass also hashes each 8 MiB block and builds a Merkle tree
over those leaves. That buys resumable acquisition, per-clip inclusion proofs,
and tamper *localisation* — see `demo/tamper_demo.py`.

**Bad sectors are zero-filled in place, never skipped.** Skipping would shift
every downstream offset and silently corrupt the provenance record.

**Confidence, not yes/no.** CP Plus boards are frequently Dahua rebadges, so
vendor attribution is scored from weighted signatures, with a large bonus for a
magic found at its documented offset and sharply diminishing returns for repeats.

```
core/      contract.py   frozen JSON contract (v1.0.0, frozen 2026-09-22)
           hashing.py    streaming hashes, Merkle tree + inclusion proofs
acquire/   device.py     read-only raw block device (Windows ctypes / POSIX)
           ledger.py     hash-chained chain-of-custody ledger
           scanner.py    single-pass acquisition
detect/    signatures.py vendor + filesystem signature database
           engine.py     scoring, codec profiling, partition parsing
tests/     synth_dvr.py  synthetic DVR image generator
demo/      tamper_demo.py
```

## Status

| Component | State |
|---|---|
| Read-only device layer, bad-sector handling | working |
| Survives a USB drop mid-pass (verified reconnect) | working |
| Single-pass hash + block map + Merkle root | working |
| Custody ledger + verification | working |
| Signature detection + confidence scoring | working |
| Recorder model (platter strings + examiner's reading, cross-checked) | working; on real media: Hikvision `DS-7B08HUHI-K1`, platter and unit agree |
| Partition parsing (MBR/GPT) | working |
| Hikvision FS parser | working, `spec_only` (layout observed on drive 2; not yet run on an intact Hikvision disk) |
| Honeywell NVR (plugin, from Yoon & Hwang 2026) | working, `spec_only` (no Honeywell media) |
| HeimVision DVR (plugin, read off the NIST CFReDS image) | working on that real image, `spec_only` |
| Dahua DHFS 4.1 parser + extract | working on real media, `spec_only` |
| Indexless carver, inline in the scan | working on real media, `spec_only` |
| MPEG-PS carver (Hikvision video, dated) | working on real media, `spec_only` |
| Raw H.264/H.265 carver for vendors with no parser | working, `synthetic_only` |
| Hikvision index records → cameras for carved footage | working on real media, `spec_only` |
| Byte-match against the recorder's own export (`validate-export`) | working on generated footage; no real export yet |
| Metadata preservation | working |
| Timeline (normalization, gaps, correlation) | working |
| Report (HTML + JSON) and local UI | working |
| Drop-in vendor plugins | working |
| Unknown-vendor survey | working |
| Motion activity from frame sizes (lead, not evidence) | working |
| Video decode, face/object detection | not started (optional layer) |
| BSA s.63 certificate (draft from the case record) | working; wording matches the Gazette word for word |
| CASE/UCO export (JSON-LD; `Conforms: True` under the official `case_validate`) | working |

Nothing is `validated`: that needs a byte-match between recovered footage and
the recorder's own export. The CP Plus drive (Dahua-family DHFS) is real
media; Hikvision is still tested only against the synthetic fixture until the
team's second drive is read.

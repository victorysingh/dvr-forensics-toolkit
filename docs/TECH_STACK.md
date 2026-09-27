# Tech stack decisions

Decided 23 Sep 2026. Each entry records what we chose, what we rejected, and
why — so nobody re-litigates it in week three, and so the reasoning survives
into the final project report.

---

## The organising principle

> **The forensic core stays stdlib-only. Every dependency lives in the UI and
> AI layers.**

`core/`, `acquire/`, `detect/`, `parsers/`, `recover/` and `validate/` import nothing
outside the Python standard library. The code that touches evidence stays
small and auditable — which is precisely what a validation report needs to
claim — and it runs on an air-gapped workstation with a bare Python install.

Everything heavy (web framework, OCR, neural nets) sits in layers that can be
omitted entirely without affecting acquisition or recovery. If the AI layer
fails to install on the forensic machine, the tool still acquires evidence.

---

## Core language: Python 3.11+

Kept. But with a measured caveat, benchmarked on 1 GiB, 8 MiB blocks:

| Stage | Throughput |
|---|---|
| Raw read (OS-cached) | 1156 MB/s |
| + linear MD5 + SHA-256 | 139 MB/s |
| + per-block SHA-256 + Merkle root | ~unchanged (free) |
| **+ signatures + codec + entropy** | **41.9 MB/s** |

A USB 3.0 HDD delivers roughly 120–150 MB/s, so **we are currently CPU-bound at
about a third of the drive's speed**. Extrapolated: 1 TB ≈ 7 h, 2 TB ≈ 14 h,
4 TB ≈ 28 h.

**Decision: accept this for now, fix it after the parsers land.** Recovery
capability matters more before the idea-round deadline than scan speed.

The fix, when we take it (expected to reach I/O-bound, 120–200 MB/s):

1. **One regex pass, not six.** Detection currently scans every byte six times:
   the signature alternation, `bytes.count` for start codes, and four separate
   NAL `findall`s. Merging them into a single alternation and classifying by
   the matched bytes removes five full passes.
2. **Thread the linear hashes.** `hashlib` releases the GIL on large updates,
   so MD5 and SHA-256 can run concurrently and cost `max()` rather than `sum()`.
3. **Process pool for block detection.** Embarrassingly parallel across 8 MiB
   blocks. Linear hashing must stay sequential in the main thread.

### Consequence for anyone writing a parser

**Parsers must be stateless per block** — a pure `(offset, bytes) -> findings`
shape, with no accumulation across blocks. Anything that carries state between
blocks makes the process pool impossible and turns step 3 above from a drop-in
change into a rewrite. Where cross-block context is genuinely needed (a
structure straddling a boundary), use the carry-over-tail pattern already
implemented in `detect/engine.py::scan_block`.

Rejected: rewriting the hot loop in Rust or C. It would be faster, but it costs
a toolchain in CI, an air-gap packaging problem, and it shrinks the number of
teammates who can work on the core from six to two.

---

## UI: FastAPI + React (Vite), served locally

```
core/ acquire/ detect/ parsers/ recover/   stdlib only
api/                                       FastAPI, wraps the core
ui/                                        React + Vite
```

Runs on localhost, fully offline — no cloud, no telemetry, consistent with the
offline-by-design differentiator.

Why: fastest route to a demo that reads well on a projector, and the
timeline and hex views (the two visually important screens) are far easier in
a browser than in a native toolkit. It also matches the backend-API ownership
already assigned.

Rejected:
- **PySide6 / Qt** — feels more like real forensic software (Autopsy, FTK and
  X-Ways are all native) and avoids running a web server on an evidence
  machine, but the timeline and hex views become custom widgets, which is the
  wrong place to spend the remaining days.
- **Tauri + React** — best "product" feel and a strong signed-builds story at
  ~10 MB, but adds a Rust toolchain days before the deadline. Reconsider for
  Phase 2 if we want a shippable binary; the React frontend ports over
  unchanged, so this decision is not a trap.
- **Electron** — ~150 MB for the same thing Tauri does in 10.

The API must stay a thin wrapper. No forensic logic in `api/` — anything the
UI can do must also be doable from `cli.py` on a machine with no browser.

---

## Dependencies, by layer

| Need | Chosen | Rejected | Reason |
|---|---|---|---|
| Ed25519 signing | `cryptography` | PyNaCl | No stdlib option; widely audited |
| Codec validation | bundled `ffmpeg` / `ffprobe` | PyAV | External binary, no Python ABI risk, and we need the CLI tools anyway |
| OSD clock OCR | **Tesseract** + digit whitelist | PaddleOCR, EasyOCR | ~30 MB vs ~2 GB of torch. DVR clock text is high-contrast, fixed-position, fixed-font — near best case for Tesseract. **Trap found when it was built:** `tessedit_char_whitelist` is honoured by the legacy engine and silently ignored by the LSTM engine in Tesseract 4 and 5, so the whitelist is also re-applied to the output in Python (`analytics/osd_rules.py`) — passing the flag alone does nothing on a modern install |
| AI triage | **ONNX Runtime** + YOLO exported to ONNX | `ultralytics` + torch | ~50 MB vs ~2.5 GB. On an air-gapped deployment that difference *is* the deployment story |
| Case index | `sqlite3` (stdlib) | Postgres | Single file, portable, zero setup, already in Python |
| Web API | FastAPI + uvicorn | Flask, Django | Async, typed, automatic OpenAPI — the schema doubles as user-manual material |
| Tests | stdlib runner, pytest optional | pytest-only | `tests/test_pipeline.py` must run on a bare Python install |

---

## Trusted timestamping: two-stage, and say so

RFC 3161 requires contacting a Time Stamping Authority over the network. Our
tool claims to run air-gapped. **These contradict each other**, and pretending
otherwise is the kind of detail a knowledgeable judge finds.

Decision:

1. **At acquisition, offline:** Ed25519-sign the report and the Merkle root
   locally. Fully self-contained, no network.
2. **Later, when connected:** request an RFC 3161 token over the
   already-computed root and append it as a second, independent attestation.

The report states which stage each artifact has reached. This is a stronger
position than a timestamp feature that cannot run in the environment we are
selling, and it should be said explicitly in the deck rather than quietly
dropped.

---

## Format definitions: Kaitai Struct as documentation, hand-written parsers

`.ksy` files are declarative, readable, and double as the **comparative
analysis of DVR/NVR OEMs** the problem statement asks for as a deliverable.
That is free value and we should write them.

But the generated Python is slow and handles truncated or corrupt input badly
— and "does not crash on corrupt input" is one of our stated differentiators,
on media that is frequently failing. So the shipped parsers are hand-written
against the `.ksy` spec, and the `.ksy` files are the documentation artifact
and the cross-check, not the runtime.

---

## Packaging

- **PyInstaller** one-file builds per platform; AppImage for Linux.
- Vendor all wheels into the repo for air-gapped installation — a forensic
  workstation cannot `pip install`.
- Code-signed builds, matching the offline/intel-agency profile.
- Docker for Shrestha's development convenience only. It is not the
  deployment target; a forensic examiner does not run Docker on the evidence
  machine.

## CI and robustness

- GitHub Actions running `tests/test_pipeline.py` on Linux and Windows. The
  cross-platform device layer is exactly the kind of code that breaks silently
  on one OS.
- **Fuzzing the parsers** is a stated differentiator, not optional polish.
  `tests/synth_dvr.py` already generates structurally valid images from a
  seed — mutating its output is a ready-made fuzz corpus. Every parser needs a
  "survives corrupt input" test before it is called done.

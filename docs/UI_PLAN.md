# UI plan: a dynamic, demo-ready case console

**For:** whoever builds the UI (Aakash, or Claude: see §13 for a prompt to
paste). **Goal:** replace today's plain 7-tab viewer with a polished,
live console that shows *everything* the tool produces for a case, and that
looks good in the SIH demo video. **Branch:** `jp/ui` (from `setup`).

---

## 1. Ground rules (non-negotiable)

These come from the product itself. A UI that breaks one of them cannot ship.

| Rule | What it means for the UI |
|---|---|
| **Air-gapped** | No CDN, no Google Fonts, no external calls of any kind. Everything the page loads comes from `viewer/static/`. Use system fonts. |
| **Loopback only** | The server binds `127.0.0.1` (already true in `viewer/server.py`). Keep it that way. |
| **Read-only** | The UI never opens an evidence device and never writes. It only reads files the pipeline wrote inside a case folder. |
| **Ships in the .exe** | `packaging/ps26150.spec` bundles `viewer/static/` into `ps26150-dvr.exe`. So no build step at run time, and all files live in that folder. |
| **Honest statuses** | Every parsed result carries a status: `validated` / `spec_only` / `synthetic_only` / `detected_not_parsed`. Show it next to the result, never hide it. |
| **AI = lead, not evidence** | Every AI screen carries that label and the models' hashes. Never say "person identified". This is face *detection*; there is no recognition. |
| **Time is recorder-local** | Unless a case states a zone, times are the recorder's own clock. Label them "recorder clock", never "UTC". |
| **Traceable numbers** | Every number shown should say which file it came from, with that file's SHA-256 on hover. `load_case` already returns the hashes. |

---

## 2. What exists today

- `viewer/server.py` is a stdlib HTTP server with these routes:
  - `/api/cases` and `/api/case/<id>`: `report/case.py::load_case`, one JSON with everything
  - `/api/vendors`: the vendor matrix, plugins, onboarding steps
  - `/report/<id>`: the HTML report
  - `/thumb/<id>/<file>`: analytics thumbnails
  - static files from `viewer/static/`
- `viewer/static/` (`index.html`, `app.js` 364 lines, `style.css`) has a case
  picker, a pipeline strip, and 7 tabs: Overview, Vendors, Acquisition &
  custody, Filesystem, Recovered, Timeline, Report. It is mostly tables. It
  re-polls every 5 s while a scan is in progress.
- Start it with `python cli.py serve --out <folder of cases> --port 8150`, or
  `ps26150-dvr.exe serve --out ...`.

**Gaps:**
- Nothing is shown for the AI detections and thumbnails, the s.63
  certificate, the NIST export, the CASE/UCO export, extraction manifests,
  the codec profile or OEM coverage.
- There is no video playback and no disk map.
- There is no motion, colour or live feel.

---

## 3. Technology choice

**Recommended: plain HTML + CSS + JavaScript (ES modules), no build step.**
- It runs from the .exe and air-gapped with nothing to install.
- It is readable by a reviewer.
- Charts are small hand-written SVG or canvas: a timeline, a disk strip, bars
  and a heatmap. None needs a library.
- Split `app.js` into modules: `viewer/static/js/{api,router,ui,charts}.js`
  plus one file per screen in `viewer/static/js/screens/`.

**Alternative, only if the builder is much faster in it:** React + Vite. The
built `dist/` must be committed into `viewer/static/`, so the .exe and
air-gapped machines still need no Node. No CDN imports.

**Not now:** FastAPI or any new Python dependency. The forensic core is
stdlib-only by design (`docs/TECH_STACK.md`).

---

## 4. Look and feel

A dark "forensic console" by default, with a light theme toggle (remembered
in `localStorage`).

**Colour tokens** (CSS variables on `:root`, redefined for light):

| Token | Dark | Use |
|---|---|---|
| `--bg` / `--panel` / `--line` | `#0b0f14` / `#121821` / `#1f2a37` | page, cards, borders |
| `--text` / `--muted` | `#e6edf3` / `#8b98a5` | text |
| `--accent` | `#2dd4bf` (teal) | links, focus, live indicators |
| `--validated` | `#22c55e` | status: validated |
| `--spec` | `#3b82f6` | status: spec_only |
| `--synthetic` | `#f59e0b` | status: synthetic_only |
| `--detected` | `#94a3b8` | status: detected_not_parsed |
| `--lead` | `#a78bfa` | anything from AI (always this colour) |
| `--danger` | `#ef4444` | bad sectors, broken chain, gaps |

**Type:** `system-ui` for text; `ui-monospace, Consolas, monospace` for
hashes, offsets and times. Numbers use tabular figures.

**Shared components** (build these once, use them everywhere):
- KPI card: a big number, a label, and a small "from `scan_report.json`" source line
- status pill
- hash chip: shortened `d728b6…12b8`, with click-to-copy and the full value on hover
- data table: search, sort and pagination; virtualise over 500 rows (a real drive had 2,025 streams)
- "lead, not evidence" banner
- empty state ("Not run for this case - run `cli.py timeline ...`")
- skeleton loader
- toast ("hash copied")

**Motion (keep it subtle):**
- counters animate up on first load
- cards fade and slide in
- the pipeline stepper fills stage by stage
- the disk map paints left to right

Respect `prefers-reduced-motion`.

---

## 5. App shell and navigation

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ◧ PS26150 DVR Forensics   Case [R1 · REHEARSAL-HV ▾]  ● chain intact     │
│                            offline · read-only       ☾/☀   Open report ↗ │
├───────────┬──────────────────────────────────────────────────────────────┤
│ Dashboard │  Acquire ─ Identify ─ Parse ─ Recover ─ Timeline ─ AI ─ Report│
│ Evidence  │  (stepper: done ✓ / running ◌ / not run ○, click = go there) │
│ Vendors   ├──────────────────────────────────────────────────────────────┤
│ Recordings│                                                              │
│ Recovered │                    screen content                            │
│ Timeline  │                                                              │
│ AI leads  │                                                              │
│ Custody   │                                                              │
│ Exports   │                                                              │
└───────────┴──────────────────────────────────────────────────────────────┘
```

- **Hash routing** `#/R1/timeline`, so a URL opens straight to a screen (useful when recording the video).
- **Case switcher** in the top bar, and a **Cases home** (`#/`) with one card per case: device, vendor, size, progress, and which stages have run.
- **Top-bar badges:**
  - custody chain intact (green) or broken (red)
  - offline · read-only
  - LIVE (pulsing) while a scan is running
- **Keyboard:** `1`-`9` switch screens, `/` focuses search, `t` toggles the theme.
- **Layout:**
  - 1920×1080 is the recording size, and the layout must also work at 1366×768.
  - The sidebar collapses to icons under 1100 px.

---

## 6. Screens

For each screen: what it shows, where the data comes from (`load_case` key
or file), how it moves, and the demo moment.

### 6.1 Dashboard
- **Header:** case ID, investigator, organisation, device path and model, size, acquired time.
- **KPI cards:**
  - device size and hash status: "complete pass" or "triage: first 4 GiB"
  - vendor and confidence (e.g. *HeimVision 99.5%*)
  - recordings and cameras
  - footage recovered: streams, frames, GB
  - timeline span
  - AI leads (violet)
  - custody entries, with chain status
- **Mini-charts:** the disk-map strip (6.2), cameras as small lanes (6.6), and the top AI thumbnails (6.7).
- **Data:** `scan.*`, `parse.recordings_total` and `per_camera`, `carve.stats`, `timeline.cameras`, `analytics.totals`, `custody.verify`.
- **Demo moment:** counters count up and the stepper fills. You see the whole case in one look.

### 6.2 Evidence and acquisition
- **Device card:** path, model, serial, sector size, bus, and write-block method and state.
- **Hashes:**
  - MD5, SHA-1, SHA-256 and the Merkle root, as hash chips
  - the scope ("whole device" vs "region 0-4 GiB")
  - the timestamps
- **Scan stats:** bytes read, throughput (MB/s), duration, bad sectors, complete pass yes or no.
- **Disk map** (the wow element):
  - One cell per 8 MiB block, from `blockmap.jsonl`:
    - colour by type: video (start codes and SPS/PPS/IDR), high-entropy-without-video (flagged), empty, or bad (red)
    - brightness by `incompressibility`
  - Hover shows the offset, block hash and start codes. Click copies the offset.
  - Legend: the verdict from `regions.json` (e.g. "no high-entropy region without video structure").
  - A 150 GB drive is ~18,000 blocks. Downsample on the server: new route `/api/case/<id>/blockmap?bins=2000`.
- **Preserved metadata** (`preserved.*`) if present.
- **Codec profile** (`codec_profile.json`): start codes, SPS/PPS/IDR counts, likely codec.

### 6.3 Vendor identification
- **The 8 PS vendors** as cards (`vendors` / `oem_coverage.json`). Each card shows:
  - detected on this disk yes or no, with a confidence bar
  - parser available
  - the status pill
  - the format family (e.g. "Qualvision QVFS")
- **The winning detection expanded:** the evidence strings from `scan.detections[0].evidence`, e.g. `/root/rec/a1` (ext3 mount), `dvr_log` schema, with hit counts.
- **Plugins list and the onboarding path** Detect → Carve → Survey → Plugin → Validate, from `/api/vendors`.
- **Demo moment:** the confidence bars animate. Only one vendor lights up.

### 6.4 Recordings (filesystem parse)
- **Per-camera cards:** recordings, first and last time, total covered.
- **Recordings table:**
  - ID, camera, start and end (recorder clock), duration, codec, offset, confidence
  - filter by camera and search
- **Field provenance table:** structure, field, offset, source, citation. It proves every field was read from a documented place.
- **Notes and errors** from the parser.
- **Data:** `parse.*`.

### 6.5 Recovered footage
- **Carve summary** (`carve.labels`): streams, frames and bytes per label.
  - Highlight **outside_index**: footage the recorder's own index no longer knows about.
  - Explain it in one sentence on screen.
- **Tables:** outside-index streams, raw H.264/H.265 streams (`es_carve`), Hikvision PS streams (`ps_carve`, by month).
- **Extracted files** (`carve.extracted` and `extract/*.manifest.json`): file, frames, bytes, SHA-256, frames-match check.
- **Video player:**
  - Plays any `.mp4` in the case, e.g. the NIST export `carve-00000.nist.mp4` (H.264, 2592×1520).
  - Needs a new file route with HTTP Range support (see §8).
  - Raw `.h264`, `.h265` and `.dav` cannot play in a browser. List them with their hash and the command that makes a playable copy (`export-nist`).
- **OSD titles read from the picture** (`osd.named`), if present.
- **Demo moment:** press play on footage the tool recovered, with its SHA-256 beside it.

### 6.6 Timeline (interactive)
- **Canvas or SVG,** one lane per camera (`timeline.cameras`, `timeline.events`):
  - indexed recordings are solid blocks
  - unindexed and remnant recordings are hatched
  - gaps are red
  - recorder log events (`recorder_events`) show as markers
- **Zoom and pan** with wheel and drag, from the whole span down to minutes. A brush on a mini-map.
- **Hover** shows the recording ID, start and end, and confidence. Click opens it in 6.4 or 6.5.
- **A clock banner** always on top: "Recorder clock - not converted to UTC: the recorder's zone was not stated" (`timeline.clock.rule`).
- **Tables below the chart:** anomalies, cross-camera correlations, and the motion peaks from `activity` if present.
- **Demo moment:** zoom from 24 h down to one minute across 4 cameras.

### 6.7 AI leads (analytics)
- **Violet banner** "Leads, not evidence". It includes the models with their hashes, the thresholds, and the tiling (`analytics.models`, `thresholds`, `tiling`).
- **Totals as chips:** person / face / vehicle frames; static and implausible counted separately.
- **Thumbnail gallery** (`analytics.thumbnails` via `/thumb/`):
  - boxes are already drawn
  - click opens a lightbox with the clip, time, labels and scores, and a link to that clip in 6.5
- **Filters** by label and minimum score.
- **Motion activity** (`activity`), if present: a camera × hour heatmap with peaks marked.
- **Measured accuracy card:** "on 287 labelled real frames: person 24/57, 1 false alarm" (VALIDATION_REPORT §8a, once PR #56 merges), so the demo is honest about limits.
- **Demo moment:** the gallery of detections, each one a lead with a score, not a verdict.

### 6.8 Chain of custody
- **A vertical timeline of ledger entries** (`custody.entries`):
  - action, actor, UTC time, the detail
  - `data_hash`, and `entry_hash` → next entry's `prev_hash`, drawn as links in a chain
- **Verify status** (`custody.verify`) at the top, big and green (or red with the broken entry).
- **"Re-verify" button:** re-fetches the case; the server re-runs `ledger.verify()`.
- **Demo moment:** the chain draws link by link and ends in "chain intact ✓".

### 6.9 Reports and exports
One card per artefact, each with its file name, size, SHA-256, and Open or Download:
- the HTML report (`/report/<id>` in a new tab or an iframe)
- the s.63 certificate draft (`certificate_s63_partB.html`, and `.json` for the fields)
  - Show "DRAFT - to be signed" and which fields are still empty (`fields`, `declarant`).
- CASE/UCO JSON-LD (`case.jsonld`), with its object count
- NIST CCTV export (`*.nist.mp4` + `.manifest.json`):
  - profile, pictures, resolution
  - Level 0 met yes or no, and why not (`not_level0_because`)
- extraction manifests (`extract/*.manifest.json`)
- the report JSON, the timeline JSON, and the parse and carve reports

---

## 7. Making it dynamic

1. **Live scan.** While `scan_state.json` exists and `scan_report.json` does not, the case is in progress:
   - poll every 2 s
   - show a progress ring, bytes read, MB/s and ETA
   - paint the disk map as blocks arrive
   - light the LIVE badge
2. **Auto-refresh.** New route `/api/case/<id>/stamp` returns the case's newest file mtime. Poll it every 5 s; when it changes (e.g. `timeline` or `analyse-video` just ran in another window):
   - reload that case
   - show a toast: "Timeline updated"
3. **Cross-links everywhere:**
   - a gap on the dashboard → the timeline, zoomed to it
   - a detection → its clip
   - a hash → the custody entry that recorded it
4. **Search across the case** (`/`): recording IDs, cameras, hashes, file names.
5. **Deep links and state in the URL,** so the demo can cut straight to a screen.
6. **Skeletons while loading,** never a blank page.

---

## 8. Server work (`viewer/server.py`, `report/case.py`)

Keep the stdlib server and add:

| Route | Returns | Rules |
|---|---|---|
| `GET /file/<case>/<relpath>` | a file from inside the case folder, e.g. the NIST `.mp4`, certificate `.html`, `case.jsonld`, manifests | Resolve the real path and refuse anything outside the case folder (no `..`, no absolute paths, no symlinks out). Serve only these extensions: `.mp4 .html .json .jsonld .jpg .png .txt`. **Support `Range`** (206 Partial Content) so video can seek. GET only. |
| `GET /api/case/<id>/blockmap?bins=N` | the block map downsampled to N bins: per bin the max `start_codes`, mean `incompressibility`, any `bad` | reads `blockmap.jsonl` line by line; cap N at 5000 |
| `GET /api/case/<id>/stamp` | `{"mtime": newest file mtime in the case}` | cheap; for auto-refresh |

Additions to `load_case()`:
- `artifacts`: every known output file with path, size and SHA-256. This includes the report, certificate, `case.jsonld`, `*.nist.mp4` and manifests, `extract/*.manifest.json`, `codec_profile.json`, `oem_coverage.json`, and the parse, carve, timeline and analytics JSON.
- `extracts`: a summary of each `extract/*.manifest.json` (camera, frames, bytes, SHA-256, first and last time).
- `nist_exports`: a summary of each `*.nist.mp4.manifest.json` (profile, level0, why not, pictures, size).
- `certificate`: part, status, and which fields are filled or empty.
- `codec_profile` and `oem_coverage`: as stored.
- `analytics.tiling`: pass through if present (added in PR #56).

**Tests** (add to `tests/test_pipeline.py`, stdlib only):
- the file route refuses `../`, absolute paths and unlisted extensions
- a Range request returns the right bytes and status 206
- blockmap binning is correct
- `load_case` returns the new keys on a generated case

The existing suite must still pass.

---

## 9. Demo data

Case folders ready on JP's machine: `C:\Users\JAIPREET SINGH\150\demo\`,
copies of the rehearsal cases. The large video files (R1's extracted
`.h265`, R2's carved streams and MP4) are hard links to the rehearsal
copies, to save disk: read them, never write to them.

| Case | What it has | Screens it fills |
|---|---|---|
| **R1** (NIST HeimVision E01, 150 GB) | scan (triage, first 4 GiB), vendor HeimVision 99.5%, parse (806 files, 4 cameras), 24 h timeline, extraction (1.3 M frames, 615 MB), s.63 certificate draft, CASE/UCO export, 8 custody entries | dashboard, evidence, vendors, recordings, timeline, custody, exports |
| **R2** (real Dahua `.dav`, 2017, a fisheye camera) | scan, DHAV carve (2,042 frames), extracted stream, **playable NIST MP4**, certificate, **AI detections** (YOLOX-S + YuNet, 29 Sep: a person in 9 of 48 frames, 6 thumbnails) | recovered + video player, AI leads, exports |
| **SAMPLE** | a small sample case with a carve and a device record | empty states, a second case |

**Not in any case yet:** OSD titles and motion activity. The AI detections
in R2 came from:

```bash
python cli.py analyse-video --out "C:/Users/JAIPREET SINGH/150/demo/R2" --fps 1
```

Run the UI over them:

```bash
python cli.py serve --out "C:/Users/JAIPREET SINGH/150/demo" --port 8150
```

---

## 10. Build order

| Phase | Scope | Done when |
|---|---|---|
| **P0 shell** | tokens, dark/light, sidebar, top bar, hash router, case switcher, cases home, shared components (§4) | every screen route exists with an empty state; switching cases works |
| **P1 core screens** | dashboard, evidence (without disk map), vendors, custody | all R1 numbers visible and matching `report.html` |
| **P2 server** | `/file` with Range, `/blockmap`, `/stamp`, `load_case` additions, tests | new tests pass; the suite still passes; `../` is refused |
| **P3 rich screens** | disk map, timeline with zoom and pan, recovered with video player, exports | R2's MP4 plays and seeks; R1 timeline zooms 24 h → 1 min |
| **P4 AI + live** | AI leads gallery and lightbox, activity heatmap, live scan polling, auto-refresh, cross-links, search | a scan started in another window shows live; running `analyse-video` makes the AI screen appear without a manual reload |
| **P5 polish + ship** | motion, 1366×768 check, reduced motion, keyboard shortcuts, rebuild `ps26150-dvr.exe`, update `docs/USER_MANUAL.md` (the `serve` section) with screenshots | the .exe serves the new UI on a machine with no network |

P0-P3 alone already make a strong demo. P4-P5 make it feel alive.

---

## 11. Checks before calling it done

- [ ] It works from `ps26150-dvr.exe serve` (static files bundled), not only from Python.
- [ ] It works with the network disabled: no request leaves `127.0.0.1` (check the browser's Network tab).
- [ ] Every screen has an empty state. SAMPLE, which has almost nothing, must look fine.
- [ ] Big tables stay smooth at 2,000+ rows.
- [ ] Every status pill, "recorder clock" label and "lead, not evidence" banner is present where §1 requires it.
- [ ] 1920×1080 and 1366×768; dark and light.
- [ ] `python tests/test_pipeline.py` passes, and the test-count lines in README, START_HERE, STATUS, VALIDATION_REPORT §1 and FINAL_REPORT §5 are updated.

---

## 12. Demo video storyboard (about 2.5 minutes)

1. **Cases home** (5 s): three cases; R1 selected.
2. **Dashboard** (20 s): counters rise and the stepper fills. "One pass: hashed, identified, parsed, timeline, report."
3. **Evidence** (20 s): the disk map paints. Hover a video block, copy the SHA-256. "Read-only, write-blocked, every block hashed."
4. **Vendors** (15 s): HeimVision lights up at 99.5% with the evidence strings. The 8 PS vendors are all covered.
5. **Timeline** (25 s): 4 cameras × 24 h; zoom to a minute; the clock banner. "Recorder clock, never a guessed UTC."
6. **Switch to R2** → **Recovered** (25 s): outside-index footage; press play on the recovered MP4, its SHA-256 beside it.
7. **AI leads** (20 s): the gallery, the violet banner, the accuracy card. "Leads for an examiner, not verdicts."
8. **Custody** (15 s): the chain draws; "chain intact ✓".
9. **Exports** (15 s): the s.63 certificate draft, CASE/UCO, NIST export Level 0 check.

---

## 13. Handoff

**If Aakash builds it:**
1. Branch off `jp/ui` (or `setup`).
2. Touch only `viewer/`, `report/case.py`, `tests/test_pipeline.py` and the `serve` docs.
3. Open a PR into `setup`.
4. Don't change `setup` directly or any other `jp/*` branch.
5. `report/case.py::load_case` is the single source of data. Add to it; don't read files from the front-end by path.

**If Claude builds it,** paste this:

> Build the UI described in `docs/UI_PLAN.md` on branch `jp/ui` of
> victorysingh/dvr-forensics-toolkit (local clone
> `C:\Users\JAIPREET SINGH\150\dvr-forensics-toolkit`), phases P0-P5 in
> order. Keep every rule in §1. Use the demo cases in
> `C:\Users\JAIPREET SINGH\150\demo` and check each phase in the built-in
> browser with screenshots at 1920×1080. Run the full test suite before each
> commit. Push `jp/ui` and open a PR into `setup` when P3 is done, then
> update it as P4 and P5 land. Rebuild `pkg_dist/ps26150-dvr.exe` at the end.

# Reading the burned-in OSD: camera titles and the recorder's clock

Footage carved from outside every filesystem index has no camera anywhere in
its bytes. The picture still has one, because the recorder painted the channel
title into it. This is how that is read, what it is worth, and what it is not.

Code: `analytics/osd_rules.py` (rules, stdlib only, tested) and
`analytics/osd.py` (ffmpeg + Tesseract). Command: `cli.py read-osd`.
Status: **`synthetic_only`** — see §6, which says plainly what has not been run.

---

## 1. Why this exists

| Drive | Streams no index accounts for | What names the camera |
|---|---|---|
| 1 — CP Plus (`WWD4A3NX`) | 2,246 streams, March → August 2026 | nothing in the bytes: the DHAV channel byte is `0` for every camera (`DAHUA_DHFS.md` §4). The picture reads *Parking*, *Road View 1*, *Road View 2* |
| 2 — Hikvision (`Z9C2632A`) | 495 of 2,516 streams, older than the surviving index | nothing: no HIKBTREE record covers them. The picture reads *Camera 01*, *Camera 03* |

Those titles are not a guess — an examiner read them off decoded frames by eye
during validation (`VALIDATION_REPORT.md` §8a, §8b). This code does the same
thing at 2,741 streams instead of five, and that is the whole of its ambition.

There is a second use. Every stream carries a date decoded from its container
(the DHAV packed date, or the Hikvision `HK` descriptor) *and* a clock painted
into the picture. Both are the recorder's own wall clock reached by different
routes, so they should agree. Checking that across many streams is the output
verification the validation report asks for, and it is what caught nothing so
far only because it has been done on three frames by hand.

## 2. What the tool does

```bash
# after extract-carved has written the clips
python cli.py read-osd --out out/CASE --unlabelled
```

`--unlabelled` restricts the run to the streams no index named — the ones this
is for. Output is `out/CASE/analytics/osd.json`, hashed into the custody
ledger, and a section in the report (6c) and the viewer.

For each stream: up to six frames from the first 30 s are cropped to the OSD
band, upscaled 4×, converted to grey and passed to Tesseract with a character
whitelist. The readings are then voted on.

## 3. Three decisions worth keeping

**No hardcoded text position.** Where a recorder paints the title differs by
vendor, by firmware and by installer. Rather than assert coordinates we do not
have, the reader OCRs four candidate bands (the four corners, `BANDS`) on the
first few streams of a case and keeps whichever band read *consistently within
a stream*, averaged across streams — pooling readings across streams would
punish a band that reads two different camera names perfectly. Both polarities
are tried too, because DVR OSD is light text on dark and Tesseract is trained
on the opposite. Every band's score is kept in `osd.json`: it is the audit
trail, and it states where this OEM puts its OSD, which the comparative
analysis deliverable wants.

**A vote, not a reading.** One OCR pass on one frame is a guess. A label is
emitted only when at least 3 frames read as a plausible title and at least 60%
of them agree, and it carries that share plus every rejected alternative. A
stream whose frames disagree stays unnamed rather than being given the
best-scoring guess. (Rule 4, `START_HERE.md`: confidence, never yes/no.)

**An ambiguous date stays ambiguous.** `01/02/2024` is two dates. The parser
returns both and flags them; the only thing allowed to choose is the
container's own decoded date, and when it does, `resolved_by` records that the
container chose — the OSD did not become unambiguous. Two readings that fit
equally well resolve to nothing.

A fourth, smaller one: the whitelist is passed to Tesseract **and** re-applied
to its output in Python. `tessedit_char_whitelist` is honoured by the legacy
engine but silently ignored by the LSTM engine in Tesseract 4 and 5, so
relying on the flag alone would do nothing on a modern install.

## 4. The clock cross-check

For each sampled frame the reader compares the clock in the picture with
`container_start + the frame's offset into the stream`, and reports per stream:

| verdict | means |
|---|---|
| `agrees` | at least half the compared frames are within 3 s of the container's date |
| `disagrees` | they are not — one of the two is wrong, and **this does not decide which** |
| `read, not compared` | the picture's clock was read; the container gave no date for this stream |
| `not compared` | no clock was read |

This measures the two routes against each other. It does **not** measure the
recorder against true time: only an examiner who read the unit's zone and
compared its display with a trusted clock at seizure can do that
(`analyse/timeline.py::ClockModel`, `SOP_EXAMINATION.md`). Nothing here emits
UTC.

## 5. What it is not

- **Not identification.** It reads a camera's name. There is no recognition of
  any kind in this tool.
- **Not evidence.** A title here is pixels read by a machine; the examiner
  confirms it in the frame itself. In the data contract it is a claim with
  `source="osd_ocr"`, which is the weakest timestamp source we define.
- **Not a camera number.** *Parking* is what the installer typed. It maps to a
  channel only if someone recorded which channel that was.
- **Not available on every recorder.** The OSD can be switched off, and on
  drive 1 every channel's stored title is the factory default `CPPlusIPCam`
  (17,557 occurrences) — identical titles separate nothing. The *painted*
  titles on that drive do differ, which is exactly why this reads the picture
  and not the string in the aux frame.
- **Not possible where footage does not decode.** On drive 1 each frame
  missing from the disk breaks the rest of its group of pictures, and 221
  outside-index streams have no keyframe at all (`VALIDATION_REPORT.md` §7).
  No frame, no reading, no label.

## 6. Validation status — what has NOT been run

`synthetic_only`, and weaker than that label normally implies. Being exact,
because Rule 3 says the weakest piece of evidence sets the status:

- **No rendered frame has ever been OCR'd by this code.** It was written on a
  machine with neither `ffmpeg` nor `tesseract` installed. Tesseract's accuracy
  on DVR OSD is therefore an assumption here, not a measurement.
- What *is* tested (`tests/test_pipeline.py`, 22 checks): every rule — title
  normalisation, the vote and its thresholds, band choice and its
  per-stream scoring, ambiguous-date handling and resolution, the clock
  comparison and its tolerance — plus the whole reader end to end with
  `sample` and `ocr` replaced by a stubbed recorder that paints a known title
  in one corner and a known clock in another.
- The ffmpeg filter chain and the Tesseract invocation are therefore **unrun
  code paths**.

### The route to a real status

The reference readings already exist, taken by eye during validation:

| Source | Stream | Title in the picture | Clock in the picture |
|---|---|---|---|
| `VALIDATION_REPORT.md` §8a | drive 1, outside-index clips | *Parking*, *Road View 1*, *Road View 2* | 9 Aug 2026; 13/08/2026 05:59 PM |
| `VALIDATION_REPORT.md` §8b | drive 2, CH01 | *Camera 01* | 28-07-2024 08:19:42 |
| `VALIDATION_REPORT.md` §8b | drive 2, CH03 | *Camera 03* | 22-07-2023 11:28:55 |

So: install both binaries, run `read-osd` over those same streams, and compare
the output with the table. Titles matching what a human read, on two vendors,
makes this `spec_only`. Where the reader disagrees with the eye, the frame is
the arbiter and the disagreement belongs in the validation report — it is a
measurement of the OCR, which is the one thing currently missing.

The clock check has ground truth in the same rows: on drive 2 the burned-in
clock ran 1–2 s ahead of the `HK` time on both frames, which is inside the 3 s
tolerance, so those streams should come back `agrees`.

## 7. The other route, not taken

Dahua aux frames (type `0xF1`) carry a `TEXT` block holding the channel title
— on the platter, in the bytes, not in the picture. That would be *stronger*
than OCR: stdlib-only, inside the forensic core, provable to a Merkle leaf, no
pixels involved. It is not implemented because on the one Dahua drive we hold
every stored title is the factory default, so it attributes nothing there, and
the block's field layout has not been read off real media — writing it from a
guess would be a `synthetic_only` parser dressed as a decode.

On a recorder whose channels are named it is the better answer, and
`DAHUA_DHFS.md` §3 says so. The work is: dump a few hundred `0xF1` payloads
from a drive whose channels carry real names, establish the layout, then
attribute carved streams from it and use the OSD only to corroborate.

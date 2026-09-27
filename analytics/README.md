# Optional analytics layer

Face and object detection on **extracted clips**, as leads for an examiner.
Not part of the forensic core: acquisition, recovery, timeline and reporting
never import this, and the tool works without it (`docs/TECH_STACK.md`).

## Install

```bash
sudo apt install ffmpeg                       # decoding
python3 -m venv .venv
.venv/bin/pip install -r analytics/requirements.txt
.venv/bin/python analytics/fetch_models.py    # downloads, then checks the pinned SHA-256
```

Air-gapped workstation: on a connected machine run the above, then copy
`analytics/models/` and a wheelhouse (`pip download -r analytics/requirements.txt -d wheels/`)
across; install with `pip install --no-index -f wheels/ -r analytics/requirements.txt`
and confirm the models with `.venv/bin/python analytics/fetch_models.py --check`.

## Run

```bash
python cli.py extract-carved --device /dev/sdX --out out/CASE     # clips first
.venv/bin/python cli.py analyse-video --out out/CASE --fps 1
```

Writes `out/CASE/analytics/analytics.json` and thumbnails with boxes drawn,
records the model hashes in the custody ledger, and adds a section to the
report and the viewer.

## The OSD reader (`cli.py read-osd`)

A second, independent tool in this layer: it reads the **burned-in on-screen
display** — the channel title the recorder painted into the picture, and the
clock it displayed. It needs no Python packages at all, only two binaries:

```bash
sudo apt install ffmpeg tesseract-ocr
python cli.py extract-carved --device /dev/sdX --out out/CASE
python cli.py read-osd --out out/CASE --unlabelled
```

`--unlabelled` restricts it to the streams no filesystem index accounts for,
which are the only streams that need it: those carry no camera anywhere in
their bytes. Writes `out/CASE/analytics/osd.json`, records it in the custody
ledger, and adds section 6c to the report and a panel to the viewer.

It also cross-checks the clock in the picture against the date decoded from the
container — two routes to the recorder's own wall clock, which should agree.

Full account, including exactly what has **not** been run: `docs/OSD_OCR.md`.

## Models

| | Model | Licence | Source |
|---|---|---|---|
| Faces | UltraFace version-RFB-320 (1.2 MB) | MIT | github.com/onnx/models |
| People, vehicles, bags | SSD-MobileNet v1, COCO (29 MB) | Apache-2.0 | github.com/onnx/models |

SHA-256 pinned in `analytics/detect.py`; a model file with any other hash is
refused.

## What it is not

- **Not face recognition.** It detects that a face is present and where; it
  identifies no one. The OSD reader reads a camera's *name*; it identifies
  no one either.
- **Not evidence.** Scores are the models' confidence, not the probability a
  detection is right. Small, distant, dark or blurred subjects are missed;
  shapes are sometimes taken for people or vehicles. Every result is a moment
  to review in the footage itself.

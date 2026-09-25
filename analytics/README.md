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

## Models

| | Model | Licence | Source |
|---|---|---|---|
| Faces | UltraFace version-RFB-320 (1.2 MB) | MIT | github.com/onnx/models |
| People, vehicles, bags | SSD-MobileNet v1, COCO (29 MB) | Apache-2.0 | github.com/onnx/models |

SHA-256 pinned in `analytics/detect.py`; a model file with any other hash is
refused.

## What it is not

- **Not face recognition.** It detects that a face is present and where; it
  identifies no one.
- **Not evidence.** Scores are the models' confidence, not the probability a
  detection is right. Small, distant, dark or blurred subjects are missed;
  shapes are sometimes taken for people or vehicles. Every result is a moment
  to review in the footage itself.

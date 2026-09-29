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

By default (`--models yolox`), YOLOX-S looks for people, vehicles and bags
on the whole 1920 x 1080 frame and on each tile of a 2 x 2 grid of
overlapping tiles, and YuNet looks for faces on the whole frame. This takes
about 0.6 s of model time a frame on a laptop CPU.
- `--tiles 1` skips the tiles: about 0.24 s a frame, for triage of long
  footage.
- `--models classic` is the SSD-MobileNet + UltraFace set measured before
  29 Sep 2026, kept to reproduce those results.
- A car, bus or truck that stays in one place through much of a clip is
  reported once per place, as a **parked vehicle** (`parked_vehicles` in
  `analytics.json`, and a table in the report). Its boxes count from 0.3
  because they recur. It is not counted among the moving vehicles.
- `--rotate auto` (the default) also looks at a round fisheye picture turned
  a quarter, a half and three quarters of a turn. A camera that looks down
  shows people at every angle. Use `--rotate on` for a ceiling camera that
  is not a round fisheye, and `--rotate off` to skip it.

Writes `out/CASE/analytics/analytics.json` and thumbnails with boxes drawn,
records the model hashes in the custody ledger, and adds a section to the
report and the viewer.

## Face search (`cli.py face-search`)

Given a photo of a person, it ranks the faces in the clips by how alike they
are to the face in the photo. It runs only when an examiner supplies a photo;
`analyse-video` never compares faces.

```bash
.venv/bin/python cli.py face-search --out out/CASE --photo suspect.jpg            # the case's extracted clips
.venv/bin/python cli.py face-search --out out/CASE --photo suspect.jpg --video exported.mp4
```

- YuNet finds each face and five points on it (eyes, nose tip, mouth
  corners). The face is lined up on those points and SFace turns it into 128
  numbers; two faces are compared by the cosine between them (1 = alike,
  0 = unrelated).
- A face at or above **0.363** (OpenCV's published threshold for SFace) whose
  eyes are at least `MIN_EYE_PX` pixels apart in the recording is a
  **candidate**. Smaller faces are listed with their score, never as
  candidates.
- The recording keeps its shape when decoded (a 704 x 576 picture is read at
  1320 x 1080), so faces are not stretched.
- Checked against OpenCV's own `FaceRecognizerSF` on the same photos: the
  points agree to 0.005 px and the vectors to a cosine of 0.99999.
- Measured on LFW faces shrunk and encoded like recorder footage, and for
  false candidates on real recorder clips (`python -m validate.face_eval`,
  `docs/VALIDATION_REPORT.md` §8n).

Writes `out/CASE/analytics/face_search.json` and, in
`analytics/face_search/`, the photo with the face used, and for the most
alike faces in each clip the frame and the lined-up face side by side with
the reference. The photo's SHA-256, the models' and the thresholds go into
the custody ledger; the report gains section 6b-ii.

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
| Faces (default) | YuNet, 2026may, any input size (0.2 MB) | MIT | github.com/opencv/opencv_zoo |
| People, vehicles, bags (default) | YOLOX-S, COCO (36 MB) | Apache-2.0 | github.com/Megvii-BaseDetection/YOLOX, release 0.1.1rc0 |
| Faces (`--models classic`) | UltraFace version-RFB-320 (1.2 MB) | MIT | github.com/onnx/models |
| People, vehicles, bags (`--models classic`) | SSD-MobileNet v1, COCO (29 MB) | Apache-2.0 | github.com/onnx/models |
| Face search only | SFace, 2021dec (37 MB) | Apache-2.0 | github.com/opencv/opencv_zoo |

SHA-256 pinned in `analytics/models.py`; a model file with any other hash is
refused.

## What it is not

- **Not identification.** `analyse-video` detects that a face is present and
  where. Face search, run only on an examiner's photo, ranks faces by
  likeness: a candidate is a face to compare by eye, not a name. On
  recorder-sized faces the same person can score below the threshold and a
  stranger above it. The OSD reader reads a camera's *name*; it identifies
  no one either.
- **Not evidence.** Scores are the models' confidence, not the probability a
  detection is right. Small, distant, dark or blurred subjects are missed;
  shapes are sometimes taken for people or vehicles. Every result is a moment
  to review in the footage itself.
- **Not proof of absence.** Scored against 287 frames of real recorder
  footage labelled by eye (`docs/VALIDATION_REPORT.md` §8a), it reports a
  person in 44 of the 57 frames that had one, and a face in 22 of 27.
  The first version found no person.
  - On CAVIAR CCTV footage, which played no part in choosing, it finds 810
    of 1,089 labelled people (`python -m validate.caviar_eval`).
  - It still misses distorted and distant people.
  - The static rule can remove a person who sits still.

  Measure it on your own
  footage with `python -m validate.analytics_eval` (sample, label, score,
  sweep).

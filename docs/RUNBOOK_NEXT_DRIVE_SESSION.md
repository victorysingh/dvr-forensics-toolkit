# Runbook: the next session on the real drives

For Shrestha, on the Linux machine that holds the two drives and their case
folders. Every step reads the drives through the write block and writes only
under `out/`. Run the steps in order. Each ends with what to bring back.
Nothing here needs the recorders.

Written 29 Sep 2026 against `staging`. Where this runbook and the code
disagree, the code's `--help` wins; say so in the results.

## 0. Setup (once)

```bash
git fetch origin && git checkout staging && git merge --ff-only origin/staging
sudo apt install ffmpeg tesseract-ocr
python3 -m venv .venv
.venv/bin/pip install -r analytics/requirements.txt kaitaistruct==0.11
.venv/bin/python analytics/fetch_models.py      # YOLOX-S, YuNet and the classic set; checks each SHA-256

CASE1=out/cpplus_WWD4A3NX        # drive 1, CP Plus NVR (Seagate s/n WWD4A3NX)
CASE2=out/drive2_Z9C2632A        # drive 2, Hikvision footage (s/n Z9C2632A)
DEV1=/dev/sdX                    # drive 1 on the write-blocked bridge (check `python cli.py devices`)
```

`read-osd` and `osd_eval` need Tesseract (`tesseract-ocr` above). Steps 1
and 2 use `.venv/bin/python` for the AI. Every other step runs with the
system `python`.

**The six drive-1 clips.** Steps 1 and 2 use the same six indexed recordings
that `out/realchecks/drive1_recall/` was sampled from (§8a of the validation
report): *Road View 1*, *Road View 2* and *Parking*, at 17:00 and at 22:00 on
3 Sep 2026. Their names and SHA-256 are in that folder's `detections.json`
under `clips`. Use exactly those files:

```bash
CLIPS1=(/path/to/clip1.dav /path/to/clip2.dav /path/to/clip3.dav \
        /path/to/clip4.dav /path/to/clip5.dav /path/to/clip6.dav)
sha256sum "${CLIPS1[@]}"         # must equal the clip_sha256 values in drive1_recall/detections.json
```

## 1. AI on our own cameras, with the current default detector

PR #60 scored the 210 frames with the earlier tiled SSD. The default is now
YOLOX-S + YuNet, so re-sample the same frames with it:

```bash
.venv/bin/python -m validate.analytics_eval sample "${CLIPS1[@]}" \
    --out out/realchecks/drive1_recall_yolox --frames 35 --models yolox
```

The same clips at `--frames 35` give the same 210 keyframes, so the labels
already written carry over. Check that, then copy them:

```bash
.venv/bin/python - <<'EOF'
import csv, filecmp, os
a, b = "out/realchecks/drive1_recall", "out/realchecks/drive1_recall_yolox"
same = all(filecmp.cmp(f"{a}/frames/{f}", f"{b}/frames/{f}", shallow=False)
           for f in os.listdir(f"{a}/frames"))
print("same frames:", same)          # if False, label drive1_recall_yolox/labels.csv afresh
if same:
    old = {r["frame"]: r for r in csv.DictReader(open(f"{a}/labels.csv", encoding="utf-8"))}
    rows = list(csv.DictReader(open(f"{b}/labels.csv", encoding="utf-8")))
    for r in rows:
        for k in ("person", "face", "vehicle", "notes"):
            r[k] = old[r["frame"]][k]
    w = csv.DictWriter(open(f"{b}/labels.csv", "w", newline="", encoding="utf-8"), fieldnames=list(rows[0]))
    w.writeheader(); w.writerows(rows)
EOF
.venv/bin/python -m validate.analytics_eval score out/realchecks/drive1_recall_yolox
.venv/bin/python -m validate.analytics_eval sweep out/realchecks/drive1_recall_yolox
```

**Bring back:** the `score` and `sweep` printout, and `score.json` with its
SHA-256. The frames stay on this machine: they show the site.

## 2. On-screen titles and clocks (OCR) against what the eye read

The reader has been measured on six public recorders (validation report
§8c), but not yet on ours. Two parts:

**Drive 2's two reference streams**, already read by eye (§8b):

```bash
python cli.py read-osd --out $CASE2 --ids ps-00321,ps-03023
```

Expected: `ps-00321` titled *Camera 01*, and `ps-03023` titled *Camera 03*.
Clocks `28-07-2024 08:19:42` and `22-07-2023 11:28:55` should come back
`agrees`, since the picture ran 1-2 s ahead of the `HK` time, inside the 3 s
tolerance. If `read-osd` says a stream is not extracted, extract it first,
with drive 2 attached behind the write block:
`python cli.py extract-carved --device /dev/sdY --out $CASE2 --format ps --ids ps-00321,ps-03023`.

**Drive 1, frame by frame against the eye**, on the six clips above:

```bash
python -m validate.osd_eval sample "${CLIPS1[@]}" --out out/realchecks/osd_drive1
```

Open `out/realchecks/osd_drive1/frames/` and fill two columns of
`osd_labels.csv` for every row:
- `clock_true`: the clock painted on that frame, as `YYYY-MM-DD HH:MM:SS` in
  24-hour time. CP Plus paints `01/05/2026 01:20:26 PM`, which is
  `2026-05-01 13:20:26` (or `2026-01-05`, whichever the frame's date is).
- `title_true`: *Parking*, *Road View 1* or *Road View 2*, as painted.

Then score:

```bash
python -m validate.osd_eval score out/realchecks/osd_drive1
```

**Bring back:** both printouts and `score.json`. If titles match the eye on
both drives, the OSD reader can move from `synthetic_only` to `spec_only`
(`docs/OSD_OCR.md` §6).

## 3. UTC from daylight, on the outdoor cameras

The site is **Bengaluru, 12.97° N, 77.59° E** (JP, 29 Sep). It also needs
several days of one outdoor camera, so that it sees several dusks and dawns.

Pick the recordings of **one** camera (e.g. *Road View 1*) covering 3-5
consecutive days from `$CASE1/parse_dahua.json` (or the viewer's Filesystem
tab), and extract them as stored, with the recorder's own DHAV times:

```bash
mkdir -p out/realchecks/daylight_clips
for ID in REC_ID_1 REC_ID_2 REC_ID_3; do        # the chosen recording ids
    python cli.py extract --device $DEV1 --recording $ID --out out/realchecks/daylight_clips
done
python -m analyse.daylight sample out/realchecks/daylight_clips/*.dav \
    --out out/realchecks/daylight.jsonl --every 60
python -m analyse.daylight estimate out/realchecks/daylight.jsonl \
    --lat 12.97 --lon 77.59 --zone 330
```

A second estimate, from footage already on disk, uses the 2,246 streams
carved outside the index (March-August 2026). Their cameras are mixed, which
widens the spread:

```bash
python -m analyse.daylight sample $CASE1/carve/streams/*.dav --out out/realchecks/daylight_carved.jsonl --every 60
python -m analyse.daylight estimate out/realchecks/daylight_carved.jsonl --lat 12.97 --lon 77.59 --zone 330
```

**Bring back:** both `estimate` printouts. They give the offset from UTC, the
camera's switch elevation, and the spread of the per-switch offsets. With
`--zone 330`, the clock error against IST is the number the timeline needs
(`--tz-offset 330` plus that error).

## 4. The CP Plus drive: indexed `.dav` cross-check, and the unit's identifiers

The ffmpeg cross-check has run on all 2,246 carved streams (29 Sep: 719,097
of 719,097 frames identical). Run it on the indexed recordings extracted
above too:

```bash
python -m validate.dhav_crosscheck out/realchecks/daylight_clips "${CLIPS1[@]}" \
    --out out/realchecks/drive1_dhav_crosscheck_indexed.json
```

Then search the whole drive for the unit's own identifiers. First record them
from the label photo or System Info, if not done yet. Use the values in the
photos: they are not written in this repository.

```bash
python cli.py record-device --out $CASE1 --model CP-UNR-104F1 --serial SERIAL \
    --mac MAC --device-id DEVID --firmware FIRMWARE --read-from system-info \
    --photo /path/to/label.jpg /path/to/system_info.jpg
python cli.py identify-model --device $DEV1 --out $CASE1 --max-gb 1000
```

`identify-model` over 1 TB takes about 4 h as it is, or about 35 min with
Shrestha's PR #61 (worker processes). Merge #61 into `staging` first if it
has not been.

**Bring back:** the cross-check summary with its JSON's SHA-256, and
`identify-model`'s result: how many times, and where, the model, serial,
DevID and MAC appear on the platter.

## After the session

Put the numbers into `docs/VALIDATION_REPORT.md`: §8a (AI), §8c (OCR), §8l
(daylight), §8g (cross-check) and the drive-1 row of §1. Commit to `staging`,
never straight to `setup`. Keep the case folders, frames and clips on this
machine: they are evidence.

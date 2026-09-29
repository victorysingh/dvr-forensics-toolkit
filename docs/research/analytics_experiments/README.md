# How the analytics choices were made (29 Sep 2026)

The scripts behind each choice in the analytics layer, kept so the comparisons in
`docs/VALIDATION_REPORT.md` §8a can be checked. They are research scripts, not part
of the tool:
- They carry the paths of the machine they ran on
  (`C:/Users/JAIPREET SINGH/150/recall/`).
- They import the tool from its clone.
- They need the analytics layer (numpy, onnxruntime, ffmpeg).

**Reproducing a result does not need these.** The tool's own commands measure what
the tool does:
- `python -m validate.analytics_eval sample ... / score / sweep` on #53's labelled
  frames (set A);
- `python -m validate.caviar_eval DIR` on CAVIAR (set B).

**Data (not in git):**
- **Set A:** the six public recorder clips listed in §8a, with #53's labels in
  `validate/analytics_labels.csv`.
- **Set B:** six CAVIAR clips (EC-funded CAVIAR project, IST 2001 37540, CC BY-SA,
  https://homepages.inf.ed.ac.uk/rbf/CAVIAR/) and their ground-truth XML: Walk1,
  Browse1, Meet_WalkTogether1, WalkByShop1cor, OneLeaveShop1cor, ThreePastShop1cor.
- **Models:** `analytics/fetch_models.py`. YOLOX-Tiny, tried and not adopted, came
  from the same Megvii release (0.1.1rc0).

| Step | Scripts | What it decided |
|---|---|---|
| 1. Tiling | `exp.py` (native resolution; full, 2x2, 3x2 and 3x3 grids), `exp2.py` (640 x 360), `exp3.py` (1280 x 720); scored by `score_exp.py`, `score2.py`, `score3.py` | #56: 3 x 3 tiles, objects on a 1920 x 1080 decode, faces on 640 x 360. People went from 0 of 57 to 24 of 57. |
| 2. Models, on both sets | `newdet.py` (YOLOX and YuNet decoders), `exp_v3.py` (11 detector configurations on set A and CAVIAR), `score_v3.py`; `inspect_v3.py` (every false alarm and per-clip result), `sheet_unmatched.py` (CAVIAR boxes that match no label, for looking at by eye), `gt_check.py` (CAVIAR ground truth drawn on decoded frames, to check the frame numbering) | YOLOX-S with 2 x 2 tiles, and YuNet on the whole 1920 x 1080 frame. Chosen on set A and confirmed on CAVIAR. |
| 3. Static rule | `static_v3.py` (box-match looseness 0.8 / 0.7 / 0.6 / 0.5), `desk_check.py` (is anyone at the reception desk?) | The rule is kept at 0.8. Loosening it did not catch the desk box, and it dropped the seated pair on set A. |
| 4. Person threshold | `score_v3.py`, plus the `sweep` of `validate.analytics_eval` | People at 0.4, vehicles at 0.5. Seen on set A and confirmed on CAVIAR. |
| 5. Rotation | `exp_rot.py` (the frame also turned 90/180/270 degrees; includes a self-check of the box mapping), `score_rot.py` | `--rotate auto`: round fisheye pictures only. Turning every camera added upside-down "faces" on an upright street camera. |

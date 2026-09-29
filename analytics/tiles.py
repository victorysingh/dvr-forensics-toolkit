"""Tiling for the analytics layer - stdlib only, so the core test suite can
check it without the layer's dependencies.

The object model shrinks whatever it is given to 300 x 300, so a person 40
pixels tall in a 1080p picture is a few pixels by the time it is looked at.
On 287 labelled frames of real recorder footage the tool found a person in
none of the 57 frames that had one (docs/VALIDATION_REPORT.md section 8a).
Each detector therefore also runs on every tile of an n x n grid of
overlapping tiles, where a small person fills much more of the model's
input, and the boxes are mapped back to the whole frame.
"""

from __future__ import annotations

from analytics.static import _iou

TILES = 3               # a 3 x 3 grid, and the whole frame
TILE_OVERLAP = 0.2      # neighbouring tiles share this share of a tile
MERGE_IOU = 0.5         # the same label boxed twice where tiles overlap


def tiles(w: int, h: int, n: int = TILES, overlap: float = TILE_OVERLAP) -> list[tuple]:
    """(x, y, width, height) of each tile of an n x n grid over a w x h frame,
    row by row, neighbours overlapping by `overlap` of a tile.  The grid
    spans the frame edge to edge."""
    tw, th = int(w / (n - (n - 1) * overlap)), int(h / (n - (n - 1) * overlap))
    at = lambda i, span, t: 0 if n == 1 else int(i * (span - t) / (n - 1))
    return [(at(c, w, tw), at(r, h, th), tw, th) for r in range(n) for c in range(n)]


def to_frame(box: list[float], tile: tuple, w: int, h: int) -> list[float]:
    """A box found in a tile (0-1 of the tile) in whole-frame coordinates
    (0-1 of the frame)."""
    x, y, tw, th = tile
    x1, y1, x2, y2 = box
    return [round((x + x1 * tw) / w, 4), round((y + y1 * th) / h, 4),
            round((x + x2 * tw) / w, 4), round((y + y2 * th) / h, 4)]


# A camera on the ceiling - a fisheye above all - sees people lying at every
# angle round the picture, and the detectors learned upright people.  Running
# them on the frame turned a quarter, a half and three quarters of a turn
# (numpy's rot90, k = 1, 2, 3: anticlockwise) and turning each box back finds
# the people who lie sideways or upside down (docs/VALIDATION_REPORT.md 8a).
ROTATIONS = (1, 2, 3)


def unrotate(box: list[float], k: int) -> list[float]:
    """A box (0-1) found in the frame turned k quarter turns anticlockwise, in
    the unturned frame's own 0-1 coordinates."""
    u1, v1, u2, v2 = box
    if k == 1:
        out = [1 - v2, u1, 1 - v1, u2]
    elif k == 2:
        out = [1 - u2, 1 - v2, 1 - u1, 1 - v1]
    elif k == 3:
        out = [v1, 1 - u2, v2, 1 - u1]
    else:
        out = [u1, v1, u2, v2]
    return [round(v, 4) for v in out]


def merge(dets: list[dict], iou: float = MERGE_IOU) -> list[dict]:
    """One box per object where tiles overlap: strongest first, a box is
    dropped if one already kept has the same label and overlaps it by `iou`
    or more.  A box is only ever dropped for a stronger one, so keeping
    boxes down to a low score and filtering afterwards gives the same boxes
    as filtering first (validate/analytics_eval.py relies on this)."""
    kept: list[dict] = []
    for d in sorted(dets, key=lambda d: -d["score"]):
        if all(k["label"] != d["label"] or _iou(k["box"], d["box"]) < iou for k in kept):
            kept.append(d)
    return kept

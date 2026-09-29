"""Face search rules - standard library only, so the core test suite can check
them without the analytics layer's dependencies (analytics/face_search.py
runs the models).

Face search ranks the faces in extracted clips by how alike they are to one
face in a reference photo the examiner supplies.  A face scoring at or above
MATCH_MIN is a CANDIDATE: a moment for the examiner to compare by eye with
the photo.  It is never an identification.

How two faces are compared:
  1. YuNet gives each face five points: the two eyes, the nose tip and the two
     corners of the mouth.
  2. The face is turned, scaled and moved so that those points sit as close as
     they can to TEMPLATE, the five places SFace was trained to see them in a
     112 x 112 picture (similarity(); least squares, no mirroring).
  3. SFace turns the 112 x 112 face into 128 numbers.  Two faces are compared
     by the cosine of the angle between their vectors: 1 = pointing the same
     way, 0 = unrelated.
"""

from __future__ import annotations

import math

# The five points in a 112 x 112 face picture: the eye on the left of the
# picture, the other eye, nose tip, left then right mouth corner.  The
# standard 5-point template of ArcFace (insightface, MIT), which SFace was
# trained with and OpenCV aligns to.  YuNet gives its points in this order.
TEMPLATE = ((38.2946, 51.6963), (73.5318, 51.5014), (56.0252, 71.7366),
            (41.5493, 92.3655), (70.7299, 92.2041))
SIZE = 112

# The cosine at or above which two faces are called a match by OpenCV, who
# publish SFace with it (opencv_zoo models/face_recognition_sface/sface.py;
# the model scores 99.40% on the LFW benchmark).  LFW is photographs;
# docs/VALIDATION_REPORT.md section 8n measures it on recorder-quality faces.
MATCH_MIN = 0.363

# Below this distance between the eyes, in pixels of the frame the face was
# found in, a face is too small to compare: SFace then sees mostly blur that
# the alignment enlarged.  Such faces are listed with their score and never
# made a candidate.  Measured in section 8n.
MIN_EYE_PX = 12

RULE = "analytics.face_search.sface.v1"


def similarity(src, dst=TEMPLATE) -> list:
    """The rotation, uniform scale and shift that carry the points `src` as
    close as they can get to `dst` (least squares, no mirroring), as a 2 x 3
    matrix [[a, -b, tx], [b, a, ty]]: a point (x, y) goes to
    (a x - b y + tx, b x + a y + ty)."""
    n = len(src)
    sx, sy = sum(p[0] for p in src) / n, sum(p[1] for p in src) / n
    dx, dy = sum(p[0] for p in dst) / n, sum(p[1] for p in dst) / n
    num_a = num_b = den = 0.0
    for (x, y), (u, v) in zip(src, dst):
        x, y, u, v = x - sx, y - sy, u - dx, v - dy
        num_a += x * u + y * v
        num_b += x * v - y * u
        den += x * x + y * y
    if den == 0:
        raise ValueError("the five points coincide")
    a, b = num_a / den, num_b / den
    return [[a, -b, dx - a * sx + b * sy], [b, a, dy - b * sx - a * sy]]


def apply(m, p) -> tuple:
    return (m[0][0] * p[0] + m[0][1] * p[1] + m[0][2], m[1][0] * p[0] + m[1][1] * p[1] + m[1][2])


def eye_px(points) -> float:
    """Distance between the eyes, in pixels of the picture the points are in."""
    (x1, y1), (x2, y2) = points[0], points[1]
    return round(math.hypot(x2 - x1, y2 - y1), 1)


def is_candidate(face: dict, match_min: float = MATCH_MIN, min_eye_px: float = MIN_EYE_PX) -> bool:
    """A face is a candidate if it is alike enough and large enough to compare."""
    return face["similarity"] >= match_min and face["eye_px"] >= min_eye_px


def ranked(clips: list, top: int = 50) -> list:
    """Every compared face across the clips, most alike first."""
    faces = [dict(f, clip=c["clip"]) for c in clips for f in c.get("faces", [])]
    faces.sort(key=lambda f: (-f["similarity"], f["clip"], f["t_s"]))
    return faces[:top]


NOTES = [
    "A CANDIDATE, NOT AN IDENTIFICATION. Each face is scored by how alike it is to the "
    "face in the reference photo. A candidate is a moment for the examiner to compare by "
    "eye with the photo; it does not say who anyone is.",
    "The score is the cosine between two SFace vectors (1 = alike, 0 = unrelated), not "
    "a probability. The match threshold is the one OpenCV publishes for photographs; "
    "recorder footage is smaller, blurred, dark and seen from above, and on it the "
    "same person can score below the threshold and a different person above it "
    "(docs/VALIDATION_REPORT.md section 8n).",
    "A face with its eyes closer together than the minimum is listed with its score but "
    "is never a candidate: at that size the comparison is mostly blur.",
    "No candidate does not mean the person is absent: a face that is turned away, "
    "covered, too small or missed by the face detector is never compared.",
    "Face recognition errs more for some groups of people than others. Treat every "
    "candidate as a lead to be checked by a person against the footage itself.",
    "t_s is seconds from the first decodable frame of the clip, not a recorder timestamp.",
]

"""How well face search works on faces the size recorders capture.

Two measurements, both run through the tool's own code (analytics/face_search.py):

    python -m validate.face_eval lfw  --lfw DIR --pairs pairs.txt --out OUT [--folds 4]
    python -m validate.face_eval cctv --lfw DIR --pairs pairs.txt --clips A.mp4 B.mpg ... --out OUT
    python -m validate.face_eval summary --out OUT

lfw   Labeled Faces in the Wild (Huang et al. 2007), the benchmark SFace is
      published with: its official pairs.txt, 300 pairs of the same person and
      300 of different people per fold.  The first photo of each pair is the
      reference, read as a photo.  The second is (1) read as a photo, and (2)
      made small - scaled to a fraction of its size, placed in a 704 x 576
      picture and encoded as H.264 at CRF 28, as a recorder might - then found
      and compared the way face-search reads a recording.  Results are binned
      by the distance between the eyes the tool measures (eye_px, pixels of the
      recording), the size face_rules.MIN_EYE_PX is set in.
cctv  Every face the tool finds in real recorder clips, compared with the
      reference faces of the LFW pairs.  Nobody in those clips is an LFW
      public figure, so every face at or above the threshold is a false
      candidate: the rate at which a stranger in recorder footage is called
      alike.

LFW's images are not part of this repository (pairs.txt and lfw.tgz are
fetched as scikit-learn's fetch_lfw_pairs fetches them, checksums in
docs/VALIDATION_REPORT.md section 8n).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import proc  # noqa: E402

SCALES = (0.12, 0.16, 0.2, 0.25, 0.3, 0.4, 0.55, 0.75)
CANVAS = (704, 576)
CRF = 28
# eye_px bins: [low, high)
BINS = ((0, 8), (8, 10), (10, 12), (12, 14), (14, 16), (16, 20), (20, 24), (24, 32), (32, 1000))


def read_pairs(path: str, folds: int) -> list:
    """(same person?, first photo, second photo) for the first `folds` folds."""
    with open(path, encoding="utf-8") as fh:
        n_folds, n = (int(x) for x in fh.readline().split())
        rows = [ln.split() for ln in fh if ln.strip()]
    out = []
    for f in range(min(folds, n_folds)):
        for r in rows[f * 2 * n:(f + 1) * 2 * n]:
            if len(r) == 3:
                out.append((True, (r[0], int(r[1])), (r[0], int(r[2]))))
            else:
                out.append((False, (r[0], int(r[1])), (r[2], int(r[3]))))
    return out


def photo(lfw: str, who: tuple) -> str:
    return os.path.join(lfw, who[0], f"{who[0]}_{who[1]:04d}.jpg")


def central(faces: list, cx: float = 0.5, cy: float = 0.5, within: float = 0.2):
    """The face whose box centre is nearest (cx, cy), if within `within` of it."""
    def dist(d):
        b = d["box"]
        return ((b[0] + b[2]) / 2 - cx) ** 2 + ((b[1] + b[3]) / 2 - cy) ** 2
    near = [d for d in faces if dist(d) <= within ** 2]
    return min(near, key=dist) if near else None


def binned(rows: list, match_min: float) -> list:
    """Per eye_px bin: faces found, same-person pairs at or above the
    threshold, different-person pairs at or above it.  rows are dicts with
    same, eye_px, similarity (standard library only)."""
    out = []
    for lo, hi in BINS:
        r = [x for x in rows if lo <= x["eye_px"] < hi]
        same = [x for x in r if x["same"]]
        diff = [x for x in r if not x["same"]]
        out.append({"eye_px": f"{lo}-{hi}" if hi < 1000 else f">={lo}", "faces": len(r),
                    "same": len(same), "same_pass": sum(x["similarity"] >= match_min for x in same),
                    "diff": len(diff), "diff_pass": sum(x["similarity"] >= match_min for x in diff)})
    return out


def lfw(args) -> dict:
    import numpy as np
    from analytics import face_search as F
    from analytics.detect import decode
    from analytics.face_rules import MATCH_MIN

    S = F.load()
    pairs = read_pairs(args.pairs, args.folds)
    vecs: dict = {}

    def vec(who):
        if who not in vecs:
            img = F.load_picture(photo(args.lfw, who))
            d = central(F.faces_any_size(S["faces"], img))
            vecs[who] = None if d is None else F.embed(S["sface"], F.align(img, d["points"]))
        return vecs[who]

    full = []
    for same, a, b in pairs:
        va, vb = vec(a), vec(b)
        full.append(None if va is None or vb is None else float(np.dot(va, vb)))
    photo_rows = [{"same": p[0], "similarity": s} for p, s in zip(pairs, full) if s is not None]
    small = []
    W, H, f = F.decode_size(*CANVAS)
    with tempfile.TemporaryDirectory() as tmp:
        lst = os.path.join(tmp, "list.txt")
        with open(lst, "w", encoding="utf-8") as fh:
            for _, _, b in pairs:
                fh.write(f"file '{photo(args.lfw, b)}'\nduration 1\n".replace("\\", "/"))
            fh.write(f"file '{photo(args.lfw, pairs[-1][2])}'\n".replace("\\", "/"))
        for s in SCALES:
            clip = os.path.join(tmp, f"s{s}.h264")
            vf = (f"scale=trunc(iw*{s}/2)*2:trunc(ih*{s}/2)*2:flags=area,"
                  f"pad={CANVAS[0]}:{CANVAS[1]}:(ow-iw)/2:(oh-ih)/2:color=gray,fps=1,format=yuv420p")
            proc.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", lst,
                      "-vf", vf, "-c:v", "libx264", "-crf", str(CRF), "-g", "1", clip],
                     timeout=proc.CLIP_S, check=True)
            n = 0
            for i, (t, rgb) in enumerate(decode(clip, 1.0, "h264", size=(W, H))):
                if i >= len(pairs):
                    break
                n += 1
                same, a, b = pairs[i]
                d = central(F.faces_in(S, rgb, f), within=0.15)
                va = vec(a)
                if d is None or va is None:
                    small.append({"scale": s, "pair": i, "same": same, "found": False})
                    continue
                small.append({"scale": s, "pair": i, "same": same, "found": True,
                              "eye_px": d["eye_px"], "similarity": round(float(np.dot(va, d["_vec"])), 4)})
            print(f"  scale {s}: {n} frames, {sum(x['found'] for x in small if x['scale'] == s)} faces found",
                  flush=True)
    res = {"pairs": len(pairs), "folds": args.folds, "match_min": MATCH_MIN, "crf": CRF,
           "canvas": CANVAS, "decoded_at": [W, H], "scales": SCALES,
           "photo": {"compared": len(photo_rows),
                     "same": sum(r["same"] for r in photo_rows),
                     "same_pass": sum(r["same"] and r["similarity"] >= MATCH_MIN for r in photo_rows),
                     "diff": sum(not r["same"] for r in photo_rows),
                     "diff_pass": sum((not r["same"]) and r["similarity"] >= MATCH_MIN for r in photo_rows)},
           "found_by_scale": {str(s): [sum(x["found"] for x in small if x["scale"] == s),
                                       sum(1 for x in small if x["scale"] == s)] for s in SCALES},
           "small": small}
    res["bins"] = binned([x for x in small if x["found"]], MATCH_MIN)
    return res


def cctv(args) -> dict:
    import numpy as np
    from analytics import face_search as F
    from analytics.detect import decode
    from analytics.face_rules import MATCH_MIN

    S = F.load()
    pairs = read_pairs(args.pairs, args.folds)
    refs = []
    for who in sorted({p[1] for p in pairs}):
        img = F.load_picture(photo(args.lfw, who))
        d = central(F.faces_any_size(S["faces"], img))
        if d is not None:
            refs.append(F.embed(S["sface"], F.align(img, d["points"])))
    R = np.stack(refs)
    rows = []
    for c in args.clips:
        codec = F.CODECS.get(os.path.splitext(c)[1].lower(), "")
        first = F._first_frame(c, ["-f", codec] if codec else [])
        if first is None:
            continue
        W, H, f = F.decode_size(first.shape[1], first.shape[0])
        n = 0
        for t, rgb in decode(c, args.fps, codec, size=(W, H)):
            for d in F.faces_in(S, rgb, f):
                sims = R @ d["_vec"]
                rows.append({"clip": os.path.basename(c), "t_s": round(t, 2), "eye_px": d["eye_px"],
                             "score": d["score"], "max": round(float(sims.max()), 4),
                             "over": int((sims >= MATCH_MIN).sum())})
                n += 1
        print(f"  {os.path.basename(c)}: {n} faces", flush=True)
    out = {"references": len(refs), "match_min": MATCH_MIN, "fps": args.fps,
           "clips": [os.path.basename(c) for c in args.clips], "faces": rows, "bins": []}
    for lo, hi in BINS:
        r = [x for x in rows if lo <= x["eye_px"] < hi]
        out["bins"].append({"eye_px": f"{lo}-{hi}" if hi < 1000 else f">={lo}", "faces": len(r),
                            "comparisons": len(r) * len(refs), "over": sum(x["over"] for x in r),
                            "faces_over_any": sum(x["over"] > 0 for x in r)})
    return out


def summary(out: str) -> None:
    for name in ("lfw.json", "cctv.json"):
        p = os.path.join(out, name)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as fh:
            r = json.load(fh)
        print(f"\n{name}")
        if "photo" in r:
            ph = r["photo"]
            print(f"  photos: same {ph['same_pass']}/{ph['same']} pass, different {ph['diff_pass']}/{ph['diff']} pass")
            print(f"  found by scale: {r['found_by_scale']}")
            print("  eye_px   faces  same pass        different pass")
            for b in r["bins"]:
                pct = lambda a, n: f"{a}/{n} ({100 * a / n:.1f}%)" if n else "-"
                print(f"  {b['eye_px']:>7}  {b['faces']:>5}  {pct(b['same_pass'], b['same']):<16} "
                      f"{pct(b['diff_pass'], b['diff'])}")
        else:
            print(f"  {r['references']} reference faces x faces in {len(r['clips'])} clips")
            print("  eye_px   faces  comparisons over  faces over any")
            for b in r["bins"]:
                print(f"  {b['eye_px']:>7}  {b['faces']:>5}  {b['comparisons']:>11} {b['over']:>5}  "
                      f"{b['faces_over_any']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("lfw", "cctv"):
        p = sub.add_parser(name)
        p.add_argument("--lfw", required=True, help="the unpacked lfw/ folder")
        p.add_argument("--pairs", required=True, help="LFW's pairs.txt")
        p.add_argument("--folds", type=int, default=4)
        p.add_argument("--out", required=True)
        if name == "cctv":
            p.add_argument("--clips", nargs="+", required=True)
            p.add_argument("--fps", type=float, default=2.0)
    p = sub.add_parser("summary")
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "summary":
        summary(a.out)
        return 0
    os.makedirs(a.out, exist_ok=True)
    res = lfw(a) if a.cmd == "lfw" else cctv(a)
    with open(os.path.join(a.out, f"{a.cmd}.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    summary(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

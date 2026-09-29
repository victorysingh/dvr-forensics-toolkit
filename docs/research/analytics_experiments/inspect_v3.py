"""What are the person false alarms on set A, per config; and per-clip person recall."""
import sys

sys.path.insert(0, r"C:/Users/JAIPREET SINGH/150/recall")
from score_v3 import A, applied, frames, labels, VEH  # noqa: E402
from analytics.static import counted  # noqa: E402

for cfg, thr in (("ssd_t3", 0.5), ("ys_t1", 0.5), ("ys_t2", 0.5), ("yt_t3", 0.5), ("ys_t2", 0.7)):
    out = applied(cfg, thr, {"person"} | VEH)
    print(f"\n== {cfg} @ {thr}")
    per = {}
    for k, i in enumerate(A):
        lab = labels[k]
        said = [d for d in out[i] if d["label"] == "person" and counted(d)]
        c = frames[i]["clip"][:20]
        e = per.setdefault(c, [0, 0, 0])
        e[0] += lab["person"] == "y"
        e[1] += bool(said) and lab["person"] == "y"
        e[2] += any(d["label"] == "person" and d.get("static") for d in out[i]) and lab["person"] == "y" and not said
        if said and lab["person"] != "y":
            print(f"   FA frame {k} {c} {lab['position']:>8}  {[(d['score'], d['box']) for d in said][:3]}  | {lab['notes'][:70]}")
        vs = [d for d in out[i] if d["label"] in VEH and counted(d)]
        if vs and lab["vehicle"] != "y":
            print(f"   vehicle FA frame {k} {c} {[(d['label'], d['score']) for d in vs][:3]} | {lab['notes'][:50]}")
    print("   per clip (with person, found, static-removed):", {k: v for k, v in per.items() if v[0]})

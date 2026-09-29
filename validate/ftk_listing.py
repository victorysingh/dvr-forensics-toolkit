"""A second tool's reading of the same disk: FTK Imager's file listing.

NIST's HeimVision image ships with the file listing FTK Imager 4.3.1.1 made
when the image was taken (`HeimVision K9604-W File Listing.csv`, UTF-16,
tab-separated).  FTK's FAT32 and ext3 code is commercial and was written
independently of this tool, so where both list the same files with the same
sizes and times, a reading error in either would have to be repeated by the
other.  This compares, file by file:

  FAT32 (partition 2)  every entry under the root and its folders: present on
                       both sides, size, and write time as stored (FTK shows
                       "N/A" where the entry was never written)
  ext3  (partition 1)  the recorder's own files: size, and mtime/atime, which
                       FTK prints as UTC from the inode's Unix seconds

and states the recorder's zone setting implied by FTK's ext3 times against
the recorder's own log - the same measurement as the plugin's, made on
FTK's numbers.  It checks our filesystem reading, not the video format.

Usage:
  python -m validate.ftk_listing IMAGE.E01 LISTING.csv [--out ftk_listing.json]
"""

from __future__ import annotations

import argparse
import csv
import importlib
import io
import json
import sys
from datetime import datetime, timezone
from typing import Optional

RULE = "validate.ftk_listing.v1"
FAT_ROOT = "NONAME [FAT32]\\[root]\\"
EXT_ROOT = "NONAME [Ext3]\\[root]\\"


def load_listing(path: str) -> list[dict]:
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8")
    return list(csv.DictReader(io.StringIO(text), delimiter="\t"))


def _fat_fmt(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%b-%d %H:%M:%S") if dt else "N/A"


def _utc_fmt(t: Optional[int]) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%b-%d %H:%M:%S UTC") \
        if t else ""


def ours(dev) -> dict:
    """Our reading of the same disk, keyed as FTK's listing names things."""
    hv = importlib.import_module("ps26150_plugin_heimvision")
    p = hv.HeimVisionParser()
    fat = p._fat(dev)
    out_fat: dict[str, dict] = {}
    for e in fat.entries(fat.root):
        if e["name"] in (".", ".."):
            continue
        key = e["name"].lower()
        if e["attr"] & 0x10:
            for f in fat.entries(e["cluster"]):
                if f["name"] in (".", ".."):
                    continue
                out_fat[f"{key}\\{f['name'].lower()}"] = {"size": f["size"],
                                                          "modified": _fat_fmt(f["written"])}
        else:
            out_fat[key] = {"size": e["size"], "modified": _fat_fmt(e["written"])}
    system = hv.recorder_system(dev)
    out_ext = {n: {"size": f["size"], "modified": _utc_fmt(f["mtime_raw"]),
                   "accessed": _utc_fmt(f["atime_raw"])}
               for n, f in system.get("files", {}).items()}
    log = system.get("log", [])
    return {"fat": out_fat, "ext3": out_ext,
            "log_last_display_time": max((r[2] for r in log), default=None),
            "log_file_mtime_raw": system.get("files", {}).get("dvr_log.db", {}).get("mtime_raw")}


def theirs(rows: list[dict]) -> dict:
    fat, ext = {}, {}
    for r in rows:
        path = r.get("Full Path", "")
        if FAT_ROOT in path:
            key = path.split(FAT_ROOT, 1)[1].lower()
            fat[key] = {"size": int(r["Size (bytes)"] or 0), "modified": r["Modified"].strip(),
                        "deleted": r.get("Is Deleted", "no")}
        elif EXT_ROOT in path:
            ext[path.split(EXT_ROOT, 1)[1]] = {"size": int(r["Size (bytes)"] or 0),
                                               "modified": r["Modified"].strip(),
                                               "accessed": r["Accessed"].strip()}
    return {"fat": fat, "ext3": ext}


def compare(a: dict, b: dict) -> dict:
    """a = ours, b = FTK's."""
    fa, fb = a["fat"], b["fat"]
    # FTK lists folders as entries of their own; we list their files
    files_b = {k: v for k, v in fb.items() if "." in k.rsplit("\\", 1)[-1]}
    both = sorted(set(fa) & set(files_b))
    size_diff = [k for k in both if fa[k]["size"] != files_b[k]["size"]]
    time_diff = [k for k in both if fa[k]["modified"] != files_b[k]["modified"]]
    written = [k for k in both if files_b[k]["modified"] != "N/A"]
    ext_both = sorted(set(a["ext3"]) & set(b["ext3"]))
    ext_diff = [n for n in ext_both
                if (a["ext3"][n]["size"], a["ext3"][n]["modified"], a["ext3"][n]["accessed"])
                != (b["ext3"][n]["size"], b["ext3"][n]["modified"], b["ext3"][n]["accessed"])]
    zone = None
    last, ftk_mtime = a.get("log_last_display_time"), b["ext3"].get("dvr_log.db", {}).get("modified")
    if last and ftk_mtime:
        m = datetime.strptime(ftk_mtime, "%Y-%b-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        zone = round((last - m.timestamp()) / 900) * 15
    return {
        "fat": {"ours": len(fa), "ftk_files": len(files_b), "in_both": len(both),
                "only_ours": sorted(set(fa) - set(files_b))[:20],
                "only_ftk": sorted(set(files_b) - set(fa))[:20],
                "size_differs": size_diff[:20], "time_differs": time_diff[:20],
                "written_per_ftk": len(written),
                "deleted_per_ftk": sum(1 for v in fb.values() if v["deleted"] != "no")},
        "ext3": {"compared": ext_both, "differs": ext_diff,
                 "only_ours": sorted(set(a["ext3"]) - set(b["ext3"]))},
        "zone_setting_minutes_from_ftk_times": zone,
        "identical": (not size_diff and not time_diff and not ext_diff
                      and set(fa) == set(files_b) and bool(both)),
    }


def check(image: str, listing: str) -> dict:
    import parsers  # noqa: F401  (registers the HeimVision plugin)
    from acquire.device import BlockDevice
    with BlockDevice(image) as dev:
        a = ours(dev)
    return dict(compare(a, theirs(load_listing(listing))), rule=RULE)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("image")
    ap.add_argument("listing")
    ap.add_argument("--out", default="ftk_listing.json")
    args = ap.parse_args(argv)
    rep = check(args.image, args.listing)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    f, e = rep["fat"], rep["ext3"]
    print(f"FAT32  {f['in_both']:,} files in both (ours {f['ours']:,}, FTK {f['ftk_files']:,}); "
          f"sizes differ {len(f['size_differs'])}, write times differ {len(f['time_differs'])}; "
          f"{f['written_per_ftk']} written per FTK, {f['deleted_per_ftk']} deleted per FTK")
    print(f"ext3   {len(e['compared'])} files compared, {len(e['differs'])} differ")
    print(f"zone   UTC{(rep['zone_setting_minutes_from_ftk_times'] or 0) / 60:+.2g}h from FTK's "
          f"ext3 time for dvr_log.db against the recorder's own log")
    print(f"{'IDENTICAL' if rep['identical'] else 'DIFFERENCES - see ' + args.out}")
    return 0 if rep["identical"] else 1


if __name__ == "__main__":
    sys.exit(main())

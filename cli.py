"""PS26150 forensic tool - command line entry point.

    python cli.py devices
    python cli.py scan  --device "\\\\.\\PhysicalDrive1" --case CASE-001 --investigator "Aakash"
    python cli.py scan  --device image.img --case TEST --max-mb 64
    python cli.py verify --out out/CASE-001
    python cli.py prove  --out out/CASE-001 --offset 8388608
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from acquire.device import (BlockDevice, DeviceError, PermissionNeeded,
                            human_size, is_admin, list_physical_drives)
from acquire.ledger import CustodyLedger
from acquire.scanner import ScanSession
from core.contract import CaseInfo
from core.hashing import DEFAULT_BLOCK_SIZE, merkle_proof, merkle_root, verify_merkle_proof

BANNER = "PS26150 multi-vendor DVR/NVR forensic tool"


def cmd_devices(args) -> int:
    is_win = sys.platform == "win32"
    privilege = "Administrator" if is_win else "root"
    print(f"{BANNER} - attached block devices\n")
    if not is_admin():
        print(f"!! Not running as {privilege}. Raw device reads will be denied.")
        print(f"   {'Relaunch elevated' if is_win else 'Re-run under sudo'} to acquire.\n")
    drives = list_physical_drives(args.max_index)
    if not drives:
        print("No physical drives enumerated.")
        return 1
    print(f"{'idx':<4} {'path':<20} {'size':>10}  {'bus':<6} {'sect':>5} "
          f"{'wblock':<8} model / serial")
    print("-" * 94)
    for d in drives:
        if "error" in d:
            print(f"{d['index']:<4} {d['path']:<20} {'?':>10}  {'-':<6} {'-':>5} "
                  f"{'-':<8} [{d['error']}]")
            continue
        # On Linux the kernel tells us whether the device is genuinely
        # read-only. On Windows there is no such flag - the read-only handle
        # is the block - so we say "handle" rather than implying more.
        if "read_only" in d:
            wb = "RO(kernel)" if d["read_only"] else "RW !!"
        else:
            wb = "handle"
        print(f"{d['index']:<4} {d['path']:<20} {human_size(d['size_bytes']):>10}  "
              f"{d['bus_type']:<6} {d['sector_size']:>5} {wb:<8} "
              f"{d['model']} {('/ ' + d['serial']) if d['serial'] else ''}")

    if any(d.get("read_only") is False and d.get("bus_type") == "USB" for d in drives):
        print("\n!! A USB device is writable (RW). Before acquiring, write-block it:")
        print("     sudo blockdev --setro /dev/sdX && blockdev --getro /dev/sdX")
    print("\nNote: a DVR drive usually shows NO recognisable partitions - the whole")
    print("platter is a proprietary volume. The OS may offer to format it. Never accept.")
    return 0


def cmd_scan(args) -> int:
    case = CaseInfo(case_id=args.case, investigator=args.investigator,
                    organization=args.organization, notes=args.notes)
    out_dir = args.out or os.path.join("out", args.case)

    print(f"{BANNER}\n")
    if args.device.startswith("\\\\.\\") and not is_admin():
        print("!! Raw device access needs Administrator. Relaunch elevated.\n")

    session = ScanSession(args.device, out_dir, case,
                          block_size=args.block_size * 1024 * 1024,
                          resume=args.resume)
    try:
        report = session.run(max_bytes=args.max_mb * 1024 * 1024 if args.max_mb else None)
    except PermissionNeeded as exc:
        print(f"\n[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"\n[!] {exc}")
        return 3

    _print_summary(report, session, out_dir)
    return 0


def _print_summary(report, session, out_dir: str) -> None:
    st = report.stats
    print(f"\n--- acquisition ---------------------------------------------")
    print(f"  read           {human_size(st.bytes_read)} in {st.duration_s}s "
          f"({st.throughput_mbps} MB/s)")
    print(f"  blocks         {st.blocks_hashed} x {human_size(st.block_size)}")
    print(f"  bad sectors    {st.bad_sectors}")
    print(f"  complete pass  {st.complete_pass}")
    for h in report.hashes:
        print(f"  {h.algorithm:<14} {h.value}")

    print(f"\n--- partitions ----------------------------------------------")
    if report.partitions:
        for p in report.partitions:
            print(f"  [{p.index}] {p.scheme:<20} {p.type_hint:<16} "
                  f"@ {p.start_offset} ({human_size(p.length)})")
    else:
        print("  none found - consistent with a whole-disk proprietary volume")

    print(f"\n--- vendor detection ----------------------------------------")
    if not report.detections:
        print("  no vendor signatures matched")
    for d in report.detections:
        bar = "#" * int(d.confidence * 20)
        print(f"  {d.vendor:<12} {d.confidence*100:5.1f}% [{bar:<20}] "
              f"{d.validation_status}  parser={'yes' if d.parser_available else 'NO'}")
        for e in d.evidence[:4]:
            print(f"      - {e}")

    codec = session.scanner.codec
    print(f"\n--- codec profile -------------------------------------------")
    print(f"  start codes    {codec.start_codes:,}")
    print(f"  SPS / PPS / IDR  {codec.sps:,} / {codec.pps:,} / {codec.idr:,}")
    print(f"  likely codec   {codec.likely_codec or 'none detected'}")

    hot = sorted(session.scanner.blocks, key=lambda b: b.incompressibility,
                 reverse=True)[:3]
    if hot and hot[0].incompressibility > 0.95:
        print(f"\n--- high-entropy regions (reported, not parsed) --------------")
        for b in hot:
            if b.incompressibility > 0.95:
                print(f"  @ {b.offset:>12} ratio {b.incompressibility:.3f} "
                      f"- encrypted or already-compressed; NOT claimed as encrypted")

    print(f"\n--- chain of custody ----------------------------------------")
    v = session.ledger.verify()
    print(f"  {v['message']}")
    print(f"  head  {session.ledger.head}")
    print(f"\n[+] artifacts in {out_dir}/")
    for f in sorted(os.listdir(out_dir)):
        size = os.path.getsize(os.path.join(out_dir, f))
        print(f"      {f:<24} {human_size(size):>10}")


def cmd_verify(args) -> int:
    """Re-verify a completed scan: custody chain + Merkle root recomputation."""
    out_dir = args.out
    ledger = CustodyLedger(os.path.join(out_dir, "custody_ledger.jsonl"))
    v = ledger.verify()
    print(f"{BANNER} - verification\n")
    print(f"custody chain : {v['message']}")
    if not v["valid"]:
        print(f"                expected {v['expected']}")
        print(f"                found    {v['found']}")

    leaves, blockmap = [], os.path.join(out_dir, "blockmap.jsonl")
    if os.path.exists(blockmap):
        with open(blockmap, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    leaves.append(json.loads(line)["sha256"])
        recomputed = merkle_root(leaves)
        with open(os.path.join(out_dir, "scan_report.json"), "r", encoding="utf-8") as fh:
            report = json.load(fh)
        stored = report.get("merkle_root", "")
        ok = recomputed == stored
        print(f"merkle root   : {'MATCH' if ok else 'MISMATCH'} over {len(leaves)} blocks")
        print(f"                stored     {stored}")
        if not ok:
            print(f"                recomputed {recomputed}")
        return 0 if (v["valid"] and ok) else 1
    return 0 if v["valid"] else 1


def cmd_prove(args) -> int:
    """Produce a Merkle inclusion proof for the block containing an offset.

    This is what makes a single carved clip defensible without re-reading a
    multi-TB drive: the block hash, a short sibling path, and the root that
    was signed at acquisition time.
    """
    out_dir = args.out
    with open(os.path.join(out_dir, "blockmap.jsonl"), "r", encoding="utf-8") as fh:
        blocks = [json.loads(l) for l in fh if l.strip()]
    leaves = [b["sha256"] for b in blocks]
    idx = next((i for i, b in enumerate(blocks)
                if b["offset"] <= args.offset < b["offset"] + b["length"]), None)
    if idx is None:
        print(f"[!] offset {args.offset} is outside the scanned range")
        return 1
    path = merkle_proof(leaves, idx)
    root = merkle_root(leaves)
    ok = verify_merkle_proof(leaves[idx], path, root)
    proof = {"offset": args.offset, "block_index": idx,
             "block_offset": blocks[idx]["offset"],
             "block_sha256": leaves[idx], "merkle_root": root,
             "path_length": len(path), "path": path, "verified": ok}
    print(json.dumps(proof, indent=2))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="ps26150", description=BANNER)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("devices", help="list attached block devices (read-only)")
    p.add_argument("--max-index", type=int, default=16)
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("scan", help="single-pass read-only acquisition scan")
    p.add_argument("--device", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--investigator", default=os.environ.get("USERNAME", "unknown"))
    p.add_argument("--organization", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--out", default="")
    p.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE // 1024 // 1024,
                   help="block size in MiB (default 8)")
    p.add_argument("--max-mb", type=int, default=0,
                   help="stop after N MiB - triage mode, marks the pass incomplete")
    p.add_argument("--resume", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("verify", help="re-verify custody chain and Merkle root")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("prove", help="Merkle inclusion proof for a disk offset")
    p.add_argument("--out", required=True)
    p.add_argument("--offset", type=int, required=True)
    p.set_defaults(func=cmd_prove)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

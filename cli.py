"""PS26150 forensic tool - command line entry point.

    python cli.py devices
    python cli.py scan  --device "\\\\.\\PhysicalDrive1" --case CASE-001 --investigator "Aakash"
    python cli.py scan  --device image.img --case TEST --max-mb 64
    python cli.py parse --device image.img --vendor Hikvision --out out/CASE-001
    python cli.py parse --device image.dd --vendor Dahua --remnants --out out/CASE-002
    python cli.py extract --device image.dd --recording dhfs-v1-c002120 --out out/CASE-002/clips
    python cli.py carve --device image.dd --out out/CASE-002/carve --extract outside
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

# Imported for its registration side effect: loading the plugin package is what
# populates `signatures.PARSERS_AVAILABLE`, so every command - not just `parse`
# - reports the same answer to "do we ship a parser for this vendor?".  Without
# it a scan report would say parser=NO for a vendor we do in fact parse.
import parsers  # noqa: F401,E402

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

    taps = []
    if args.carve:
        from recover.carver import CarveTap
        taps.append(CarveTap(tz_offset_min=args.tz_offset))
    session = ScanSession(args.device, out_dir, case,
                          block_size=args.block_size * 1024 * 1024,
                          resume=args.resume, taps=taps,
                          reconnect_wait_s=args.reconnect_wait * 60)
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


def cmd_parse(args) -> int:
    """Parse a vendor filesystem and emit Recording objects.

    Reads through the same read-only device layer as `scan`, so parsing a live
    evidence drive carries the same safety contract.  Where a scan report from
    a previous acquisition exists, its signature hits are passed to the plugin
    as offset hints, which keeps the single-pass design intact - the parser
    jumps straight to the structures rather than re-walking the platter.
    """
    from core.contract import dump_json, to_dict
    from parsers import available_vendors, get_parser

    hints: list[int] = []
    if args.out and os.path.exists(os.path.join(args.out, "scan_report.json")):
        with open(os.path.join(args.out, "scan_report.json"), "r",
                  encoding="utf-8") as fh:
            prior = json.load(fh)
        hints = [h["offset"] for h in prior.get("signature_hits", [])
                 if h.get("vendor") == args.vendor]

    if args.vendor not in available_vendors():
        print(f"[!] no filesystem parser ships for {args.vendor!r}.")
        print(f"    parsers available: {sorted(available_vendors()) or 'none'}")
        print("    Detection without a parser is reported as "
              "'detected_not_parsed' - it is not partial support.")
        return 1

    parser = get_parser(args.vendor)
    if getattr(args, "tz_offset", None) is not None and hasattr(parser, "tz_offset_min"):
        parser.tz_offset_min = args.tz_offset
    print(f"{BANNER} - {args.vendor} filesystem parse\n")
    remnants = []
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)})")
            print(f"  write-block   {info.write_block_method}")
            if hints:
                print(f"  offset hints  {len(hints)} from {args.out}")
            result = parser.parse(dev, hint_offsets=hints or None)
            if getattr(args, "remnants", False) and hasattr(parser, "remnant_recordings"):
                print("  remnants      scanning every indexed cluster in the image "
                      "for older footage ...")
                remnants = parser.remnant_recordings(dev)
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1

    for err in result.errors:
        print(f"\n[!] {err}")
    if not result.parsed:
        return 1

    print(f"\n--- volume {'-' * 48}")
    if "summary" in result.volume:
        for label, value in result.volume["summary"]:
            print(f"  {label:<13} {value}")
    else:
        m = result.volume.get("master", {})
        print(f"  master @      0x{m.get('offset', 0):X}")
        print(f"  model         {m.get('model', '') or '(unreadable)'}")
        print(f"  firmware      {m.get('firmware', '') or '(unreadable)'}")
        print(f"  channels      {m.get('channel_count', 0)}")
        btree = result.volume.get("btree_offset")
        print(f"  index @       "
              f"{('0x%X' % btree) if btree is not None else 'NOT FOUND'}")

    print(f"\n--- recordings ({len(result.recordings)}) {'-' * 38}")
    for rec in result.recordings[:args.limit]:
        print(f"  {rec.id}  {rec.camera_id}  {rec.state:10s} "
              f"@0x{rec.offset:<10X} {human_size(rec.length):>10s}  "
              f"{(str(rec.frame_count) + ' frames') if rec.frame_count else 'not counted':>12s}"
              f"  conf {rec.confidence:.2f}  {_when(rec)}")
    if len(result.recordings) > args.limit:
        print(f"  ... {len(result.recordings) - args.limit} more "
              f"(raise --limit to see them)")
    rstats = getattr(parser, "remnant_stats", None)
    if getattr(args, "remnants", False) and rstats is not None:
        print(f"\n--- remnants of overwritten footage ({len(remnants)}) {'-' * 20}")
        print(f"  scanned {rstats.get('clusters_scanned', 0)} clusters; runs dated >1 h "
              f"outside their cluster's window count as older footage")
        print(f"  not counted: {rstats.get('in_period_unexplained_runs', 0)} runs "
              f"({rstats.get('in_period_unexplained_frames', 0)} frames) dated inside the "
              f"current recording period, {rstats.get('short_runs_dropped', 0)} runs "
              f"under 1 s")
        for rec in remnants[:args.limit]:
            print(f"  {rec.id}  camera ?  @0x{rec.offset:<10X} "
                  f"{human_size(rec.length):>10s}  {rec.frame_count:5d} frames  "
                  f"{_when(rec)}")
        if len(remnants) > args.limit:
            print(f"  ... {len(remnants) - args.limit} more")

    # The honesty block. Printed every run, not buried in a JSON field.
    print(f"\n--- status {'-' * 48}")
    print(f"  validation    {result.validation_status.upper()}")
    fixture_fields = [f for f in result.field_provenance
                      if f["source"] == "fixture"]
    print(f"  field sources {len(result.field_provenance)} decoded fields, "
          f"{len(fixture_fields)} corroborated only by our synthetic fixture")
    for n in result.notes:
        print(f"  - {n}")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, f"parse_{args.vendor.lower()}.json")
        dump_json({
            "schema_version": __import__("core.contract", fromlist=["x"]).SCHEMA_VERSION,
            "vendor": result.vendor,
            "parser_rule": result.parser_rule,
            "validation_status": result.validation_status,
            "volume": result.volume,
            "recordings": [to_dict(r) for r in result.recordings],
            "remnants": [to_dict(r) for r in remnants],
            "remnant_scan": getattr(parser, "remnant_stats", None),
            "indexed_extents": result.indexed_extents,
            "field_provenance": result.field_provenance,
            "notes": result.notes,
            "errors": result.errors,
        }, path)
        print(f"\n[+] {path}")
    return 0


def _when(rec) -> str:
    """UTC when the parser could establish it; otherwise the recorder's own
    clock, labelled as such - never a local time passed off as UTC."""
    if rec.start_utc:
        return rec.start_utc
    if rec.timestamps:
        return rec.timestamps[0].raw_value.split(" = ", 1)[-1]
    return "no timestamp"


def cmd_extract(args) -> int:
    """Reassemble one recording into playable files, with a hashed manifest.

    Output goes to --out, never to the device.  Two files per recording: the
    DHAV stream as stored (`.dav`, which ffmpeg's dhav demuxer reads) and the
    bare video elementary stream (`.h265`/`.h264`, playable directly).  The
    manifest records every cluster read, its hash, and what was left out.
    """
    from core.contract import SCHEMA_VERSION, to_dict, utc_now
    from core.hashing import sha256_file
    from parsers import dahua, get_parser

    if args.vendor != "Dahua":
        print(f"[!] extract is implemented for Dahua DHFS only; {args.vendor!r} "
              f"recordings can be listed with `parse` but not reassembled yet.")
        return 1
    parser = get_parser(args.vendor)
    if args.tz_offset is not None:
        parser.tz_offset_min = args.tz_offset
    os.makedirs(args.out, exist_ok=True)
    print(f"{BANNER} - {args.vendor} extract {args.recording}\n")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)})")
            print(f"  write-block   {info.write_block_method}")
            result = parser.parse(dev)
            vol, f = parser.file_for(args.recording)
            if f is None:
                print(f"[!] no recording {args.recording!r}. Run `parse --vendor "
                      f"Dahua` to list recording ids.")
                return 1
            rec = next(r for r in result.recordings if r.id == args.recording)
            base = os.path.join(args.out, args.recording)
            print(f"  recording     {rec.camera_id}  {_when(rec)}  "
                  f"{len(f.clusters)} clusters")
            print("  reassembling  ...")
            with open(base + ".dav", "wb") as dav, open(base + ".es", "wb") as es:
                stats = dahua.reassemble(dev, vol, f, dav, es)
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1

    codec = stats.get("codec") or "bin"
    es_path = f"{base}.{codec if codec in ('h264', 'h265') else 'es'}"
    os.replace(base + ".es", es_path)
    outputs = {}
    for path in (base + ".dav", es_path):
        outputs[os.path.basename(path)] = {
            "bytes": os.path.getsize(path), "sha256": sha256_file(path)}

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": utc_now(),
        "tool": "ps26150-forensics extract",
        "source_device": info.path,
        "source_bytes": info.size_bytes,
        "write_block_method": info.write_block_method,
        "vendor": result.volume.get("vendor"),
        "parser_rule": parser.parser_rule,
        "validation_status": result.validation_status,
        "recording": to_dict(rec),
        "chain": {"head_cluster": f.head.index, "continuation_clusters": f.clusters,
                  "chain_intact": f.chain_ok, "chain_notes": f.chain_notes,
                  "data_base": vol.data_base, "cluster_size": vol.cluster_size},
        "reassembly": stats,
        "outputs": outputs,
        "not_included": [
            "head cluster (role not yet understood - holds <1 s of data)",
            f"{stats['spill_in']} frames of other cameras' overflow at cluster starts",
            f"{stats['remnant_frames']} frames of older overwritten footage "
            f"(list them with `parse --remnants`)",
            f"{stats['video_counter_missing']} video frames absent from the disk "
            f"(counter gaps; not interpolated)",
        ],
    }
    from core.contract import dump_json
    mpath = base + ".manifest.json"
    dump_json(manifest, mpath)

    dur = stats["video_frames"] / stats["fps"] if stats.get("fps") else 0
    print(f"\n--- result {'-' * 48}")
    print(f"  span          {stats['first_date']} -> {stats['last_date']} (recorder clock)")
    print(f"  video         {stats['codec']} {stats['width']}x{stats['height']} "
          f"@ {stats['fps']} fps, {stats['video_frames']} frames (~{dur / 60:.1f} min), "
          f"{stats['i_frames']} I-frames")
    print(f"  clusters      {stats['clusters']} read, "
          f"{stats['clusters_beyond_image']} beyond the image")
    miss, span = stats["video_counter_missing"], stats["video_counter_span"]
    print(f"  missing       {miss} video frames by counter "
          f"({(miss / span if span else 0):.2%}) - not on the disk, not interpolated")
    print(f"  excluded      {stats['spill_in']} overflow frames from other cameras, "
          f"{stats['remnant_frames']} older remnant frames")
    print(f"  stream breaks {stats['stream_breaks']}")
    for name, o in outputs.items():
        print(f"  [+] {name:<34} {human_size(o['bytes']):>10}  sha256 {o['sha256'][:16]}...")
    print(f"  [+] {os.path.basename(mpath)}")
    print(f"\n  status {result.validation_status.upper()} - reassembled from observed "
          f"structure, not validated against the recorder's own export.")
    if codec in ("h264", "h265"):
        print(f"  play:   ffplay {es_path}      (or: ffmpeg -f dhav -i {base}.dav "
              f"-c copy out.mp4)")
    return 0


def cmd_carve(args) -> int:
    """Carve DHAV streams from raw bytes, with no filesystem index.

    The fallback when an index is damaged or wiped, and the route to footage
    no index describes.  If a DHFS index is readable it is used only
    afterwards, to label each carved stream - never to find the frames - so
    the carve stands on its own and the two can be checked against each other.
    """
    from core.contract import dump_json
    from core.hashing import sha256_file
    from parsers import get_parser
    from recover import carver

    def num(v):
        return int(v, 0) if v else None

    os.makedirs(args.out, exist_ok=True)
    print(f"{BANNER} - indexless DHAV carve\n")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            start, end = num(args.start) or 0, num(args.end) or dev.size_bytes
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)})")
            print(f"  write-block   {info.write_block_method}")
            print(f"  region        0x{start:X} - 0x{end:X} ({human_size(end - start)})")

            def progress(done, total, live):
                print(f"    {done / total:6.1%}  {live} live streams", flush=True)

            labeler = None
            parser = get_parser("Dahua")
            if not args.no_index and parser.detect(dev):
                print("  index         DHFS found - used only to LABEL carved streams")
                parser.parse(dev)
                labeler = carver.IndexLabeler(parser.volumes) or None
            streams, stats = carver.carve(dev, start, end, progress=progress,
                                          labeler=labeler)
            xref = carver.label_streams(streams)
            kept = [s for s in streams if s.frames >= carver.MIN_FRAMES]

            want = {"none": set(), "all": {s.sid for s in kept},
                    "outside": {s.sid for s in kept
                                if xref.get(s.sid, {}).get("label") == "outside_index"}}[args.extract]
            outputs = {}
            for s in kept:
                if s.sid not in want:
                    continue
                base = os.path.join(args.out, f"carve-{s.sid:05d}")
                with open(base + ".dav", "wb") as dav, open(base + ".es", "wb") as es:
                    _, codec = carver.write_stream(dev, s, dav, es)
                es_path = base + (f".{codec}" if codec in ("h264", "h265") else ".es")
                os.replace(base + ".es", es_path)
                for path in (base + ".dav", es_path):
                    outputs[os.path.basename(path)] = {
                        "bytes": os.path.getsize(path), "sha256": sha256_file(path)}
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1

    report = carver.build_report(streams, stats, xref, info, labeler is not None,
                                 args.tz_offset, outputs)
    rows = report["streams"]
    path = os.path.join(args.out, "carve_report.json")
    dump_json(report, path)

    labels: dict = {}
    for r in rows:
        k = r["index_label"] or "no index"
        labels.setdefault(k, [0, 0])
        labels[k][0] += 1
        labels[k][1] += r["recording"]["frame_count"]
    print(f"\n--- carve {'-' * 49}")
    print(f"  frames        {stats['frames']:,} validated, {stats['joined_by_contiguity']:,} "
          f"joined by contiguity, {stats['joined_by_closest']:,} by clear closest match")
    print(f"  streams       {len(kept)} kept (>= {carver.MIN_FRAMES} frames); "
          f"{stats['ambiguous_splits']} ambiguous boundaries split, not guessed")
    for k, (n, f) in sorted(labels.items()):
        print(f"    {k:<16} {n:4d} streams  {f:>10,} frames")
    outside = [r for r in rows if r["index_label"] == "outside_index"]
    if outside:
        print(f"\n--- outside every index window ({len(outside)}) {'-' * 24}")
        for r in outside[:args.limit]:
            rec = r["recording"]
            print(f"  {rec['id']}  @0x{rec['offset']:<10X} {rec['frame_count']:6d} frames  "
                  f"{rec['timestamps'][0]['raw_value'].split(' = ', 1)[-1]}")
        if len(outside) > args.limit:
            print(f"  ... {len(outside) - args.limit} more in {path}")
    if outputs:
        total = sum(o["bytes"] for o in outputs.values())
        print(f"\n  [+] {len(outputs) // 2} streams written to {args.out} "
              f"({human_size(total)}); per-file SHA-256 in the report")
    print(f"\n[+] {path}")
    print("  status SPEC_ONLY - carved by stream continuity; not validated against a "
          "recorder export.")
    return 0


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
        return 0 if (v["valid"] and ok and _verify_preserved(out_dir, ledger)) else 1
    return 0 if v["valid"] else 1


def _verify_preserved(out_dir: str, ledger: CustodyLedger) -> bool:
    """Check a preserved-metadata bundle, if the case has one."""
    from core.hashing import sha256_file
    from recover.preserve import verify_bundle

    bundle = os.path.join(out_dir, "preserved")
    if not os.path.exists(os.path.join(bundle, "manifest.json")):
        return True
    r = verify_bundle(bundle)
    recorded = [e["data_hash"] for e in ledger.entries
                if e["action"] == "metadata_preserved"]
    in_ledger = bool(recorded) and \
        recorded[-1] == sha256_file(os.path.join(bundle, "manifest.json"))
    print(f"preserved     : {'OK' if r['ok'] else 'FAILED'} - {r['blocks']} blocks "
          f"({r['proven_to_root']} proven to the Merkle root), {r['regions']} regions")
    print(f"                manifest {'matches' if in_ledger else 'DOES NOT match'} "
          f"the custody ledger")
    for prob in r["problems"]:
        print(f"                [!] {prob}")
    return r["ok"] and in_ledger


def cmd_preserve(args) -> int:
    """Save every filesystem structure on the drive, tied to the acquisition.

    The drive's video is too large to keep; its metadata is a few megabytes
    and everything else rests on it.  See recover/preserve.py for why whole
    scan blocks are saved rather than just the structure bytes.
    """
    from core.hashing import sha256_file
    from recover import preserve

    blockmap = preserve.load_blockmap(args.out)
    if not blockmap:
        print(f"[!] no blockmap.jsonl in {args.out} - run `scan` first so the "
              f"preserved blocks can be tied to an acquisition hash")
        return 1
    bundle = os.path.join(args.out, "preserved")
    print(f"{BANNER} - metadata preservation\n")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            vendor = args.vendor
            if not vendor:
                vendor = "Dahua" if dev.read_at(0, 4) == b"DHFS" else ""
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)})")
            print(f"  write-block   {info.write_block_method}")
            print(f"  vendor        {vendor or 'unknown - generic head/tail only'}")
            m = preserve.preserve(dev, bundle, vendor=vendor, blockmap=blockmap)
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1

    print(f"\n--- regions {'-' * 47}")
    for r in m["regions"]:
        print(f"  {r['name']:<34} 0x{r['start']:>12X}  {human_size(r['length']):>10}")
    print(f"\n  blocks saved  {len(m['blocks'])}  ({human_size(m['bytes_saved'])})")
    match = m["all_blocks_match"]
    print(f"  vs scan       {'every block matches the acquisition hash' if match else 'MISMATCH - see notes'}")
    print(f"  merkle root   {m['acquisition_merkle_root'] or '(none - scan incomplete)'}")
    for n in m["notes"]:
        print(f"  [!] {n}")
    digest = sha256_file(os.path.join(bundle, "manifest.json"))
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
    ledger.append("metadata_preserved", {
        "bundle": "preserved/manifest.json", "vendor": vendor or "generic",
        "regions": len(m["regions"]), "blocks": len(m["blocks"]),
        "bytes_saved": m["bytes_saved"], "all_blocks_match": match,
        "write_block_method": info.write_block_method}, data_hash=digest)
    print(f"  manifest      {digest}  (recorded in the custody ledger)")
    return 0 if match else 1


def cmd_timeline(args) -> int:
    """Build the camera timeline from a case's parse and carve reports."""
    from analyse.timeline import ClockModel, build
    from core.contract import utc_now
    from core.hashing import sha256_file

    def load(*names):
        for n in names:
            path = os.path.join(args.out, n)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh), n
        return None, None

    parse_rep, pname = load("parse_dahua.json", "parse_hikvision.json")
    carve_rep, cname = load("carve/carve_report.json")
    if not parse_rep and not carve_rep:
        print(f"[!] nothing to build from in {args.out}: run `parse` and/or `scan --carve`")
        return 1
    clock = ClockModel.from_observation(args.tz_offset, args.clock_observed,
                                        args.clock_reference)
    t = build(parse_rep, carve_rep, clock)
    t["generated_utc"] = utc_now()
    t["inputs"] = {n: sha256_file(os.path.join(args.out, n)) for n in (pname, cname) if n}
    path = os.path.join(args.out, "timeline.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(t, fh, indent=2)

    print(f"{BANNER} - camera timeline\n")
    print(f"  clock         {t['clock']['rule']}")
    c = t["counts"]
    print(f"  events        {c['indexed']} indexed, {c['unindexed']} unindexed (carved), "
          f"{c['remnant']} remnant")
    for cam, v in t["cameras"].items():
        print(f"  {cam:<13} {v['recordings']:4d} files  {v['first_local']} -> "
              f"{v['last_local']}  {v['covered_s'] / 3600:7.1f} h  {v['gaps']} gap(s)")
    kinds: dict = {}
    for x in t["correlations"] + t["anomalies"]:
        kinds[x["kind"]] = kinds.get(x["kind"], 0) + 1
    for k, n in sorted(kinds.items()):
        print(f"  {k:<32} {n}")
    print(f"\n[+] {path}")
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("timeline_built", {"inputs": t["inputs"], "clock": t["clock"],
                                         "counts": c}, data_hash=sha256_file(path))
    return 0


def cmd_report(args) -> int:
    """Write the forensic report (HTML) and the case summary (JSON)."""
    from core.hashing import sha256_file
    from report.case import load_case
    from report.html import render

    case = load_case(args.out)
    if not case.get("scan"):
        print(f"[!] {args.out} has no completed scan - a report without a complete "
              f"acquisition would have no evidence hash to anchor it")
        return 1
    html_path = os.path.join(args.out, "report.html")
    json_path = os.path.join(args.out, "report.json")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render(case, args.notes))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(case, fh, indent=2, default=str)
    hh, jh = sha256_file(html_path), sha256_file(json_path)
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    ledger.actor = ledger.entries[0].get("actor", "unknown")
    ledger.case_id = ledger.entries[0].get("case_id", "")
    ledger.append("report_generated", {"html": "report.html", "html_sha256": hh,
                                       "json": "report.json", "json_sha256": jh},
                  data_hash=hh)
    print(f"{BANNER} - report\n")
    print(f"  [+] {html_path}\n      sha256 {hh}")
    print(f"  [+] {json_path}\n      sha256 {jh}")
    print("  both hashes recorded in the custody ledger")
    return 0


def cmd_serve(args) -> int:
    """Start the local web UI (loopback only, read-only viewer)."""
    from ui.server import serve
    serve(args.out, args.port)
    return 0


def cmd_writeblock_rule(args) -> int:
    """Print a udev rule that keeps one drive write-blocked across reconnects."""
    from acquire.device import udev_properties, udev_writeblock_rule

    serial = args.serial
    if not serial and args.device:
        serial = udev_properties(args.device).get("ID_SERIAL_SHORT", "")
        if not serial:
            print(f"[!] udev reports no drive serial for {args.device} - pass --serial")
            return 1
    try:
        rule = udev_writeblock_rule(serial, args.user)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1
    print(rule, end="")
    print(f"\n# install (runtime only, cleared at reboot):\n"
          f"#   sudo mkdir -p /run/udev/rules.d\n"
          f"#   python cli.py writeblock-rule --serial {serial}"
          f"{' --user ' + args.user if args.user else ''} | "
          f"sudo tee /run/udev/rules.d/70-ps26150-writeblock-{serial}.rules\n"
          f"#   sudo udevadm control --reload\n"
          f"#   sudo udevadm test /sys/block/<name> 2>&1 | grep setro   # confirm it matches")
    return 0


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
    p.add_argument("--carve", action="store_true",
                   help="also carve DHAV streams in the same pass (no second read)")
    p.add_argument("--tz-offset", type=int, default=None,
                   help="recorder zone in minutes east of UTC, for carved timestamps")
    p.add_argument("--reconnect-wait", type=float, default=30,
                   help="minutes to wait for a drive that drops off USB to come back "
                        "write-blocked and verified (0 = fail at once)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("parse", help="parse a vendor filesystem into recordings")
    p.add_argument("--device", required=True)
    p.add_argument("--vendor", default="Hikvision")
    p.add_argument("--out", default="",
                   help="scan output dir: reads offset hints, writes the parse")
    p.add_argument("--limit", type=int, default=25,
                   help="recordings to print (default 25)")
    p.add_argument("--tz-offset", type=int, default=None,
                   help="recorder's UTC offset in minutes, read off the DVR's own "
                        "settings (e.g. 330 for IST); without it times stay "
                        "recorder-local")
    p.add_argument("--remnants", action="store_true",
                   help="also list older footage surviving in reused clusters "
                        "(reads every indexed cluster in the image)")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("extract", help="reassemble one recording into playable files")
    p.add_argument("--device", required=True)
    p.add_argument("--vendor", default="Dahua")
    p.add_argument("--recording", required=True, help="recording id from `parse`")
    p.add_argument("--out", required=True, help="output directory (never the device)")
    p.add_argument("--tz-offset", type=int, default=None)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("carve", help="carve DHAV streams with no filesystem index")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="output directory (never the device)")
    p.add_argument("--start", default="", help="region start in bytes (0x.. ok)")
    p.add_argument("--end", default="", help="region end in bytes (0x.. ok)")
    p.add_argument("--extract", choices=["none", "outside", "all"], default="none",
                   help="write carved streams out: none, only those outside every "
                        "index window, or all")
    p.add_argument("--no-index", action="store_true",
                   help="do not use a DHFS index even to label streams")
    p.add_argument("--tz-offset", type=int, default=None)
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=cmd_carve)

    p = sub.add_parser("preserve", help="save all filesystem metadata, tied to the scan")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="case directory holding the scan")
    p.add_argument("--vendor", default="", help="default: detect from the superblock")
    p.set_defaults(func=cmd_preserve)

    p = sub.add_parser("timeline", help="normalize timestamps and correlate cameras")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--tz-offset", type=int, default=None,
                   help="recorder zone, minutes east of UTC (IST = 330); omit if unknown")
    p.add_argument("--clock-observed", default="",
                   help="what the DVR displayed at seizure, 'YYYY-MM-DD HH:MM:SS'")
    p.add_argument("--clock-reference", default="",
                   help="trusted time at that same instant, same zone")
    p.set_defaults(func=cmd_timeline)

    p = sub.add_parser("report", help="write the forensic report (HTML + JSON)")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--notes", default="", help="examiner notes to include")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("serve", help="local web UI over the case directories")
    p.add_argument("--out", default="out", help="directory holding case folders")
    p.add_argument("--port", type=int, default=8150)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("writeblock-rule",
                       help="print a udev rule that write-blocks a drive across reconnects")
    p.add_argument("--serial", default="", help="drive serial (ID_SERIAL_SHORT)")
    p.add_argument("--device", default="", help="or read the serial from this node")
    p.add_argument("--user", default="", help="also grant this user READ-only access")
    p.set_defaults(func=cmd_writeblock_rule)

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

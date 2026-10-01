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
    drives = list_physical_drives(args.max_index)
    if not drives:
        print("No physical drives enumerated.")
        return 1
    system = set()
    if not is_win:
        from acquire.device import mounted_disks
        system = mounted_disks()
    if not is_admin():
        readable = [d["path"] for d in drives if d.get("path") not in system
                    and not is_win and os.access(d["path"], os.R_OK)]
        if readable:
            print(f"   Not {privilege}; readable through an ACL: {', '.join(readable)}\n")
        else:
            print(f"!! Not running as {privilege}. Raw device reads will be denied.")
            print(f"   {'Relaunch elevated' if is_win else 'Re-run under sudo, or grant a read-only ACL (writeblock-rule --user)'} to acquire.\n")
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
        if d["path"] in system:
            wb = "system"                  # holds a mounted filesystem: this workstation
        elif "read_only" in d:
            wb = "RO(kernel)" if d["read_only"] else "RW !!"
        else:
            wb = "handle"
        print(f"{d['index']:<4} {d['path']:<20} {human_size(d['size_bytes']):>10}  "
              f"{d['bus_type']:<6} {d['sector_size']:>5} {wb:<8} "
              f"{d['model']} {('/ ' + d['serial']) if d['serial'] else ''}")

    if any(d.get("read_only") is False and d.get("bus_type") == "USB"
           and d["path"] not in system for d in drives):
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

    wanted = [("carve", {"tz_offset_min": args.tz_offset}) if args.carve else None,
              ("activity", {}) if args.activity else None,
              ("carve_ps", {}) if args.carve_ps else None,
              ("carve_annexb", {}) if args.carve_annexb else None]
    wanted = [w for w in wanted if w]
    from acquire.parallel import TAPS, ProcessTap, _resolve
    # Each tap in its own process unless told otherwise: same code, same
    # output, and the taps stop waiting for each other (docs/PERFORMANCE.md).
    parallel = not args.no_parallel and (os.cpu_count() or 1) > 1 and len(wanted) > 0
    taps = [ProcessTap(TAPS[n], **kw) if parallel else _resolve(TAPS[n])(**kw)
            for n, kw in wanted]
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
    _auto_sign(out_dir, "acquisition completed")
    return 0


# ---------------------------------------------------------------------------
# Examiner signatures (core/signing.py, acquire/signatures.py).  Optional: they
# need the `cryptography` package and an examiner key; without either, every
# command runs exactly as before.
# ---------------------------------------------------------------------------
def _auto_sign(out_dir: str, reason: str) -> None:
    """Sign the case if the examiner has a key that opens without asking."""
    from core import signing
    if not signing.available() or not os.path.exists(signing.key_path()):
        return
    from acquire.signatures import sign_case
    try:
        r = sign_case(out_dir, signing.load_signer(), reason=reason)
    except signing.SigningError as exc:
        print(f"  [i] not signed: {exc}")
        print(f"      sign by hand: cli.py sign --out {out_dir}")
        return
    st = r["statement"]
    print(f"  signed        by {st['signer']['name'] or 'this key'} (key {st['signer']['key_id']}), "
          f"{len(st['files'])} files -> {r['file']}")


def _ask_passphrase(confirm: bool) -> str:
    import getpass
    while True:
        first = getpass.getpass("  passphrase: ")
        if not confirm or first == getpass.getpass("  repeat    : "):
            return first
        print("  they do not match - again")


def cmd_keygen(args) -> int:
    """Make (or show) this examiner's RSA signing key."""
    from core import signing
    path = args.key or signing.key_path()
    if args.show:
        try:
            with open(signing.public_path(path), "r", encoding="utf-8") as fh:
                pem = fh.read()
        except OSError:
            print(f"  [!] no public key at {signing.public_path(path)}")
            return 1
        fp = signing.fingerprint(pem)
        print(f"  key id       {signing.key_id(fp)}\n  fingerprint  {fp}\n\n{pem}")
        return 0
    if not args.name:
        print("  [!] --name is required: the examiner the key belongs to")
        return 2
    passphrase = ""
    if args.passphrase_stdin:
        passphrase = sys.stdin.readline().rstrip("\r\n")
    elif not args.no_passphrase:
        print("  A passphrase protects the key file if it is copied. Leave it empty to")
        print("  let scans and reports sign by themselves without asking.")
        passphrase = _ask_passphrase(confirm=True)
    try:
        k = signing.generate(args.name, path, passphrase)
    except signing.SigningError as exc:
        print(f"  [!] {exc}")
        return 1
    print(f"{BANNER} - examiner signing key\n")
    print(f"  examiner     {k['name']}")
    print(f"  algorithm    {k['algorithm']}, {k['bits']}-bit")
    print(f"  key id       {k['key_id']}")
    print(f"  fingerprint  {k['fingerprint']}")
    print(f"  private key  {k['path']}   (keep it; back it up; never share it)")
    print(f"  public key   {k['public_path']}   (give this to whoever verifies)")
    print("\n  Publish the fingerprint where a verifier can find it independently -")
    print("  a key carried inside a signed file proves integrity, not identity.")
    return 0


def cmd_sign(args) -> int:
    """Sign the case as it stands, and record that in the custody ledger."""
    from acquire.signatures import sign_case
    from core import signing
    try:
        try:
            signer = signing.load_signer(args.key)
        except signing.SigningError as exc:
            if "passphrase" not in str(exc) or not sys.stdin.isatty():
                raise
            signer = signing.load_signer(args.key, _ask_passphrase(confirm=False))
        r = sign_case(args.out, signer, reason=args.reason)
    except signing.SigningError as exc:
        print(f"  [!] {exc}")
        return 1
    st = r["statement"]
    print(f"{BANNER} - case signed\n")
    print(f"  signer       {st['signer']['name'] or '-'}  (key {st['signer']['key_id']})")
    print(f"  covers       {len(st['files'])} files, custody ledger to entry "
          f"{st['ledger']['entries']}, acquisition hashes and Merkle root")
    print(f"  [+] {r['path']}\n  recorded in the custody ledger")
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

    reg = session.regions
    if reg:
        c = reg["counts"]
        print(f"\n--- high entropy without video structure (regions.json) ------")
        print(f"  blocks        {c['video']} video, {c['structured']} structured, "
              f"{c['empty']} empty, {c['container_without_video']} container without video, "
              f"{c['unstructured']} unstructured")
        print(f"  verdict       {reg['verdict']}")
        for r in reg["regions"][:5]:
            print(f"  @ 0x{r['offset']:X}  {human_size(r['length'])}  {r['kind']}")
        if len(reg["regions"]) > 5:
            print(f"  ... {len(reg['regions']) - 5} more in regions.json")

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
            elif getattr(args, "remnants", False) and hasattr(parser, "recover_video_area"):
                print("  video area    walking frame headers, no index needed ...")
                remnants = parser.recover_video_area(dev)
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
    elif getattr(args, "remnants", False) and hasattr(parser, "video_area_stats"):
        vs = parser.video_area_stats
        print(f"\n--- footage found by frame headers ({len(remnants)}) {'-' * 24}")
        print(f"  {vs['frames']} frames in {vs['runs']} chunk(s); {vs['padding_skips']} "
              f"padding skip(s). One run per chunk, camera unknown: frame headers carry "
              f"no channel")
        for rec in remnants[:args.limit]:
            print(f"  {rec.id}  @0x{rec.offset:<10X} {human_size(rec.length):>10s}  "
                  f"{rec.frame_count:5d} frames  {_when(rec)}")
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
        ledger_path = os.path.join(args.out, "custody_ledger.jsonl")
        if os.path.exists(ledger_path):
            from core.hashing import sha256_file
            ledger = CustodyLedger(ledger_path)
            ledger.actor = ledger.entries[0].get("actor", "unknown")
            ledger.case_id = ledger.entries[0].get("case_id", "")
            ledger.append("filesystem_parsed", {
                "report": os.path.basename(path), "vendor": result.vendor,
                "recordings": len(result.recordings), "remnants": len(remnants),
                "validation_status": result.validation_status,
                "write_block_method": info.write_block_method},
                data_hash=sha256_file(path))
    return 0


def _when(rec) -> str:
    """UTC when the parser could establish it; otherwise the recorder's own
    clock, labelled as such - never a local time passed off as UTC."""
    if rec.start_utc:
        return rec.start_utc
    if rec.timestamps:
        return rec.timestamps[0].raw_value.split(" = ", 1)[-1]
    return "no timestamp"


def _extract_with_plugin(args, plugin) -> int:
    """A plugin's own reassembly (e.g. Honeywell): playable video plus a
    manifest with its hash, the parse's status, and what the plugin measured."""
    from core.contract import SCHEMA_VERSION, dump_json, utc_now
    from parsers.base import ExtractRefused

    os.makedirs(args.out, exist_ok=True)
    if getattr(args, "tz_offset", None) is not None and hasattr(plugin, "tz_offset_min"):
        plugin.tz_offset_min = args.tz_offset
    print(f"{BANNER} - {args.vendor} extract {args.recording}\n")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            result = plugin.parse(dev)
            stats = plugin.extract_recording(dev, args.recording,
                                             os.path.join(args.out, args.recording))
    except KeyError:
        print(f"[!] no recording {args.recording!r}. Run `parse --vendor {args.vendor}` "
              f"to list recording ids.")
        return 1
    except ExtractRefused as exc:
        print(f"[!] {args.recording} not extracted: {exc}")
        return 1
    except (PermissionNeeded, DeviceError) as exc:
        print(f"[!] {exc}")
        return 1
    manifest = {"schema_version": SCHEMA_VERSION, "generated_utc": utc_now(),
                "tool": "ps26150-forensics extract", "vendor": args.vendor,
                "source_device": info.path, "write_block_method": info.write_block_method,
                "parser_rule": plugin.parser_rule, "validation_status": result.validation_status,
                "recording": args.recording, "output": stats}
    mpath = os.path.join(args.out, args.recording + ".manifest.json")
    dump_json(manifest, mpath)
    print(f"  [+] {stats['file']}  {human_size(stats['bytes'])}  {stats['frames']} frames  "
          f"sha256 {stats['sha256'][:16]}...")
    if stats.get("first_time_local"):
        print(f"  span          {stats['first_time_local']} -> {stats.get('last_time_local')} "
              f"(recorder-local)")
        if stats.get("first_time_utc"):
            print(f"  span (UTC)    {stats['first_time_utc']} -> {stats.get('last_time_utc')} "
                  f"(zone as stated; clock error not measured)")
    else:
        print(f"  span          {stats.get('first_time_utc')} -> {stats.get('last_time_utc')} "
              f"(recorder clock, zone not established)")
    print(f"  [+] {os.path.basename(mpath)}")
    print(f"\n  status {result.validation_status.upper()}")
    return 0


def cmd_extract(args) -> int:
    """Reassemble recordings into playable files, each with a hashed manifest.

    Output goes to --out, never to the device.  Two files per recording: the
    DHAV stream as stored (`.dav`, which ffmpeg's dhav demuxer reads) and the
    bare video elementary stream (`.h265`/`.h264`, playable directly).  The
    manifest records every cluster read, its hash, and what was left out.
    Several recording ids may be given: the disk is parsed once and each is
    reassembled in turn - over USB a whole-drive parse takes minutes, too long
    to repeat for every hour of footage.
    """
    from parsers import dahua, get_parser

    ids = list(args.recording) if isinstance(args.recording, (list, tuple)) else [args.recording]
    if args.vendor != "Dahua":
        plugin = get_parser(args.vendor)
        if plugin is not None and hasattr(plugin, "extract_recording"):
            rc = 0
            for rid in ids:
                rc = _extract_with_plugin(argparse.Namespace(**{**vars(args), "recording": rid}),
                                          plugin) or rc
            return rc
        print(f"[!] extract is implemented for Dahua DHFS and plugins that offer it; "
              f"{args.vendor!r} recordings can be listed with `parse` but not reassembled yet.")
        return 1
    parser = get_parser(args.vendor)
    if args.tz_offset is not None:
        parser.tz_offset_min = args.tz_offset
    os.makedirs(args.out, exist_ok=True)
    print(f"{BANNER} - {args.vendor} extract "
          f"{' '.join(ids) if len(ids) <= 3 else f'{len(ids)} recordings'}\n")
    failed = 0
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)})")
            print(f"  write-block   {info.write_block_method}")
            result = parser.parse(dev)
            for k, rid in enumerate(ids):
                if len(ids) > 1:
                    print(f"\n=== {k + 1}/{len(ids)}  {rid} ===")
                vol, f = parser.file_for(rid)
                if f is None:
                    print(f"[!] no recording {rid!r}. Run `parse --vendor "
                          f"Dahua` to list recording ids.")
                    failed += 1
                    continue
                rec = next(r for r in result.recordings if r.id == rid)
                base = os.path.join(args.out, rid)
                print(f"  recording     {rec.camera_id}  {_when(rec)}  "
                      f"{len(f.clusters)} clusters")
                print("  reassembling  ...")
                with open(base + ".dav", "wb") as dav, open(base + ".es", "wb") as es:
                    stats = dahua.reassemble(dev, vol, f, dav, es)
                _extract_outputs(base, info, parser, result, rec, vol, f, stats)
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1
    return 1 if failed else 0


def _extract_outputs(base, info, parser, result, rec, vol, f, stats) -> None:
    """One reassembled recording: the stream renamed by its codec, both files
    hashed into its manifest, and the summary printed."""
    from core.contract import SCHEMA_VERSION, dump_json, to_dict, utc_now
    from core.hashing import sha256_file

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
            f"{stats['video_counter_missing']} video frames with no intact copy on the "
            f"disk (counter gaps; not interpolated)",
        ],
    }
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
          f"({(miss / span if span else 0):.2%}) - no intact copy on the disk, "
          f"not interpolated")
    if stats.get("boundary_joined"):
        print(f"  rejoined      {stats['boundary_joined']} frames cut at a cluster end and "
              f"finished in the next chain cluster (both halves listed in the manifest)")
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
    seal = ledger.verify_seal()
    print(f"custody seal  : {seal['message']}")
    chain_ok = v["valid"] and seal["valid"] and _verify_signatures(out_dir, args.trust)

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
        return 0 if (chain_ok and ok and _verify_preserved(out_dir, ledger)) else 1
    return 0 if chain_ok else 1


def _verify_signatures(out_dir: str, trust: Optional[list] = None) -> bool:
    """Check the examiner signatures, if the case has any."""
    from acquire.signatures import verify_case
    r = verify_case(out_dir, trust or [])
    print(f"signatures    : {r['message']}")
    for s in r.get("signatures", []):
        state = "valid" if s.get("valid") else "FAILED"
        trust_txt = ("trusted: " + os.path.basename(s["trusted_as"]) if s.get("trusted")
                     else "key NOT in your trusted keys - compare its fingerprint "
                          "with the examiner's" if s.get("trusted") is False
                     else "no trusted keys given (--trust)")
        print(f"                {s['file']}: {state}, {s.get('signer') or 'unnamed'} "
              f"(key {s.get('key_id', '?')}), {trust_txt}")
        if s.get("unsigned_newer"):
            print(f"                newer, not yet signed: {', '.join(s['unsigned_newer'])}")
    return r["valid"]


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
            # Surviving Hikvision structures the scan found (e.g. under a later
            # reformat): the master sector copy and the index region.
            extra = []
            sr = os.path.join(args.out, "scan_report.json")
            if os.path.exists(sr):
                with open(sr, "r", encoding="utf-8") as fh:
                    hits = json.load(fh).get("signature_hits", [])
                for h in hits:
                    if h["signature_id"] == "hik.master":
                        extra.append(preserve.Region(f"hikvision_master_0x{h['offset']:X}",
                                                     h["offset"] - 0x10, h["offset"] - 0x10 + 512,
                                                     "Hikvision master sector copy"))
                    elif h["signature_id"] == "hik.btree":
                        extra.append(preserve.Region(f"hikvision_hikbtree_0x{h['offset']:X}",
                                                     h["offset"] - 0x10000, h["offset"] + (4 << 20),
                                                     "Hikvision HIKBTREE header and its pages"))
            if extra:
                print(f"  hikvision     {len(extra)} surviving structure(s) added")
            m = preserve.preserve(dev, bundle, vendor=vendor, blockmap=blockmap, extra=extra)
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
    from report.case import parse_report_names

    def load(*names):
        for n in names:
            path = os.path.join(args.out, n)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh), n
        return None, None

    parse_rep, pname = load(*parse_report_names(args.out))
    carve_rep, cname = load("carve/carve_report.json")
    ps_rep, psname = load("carve/ps_report.json")
    ps_lab, plname = load("carve/ps_labels.json")
    if ps_rep and ps_lab:
        lab = {x["id"]: x["label"] for x in ps_lab["streams"]}
        for row in ps_rep["streams"]:
            row["index_label"] = lab.get(row["id"])
    if not parse_rep and not carve_rep and not ps_rep:
        print(f"[!] nothing to build from in {args.out}: run `parse` and/or `scan --carve`")
        return 1
    clock = ClockModel.from_observation(args.tz_offset, args.clock_observed,
                                        args.clock_reference)
    hik_idx, hname = load("carve/hik_index.json")
    rlog, rname = load("hik_log.json")
    t = build(parse_rep, carve_rep, clock, ps_report=ps_rep, hik_index=hik_idx,
              recorder_log=rlog)
    t["generated_utc"] = utc_now()
    t["inputs"] = {n: sha256_file(os.path.join(args.out, n))
                   for n in (pname, cname, psname, plname, hname, rname) if n}
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
    for cam, v in (t.get("index_coverage") or {}).items():
        print(f"  {cam:<13} index: recorded {v['recorded_s'] / 3600:6.1f} h in {v['blocks']} "
              f"blocks; recovered {v['recovered_share']:.1%}")
    if "power_cuts" in c:
        print(f"  recorder log  {c['recorder_events']} power/user events; "
              f"{c['power_cuts']} silence(s) on every camera explained by a logged power "
              f"cut, {c['silences_not_in_log']} not in the log")
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


def cmd_seal(args) -> int:
    """Seal case files for one recipient: AES-256-GCM, RSA-OAEP, signed."""
    from acquire import sealed
    from core import signing
    from core.contract import utc_now as _now
    from core.hashing import sha256_file
    try:
        with open(args.to, "r", encoding="utf-8") as fh:
            recipient_pem = fh.read()
        signer = None
        if not args.unsigned:
            try:
                signer = signing.load_signer(args.key)
            except signing.SigningError as exc:
                if "passphrase" not in str(exc) or not sys.stdin.isatty():
                    raise
                signer = signing.load_signer(args.key, _ask_passphrase(confirm=False))
        files = [] if args.only else sealed.default_selection(args.out)
        files += [f for f in (args.include or []) if f not in files]
        rkid = signing.key_id(signing.fingerprint(recipient_pem))
        dest = args.dest or os.path.join(
            args.out, "sealed",
            f"{os.path.basename(os.path.abspath(args.out))}_for_{rkid}_"
            f"{_now().replace(':', '').replace('-', '')[:15]}.adseal")
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        ledger = _case_ledger(args.out)
        r = sealed.seal(args.out, files, recipient_pem, dest, signer=signer,
                        case_id=(ledger.case_id if ledger else ""), note=args.note)
    except (OSError, signing.SigningError, sealed.SealError) as exc:
        print(f"  [!] {exc}")
        return 1
    if ledger:
        ledger.append("evidence_sealed", {
            "package": os.path.relpath(r["path"], args.out).replace(os.sep, "/"),
            "recipient_key_id": rkid,
            "recipient_fingerprint": r["header"]["recipient"]["fingerprint"],
            "signed_by": signer.key_id if signer else "", "note": args.note,
            "files": [{"path": m["path"], "sha256": m["sha256"]} for m in r["header"]["manifest"]],
        }, data_hash=r["sha256"])
    print(f"{BANNER} - evidence sealed\n")
    print(f"  for          key {rkid} only (RSA-OAEP), contents AES-256-GCM")
    print(f"  sealed by    {(signer.name or signer.key_id) if signer else 'nobody - unsigned'}")
    print(f"  files        {len(r['header']['manifest'])}")
    print(f"  [+] {r['path']}\n      sha256 {r['sha256']}")
    if ledger:
        print("  recorded in the custody ledger")
    return 0


def cmd_unseal(args) -> int:
    """Open a sealed package - all of it, verified, or nothing - or just inspect it."""
    from acquire import sealed
    from core import signing
    try:
        if args.info:
            i = sealed.inspect(args.package, args.trust)
            h = i["header"]
            s = h.get("sender") or {}
            print(f"{BANNER} - sealed package\n")
            print(f"  for          key {h['recipient']['key_id']}")
            print(f"  sealed by    {s.get('name') or '-'} (key {s.get('key_id', '-')}), "
                  f"signature {'valid' if i['signature_valid'] else 'NOT valid' if i['signed'] else 'absent'}"
                  + ("" if i["sender_trusted"] is None else
                     ", trusted" if i["sender_trusted"] else ", key NOT in your trusted keys"))
            print(f"  sealed       {h.get('created_utc', '')}  case {h.get('case_id') or '-'}")
            print(f"  contents     {'intact' if i['ciphertext_intact'] else 'CHANGED'}, "
                  f"{len(i['files'])} files")
            for f in i["files"]:
                print(f"               {f['path']}  {f['bytes']:,} B  {f['sha256'][:16]}...")
            return 0 if i["ciphertext_intact"] and i["signature_valid"] is not False else 1
        if not args.dest:
            print("  [!] --dest is required: a new or empty folder to open the package into")
            return 2
        passphrase = None
        if sys.stdin.isatty() and not os.environ.get(signing.PASSPHRASE_ENV):
            try:
                signing.load_signer(args.key)
            except signing.SigningError as exc:
                if "passphrase" in str(exc):
                    passphrase = _ask_passphrase(confirm=False)
        r = sealed.unseal(args.package, args.key, args.dest, passphrase=passphrase,
                          trusted_paths=args.trust, allow_unsigned=args.allow_unsigned)
    except (OSError, signing.SigningError, sealed.SealError) as exc:
        print(f"  [!] {exc}")
        return 1
    s = r["info"]["header"].get("sender") or {}
    print(f"{BANNER} - package opened\n")
    print(f"  sealed by    {s.get('name') or '-'} (key {s.get('key_id', '-')})"
          + ("" if r["info"]["sender_trusted"] is None else
             ", trusted" if r["info"]["sender_trusted"] else
             " - key NOT in your trusted keys: compare its fingerprint with the sender's"))
    print(f"  checked      signature, AES-GCM authentication, and the SHA-256 of all "
          f"{len(r['files'])} files")
    print(f"  [+] {r['dest']}")
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
    _auto_sign(args.out, "report generated")
    return 0


def cmd_serve(args) -> int:
    """Start the local web UI (loopback only, read-only viewer)."""
    from viewer.server import serve
    try:
        serve(args.out, args.port, require_access=args.require_access,
              access_dir=args.access_dir, allow_signup=not args.no_signup,
              access_store=args.access_store, supabase_env=args.supabase_env,
              cookie_secure=args.cookie_secure, trust_proxy=args.trust_proxy)
    except Exception as exc:                               # noqa: BLE001
        from access.store import StoreError   # imported only if the gate was asked for
        if isinstance(exc, StoreError):
            raise SystemExit(f"  [!] access store: {exc}")
        raise
    return 0


# ---------------------------------------------------------------------------
# Temporary access control (access/).  These commands are the only way to make
# an administrator: an account that can approve requests is never created over
# HTTP, so an attacker who can reach the sign-up form cannot mint one.
# ---------------------------------------------------------------------------
def _access(args):
    from access.service import open_control
    from access.store import StoreError

    directory = args.access_dir or os.path.join(args.out, ".access")
    try:
        return open_control(directory, args.access_store, args.supabase_env)
    except StoreError as exc:           # includes missing Supabase credentials
        raise SystemExit(f"  [!] access store: {exc}")


def _ask_password(confirm: bool = True, from_stdin: bool = False) -> str:
    """Read a password without echoing it. Never taken from the argv.

    `--password-stdin` exists because getpass cannot be scripted on Windows:
    win_getpass reads the console device directly, so a piped password is
    ignored and the prompt blocks forever waiting for a keystroke that will
    never come.  Reading the first line of stdin instead makes setup
    automatable without ever putting the password in a command line, where it
    would land in the shell history and in every process listing.
    """
    import getpass

    if from_stdin:
        line = sys.stdin.readline()
        if not line:
            raise SystemExit("  [!] --password-stdin given but stdin was empty")
        return line.rstrip("\r\n")

    while True:
        first = getpass.getpass("  password: ")
        if not confirm:
            return first
        if first == getpass.getpass("  repeat  : "):
            return first
        print("  they do not match - again")


def cmd_access_admin(args) -> int:
    """Create an administrator, or promote an existing account to one."""
    ac = _access(args)
    name = args.username.strip().lower()
    existing = ac.store.user_by_name(name)
    if existing:
        r = ac.set_role(name, "admin", actor="cli")
        print(f"  {'[+]' if r.ok else '[!]'} {r.message}")
        if r.ok and args.password_too:
            p = ac.set_password(name, _ask_password(
                from_stdin=args.password_stdin), actor="cli")
            print(f"  {'[+]' if p.ok else '[!]'} {p.message}")
        return 0 if r.ok else 1
    r = ac.create_user(name, _ask_password(from_stdin=args.password_stdin),
                       role="admin", actor="cli")
    print(f"  {'[+]' if r.ok else '[!]'} {r.message}")
    if r.ok:
        print(f"      {name} may now approve requests at /admin")
    return 0 if r.ok else 1


def cmd_access_user(args) -> int:
    """List accounts, or add / disable / enable one, or set a password."""
    ac = _access(args)
    if args.action == "list":
        users = ac.store.list_users()
        if not users:
            print("  no accounts yet")
            return 0
        print(f"  {'USER':<20} {'ROLE':<6} {'STATE':<9} LAST SIGN-IN")
        for u in users:
            state = "disabled" if u["disabled"] else "enabled"
            print(f"  {u['username']:<20} {u['role']:<6} {state:<9} "
                  f"{u['last_login_utc'] or 'never'}")
        return 0

    if not args.username:
        print("  [!] --username is required for that action")
        return 2
    name = args.username.strip().lower()

    if args.action == "add":
        r = ac.create_user(name, _ask_password(from_stdin=args.password_stdin),
                           role="user", actor="cli")
    elif args.action == "passwd":
        r = ac.set_password(name, _ask_password(from_stdin=args.password_stdin),
                            actor="cli")
    elif args.action == "disable":
        r = ac.set_disabled(name, True, actor="cli")
    elif args.action == "enable":
        r = ac.set_disabled(name, False, actor="cli")
    else:
        print("  [!] unknown action")
        return 2
    print(f"  {'[+]' if r.ok else '[!]'} {r.message}")
    return 0 if r.ok else 1


def cmd_access_request(args) -> int:
    """List access requests, or decide one without opening a browser."""
    ac = _access(args)
    if args.action == "list":
        rows = ac.pending() if args.pending_only else ac.recent(args.limit)
        if not rows:
            print("  nothing to show")
            return 0
        print(f"  {'REQUEST':<11} {'USER':<16} {'STATE':<9} "
              f"{'DECIDED BY':<14} ACCESS UNTIL")
        for r in rows:
            print(f"  {r['public_id']:<11} {r['username']:<16} "
                  f"{r['status']:<9} {(r['decided_by'] or '-'):<14} "
                  f"{r['access_expires_utc'] or '-'}")
        return 0

    if not args.id:
        print("  [!] --id <9 digits> is required for that action")
        return 2
    who = args.admin or "cli"
    if args.action == "approve":
        r = ac.approve(args.id, who, args.note)
    elif args.action == "reject":
        r = ac.reject(args.id, who, args.note)
    elif args.action == "revoke":
        r = ac.revoke(args.id, who, args.note)
    else:
        print("  [!] unknown action")
        return 2
    print(f"  {'[+]' if r.ok else '[!]'} {r.message}")
    return 0 if r.ok else 1


def cmd_access_audit(args) -> int:
    """Print the access audit log and verify its hash chain."""
    ac = _access(args)
    entries = ac.audit.recent(args.limit)
    for e in reversed(entries):
        detail = json.dumps(e.get("detail") or {}, sort_keys=True)
        print(f"  {e['ts_utc']}  {e['actor']:<14} {e['action']:<26} {detail}")
    v = ac.audit.verify()
    print(f"\n  entries : {len(ac.audit.entries)}")
    print(f"  chain   : {v['message']}")
    if not v["valid"]:
        print(f"  BROKEN at seq {v.get('broken_at_seq')}: {v.get('reason')}")
    return 0 if v["valid"] else 1


def cmd_writeblock_rule(args) -> int:
    """Print a udev rule that keeps one drive write-blocked across reconnects."""
    from acquire.device import (udev_properties, udev_writeblock_rule,
                                usb_ids_of_mounted_disks)

    serial = args.serial
    if not serial and args.device and not args.usb_id:
        serial = udev_properties(args.device).get("ID_SERIAL_SHORT", "")
        if not serial:
            print(f"[!] udev reports no drive serial for {args.device} - pass --serial, "
                  f"or --usb-id to cover every disk behind the evidence adapter")
            return 1
    if args.usb_id and args.usb_id.lower() in usb_ids_of_mounted_disks():
        print(f"[!] refusing: USB adapter {args.usb_id} holds a MOUNTED filesystem on this "
              f"workstation - a rule for it would make the workstation's own disk read-only")
        return 1
    try:
        rule = udev_writeblock_rule(serial, args.user, args.usb_id)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1
    key = serial or args.usb_id.replace(":", "-")
    flag = f"--serial {serial}" if serial else f"--usb-id {args.usb_id}"
    print(rule, end="")
    print(f"\n# install (runtime only, cleared at reboot):\n"
          f"#   sudo mkdir -p /run/udev/rules.d\n"
          f"#   python cli.py writeblock-rule {flag}"
          f"{' --user ' + args.user if args.user else ''} | "
          f"sudo tee /run/udev/rules.d/70-ps26150-writeblock-{key}.rules\n"
          f"#   sudo udevadm control --reload\n"
          f"#   sudo udevadm test /sys/block/<name> 2>&1 | grep setro   # confirm it matches")
    return 0


def _has_dhav_streams(out: str) -> bool:
    path = os.path.join(out, "carve", "carve_report.json")
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        return bool(json.load(fh).get("streams"))


def _extract_ps(args) -> int:
    """Save carved MPEG-PS streams unmodified as playable .ps files."""
    import shutil
    from acquire.device import DeviceLost
    from core.hashing import sha256_file
    from recover import pscarve

    rpath = os.path.join(args.out, "carve", "ps_report.json")
    if not os.path.exists(rpath):
        print(f"[!] no MPEG-PS carve report in {args.out} - run `scan --carve-ps` first")
        return 1
    with open(rpath, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    rows = report["streams"]
    if args.ids:
        want = set(args.ids.split(","))
        rows = [r for r in rows if r["id"] in want]
    need = sum(r["bytes"] for r in rows)
    out_dir = os.path.join(args.out, "carve", "ps_streams")
    os.makedirs(out_dir, exist_ok=True)
    free = shutil.disk_usage(out_dir).free
    print(f"{BANNER} - extract carved MPEG-PS streams\n")
    print(f"  selected      {len(rows)} stream(s){', ids ' + args.ids if args.ids else ''}")
    print(f"  size          {human_size(need)}; {human_size(free)} free")
    if need > free - (5 << 30):
        print("[!] not enough free space (keeping 5 GB spare) - narrow the selection with --ids")
        return 1
    manifest_path = os.path.join(args.out, "carve", "ps_extracted.json")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"  device        {dev.path}  ({info.write_block_method})\n")
            if dev.size_bytes != report.get("source_bytes"):
                print(f"[!] {dev.path} is not the size of the carved device - wrong drive?")
                return 1
            m = pscarve.extract(dev, rows, out_dir, manifest_path)
    except DeviceLost as exc:
        print(f"\n[!] {exc}\n    finished streams are kept; re-run to continue")
        return 3
    except (DeviceError, IOError) as exc:
        print(f"[!] {exc}")
        return 1
    m.update({"source_device": info.path, "write_block_method": info.write_block_method,
              "report_sha256": sha256_file(rpath)})
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2)
    bad = [k for k, v in m["streams"].items() if not v["bytes_match"]]
    total = sum(v["bytes"] for v in m["streams"].values())
    print(f"\n  [+] {len(m['streams'])} stream(s), {human_size(total)} in {out_dir}")
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("ps_streams_extracted", {
            "manifest": "carve/ps_extracted.json", "streams": len(m["streams"]),
            "bytes": total, "size_mismatches": bad,
            "write_block_method": info.write_block_method},
            data_hash=sha256_file(manifest_path))
        print("  manifest SHA-256 recorded in the custody ledger")
    return 0 if not bad else 1


def _extract_annexb(args) -> int:
    """Save raw H.264/H.265 carved without a parser, as stored, hashed."""
    from acquire.device import DeviceLost
    from core.hashing import sha256_file
    from recover import annexb

    rpath = os.path.join(args.out, "carve", "annexb_report.json")
    report = _load_json(rpath)
    if report is None:
        print(f"[!] no raw H.264/H.265 carve in {args.out} - run `carve-annexb` or "
              f"`scan --carve-annexb` first")
        return 1
    rows = list(annexb.iter_rows(report, set(args.ids.split(",")) if args.ids else None))
    out_dir = os.path.join(args.out, "carve", "es_streams")
    manifest_path = os.path.join(args.out, "carve", "es_extracted.json")
    print(f"{BANNER} - extract raw H.264/H.265 streams\n")
    print(f"  selected      {len(rows)} stream(s)")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            if dev.size_bytes != report.get("source_bytes"):
                print(f"[!] {dev.path} is not the size of the carved device - wrong drive?")
                return 1
            m = annexb.extract(dev, rows, out_dir, manifest_path)
    except DeviceLost as exc:
        print(f"\n[!] {exc}\n    finished streams are kept; re-run to continue")
        return 3
    except (DeviceError, IOError) as exc:
        print(f"[!] {exc}")
        return 1
    bad = [k for k, v in m["streams"].items() if not v["bytes_match"]]
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("es_streams_extracted", {
            "manifest": "carve/es_extracted.json", "streams": len(m["streams"]),
            "size_mismatches": bad, "write_block_method": info.write_block_method},
            data_hash=sha256_file(manifest_path))
        print("  manifest SHA-256 recorded in the custody ledger")
    print(f"\n  [+] {len(m['streams'])} stream(s) in {out_dir}")
    print("  these play, but are not the recorder's bitstream byte for byte: an unknown "
          "container's bytes sit between frames")
    return 0 if not bad else 1


def cmd_case_export(args) -> int:
    """The case as CASE/UCO JSON-LD, for other forensic tools."""
    from core.hashing import sha256_file
    from report import case_uco

    doc = case_uco.build(args.out)
    path = os.path.join(args.out, "case.jsonld")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    kinds: dict[str, int] = {}
    for n in doc["@graph"]:
        kinds[n["@type"]] = kinds.get(n["@type"], 0) + 1
    print(f"{BANNER} - CASE/UCO export\n")
    for k, v in sorted(kinds.items()):
        print(f"  {v:6d}  {k}")
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("case_exported", {"file": "case.jsonld", "nodes": len(doc["@graph"])},
                      data_hash=sha256_file(path))
        print("  SHA-256 recorded in the custody ledger")
    print(f"\n[+] {path}")
    return 0


def cmd_export_nist(args) -> int:
    """An extracted H.264 stream as a NIST CCTV Export Profile Level 0 MP4
    (NISTIR 8161r1): per-frame MISB precision time stamps in UTC, the
    recorder's clock-set source, and the ClockOffset from the examiner's
    reading of the recorder's clock against a reference.  Not re-encoded."""
    from datetime import timedelta

    from analyse.timeline import ClockModel
    from core.contract import SCHEMA_VERSION, utc_now
    from core.hashing import sha256_file
    from report import nist_export as N

    if not os.path.isfile(args.es):
        print(f"[!] no extracted stream at {args.es} - run `extract-carved` or `extract` first")
        return 1
    es = open(args.es, "rb").read()
    try:
        start = N._parse_local(args.start)
        if args.times:
            with open(args.times, encoding="utf-8") as fh:
                times = [N._parse_local(line) for line in fh if line.strip()]
        else:
            n = len(N.access_units(N.split_nals(es)))
            times = [start + timedelta(seconds=k / args.fps) for k in range(n + 1)]
        clock = ClockModel.from_observation(args.tz_offset, args.clock_observed,
                                            args.clock_reference)
        reading = None
        if args.clock_observed and args.clock_reference:
            reading = (N._parse_local(args.clock_observed), N._parse_local(args.clock_reference))
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, os.path.splitext(os.path.basename(args.es))[0] + ".nist.mp4")
        res = N.export(es, path, times, tz_offset_min=args.tz_offset,
                       drift_s=clock.drift_s if clock.drift_source else None,
                       clock_set=args.clock_set, clock_reading=reading,
                       recorder_clock_source=args.recorder_clock_source,
                       reference_source=args.reference_source)
    except (ValueError, OSError) as exc:
        print(f"[!] {exc}")
        return 1
    manifest = {"schema_version": SCHEMA_VERSION, "generated_utc": utc_now(),
                "tool": "ps26150-forensics export-nist", "input": os.path.abspath(args.es),
                "input_sha256": sha256_file(args.es), "clock": clock.to_dict(),
                "frame_times": ("one per picture from " + os.path.basename(args.times)
                                if args.times else f"first picture {args.start}, then "
                                f"{args.fps:g} per second (recorder clock)"),
                "output": res}
    mpath = path + ".manifest.json"
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"{BANNER} - NIST CCTV export (NISTIR 8161r1 Level 0)\n")
    print(f"  [+] {res['file']}  {human_size(res['bytes'])}  {res['pictures']} pictures, "
          f"{res['width']}x{res['height']}  sha256 {res['sha256'][:16]}...")
    print(f"  pictures      {'unchanged' if res['pictures_unchanged'] else 'CHANGED - do not use'}"
          f" (input NAL units = output NAL units without the added SEI)")
    if res["first_utc"]:
        print(f"  time stamps   {res['time_stamps']}, {res['first_utc']} -> {res['last_utc']}; "
              f"{clock.rule()}")
    print(f"  Level 0       {'yes' if res['level0'] else 'no'}")
    for why in res["not_level0_because"]:
        print(f"    - {why}")
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("nist_export", {"file": res["file"], "level0": res["level0"],
                                      "input_sha256": manifest["input_sha256"]},
                      data_hash=res["sha256"])
    print(f"  [+] {os.path.basename(mpath)}")
    return 0 if res["pictures_unchanged"] else 1


def cmd_ewf_info(args) -> int:
    """What an E01 image holds, and - with --verify - whether this reader
    reproduces the MD5/SHA-1 the image stores for its own media."""
    from acquire import ewf

    try:
        img = ewf.EwfImage(args.image)
    except (ewf.EwfError, OSError) as exc:
        print(f"[!] {exc}")
        return 1
    try:
        comp = sum(1 for c in img.chunks if c[3])
        print(f"{BANNER} - E01 image\n")
        print(f"  segments      {len(img.paths)}: " + ", ".join(os.path.basename(p) for p in img.paths))
        print(f"  media         {img.size_bytes:,} bytes ({human_size(img.size_bytes)}), "
              f"{img.sectors:,} sectors of {img.bytes_per_sector}")
        print(f"  chunks        {len(img.chunks):,} of {human_size(img.chunk_size)}, "
              f"{comp:,} compressed")
        print(f"  stored MD5    {img.stored_md5 or '(none)'}")
        print(f"  stored SHA-1  {img.stored_sha1 or '(none)'}")
        if not args.verify:
            return 0

        def progress(done, total):
            if done % (1 << 30) < img.chunk_size * 256 or done == total:
                print(f"    {human_size(done)} of {human_size(total)}", flush=True)

        v = img.verify(progress)
        print(f"\n  computed MD5  {v['computed']['md5']}"
              + {True: "  = stored", False: "  DIFFERS from stored", None: ""}[v["md5_match"]])
        print(f"  computed SHA1 {v['computed']['sha1']}"
              + {True: "  = stored", False: "  DIFFERS from stored", None: ""}[v["sha1_match"]])
        ok = v["md5_match"] is not False and v["sha1_match"] is not False
        print("\n  " + ("the reader reproduces the image's own hash of its media"
                        if v["md5_match"] or v["sha1_match"] else
                        "the image stores no hash to check against" if ok else
                        "MISMATCH - do not use this reader's output for this image"))
        return 0 if ok else 1
    finally:
        img.close()


def cmd_decode_check(args) -> int:
    """Which extracted DHAV frames did not decode, and was a frame missing
    from the disk (a counter gap) since the last keyframe?"""
    from core.contract import dump_json
    from core.hashing import sha256_file
    from analytics import decodecheck as D

    man = _load_json(os.path.join(args.out, "carve", "extracted.json"))
    if not man or not man.get("streams"):
        print(f"[!] no extracted DHAV streams in {args.out} - run `extract-carved` first")
        return 1
    if not D.have_ffprobe():
        print("[!] decode-check needs ffprobe (apt install ffmpeg); nothing else is affected")
        return 1
    ids = set(args.ids.split(",")) if args.ids else None
    sdir = os.path.join(args.out, "carve", "streams")
    print(f"{BANNER} - decode check against the DHAV counter\n")
    per = {}
    for sid, v in sorted(man["streams"].items()):
        if (ids and sid not in ids) or (args.limit and len(per) >= args.limit):
            continue
        codec = v.get("codec") or "h265"
        dav, es = os.path.join(sdir, sid + ".dav"), os.path.join(sdir, f"{sid}.{codec}")
        if os.path.exists(dav) and os.path.exists(es):
            per[sid] = D.check_stream(dav, es, codec)
            if len(per) % 100 == 0:
                print(f"    {len(per)} streams checked", flush=True)
    s = D.summarise(per)
    res = {"rule": D.RULE, "summary": s, "streams": per}
    path = os.path.join(args.out, "analytics", "decode_check.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    dump_json(res, path)
    c = s["classes"]
    print(f"  streams       {s['streams']}; {s['video_frames']:,} video frames, "
          f"{s['decoded']:,} decoded, {s['not_decoded']:,} not")
    print(f"  not decoded   before the first keyframe (expected)  {c['before_first_keyframe']:,}")
    print(f"                after a counter gap (a frame missing)  {c['after_a_gap']:,}")
    print(f"                unexplained                          {c['unexplained']:,}")
    if s["share_explained_by_a_gap"] is not None:
        print(f"\n  a missing frame explains {s['share_explained_by_a_gap']:.1%} of the "
              f"failures after a keyframe")
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("decode_checked", {"result": "analytics/decode_check.json",
                                         "streams": s["streams"], "classes": c},
                      data_hash=sha256_file(path))
        print("  result SHA-256 recorded in the custody ledger")
    print(f"\n[+] {path}")
    return 0


def cmd_carve_annexb(args) -> int:
    """Carve raw H.264/H.265 from an image or drive, no parser needed."""
    from core.hashing import sha256_file
    from recover import annexb

    print(f"{BANNER} - raw H.264/H.265, anchored on parameter sets\n")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)}, "
                  f"{info.write_block_method})")
            end = min(dev.size_bytes, args.max_mb << 20) if args.max_mb else dev.size_bytes
            if end < dev.size_bytes:
                print(f"  range         first {human_size(end)} only (--max-mb)")
            streams, stats = annexb.carve(dev, 0, end)
    except (PermissionNeeded, DeviceError) as exc:
        print(f"[!] {exc}")
        return 1
    rep = annexb.build_report(streams, stats, info, tool="carve-annexb")
    rep["range"] = [0, end]
    res = annexb.write_report(rep, args.out, sha256_file)
    for r in rep["streams"][:20]:
        print(f"  {r['id']}  {r['codec']} {r['width']}x{r['height']}  at 0x{r['offset']:X}  "
              f"{human_size(r['bytes'])}  {r['slices']} slices, {r['keyframes']} keyframes")
    print(f"\n  kept {stats['streams_kept']} stream(s); {stats['fragments']} fragment(s) too "
          f"short to report; {stats['splits_on_new_parameter_set']} split(s) at a new "
          f"parameter set, {stats['splits_on_gap']} at a gap")
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("annexb_carved", {"report": res["report"],
                                        "streams": res["streams_kept"], "bytes": res["bytes"],
                                        "write_block_method": info.write_block_method},
                      data_hash=res["sha256"])
        print("  report SHA-256 recorded in the custody ledger")
    print(f"\n[+] {os.path.join(args.out, res['report'])}")
    return 0


def cmd_extract_carved(args) -> int:
    """Save carved streams as files, from the scan's carve report."""
    import shutil
    from acquire.device import DeviceLost
    from core.hashing import sha256_file
    from recover import carver

    fmt = args.format
    if fmt == "auto":
        fmt = "ps" if (os.path.exists(os.path.join(args.out, "carve", "ps_report.json"))
                       and not _has_dhav_streams(args.out)) else "dhav"
    if fmt == "ps":
        return _extract_ps(args)
    if fmt == "annexb":
        return _extract_annexb(args)
    rpath = os.path.join(args.out, "carve", "carve_report.json")
    if not os.path.exists(rpath):
        print(f"[!] no carve report in {args.out} - run `scan --carve` first")
        return 1
    with open(rpath, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    ids = set(args.ids.split(",")) if args.ids else None
    label = None if args.label == "all" else args.label
    streams = carver.streams_from_report(report, label=label, ids=ids)
    need = sum(e.length for s in streams for e in s.extents)
    out_dir = os.path.join(args.out, "carve", "streams")
    os.makedirs(out_dir, exist_ok=True)
    free = shutil.disk_usage(out_dir).free
    print(f"{BANNER} - extract carved streams\n")
    print(f"  selected      {len(streams)} stream(s), label {args.label}"
          f"{', ids ' + args.ids if args.ids else ''}")
    print(f"  size          up to {human_size(need * 2)} (.dav + bare video); "
          f"{human_size(free)} free")
    if need * 2 > free - (5 << 30):
        print("[!] not enough free space (keeping 5 GB spare) - narrow the selection "
              "with --ids or --label")
        return 1
    manifest_path = os.path.join(args.out, "carve", "extracted.json")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"  device        {dev.path}  ({info.write_block_method})\n")
            if dev.size_bytes != report.get("source_bytes"):
                print(f"[!] {dev.path} is {dev.size_bytes} bytes; the carve was of a "
                      f"{report.get('source_bytes')}-byte device - wrong drive?")
                return 1
            m = carver.extract_from_report(dev, streams, out_dir, manifest_path)
    except DeviceLost as exc:
        print(f"\n[!] {exc}\n    finished streams are kept; re-run with the drive's new "
              f"device path to continue")
        return 3
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1
    m.update({"source_device": info.path, "write_block_method": info.write_block_method,
              "carve_report_sha256": sha256_file(rpath)})
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2)
    bad = [k for k, v in m["streams"].items() if not v["frames_match"]]
    total = sum(f["bytes"] for v in m["streams"].values() for f in v["files"].values())
    print(f"\n  [+] {len(m['streams'])} stream(s), {human_size(total)} in {out_dir}")
    if bad:
        print(f"  [!] {len(bad)} stream(s) wrote a different frame count than the carve "
              f"recorded: {', '.join(bad[:10])}")
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("carved_streams_extracted", {
            "manifest": "carve/extracted.json", "streams": len(m["streams"]),
            "bytes": total, "frame_count_mismatches": bad,
            "write_block_method": info.write_block_method},
            data_hash=sha256_file(manifest_path))
        print("  manifest SHA-256 recorded in the custody ledger")
    return 0 if not bad else 1


def cmd_survey(args) -> int:
    """Draft the layout of an unknown disk: headers, length and date fields."""
    from detect.survey import diff_blockmaps, sample_offsets, survey

    if args.diff:
        a, b = args.diff
        maps = []
        for d in (a, b):
            path = d if d.endswith(".jsonl") else os.path.join(d, "blockmap.jsonl")
            with open(path, "r", encoding="utf-8") as fh:
                maps.append([json.loads(l) for l in fh if l.strip()])
        r = diff_blockmaps(*maps)
        print(f"{BANNER} - block-map diff\n")
        print(f"  compared      {r['blocks_compared']:,} blocks of {human_size(r['block_size'])}")
        print(f"  changed       {r['blocks_changed']:,} blocks in {len(r['changed_regions'])} region(s)")
        for g in r["changed_regions"][:args.limit]:
            print(f"    0x{g['start']:>12X} - 0x{g['end']:>12X}  {human_size(g['bytes']):>10}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(r, fh, indent=2)
            print(f"\n[+] {args.json}")
        return 0
    if not args.device:
        print("[!] --device, or --diff A B")
        return 1
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            offs = sample_offsets(dev.size_bytes, n=args.samples)
            print(f"{BANNER} - survey\n")
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)}, "
                  f"{info.write_block_method})")
            print(f"  sampling      {len(offs)} x 1 MiB spread over the disk")
            r = survey(dev, offsets=offs)
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1
    st = r["structure"]
    print(f"  structure     " + ", ".join(f"{k} {v}" for k, v in sorted(st.items())))
    c = r["codec"]
    print(f"  codec         {c['likely'] or 'none seen'} ({c['start_codes']:,} start codes, "
          f"{c['hevc_ps']} HEVC / {c['sps']} H.264 parameter sets)")
    print(f"  known vendors " + (", ".join(f"{k} ({v})" for k, v in r["known_signatures"].items())
                                 or "none"))
    print(f"\n--- candidate headers {'-' * 37}")
    for h in r["header_candidates"]:
        line = f"  {h['token']}  x{h['occurrences_sampled']:<6} in {h['samples_with_token']} samples"
        if h.get("length_field"):
            lf = h["length_field"]
            line += f"  length u32 @+0x{lf['offset']:X} ({lf['matches_distance_to_next']:.0%})"
        if h.get("date_fields"):
            df = h["date_fields"][0]
            line += f"  date @+0x{df['offset']:X} {df['encoding']}"
            if h.get("date_note"):
                line += " (ambiguous: another encoding fits too)"
        print(line)
    if not r["header_candidates"]:
        print("  none - try more samples, or the data may be encrypted/compressed")
    print(f"\n--- strings {'-' * 47}")
    for x in r["strings"][:args.limit]:
        print(f"  {x['count']:6d}  {x['text']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=2)
        print(f"\n[+] {args.json}")
    print("\n  leads for a researcher, not a format: draft signatures are 'candidate'")
    return 0


def cmd_activity(args) -> int:
    """Motion activity per camera per minute from compressed frame sizes."""
    from analyse.activity import ActivityTap
    from core.hashing import DEFAULT_BLOCK_SIZE

    tap = ActivityTap()
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            print(f"{BANNER} - motion activity (lead, not evidence)\n")
            print(f"  device        {dev.path}  ({human_size(dev.size_bytes)}, "
                  f"{info.write_block_method})")
            if dev.is_raw:
                print("  note          this reads the whole device; on a live drive, "
                      "prefer `scan --activity` in the acquisition pass")
            tap.prepare(dev, 0, dev.size_bytes, log=lambda m: print("  " + m.lstrip("[*] ")))
            for off, data, err in dev.read_blocks(DEFAULT_BLOCK_SIZE):
                tap.feed(off, data)
            res = tap.finish(args.out, info)
    except PermissionNeeded as exc:
        print(f"[!] {exc}")
        return 2
    except DeviceError as exc:
        print(f"[!] {exc}")
        return 1
    with open(os.path.join(args.out, "activity.json"), "r", encoding="utf-8") as fh:
        r = json.load(fh)
    for cam, v in r["cameras"].items():
        print(f"  {cam:<14} {v['minutes']:6d} minutes, median "
              f"{human_size(v['median_p_bytes_per_minute'])}/min of P-frames")
    print(f"  peaks         {len(r['peaks'])} camera-minutes at >= {r['peak_factor']}x the "
          f"surrounding {r['local_window_min']} min either side; "
          f"{len(r['multi_camera_peaks'])} minutes with peaks on several cameras")
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("activity_measured", res, data_hash=res["sha256"])
    print(f"\n[+] {os.path.join(args.out, 'activity.json')}  - a lead for review, not evidence")
    return 0


def _recorder_times(case_dir: str, clips: list, key: str) -> bool:
    """Hikvision PS streams carry the recorder's clock (HK descriptor): put a
    recorder-local time on each entry of clip[key], from the stream's first
    keyframe.  False if the case has no PS streams."""
    psr = os.path.join(case_dir, "carve", "ps_report.json")
    if not os.path.exists(psr):
        return False
    from datetime import datetime, timedelta
    with open(psr, "r", encoding="utf-8") as fh:
        t0 = {x["id"]: x.get("time_first_local") for x in json.load(fh)["streams"]}
    for c in clips:
        start = t0.get(os.path.splitext(c["clip"])[0])
        if start:
            s0 = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
            for h in c[key]:
                h["time_local"] = (s0 + timedelta(seconds=h["t_s"])).strftime("%Y-%m-%d %H:%M:%S")
    return True


def _extracted_clips(case_dir: str, ids: str) -> list:
    """The clips extract-carved wrote, optionally only the ids given."""
    import glob
    src = os.path.join(case_dir, "carve", "streams")
    clips = sorted(glob.glob(os.path.join(src, "*.h265")) + glob.glob(os.path.join(src, "*.h264"))
                   + glob.glob(os.path.join(case_dir, "carve", "ps_streams", "*.ps")))
    if ids:
        want = set(ids.split(","))
        clips = [c for c in clips if os.path.splitext(os.path.basename(c))[0] in want]
    return clips


def cmd_analyse_video(args) -> int:
    """Optional layer: faces and objects in extracted clips (lead, not evidence)."""
    if args.recount:
        from analytics.static import recount
        from core.hashing import sha256_file
        path = os.path.join(args.out, "analytics", "analytics.json")
        with open(path, "r", encoding="utf-8") as fh:
            r = recount(json.load(fh))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=1)
        print(f"{BANNER} - analytics recount (stored boxes, no decoding)\n")
        print("  counted       " + (", ".join(f"{k} {v}" for k, v in sorted(r["frames_with_totals"].items())) or "none"))
        print("  not counted   " + (", ".join(f"{k} {v}" for k, v in sorted(r["flagged_not_counted"].items())) or "none")
              + "  (static, or an implausible face box)")
        ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
        if ledger.entries:
            ledger.actor = ledger.entries[0].get("actor", "unknown")
            ledger.case_id = ledger.entries[0].get("case_id", "")
            ledger.append("video_analytics_recounted", {
                "report": "analytics/analytics.json", "frames_with": r["frames_with_totals"],
                "not_counted": r["flagged_not_counted"], "rule": r["implausible_rule"]},
                data_hash=sha256_file(path))
        return 0
    try:
        from analytics.detect import run
    except ImportError as exc:
        print(f"[!] the optional analytics layer is not installed ({exc}).")
        print("    It needs ffmpeg, numpy and onnxruntime - see analytics/README.md.")
        print("    The forensic core does not need it.")
        return 2
    from core.hashing import sha256_file

    src = os.path.join(args.out, "carve", "streams")
    clips = _extracted_clips(args.out, args.ids)
    if not clips:
        print(f"[!] no extracted clips in {src} - run `extract-carved` first")
        return 1
    out_dir = os.path.join(args.out, "analytics")
    print(f"{BANNER} - video analytics (lead, not evidence)\n")
    print(f"  clips         {len(clips)} from {src}, sampled at {args.fps} fps")
    from analytics.models import MODEL_SETS
    tiles = MODEL_SETS[args.models]["tiles"] if args.tiles is None else args.tiles
    print(f"  models        {args.models}; tiles "
          + (f"{tiles} x {tiles} and the whole frame" if tiles > 1 else "none (whole frame only)"))
    print(f"  rotation      {args.rotate} (frames also looked at turned round, for cameras that look down)")
    try:
        r = run(clips, out_dir, fps=args.fps, log=print, tiles_n=tiles, model_set=args.models,
                rotate=args.rotate)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"[!] {exc}")
        return 1
    if _recorder_times(args.out, r["clips"], "detections"):
        with open(os.path.join(out_dir, "analytics.json"), "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=1)
    tot = r["frames_with_totals"]
    print(f"\n  frames with   " + (", ".join(f"{k} {v}" for k, v in sorted(tot.items())) or "no detections"))
    path = os.path.join(out_dir, "analytics.json")
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("video_analytics_run", {
            "report": "analytics/analytics.json", "clips": len(clips), "fps": args.fps,
            "tiles": tiles, "model_set": args.models, "rule": r["rule"],
            "rotate": args.rotate, "frames_turned": r["rotation"]["frames_turned"],
            "models": {k: v["sha256"] for k, v in r["models"].items()},
            "frames_with": tot, "status": "lead, not evidence"},
            data_hash=sha256_file(path))
    print(f"\n[+] {path}\n  every detection is a lead for review; face DETECTION, never identification")
    return 0


def cmd_face_search(args) -> int:
    """Optional layer: rank the faces in clips by likeness to a reference photo
    (candidates for an examiner to compare by eye, never an identification)."""
    try:
        from analytics.face_search import run
    except ImportError as exc:
        print(f"[!] the optional analytics layer is not installed ({exc}).")
        print("    It needs ffmpeg, numpy and onnxruntime - see analytics/README.md.")
        print("    The forensic core does not need it.")
        return 2
    from core.hashing import sha256_file

    if not os.path.isfile(args.photo):
        print(f"[!] no photo at {args.photo}")
        return 1
    if args.video:
        clips, src = list(args.video), "given"
        missing = [c for c in clips if not os.path.isfile(c)]
        if missing:
            print(f"[!] no file at {', '.join(missing)}")
            return 1
    else:
        clips = _extracted_clips(args.out, args.ids)
        src = f"from {os.path.join(args.out, 'carve')}"
        if not clips:
            print(f"[!] no extracted clips in {src[5:]} - run `extract-carved` first, or give --video")
            return 1
    out_dir = os.path.join(args.out, "analytics")
    print(f"{BANNER} - face search (candidates for review, not identification)\n")
    print(f"  clips         {len(clips)} {src}, sampled at {args.fps} fps")
    try:
        r = run(args.photo, clips, out_dir, fps=args.fps, log=print, match_min=args.min_similarity)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"[!] {exc}")
        return 1
    path = os.path.join(out_dir, "face_search.json")
    if _recorder_times(args.out, r["clips"], "faces"):
        when = {(c["clip"], f["t_s"]): f.get("time_local") for c in r["clips"] for f in c["faces"]}
        for f in r["top"]:
            f["time_local"] = when.get((f["clip"], f["t_s"]))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=1)
    tot = r["totals"]
    print(f"\n  faces compared {tot['faces_compared']}; candidates {tot['candidates']} (similarity "
          f">= {r['match_min']}, eyes >= {r['min_eye_px']} px apart); too small to compare "
          f"{tot['too_small']}")
    for f in r["top"][:10]:
        print(f"    {f['clip']}  {f['t_s']:>8.1f} s  similarity {f['similarity']:.3f}  "
              f"eyes {f['eye_px']:.0f} px" + ("  CANDIDATE" if f["candidate"] else ""))
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("face_search_run", {
            "report": "analytics/face_search.json", "rule": r["rule"],
            "photo": r["reference"]["photo"], "photo_sha256": r["reference"]["photo_sha256"],
            "clips": len(clips), "fps": args.fps, "match_min": r["match_min"],
            "min_eye_px": r["min_eye_px"],
            "models": {k: v["sha256"] for k, v in r["models"].items()},
            "totals": tot, "status": r["status"]},
            data_hash=sha256_file(path))
    print(f"\n[+] {path}\n  a candidate is a face to compare by eye with the photo; "
          "face search never identifies anyone")
    return 0


def cmd_combine(args) -> int:
    """One view across several recorders - on a shared axis only if earned.

    Two DVRs from the same premises share no clock. A shared UTC axis needs
    every case to state its recorder's timezone; without that the cases are
    shown side by side, each on its own clock, and the command says per case
    what is missing rather than quietly aligning them.
    """
    from analyse.combined import build, summary_lines
    from core.contract import utc_now
    from core.hashing import sha256_file
    from report.html import render_combined

    try:
        view = build(args.cases)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[!] {exc}")
        return 1
    view["generated_utc"] = utc_now()
    view["title"] = args.title
    os.makedirs(args.out, exist_ok=True)
    jpath = os.path.join(args.out, "combined.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(view, fh, indent=2)
    hpath = os.path.join(args.out, "combined.html")
    with open(hpath, "w", encoding="utf-8") as fh:
        fh.write(render_combined(view))

    print(f"{BANNER} - combined view across {len(view['cases'])} recorders\n")
    for line in summary_lines(view):
        print("  " + line if not line.startswith("  ") else line)
    t = view["totals"]
    print(f"\n  totals        {t['recorders']} recorders, {t['lanes']} lanes, "
          f"{t['events']} events, {t['hours_recovered']:,.1f} h recovered, "
          f"{t['gaps']} gaps, {t['anomalies']} anomalies")
    jh = sha256_file(jpath)
    # Each source case records that it was read into a combined view: the view
    # is derived from those cases, so it belongs in their chains too.
    for c in view["cases"]:
        ledger = CustodyLedger(os.path.join(c["path"], "custody_ledger.jsonl"))
        if ledger.entries:
            ledger.actor = ledger.entries[0].get("actor", "unknown")
            ledger.case_id = ledger.entries[0].get("case_id", "")
            ledger.append("combined_view_built", {
                "output": jpath.replace(os.sep, "/"),
                "with_cases": [x["case_id"] for x in view["cases"]],
                "axis": view["axis"]["axis"]}, data_hash=jh)
    print(f"\n[+] {jpath}\n      sha256 {jh}")
    print(f"[+] {hpath}")
    if not view["axis"]["shared"]:
        print("\n  the recorders are NOT on one axis - see 'needed' above; "
              "side-by-side lanes are each on their own recorder clock")
    return 0


def cmd_read_osd(args) -> int:
    """Read the burned-in OSD of carved streams: camera title, and the clock.

    The attribution route for footage no index accounts for - those streams
    carry no camera anywhere in their bytes, but the recorder painted the
    channel title into the picture.  Also cross-checks the clock in the picture
    against the date decoded from the container, which is the output
    verification the validation report asks for.
    """
    import glob
    try:
        from analytics.osd import run
        from analytics.osd_rules import OSD_RULE
    except ImportError as exc:                      # pragma: no cover - defensive
        print(f"[!] the optional OSD reader is not available ({exc}).")
        return 2
    from core.hashing import sha256_file

    src = os.path.join(args.out, "carve")
    clips = sorted(glob.glob(os.path.join(src, "streams", "*.h265"))
                   + glob.glob(os.path.join(src, "streams", "*.h264"))
                   + glob.glob(os.path.join(src, "ps_streams", "*.ps")))
    if args.unlabelled:
        clips = [c for c in clips if _unlabelled(args.out, c)]
    if args.ids:
        want = set(args.ids.split(","))
        clips = [c for c in clips if os.path.splitext(os.path.basename(c))[0] in want]
    if args.limit:
        clips = clips[:args.limit]
    if not clips:
        print(f"[!] no extracted clips in {src} - run `extract-carved` first"
              + (" (or none are unlabelled)" if args.unlabelled else ""))
        return 1
    print(f"{BANNER} - burned-in OSD: camera titles and the recorder's clock\n")
    print(f"  clips         {len(clips)}"
          + ("  (only streams no index labelled)" if args.unlabelled else "")
          + f", {args.frames} frames each from the first {args.window}s")
    try:
        r = run(clips, args.out, frames=args.frames, window_s=args.window, log=print)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    s = r["summary"]
    print(f"\n  named         {s['streams_named_by_the_picture']} of {s['streams']} streams")
    for title, n in list(s["titles"].items())[:12]:
        print(f"    {title:<24}{n:5d} streams")
    print("  clock         " + ", ".join(f"{k}: {v}" for k, v in s["clock_checks"].items()))
    if "clock_offset_s" in s:
        o = s["clock_offset_s"]
        print(f"                picture minus container: median {o['median']:+.0f} s, "
              f"range {o['min']:+.0f} to {o['max']:+.0f} s")
    path = os.path.join(args.out, "analytics", "osd.json")
    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("osd_read", {
            "report": "analytics/osd.json", "rule": OSD_RULE, "clips": len(clips),
            "layout": {k: (r["layout"].get(k) or {}).get("band") for k in ("title", "clock")},
            "named": s["streams_named_by_the_picture"],
            "clock_checks": s["clock_checks"], "status": "lead, not evidence"},
            data_hash=sha256_file(path))
    print(f"\n[+] {path}\n  a title read from pixels is a lead: confirm it in the frame itself")
    return 0


def _unlabelled(out: str, clip: str) -> bool:
    """True when no index gave this stream a camera - the streams the OSD is
    for.  Reads whichever label set the case has (HIKBTREE labels for PS
    streams, the DHFS cross-reference for DHAV)."""
    sid = os.path.splitext(os.path.basename(clip))[0]
    lp = os.path.join(out, "carve", "ps_labels.json")
    if os.path.exists(lp):
        with open(lp, "r", encoding="utf-8") as fh:
            for row in json.load(fh).get("streams", []):
                if row["id"] == sid:
                    return row.get("label") in (None, "", "outside_index", "stale_tail")
    cp = os.path.join(out, "carve", "carve_report.json")
    if os.path.exists(cp):
        with open(cp, "r", encoding="utf-8") as fh:
            for row in json.load(fh).get("streams", []):
                if row.get("recording", {}).get("id") == sid:
                    return row.get("index_label") in (None, "", "outside_index",
                                                      "mixed-evidence")
    return True


def cmd_label_ps(args) -> int:
    """Label carved MPEG-PS streams with cameras from a surviving HIKBTREE."""
    from core.hashing import sha256_file
    from parsers import hikbtree

    out = args.out
    with open(os.path.join(out, "scan_report.json"), "r", encoding="utf-8") as fh:
        scan = json.load(fh)
    heads = [h["offset"] for h in scan.get("signature_hits", []) if h["signature_id"] == "hik.btree"]
    if not heads:
        print("[!] the scan found no HIKBTREE header - nothing to label from")
        return 1
    with open(os.path.join(out, "carve", "ps_report.json"), "r", encoding="utf-8") as fh:
        rows = json.load(fh)["streams"]
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            if dev.size_bytes != scan["device"]["size_bytes"]:
                print("[!] this device is not the size of the scanned one - wrong drive?")
                return 1
            index = hikbtree.read_index(dev, heads)
    except (PermissionNeeded, DeviceError) as exc:
        print(f"[!] {exc}")
        return 1
    labels = hikbtree.label_streams(index, rows)
    ipath = os.path.join(out, "carve", "hik_index.json")
    lpath = os.path.join(out, "carve", "ps_labels.json")
    with open(ipath, "w", encoding="utf-8") as fh:
        json.dump(dict(index, headers=heads, source_device=info.path,
                       write_block_method=info.write_block_method), fh, indent=1)
    with open(lpath, "w", encoding="utf-8") as fh:
        json.dump({"rule": hikbtree.RULE, "index_sha256": sha256_file(ipath),
                   "streams": labels}, fh, indent=1)
    from collections import Counter
    tally = Counter(l["label"] for l in labels)
    print(f"{BANNER} - label MPEG-PS streams from the HIKBTREE index\n")
    print(f"  headers       {len(heads)} at " + ", ".join(f"0x{h:X}" for h in heads))
    print(f"  records       {len(index['records'])} (data-area base 0x{index['base']:X}, 1 GiB blocks)")
    print(f"  channels      " + ", ".join(f"{k}: {v}" for k, v in index["channels"].items()))
    for k, v in sorted(tally.items()):
        print(f"  {k:<14}{v:5d} streams")
    ledger = CustodyLedger(os.path.join(out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("ps_streams_labelled", {
            "index": "carve/hik_index.json", "labels": "carve/ps_labels.json",
            "records": len(index["records"]), "tally": dict(tally),
            "write_block_method": info.write_block_method}, data_hash=sha256_file(lpath))
    print(f"\n[+] {lpath}")
    return 0


def _case_ledger(out: str) -> Optional[CustodyLedger]:
    ledger = CustodyLedger(os.path.join(out, "custody_ledger.jsonl"))
    if not ledger.entries:
        return None
    ledger.actor = ledger.entries[0].get("actor", "unknown")
    ledger.case_id = ledger.entries[0].get("case_id", "")
    return ledger


def _load_json(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _print_model_checks(out: str) -> None:
    from detect import model

    rec = _load_json(os.path.join(out, "device_record.json")) or {}
    platter = _load_json(os.path.join(out, "model.json"))
    scan = _load_json(os.path.join(out, "scan_report.json")) or {}
    print("\n  checks")
    for c in model.check(rec.get("observations", []), platter, scan.get("detections")):
        print(f"    {c['verdict']:<26} {c['check']}: {c['detail']}")


def cmd_identify_model(args) -> int:
    """Search the non-video parts of the disk for the recorder's model number."""
    from core.contract import dump_json
    from core.hashing import sha256_bytes, sha256_file
    from detect import model
    from detect.survey import sample_offsets

    bm_path = os.path.join(args.out, "blockmap.jsonl")
    print(f"{BANNER} - model strings on the platter\n")
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            if os.path.exists(bm_path):
                with open(bm_path, "r", encoding="utf-8") as fh:
                    blockmap = [json.loads(l) for l in fh if l.strip()]
                head_image = bool(blockmap) and (blockmap[-1]["offset"] + blockmap[-1]["length"]
                                                 > dev.size_bytes)
                if head_image:
                    # A head image of the drive (e.g. its first 20 GiB): search the
                    # blocks it holds - once its first block hashes to the scan's.
                    b0 = blockmap[0]
                    if (b0["offset"] or b0["length"] > dev.size_bytes
                            or sha256_bytes(dev.read_at(0, b0["length"])) != b0["sha256"]):
                        print("[!] this device is not the drive the block map was made of "
                              "(its first block's hash differs)")
                        return 1
                    blockmap = [b for b in blockmap if b["offset"] + b["length"] <= dev.size_bytes]
                blocks, searched = model.select_blocks(blockmap, dev.size_bytes,
                                                       int(args.max_gb * (1 << 30)))
                if head_image:
                    searched["head_image"] = (f"the first {dev.size_bytes:,} bytes of the drive; "
                                              f"block 0 matches the scan's hash")
            else:
                sample = 1 << 20
                blocks = [(o, min(sample, dev.size_bytes - o))
                          for o in sample_offsets(dev.size_bytes, 256, sample)]
                searched = {"rule": "no block map in the case: the first and last 8 MiB and "
                                    "256 samples of 1 MiB spread across the disk",
                            "blocks": len(blocks), "bytes": sum(n for _, n in blocks),
                            "device_bytes": dev.size_bytes}
            print(f"  device        {dev.path}  ({info.write_block_method})")
            print(f"  searching     {human_size(searched['bytes'])} in {len(blocks)} blocks - "
                  f"{searched['rule']}")
            rec = _load_json(os.path.join(args.out, "device_record.json")) or {}
            forms = model.identifier_forms((rec.get("observations") or [None])[-1])
            if forms:
                print("  also for      the unit's own " + ", ".join(sorted(
                    {f"{f['identifier']} {f['value']}" for f in forms}))
                      + " (record-device)")
            ms = model.ModelSearch(forms)
            # the matching is CPU-bound (~6 MiB/s a process); a whole drive
            # needs it spread over processes to keep up with the reads
            workers = getattr(args, "workers", 0) or (min(8, max(1, (os.cpu_count() or 1) - 1))
                                                      if len(blocks) > 64 else 1)
            if workers > 1:
                print(f"  workers       {workers} processes match while this one reads")

            def progress(k: int) -> None:
                if k and k % 500 == 0:
                    print(f"    {k}/{len(blocks)} blocks", flush=True)
            model.search_blocks(dev.read_at, blocks, ms, workers, progress)
    except (PermissionNeeded, DeviceError) as exc:
        print(f"[!] {exc}")
        return 1
    res = ms.result(searched)
    res.update({"source_device": info.path, "write_block_method": info.write_block_method})
    path = os.path.join(args.out, "model.json")
    dump_json(res, path)
    print()
    if not res["candidates"]:
        print("  no model-numbered string found in what was searched")
    for c in res["candidates"][:15]:
        print(f"  {c['kind']:<9} {c['model']:<26} {c['vendor']:<10} {c['count']:>6}x  "
              f"first at 0x{c['offsets'][0]:X}"
              + ("  (possible chance match: short, seen once)"
                 if c.get("possible_chance_match") else ""))
    ui = res.get("unit_identifiers")
    for r in (ui or {}).get("found", []):
        print(f"  unit's    {r['identifier'] + ' ' + r['value']:<36} {r['form']:<20} "
              f"{r['count']:>6}x  first at 0x{r['offsets'][0]:X}")
    if ui and not ui["found"]:
        print("  none of the unit's own identifiers found in what was searched")
    _print_model_checks(args.out)
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("model_searched", {"result": "model.json", "blocks": searched["blocks"],
                                         "bytes": searched["bytes"],
                                         "candidates": len(res["candidates"]),
                                         "unit_identifiers_found":
                                             sum(r["count"] for r in (ui or {}).get("found", [])),
                                         "write_block_method": info.write_block_method},
                      data_hash=sha256_file(path))
        print("  result SHA-256 recorded in the custody ledger")
    print(f"\n[+] {path}")
    return 0


def cmd_hik_log(args) -> int:
    """Read a Hikvision disk's own system log: power cycles, logins,
    configuration, playback, disk events - each with the recorder's time."""
    from datetime import datetime, timezone
    from core.contract import dump_json
    from core.hashing import sha256_bytes, sha256_file
    from parsers import hiklog

    print(f"{BANNER} - Hikvision system log\n")
    starts = None
    ps = os.path.join(args.out, "carve", "ps_report.json")
    if os.path.exists(ps):
        with open(ps, "r", encoding="utf-8") as fh:
            starts = [int(datetime.strptime(s["time_first_local"], "%Y-%m-%d %H:%M:%S")
                          .replace(tzinfo=timezone.utc).timestamp())
                      for s in json.load(fh).get("streams", []) if s.get("time_first_local")]
    try:
        with BlockDevice(args.device) as dev:
            info = dev.info()
            bm_path = os.path.join(args.out, "blockmap.jsonl")
            if os.path.exists(bm_path):
                with open(bm_path, "r", encoding="utf-8") as fh:
                    b0 = json.loads(fh.readline())
                if (b0["length"] <= dev.size_bytes
                        and sha256_bytes(dev.read_at(0, b0["length"])) != b0["sha256"]):
                    print("[!] this device is not the drive the case was made of "
                          "(its first block's hash differs)")
                    return 1
            res = hiklog.read(dev, starts)
    except (PermissionNeeded, DeviceError) as exc:
        print(f"[!] {exc}")
        return 1
    if "error" in res:
        print(f"[!] {res['error']}")
        return 1
    # HIKBTREE copies beyond a head image: check the master's offsets against
    # where the scan found them.
    idx = os.path.join(args.out, "carve", "hik_index.json")
    if os.path.exists(idx):
        with open(idx, "r", encoding="utf-8") as fh:
            found = set(json.load(fh).get("headers", []))
        for c, k in zip(res["checks"][-2:], ("hikbtree1", "hikbtree2")):
            if c["ok"] is None:
                c["ok"] = res["master"][f"{k}_offset"] + 0x10 in found
                c["detail"] = "against the HIKBTREE copies the scan found (hik_index.json)"
    res.update({"source_device": info.path, "write_block_method": info.write_block_method})
    path = os.path.join(args.out, "hik_log.json")
    dump_json(res, path)

    m, s = res["master"], res["summary"]
    print(f"  device        {info.path}  ({info.write_block_method})")
    print(f"  master        0x{m['offset']:X}  {m['fs_version']}  initialised "
          f"{res['init_time_local']} (recorder clock)")
    for n in res["notes"]:
        print(f"                {n}")
    for c in res["checks"]:
        mark = {True: "agree", False: "DIFFER", None: "not checked"}[c["ok"]]
        print(f"    {mark:<12} {c['check']}{' - ' + c['detail'] if c.get('detail') else ''}")
    print(f"  log area      0x{m['log_offset']:X} - 0x{m['log_end']:X}")
    print(f"  records       {s['records']:,}, {s['first_local']} -> {s['last_local']} "
          f"(recorder clock); {s['defined_by_the_sdk']:,} named by Hikvision's SDK")
    for t, n in list(s["by_type"].items())[:10]:
        print(f"    {n:>7,}  {t}")
    print(f"  power         {s['power']['power on']} power-on, "
          f"{s['power']['abnormal shutdown']} abnormal shutdown, "
          f"{s['power']['power off']} orderly power-off")
    if s["user_actions"]:
        print(f"  by a user     {len(s['user_actions'])}")
        for a in s["user_actions"][:20]:
            print(f"    {a['time_local']}  {a['user']:<10} {a['type']}")
    cv = res.get("clock_vs_footage")
    if cv:
        print(f"  clock         {cv['verdict']} ({cv['followed_by_a_stream']} of "
              f"{cv['power_on_records']} power-ons followed by a new stream within "
              f"{cv['window_s']} s; next best shift {cv['next_best']})")
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("hik_log_read", {"result": "hik_log.json", "records": s["records"],
                                       "log_area": res["log_area"],
                                       "write_block_method": info.write_block_method},
                      data_hash=sha256_file(path))
        print("  result SHA-256 recorded in the custody ledger")
    print(f"\n  status {res['validation_status'].upper()} - read off real media; not yet "
          f"matched against the log the recorder itself shows or exports")
    print(f"\n[+] {path}")
    return 0


def cmd_record_device(args) -> int:
    """Record the recorder's model, serial and firmware as the examiner read
    them off the unit, with the SHA-256 of each photo that shows them."""
    from core.contract import canonical_json, dump_json, utc_now
    from core.hashing import sha256_bytes, sha256_file
    from detect import model

    photos = []
    for p in args.photo:
        if not os.path.isfile(p):
            print(f"[!] no such photo: {p}")
            return 1
        photos.append({"file": os.path.basename(p), "bytes": os.path.getsize(p),
                       "sha256": sha256_file(p)})
    mac_typed = getattr(args, "mac", "") or ""
    if mac_typed and not model.normalize_mac(mac_typed):
        print(f"[!] not a MAC address: {mac_typed!r} (12 hex digits expected)")
        return 1
    ledger = _case_ledger(args.out)
    obs = model.observation(args.model, args.serial, args.firmware, args.read_from,
                            photos or None, ledger.actor if ledger else "", utc_now(),
                            mac=mac_typed, device_id=getattr(args, "device_id", "") or "")
    path = os.path.join(args.out, "device_record.json")
    rec = _load_json(path) or {"rule": model.RULE, "observations": []}
    rec["observations"].append(obs)
    os.makedirs(args.out, exist_ok=True)
    dump_json(rec, path)

    print(f"{BANNER} - recorder as read off the unit\n")
    print(f"  model         {obs['model']}")
    ident = obs["identified"]
    print("  identified    " + (f"{ident['vendor']} {ident['kind']}; stores video as: "
                                f"{ident['storage']}" if ident else
                                "not a model numbering we know - recorded as typed"))
    for k in ("serial", "mac", "device_id", "firmware", "read_from"):
        if obs[k]:
            print(f"  {k:<13} {obs[k]}")
    for p in photos:
        print(f"  photo         {p['file']}  sha256 {p['sha256'][:16]}...")
    _print_model_checks(args.out)
    if model.identifier_forms(obs):
        print("  next: identify-model searches the disk for this unit's serial / device ID / "
              "MAC")
    if ledger:
        ledger.append("device_recorded", {"model": obs["model"], "serial": obs["serial"],
                                          "mac": obs["mac"], "device_id": obs["device_id"],
                                          "firmware": obs["firmware"],
                                          "read_from": obs["read_from"], "photos": photos},
                      data_hash=sha256_bytes(canonical_json(obs)))
        print("  recorded in the custody ledger")
    else:
        print("  [!] no custody ledger in this case directory - recorded in "
              "device_record.json only")
    return 0


def _recovered_files(paths: list[str]) -> list[str]:
    """Files to search, from files and directories.  Where a stream was
    extracted both as stored (.dav / .ps) and as bare video (.h264 / .h265),
    only the stored copy is kept - the same slices twice would be counted
    twice."""
    from validate.exportmatch import sniff_file

    found = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                found += [os.path.join(root, f) for f in sorted(files)]
        else:
            found.append(p)
    kinds = {f: sniff_file(f) for f in found if os.path.getsize(f)}
    stored = {os.path.splitext(f)[0] for f, k in kinds.items() if k in ("dhav", "ps")}
    return [f for f, k in kinds.items()
            if k in ("dhav", "ps") or (k == "annexb" and os.path.splitext(f)[0] not in stored)]


def _demux_export(path: str, out_dir: str):
    """An MP4 / AVI / ASF export's video as bare Annex-B, with ffmpeg copying
    the stream (`-c:v copy`: slices are re-framed, never re-encoded).
    Returns (path, how) or (None, None) when ffmpeg is not installed."""
    import shutil
    import subprocess

    ffmpeg, ffprobe = shutil.which("ffmpeg"), shutil.which("ffprobe")
    if not (ffmpeg and ffprobe):
        return None, None
    from core import proc
    codec = proc.run([ffprobe, "-v", "error", "-select_streams", "v:0",
                      "-show_entries", "stream=codec_name",
                      "-of", "default=nw=1:nk=1", path],
                     timeout=proc.PROBE_S, capture_output=True, text=True).stdout.strip()
    fmt = {"h264": "h264", "hevc": "hevc"}.get(codec)
    if not fmt:
        raise ValueError(f"the export's video is {codec or 'unreadable'}; "
                         f"only H.264 and H.265 can be compared")
    dst = os.path.join(out_dir, os.path.basename(path) + (".h264" if fmt == "h264" else ".h265"))
    args = ["-v", "error", "-y", "-i", path, "-map", "0:v:0", "-c:v", "copy", "-f", fmt, dst]
    proc.run([ffmpeg] + args, timeout=proc.STREAM_S, check=True)
    version = proc.run([ffmpeg, "-version"], timeout=proc.PROBE_S, capture_output=True,
                       text=True).stdout.splitlines()[0]
    return dst, {"tool": version, "command": "ffmpeg " + " ".join(args)}


def cmd_validate_export(args) -> int:
    """Byte-match footage recovered from the disk against the recorder's own
    export - the test that decides `validated` (VALIDATION_REPORT.md §9)."""
    from core.contract import SCHEMA_VERSION, dump_json, utc_now
    from core.hashing import sha256_file
    from validate import exportmatch

    vdir = os.path.join(args.out, "validation")
    os.makedirs(vdir, exist_ok=True)
    print(f"{BANNER} - compare recovered footage with the recorder's export\n")
    kind = exportmatch.sniff_file(args.export)
    compared, demux = args.export, None
    print(f"  export        {args.export}  ({kind})")
    if kind in ("mp4", "avi", "asf"):
        try:
            compared, demux = _demux_export(args.export, vdir)
        except (ValueError, OSError) as exc:
            print(f"[!] {exc}")
            return 1
        if compared is None:
            print(f"[!] a {kind.upper()} export needs ffmpeg to take out its video stream "
                  f"(nothing is re-encoded). Install ffmpeg, or run:\n"
                  f"    ffmpeg -i {args.export} -map 0:v:0 -c:v copy -f hevc export.h265\n"
                  f"  (-f h264 export.h264 for H.264) and pass that file as --export.")
            return 1
        print(f"  video out     {compared}  (ffmpeg -c:v copy)")
    elif kind == "unknown":
        print("[!] not a DHAV, MPEG-PS, MP4, AVI, ASF or Annex-B file")
        return 1

    files = _recovered_files(args.against)
    if not files:
        print("[!] no recovered footage (.dav, .ps, .h264, .h265) under --against")
        return 1
    print(f"  recovered     {len(files)} file(s)")

    def progress(path, n):
        print(f"    {os.path.basename(path)}: {n:,} slices read", flush=True)

    res = exportmatch.compare(compared, files, codec=args.codec, progress=progress)
    res["export"].update({"path": args.export, "bytes": os.path.getsize(args.export),
                          "sha256": sha256_file(args.export), "demuxed": demux})
    if demux:
        res["export"]["demuxed_sha256"] = sha256_file(compared)
    for r in res["recovered"]:
        r.update({"bytes": os.path.getsize(r["path"]), "sha256": sha256_file(r["path"])})
    res.update({"schema_version": SCHEMA_VERSION, "generated_utc": utc_now(),
                "tool": "ps26150-forensics validate-export",
                "recorder": args.recorder or None})
    rpath = os.path.join(vdir, f"export_{os.path.basename(args.export)}.json")
    dump_json(res, rpath)

    m, e = res["match"], res["export"]
    print(f"\n--- result {'-' * 48}")
    print(f"  export        {e['codec']} ({e['codec_source']}), {e['frames']} frames, "
          f"{e['slices']} slices, sha256 {e['sha256'][:16]}...")
    for r in res["recovered"]:
        if r["slices_credited"]:
            print(f"  found in      {os.path.basename(r['path'])}: {r['slices_credited']} "
                  f"slices, export slices {r['export_range'][0]}-{r['export_range'][1]}")
    print(f"  slices        {m['slices_matched']} of {m['slices_total']} byte-identical, "
          f"in order ({m['share']:.2%})")
    print(f"  frames        {m['frames_fully_matched']} of {m['frames_total']} fully matched")
    if m["unmatched_ranges_total"]:
        print(f"  not found     {m['unmatched_ranges_total']} range(s) of export slices, "
              f"first: {m['unmatched_ranges'][0]['export_slices']}")
    c = res["container"]
    if "frames_byte_identical" in c:
        print(f"  DHAV frames   {c['frames_byte_identical']} of {c['frames_compared']} "
              f"identical incl. header; dates equal {c['date_equal']}, "
              f"counters equal {c['frame_counter_equal']}")
    elif "time_equal" in c:
        print(f"  HK time       equal on {c['time_equal']} of {c['frames_compared']} frames")
    p = res["parameter_sets"]
    print(f"  param sets    {p['in_both']} in both, {p['export_only']} export only, "
          f"{p['recovered_only']} recovered only")
    for n in res["notes"]:
        print(f"  note          {n}")
    print(f"\n  verdict       {m['verdict'].upper()}"
          + ("  - meets the validation criterion" if res["meets_criterion"] else ""))
    if res["meets_criterion"]:
        print("                the vendor's status is NOT changed automatically: record this "
              "in VALIDATION_REPORT.md section 9 and change it in review")

    ledger = CustodyLedger(os.path.join(args.out, "custody_ledger.jsonl"))
    if ledger.entries:
        ledger.actor = ledger.entries[0].get("actor", "unknown")
        ledger.case_id = ledger.entries[0].get("case_id", "")
        ledger.append("export_compared", {
            "result": os.path.relpath(rpath, args.out), "export_sha256": e["sha256"],
            "verdict": m["verdict"], "slices_matched": m["slices_matched"],
            "slices_total": m["slices_total"], "meets_criterion": res["meets_criterion"],
            "recorder": args.recorder or None}, data_hash=sha256_file(rpath))
        print("  result SHA-256 recorded in the custody ledger")
    print(f"\n[+] {rpath}")
    return 0 if m["verdict"] != "none" else 1


def cmd_certificate(args) -> int:
    """Draft the BSA 2023 s.63(4)(c) certificate from what the case recorded."""
    from core.contract import dump_json
    from core.hashing import sha256_file
    from report import s63

    cert = s63.build(args.out, part=args.part, records=args.records, declarant={
        "name": args.name, "relation": args.relation, "address": args.address,
        "designation": args.designation, "date": args.date, "time": args.time,
        "place": args.place})
    base = os.path.join(args.out, f"certificate_s63_part{cert['part']}")
    dump_json(cert, base + ".json")
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(s63.render(cert))
    f = cert["fields"]
    print(f"{BANNER} - section 63 certificate, Part {cert['part']} (DRAFT)\n")
    print(f"  device        DVR; {f['make_model'] or 'make/model not recorded'}")
    print(f"  serial        {f['serial'] or 'not recorded'}")
    print(f"  hash values   {len(f['hash_values'])} ({', '.join(f['algorithm_ticks']) or 'none'}), "
          f"listed in the enclosed hash report")
    for n in cert["notes"]:
        print(f"  [!] {n}")
    print("  left blank    " + "\n                ".join(cert["left_to_the_declarant"]))
    print(f"  wording       {cert['wording_source']}")
    ledger = _case_ledger(args.out)
    if ledger:
        ledger.append("s63_certificate_drafted", {
            "part": cert["part"], "html": os.path.basename(base) + ".html",
            "html_sha256": sha256_file(base + ".html"), "hash_values": len(f["hash_values"])},
            data_hash=sha256_file(base + ".json"))
        print("  both files' SHA-256 recorded in the custody ledger")
    print(f"\n[+] {base}.html")
    return 0 if f["hash_values"] else 1


def cmd_prove(args) -> int:
    """Produce a Merkle inclusion proof for the block containing an offset.

    This is what makes a single carved clip defensible without re-reading a
    multi-TB drive: the block hash, a short sibling path, and the root that
    was recorded at acquisition time - in scan_report.json and the custody
    ledger, and, when the examiner has a key, in an RSA-signed statement
    (`cli.py sign`; `verify` checks it).
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
    p.add_argument("--activity", action="store_true",
                   help="also measure motion activity from frame sizes (lead, not evidence)")
    p.add_argument("--carve-ps", action="store_true",
                   help="also carve MPEG Program Stream footage (Hikvision and others)")
    p.add_argument("--no-parallel", action="store_true",
                   help="run carvers and activity in the scanning process instead of one "
                        "process each (same output, slower)")
    p.add_argument("--carve-annexb", action="store_true",
                   help="also carve raw H.264/H.265 - the last resort for a vendor with no "
                        "parser (no dates, no cameras)")
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

    p = sub.add_parser("extract", help="reassemble recordings into playable files")
    p.add_argument("--device", required=True)
    p.add_argument("--vendor", default="Dahua")
    p.add_argument("--recording", required=True, nargs="+",
                   help="recording id(s) from `parse`; several are reassembled after one "
                        "parse of the disk")
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
    p.add_argument("--require-access", action="store_true",
                   help="put the console behind sign-in and administrator "
                        "approval; a grant lasts 8 hours (see access/)")
    p.add_argument("--access-dir", default="",
                   help="where the access database and audit log live "
                        "(default: <out>/.access)")
    p.add_argument("--no-signup", action="store_true",
                   help="with --require-access, close the sign-up form so "
                        "only 'access-user --action add' can make an account")

    def _store_args(parser):
        parser.add_argument("--access-store", default="sqlite",
                            choices=["sqlite", "supabase"],
                            help="where accounts, requests and the access audit "
                                 "log live: sqlite in the access directory "
                                 "(default; offline), or a Supabase project "
                                 "(hosted deployments; needs its credentials)")
        parser.add_argument("--supabase-env", default="",
                            help="with --access-store supabase: a file holding "
                                 "SUPABASE_URL and SUPABASE_SERVICE_KEY, read when "
                                 "they are not in the environment (default "
                                 "~/.config/anokhidrishti/supabase.env)")

    _store_args(p)
    p.add_argument("--cookie-secure", action="store_true",
                   help="with --require-access, mark the session cookie Secure: "
                        "for a deployment reached over HTTPS through a proxy "
                        "(a browser drops a Secure cookie on plain HTTP)")
    p.add_argument("--trust-proxy", action="store_true",
                   help="with --require-access, key the per-address rate limits "
                        "on X-Forwarded-For: only behind a reverse proxy, where "
                        "every request otherwise shares the proxy's address")
    p.set_defaults(func=cmd_serve)

    # -- temporary access control ------------------------------------------
    def _access_args(parser):
        parser.add_argument("--out", default="out",
                            help="case folder root; the access store defaults "
                                 "to <out>/.access")
        parser.add_argument("--access-dir", default="",
                            help="explicit access store directory")
        _store_args(parser)

    p = sub.add_parser("access-admin",
                       help="create or promote an administrator who can "
                            "approve access requests")
    _access_args(p)
    p.add_argument("--username", required=True)
    p.add_argument("--password-too", action="store_true",
                   help="also set a new password when promoting")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the password from the first line of stdin "
                        "instead of prompting (getpass cannot be piped on "
                        "Windows); keeps it out of the command line either way")
    p.set_defaults(func=cmd_access_admin)

    p = sub.add_parser("access-user", help="list or manage access accounts")
    _access_args(p)
    p.add_argument("--action", default="list",
                   choices=["list", "add", "passwd", "disable", "enable"])
    p.add_argument("--username", default="")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the password from the first line of stdin "
                        "instead of prompting")
    p.set_defaults(func=cmd_access_user)

    p = sub.add_parser("access-request",
                       help="list access requests, or approve/reject/revoke one")
    _access_args(p)
    p.add_argument("--action", default="list",
                   choices=["list", "approve", "reject", "revoke"])
    p.add_argument("--id", default="", help="the 9-digit request identifier")
    p.add_argument("--admin", default="",
                   help="name recorded as the deciding administrator")
    p.add_argument("--note", default="", help="reason, kept in the audit log")
    p.add_argument("--pending-only", action="store_true",
                   help="with --action list, show only undecided requests")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(func=cmd_access_request)

    p = sub.add_parser("access-audit",
                       help="print the access audit log and verify its chain")
    _access_args(p)
    p.add_argument("--limit", type=int, default=60)
    p.set_defaults(func=cmd_access_audit)

    p = sub.add_parser("writeblock-rule",
                       help="print a udev rule that write-blocks a drive across reconnects")
    p.add_argument("--serial", default="", help="drive serial (ID_SERIAL_SHORT)")
    p.add_argument("--usb-id", default="",
                   help="or every disk behind this evidence adapter, vvvv:pppp")
    p.add_argument("--device", default="", help="or read the serial from this node")
    p.add_argument("--user", default="", help="also grant this user READ-only access")
    p.set_defaults(func=cmd_writeblock_rule)

    p = sub.add_parser("case-export",
                       help="the case as CASE/UCO JSON-LD (the forensic exchange standard)")
    p.add_argument("--out", required=True, help="case directory")
    p.set_defaults(func=cmd_case_export)

    p = sub.add_parser("export-nist",
                       help="an extracted H.264 stream as a NIST CCTV Export Profile "
                            "(NISTIR 8161r1 Level 0) MP4: UTC time stamps in every frame, "
                            "ClockOffset metadata; not re-encoded")
    p.add_argument("--es", required=True, help="the H.264 elementary stream (from extract)")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--start", required=True,
                   help="the first picture's time on the recorder's clock, "
                        "'YYYY-MM-DD HH:MM:SS[.ffffff]'")
    p.add_argument("--fps", type=float, default=25.0, help="frames per second (default 25)")
    p.add_argument("--times", default="",
                   help="instead of --fps: a file with one recorder-clock time per picture")
    p.add_argument("--tz-offset", type=int, default=None,
                   help="recorder zone, minutes east of UTC; without it no UTC time stamp "
                        "is written")
    p.add_argument("--clock-observed", default="",
                   help="what the recorder displayed, 'YYYY-MM-DD HH:MM:SS'")
    p.add_argument("--clock-reference", default="",
                   help="trusted time at that instant, same zone")
    p.add_argument("--clock-set", default="manual-unknown",
                   choices=("auto-network", "auto-nonnetwork", "auto-unknown", "manual-network",
                            "manual-nonnetwork", "manual-unknown"),
                   help="how the recorder's clock was set (NISTIR 8161 Table 5), from its "
                        "time settings screen")
    p.add_argument("--recorder-clock-source", default="unknown",
                   choices=("network", "nonnetwork", "unknown"))
    p.add_argument("--reference-source", default="network",
                   choices=("network", "nonnetwork", "unknown"),
                   help="how the reference clock was set (a phone: network)")
    p.set_defaults(func=cmd_export_nist)

    p = sub.add_parser("ewf-info",
                       help="an E01 image's segments, geometry and stored hashes; --verify "
                            "recomputes them")
    p.add_argument("--image", required=True, help="the .E01 (other segments are found beside it)")
    p.add_argument("--verify", action="store_true",
                   help="read every chunk and compare with the stored MD5/SHA-1")
    p.set_defaults(func=cmd_ewf_info)

    p = sub.add_parser("decode-check",
                       help="optional: which recovered frames do not decode, and whether a "
                            "missing frame explains it (needs ffprobe)")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--ids", default="", help="comma-separated stream ids (default: all extracted)")
    p.add_argument("--limit", type=int, default=0, help="stop after this many streams")
    p.set_defaults(func=cmd_decode_check)

    p = sub.add_parser("carve-annexb",
                       help="carve raw H.264/H.265 with no parser - last resort for an "
                            "unknown vendor")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--max-mb", type=int, default=0,
                   help="carve only the first N MiB (default: the whole device)")
    p.set_defaults(func=cmd_carve_annexb)

    p = sub.add_parser("extract-carved",
                       help="save carved streams as files, from the scan's carve report")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--label", default="outside_index",
                   help="index label to extract: outside_index (default), CH01.., "
                        "mixed-evidence, unlabelled (no index on the source), or all")
    p.add_argument("--ids", default="", help="comma-separated stream ids instead")
    p.add_argument("--format", choices=["auto", "dhav", "ps", "annexb"], default="auto",
                   help="which carve to extract from (auto: DHAV if it found streams, else "
                        "MPEG-PS; annexb only when asked)")
    p.set_defaults(func=cmd_extract_carved)

    p = sub.add_parser("survey", help="draft the layout of an unknown disk, or diff two scans")
    p.add_argument("--device", default="")
    p.add_argument("--samples", type=int, default=64, help="1 MiB samples between the ends")
    p.add_argument("--diff", nargs=2, metavar=("A", "B"),
                   help="compare two scans' block maps (case dirs or blockmap.jsonl)")
    p.add_argument("--json", default="", help="write the full result here")
    p.add_argument("--limit", type=int, default=15)
    p.set_defaults(func=cmd_survey)

    p = sub.add_parser("activity",
                       help="motion activity per camera per minute from frame sizes")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="case directory")
    p.set_defaults(func=cmd_activity)

    p = sub.add_parser("analyse-video",
                       help="optional: faces and objects in extracted clips (lead, not evidence)")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--fps", type=float, default=1.0, help="frames analysed per second of video")
    p.add_argument("--ids", default="", help="comma-separated clip ids (default: all extracted)")
    p.add_argument("--models", default="yolox", choices=("yolox", "classic"),
                   help="yolox: YOLOX-S + YuNet (default); classic: SSD-MobileNet + "
                        "UltraFace, as measured before 29 Sep 2026")
    p.add_argument("--tiles", type=int, default=None,
                   help="also run the object model on each tile of an n x n grid, which finds "
                        "small people (default 2 for yolox, 3 for classic; 1 = whole frame "
                        "only, about 2-3x faster)")
    p.add_argument("--rotate", default="auto", choices=("auto", "on", "off"),
                   help="also look at each frame turned round, for cameras that look down "
                        "(people lie at every angle): auto = round fisheye pictures (default), "
                        "on = every frame, for a ceiling camera, off = never")
    p.add_argument("--recount", action="store_true",
                   help="re-apply the static/implausible rules to stored results, no decoding")
    p.set_defaults(func=cmd_analyse_video)

    p = sub.add_parser("face-search",
                       help="optional: rank faces in clips by likeness to a reference photo "
                            "(candidates for review, never identification)")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--photo", required=True, help="the reference photo (one face; the largest is used)")
    p.add_argument("--fps", type=float, default=1.0, help="frames searched per second of video")
    p.add_argument("--ids", default="", help="comma-separated clip ids (default: all extracted)")
    p.add_argument("--video", nargs="+", default=None, metavar="FILE",
                   help="search these video files instead of the case's extracted clips")
    from analytics.face_rules import MATCH_MIN
    p.add_argument("--min-similarity", type=float, default=MATCH_MIN,
                   help=f"a face at or above this is a candidate (default {MATCH_MIN}, "
                        "OpenCV's published threshold for SFace)")
    p.set_defaults(func=cmd_face_search)

    p = sub.add_parser("combine",
                       help="one view across several recorders (separate axes unless "
                            "every case states its timezone)")
    p.add_argument("--cases", nargs="+", required=True, metavar="DIR",
                   help="two or more case directories, each with a timeline.json")
    p.add_argument("--out", required=True, help="directory for combined.json and combined.html")
    p.add_argument("--title", default="Combined view", help="heading for the page")
    p.set_defaults(func=cmd_combine)

    p = sub.add_parser("read-osd",
                       help="optional: camera titles and the clock from the burned-in OSD")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--frames", type=int, default=6, help="frames sampled per stream")
    p.add_argument("--window", type=int, default=30,
                   help="seconds from the start of a stream the frames come from")
    p.add_argument("--unlabelled", action="store_true",
                   help="only streams no index accounts for - what the OSD is for")
    p.add_argument("--ids", default="", help="comma-separated clip ids (default: all extracted)")
    p.add_argument("--limit", type=int, default=0, help="stop after this many streams")
    p.set_defaults(func=cmd_read_osd)

    p = sub.add_parser("label-ps",
                       help="camera labels for carved MPEG-PS streams from a surviving HIKBTREE")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="case directory")
    p.set_defaults(func=cmd_label_ps)

    p = sub.add_parser("identify-model",
                       help="search the non-video parts of the disk for the recorder's model")
    p.add_argument("--device", required=True)
    p.add_argument("--out", required=True, help="case directory (uses its block map)")
    p.add_argument("--max-gb", type=float, default=4.0,
                   help="most bytes to read (default 4 GiB; raise it to search every "
                        "non-video block of a whole drive)")
    p.add_argument("--workers", type=int, default=0,
                   help="processes for the pattern matching (default: one per core, up to 8, "
                        "for searches over 64 blocks; 1 = in this process)")
    p.set_defaults(func=cmd_identify_model)

    p = sub.add_parser("hik-log",
                       help="read a Hikvision disk's own system log (power, logins, playback)")
    p.add_argument("--device", required=True, help="the drive, or a head image of it")
    p.add_argument("--out", required=True,
                   help="case directory (its footage checks which clock the log keeps)")
    p.set_defaults(func=cmd_hik_log)

    p = sub.add_parser("record-device",
                       help="record the recorder's model/serial/firmware as read off the unit")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--model", required=True, help="as printed on the label or System Info")
    p.add_argument("--serial", default="")
    p.add_argument("--mac", default="", help="the unit's MAC address, any common form")
    p.add_argument("--device-id", default="", help="a device ID printed on the label")
    p.add_argument("--firmware", default="")
    p.add_argument("--read-from", default="", choices=["", "label", "system-info", "other"])
    p.add_argument("--photo", nargs="*", default=[],
                   help="photos showing it; hashed, not copied")
    p.set_defaults(func=cmd_record_device)

    p = sub.add_parser("validate-export",
                       help="byte-match recovered footage against the recorder's own export")
    p.add_argument("--export", required=True,
                   help="the clip the recorder exported (.dav, Hikvision .mp4/.ps, MP4/AVI/ASF, "
                        ".h264/.h265)")
    p.add_argument("--against", required=True, nargs="+",
                   help="recovered footage: files or directories (.dav, .ps, .h264, .h265)")
    p.add_argument("--out", required=True, help="case directory (result goes to validation/)")
    p.add_argument("--codec", choices=["auto", "h264", "h265"], default="auto")
    p.add_argument("--recorder", default="",
                   help="the recorder that exported the clip, as read off its label or "
                        "System Info (model, firmware)")
    p.set_defaults(func=cmd_validate_export)

    p = sub.add_parser("certificate",
                       help="draft the BSA 2023 s.63(4)(c) certificate from the case record")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--part", choices=["A", "B"], default="B",
                   help="A: by the party producing the record; B: by the expert (default)")
    p.add_argument("--records", choices=["drive", "footage", "both"], default="both",
                   help="what the hash values certify: the whole drive, the extracted "
                        "footage, or both (default)")
    for k in ("name", "relation", "address", "designation", "date", "time", "place"):
        p.add_argument(f"--{k}", default="", help=f"the declarant's {k} (left blank if omitted)")
    p.set_defaults(func=cmd_certificate)

    p = sub.add_parser("verify", help="re-verify custody chain, Merkle root and signatures")
    p.add_argument("--out", required=True)
    p.add_argument("--trust", action="append", default=[],
                   help="a public key (.pub.pem) to trust as an examiner's; repeatable. "
                        "Your own key and ~/.ps26150/trusted/*.pem are trusted already")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("keygen", help="make this examiner's RSA signing key (needs the "
                                      "optional cryptography package)")
    p.add_argument("--name", default="", help="the examiner the key belongs to")
    p.add_argument("--key", default="", help="private key path (default "
                                             "~/.ps26150/signing_key.pem)")
    p.add_argument("--no-passphrase", action="store_true",
                   help="store the key unencrypted, so scans and reports sign unattended")
    p.add_argument("--passphrase-stdin", action="store_true",
                   help="read the passphrase from the first line of stdin")
    p.add_argument("--show", action="store_true",
                   help="print the public key and its fingerprint")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("seal", help="seal case files for one recipient: AES-256-GCM, "
                                    "key wrapped with their RSA key, signed by you")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--to", required=True, help="the recipient's public key (.pub.pem)")
    p.add_argument("--include", action="append", default=[],
                   help="another file in the case to add (e.g. an extracted clip); repeatable")
    p.add_argument("--only", action="store_true",
                   help="seal only the --include files, not the default record")
    p.add_argument("--dest", default="", help="package path (default <case>/sealed/...)")
    p.add_argument("--key", default="", help="your private key (default ~/.ps26150)")
    p.add_argument("--note", default="", help="why and for whom, kept in the package and ledger")
    p.add_argument("--unsigned", action="store_true",
                   help="seal without signing (the recipient cannot then check who sealed it)")
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("unseal", help="open a sealed package with your private key, or "
                                      "--info to inspect it without opening")
    p.add_argument("package")
    p.add_argument("--key", default="", help="your private key (the recipient's)")
    p.add_argument("--dest", default="", help="a new or empty folder to open it into")
    p.add_argument("--trust", action="append", default=[],
                   help="the sender's public key, to check who sealed it; repeatable")
    p.add_argument("--allow-unsigned", action="store_true",
                   help="open a package that carries no sender signature")
    p.add_argument("--info", action="store_true",
                   help="show who sealed it, for whom, and its files - decrypts nothing")
    p.set_defaults(func=cmd_unseal)

    p = sub.add_parser("sign", help="sign the case as it stands with the examiner's key")
    p.add_argument("--out", required=True, help="case directory")
    p.add_argument("--key", default="", help="private key path")
    p.add_argument("--reason", default="", help="why it is being signed, kept in the ledger")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("prove", help="Merkle inclusion proof for a disk offset")
    p.add_argument("--out", required=True)
    p.add_argument("--offset", type=int, required=True)
    p.set_defaults(func=cmd_prove)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    # A packaged build (packaging/) starts the scan's parallel workers
    # (acquire/parallel.py, spawn) by re-running this executable; this hands
    # those runs to multiprocessing instead of the command-line parser.  A no-op
    # when run from source.
    import multiprocessing
    multiprocessing.freeze_support()
    raise SystemExit(main())

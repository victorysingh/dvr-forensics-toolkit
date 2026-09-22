"""Single-pass read-only acquisition scan.

One traversal of the device produces, together:

  * linear MD5 + SHA-256 over the whole device (what every other forensic
    tool and every court report expects to compare against)
  * a per-block SHA-256 map, and a Merkle root over it
  * every vendor/filesystem signature hit, with absolute disk offsets
  * a codec profile (where the H.264/H.265 payload actually lives)
  * a bad-sector map
  * a custody ledger entry for each stage

Reading a 2 TB drive over USB is hours, so a second pass is not an option
and everything that needs the bytes has to happen here.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict
from typing import Optional

from acquire.device import BlockDevice, human_size
from acquire.ledger import CustodyLedger
from core.contract import (BadRegion, CaseInfo, HashRecord, ScanReport,
                           ScanStats, dump_json, utc_now)
from core.hashing import DEFAULT_BLOCK_SIZE, MultiHasher, merkle_root, sha256_bytes
from detect.engine import SignatureScanner, parse_partitions

HEAD_BYTES = 1024 * 1024          # partition tables + superblock area


class ScanSession:
    def __init__(self, device_path: str, out_dir: str, case: CaseInfo,
                 block_size: int = DEFAULT_BLOCK_SIZE, resume: bool = False,
                 quiet: bool = False):
        self.device_path = device_path
        self.out_dir = out_dir
        self.case = case
        self.block_size = block_size
        self.resume = resume
        self.quiet = quiet
        os.makedirs(out_dir, exist_ok=True)

        self.blockmap_path = os.path.join(out_dir, "blockmap.jsonl")
        self.report_path = os.path.join(out_dir, "scan_report.json")
        self.state_path = os.path.join(out_dir, "scan_state.json")
        self.ledger = CustodyLedger(os.path.join(out_dir, "custody_ledger.jsonl"),
                                    actor=case.investigator, case_id=case.case_id)

    # -- helpers -----------------------------------------------------------
    def _log(self, msg: str) -> None:
        if not self.quiet:
            print(msg, file=sys.stderr, flush=True)

    def _identity(self, dev: BlockDevice) -> dict:
        return {"path": dev.path, "size_bytes": dev.size_bytes,
                "serial": dev.serial, "model": dev.model,
                "block_size": self.block_size}

    def _load_resume(self, identity: dict) -> tuple[int, list[str]]:
        """Return (blocks_done, leaf_hashes). Refuses to resume onto a
        different device - a resumed scan across two disks would silently
        produce a Merkle root belonging to neither."""
        if not (self.resume and os.path.exists(self.state_path)
                and os.path.exists(self.blockmap_path)):
            return 0, []
        with open(self.state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if state.get("identity") != identity:
            raise RuntimeError(
                "refusing to resume: saved state belongs to a different device "
                f"({state.get('identity', {}).get('serial')!r} vs {identity['serial']!r})")
        leaves = []
        with open(self.blockmap_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    leaves.append(json.loads(line)["sha256"])
        return len(leaves), leaves

    # -- main --------------------------------------------------------------
    def run(self, max_bytes: Optional[int] = None) -> ScanReport:
        started = time.time()
        with BlockDevice(self.device_path) as dev:
            info = dev.info()
            identity = self._identity(dev)
            total = dev.size_bytes if max_bytes is None else min(max_bytes, dev.size_bytes)

            blocks_done, leaves = self._load_resume(identity)
            start_offset = blocks_done * self.block_size
            complete_pass = blocks_done == 0

            self.ledger.append("device_opened_read_only", {
                "path": dev.path, "model": dev.model, "serial": dev.serial,
                "size_bytes": dev.size_bytes, "sector_size": dev.sector_size,
                "bus_type": dev.bus_type,
                "write_block_method": info.write_block_method,
            })
            self._log(f"[*] device   {dev.path}")
            self._log(f"[*] model    {dev.model or '(unreported)'}  serial {dev.serial or '(unreported)'}")
            self._log(f"[*] size     {human_size(dev.size_bytes)} "
                      f"({dev.size_bytes} B, {dev.sector_size} B sectors, bus {dev.bus_type})")
            self._log(f"[*] mode     READ-ONLY ({info.write_block_method})")
            if blocks_done:
                self._log(f"[*] resuming at block {blocks_done} "
                          f"({human_size(start_offset)} already hashed)")

            # partition table / head structures
            head = dev.read_at(0, min(HEAD_BYTES, dev.size_bytes))
            partitions = parse_partitions(head, dev.sector_size)
            self._log(f"[*] partitions: {len(partitions) or 'none (whole-disk volume?)'}")

            scanner = SignatureScanner()
            hasher = MultiHasher(("md5", "sha256")) if complete_pass else None
            bad_regions: list[BadRegion] = []
            bytes_read = 0
            index = blocks_done
            last_report = time.time()

            self.ledger.append("scan_started", {
                "block_size": self.block_size, "start_offset": start_offset,
                "scan_end": total, "resumed": not complete_pass,
            })

            bm = open(self.blockmap_path, "a", encoding="utf-8")
            try:
                for offset, data, err in dev.read_blocks(self.block_size,
                                                         start=start_offset,
                                                         end=total):
                    if hasher is not None:
                        hasher.update(data)
                    digest = sha256_bytes(data)
                    leaves.append(digest)
                    summary = scanner.scan_block(offset, data, index, digest,
                                                 bad=err is not None)
                    if err:
                        bad_regions.append(BadRegion(offset=offset,
                                                     length=len(data), error=err))
                    bm.write(json.dumps(asdict(summary), separators=(",", ":")) + "\n")

                    bytes_read += len(data)
                    index += 1
                    if time.time() - last_report >= 2.0:
                        self._progress(bytes_read, start_offset, total, started)
                        last_report = time.time()
                        bm.flush()
                        self._save_state(identity, index)
            finally:
                bm.close()
                self._save_state(identity, index)

            elapsed = max(time.time() - started, 1e-6)
            self._progress(bytes_read, start_offset, total, started, final=True)

            root = merkle_root(leaves)
            hashes: list[HashRecord] = []
            if hasher is not None:
                for algo, value in hasher.digests().items():
                    hashes.append(HashRecord(algorithm=algo, value=value,
                                             scope="full_device", offset=0,
                                             length=bytes_read))
            hashes.append(HashRecord(algorithm="sha256-merkle", value=root,
                                     scope="block_merkle_root", offset=0,
                                     length=bytes_read))

            stats = ScanStats(
                bytes_read=bytes_read, blocks_hashed=len(leaves),
                block_size=self.block_size, bad_sectors=len(bad_regions),
                duration_s=round(elapsed, 2),
                throughput_mbps=round(bytes_read / elapsed / 1024 / 1024, 2),
                complete_pass=complete_pass and bytes_read + start_offset >= total,
            )

            detections = scanner.detections()
            report = ScanReport(
                case=self.case, device=info, hashes=hashes, merkle_root=root,
                partitions=partitions, signature_hits=scanner.hits,
                detections=detections, bad_regions=bad_regions, stats=stats,
            )

            self.ledger.append("scan_completed", {
                "bytes_read": bytes_read, "blocks": len(leaves),
                "bad_sectors": len(bad_regions),
                "signature_hits": len(scanner.hits),
                "detections": [{"vendor": d.vendor, "confidence": d.confidence,
                                "status": d.validation_status} for d in detections],
                "codec": scanner.codec.to_dict(),
                "complete_pass": stats.complete_pass,
            }, data_hash=root)
            report.ledger_head = self.ledger.head

            dump_json(report, self.report_path)
            with open(os.path.join(self.out_dir, "codec_profile.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(scanner.codec.to_dict(), fh, indent=2)
            with open(os.path.join(self.out_dir, "oem_coverage.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(scanner.coverage_statement(), fh, indent=2)

            self.scanner = scanner
            return report

    def _save_state(self, identity: dict, blocks_done: int) -> None:
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump({"identity": identity, "blocks_done": blocks_done,
                       "updated_utc": utc_now()}, fh, indent=2)

    def _progress(self, read: int, start: int, total: int, t0: float,
                  final: bool = False) -> None:
        if self.quiet:
            return
        elapsed = max(time.time() - t0, 1e-6)
        rate = read / elapsed
        done = start + read
        pct = (done / total * 100) if total else 0.0
        eta = (total - done) / rate if rate > 0 and not final else 0
        bar_len = 28
        filled = int(bar_len * pct / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        msg = (f"\r    [{bar}] {pct:5.1f}%  {human_size(done)}/{human_size(total)}"
               f"  {rate/1024/1024:6.1f} MB/s")
        if not final and eta:
            msg += f"  ETA {int(eta//3600):02d}:{int(eta%3600//60):02d}:{int(eta%60):02d}"
        print(msg + ("\n" if final else ""), end="", file=sys.stderr, flush=True)

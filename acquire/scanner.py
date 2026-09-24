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

from acquire.device import (BlockDevice, DeviceError, DeviceLost, human_size,
                            list_block_devices_linux)
from acquire.ledger import CustodyLedger
from core.contract import (BadRegion, CaseInfo, HashRecord, ScanReport,
                           ScanStats, dump_json, utc_now)
from core.hashing import DEFAULT_BLOCK_SIZE, MultiHasher, merkle_root, sha256_bytes
from detect.engine import SignatureScanner, parse_partitions

HEAD_BYTES = 1024 * 1024          # partition tables + superblock area


class ScanSession:
    def __init__(self, device_path: str, out_dir: str, case: CaseInfo,
                 block_size: int = DEFAULT_BLOCK_SIZE, resume: bool = False,
                 quiet: bool = False, taps: Optional[list] = None,
                 reconnect_wait_s: float = 0.0, reconnect_poll_s: float = 5.0):
        self.device_path = device_path
        self.out_dir = out_dir
        self.case = case
        self.block_size = block_size
        self.resume = resume
        self.quiet = quiet
        # Analyses that ride the single pass (e.g. recover.carver.CarveTap).
        # A tap sees every block the hasher sees but can never alter a hash:
        # if one raises, it is switched off and the acquisition continues.
        self.taps = list(taps or [])
        self.tap_results: dict[str, dict] = {}
        # How long to wait for a device that drops off the bus to come back
        # (0 = fail immediately).  See _reconnect for what "back" requires.
        self.reconnect_wait_s = reconnect_wait_s
        self.reconnect_poll_s = reconnect_poll_s
        self.reconnects: list[dict] = []
        # Where to look for the device again - replaceable in tests.
        self.find_devices = list_block_devices_linux
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
        saved = state.get("identity", {})
        same = (saved == identity) if not identity.get("serial") else all(
            saved.get(k) == identity.get(k) for k in ("serial", "size_bytes", "block_size"))
        if not same:
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

            live_taps = []
            for tap in self.taps:
                try:
                    tap.prepare(dev, start_offset, total, log=self._log)
                    live_taps.append(tap)
                except Exception as exc:                 # noqa: BLE001
                    self._tap_failed(tap, "prepare", exc)

            self.ledger.append("scan_started", {
                "block_size": self.block_size, "start_offset": start_offset,
                "scan_end": total, "resumed": not complete_pass,
                "inline_taps": [t.name for t in live_taps],
            })

            bm = open(self.blockmap_path, "a", encoding="utf-8")
            cur = dev
            pos = start_offset
            try:
                while True:
                    try:
                        for offset, data, err in cur.read_blocks(self.block_size,
                                                                 start=pos, end=total):
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
                            for tap in list(live_taps):
                                try:
                                    tap.feed(offset, data)
                                except Exception as exc:         # noqa: BLE001
                                    live_taps.remove(tap)
                                    self._tap_failed(tap, f"feed at 0x{offset:X}", exc)

                            bytes_read += len(data)
                            index += 1
                            pos = offset + len(data)
                            if time.time() - last_report >= 2.0:
                                self._progress(bytes_read, start_offset, total, started)
                                last_report = time.time()
                                bm.flush()
                                self._save_state(identity, index)
                        break
                    except DeviceLost as lost:
                        bm.flush()
                        self._save_state(identity, index)
                        cur = self._reconnect(cur, lost, identity, leaves, pos)
            finally:
                bm.close()
                self._save_state(identity, index)
                if cur is not dev:
                    cur.close()

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

            for tap in live_taps:
                try:
                    res = tap.finish(self.out_dir, info)
                    self.tap_results[tap.name] = res
                    self.ledger.append(f"inline_{tap.name}_completed", res,
                                       data_hash=res.get("sha256", ""))
                    self._log(f"[+] {tap.name:<8} {json.dumps(res.get('labels', {}))}")
                except Exception as exc:                 # noqa: BLE001
                    self._tap_failed(tap, "finish", exc)

            self.ledger.append("scan_completed", {
                "bytes_read": bytes_read, "blocks": len(leaves),
                "bad_sectors": len(bad_regions),
                "signature_hits": len(scanner.hits),
                "detections": [{"vendor": d.vendor, "confidence": d.confidence,
                                "status": d.validation_status} for d in detections],
                "codec": scanner.codec.to_dict(),
                "complete_pass": stats.complete_pass,
                "reconnects": self.reconnects,
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

    def _reconnect(self, old: BlockDevice, lost: DeviceLost, identity: dict,
                   leaves: list[str], pos: int) -> BlockDevice:
        """Pick the pass up again after the device dropped off the bus.

        A USB-SATA bridge that resets comes back under a new name (sdb ->
        sdc) and WITHOUT the kernel read-only flag, which does not survive a
        reconnect.  The pass continues only when all of these hold:

          * a device of the same size - and the same drive serial, where the
            drive reports one - is present;
          * its kernel read-only flag is set (a udev rule keyed on the serial
            sets it at enumeration; see docs/LINUX_ACQUISITION.md).  A device
            that is not write-blocked is never opened, however long we wait;
          * block 0 and the last block already hashed read back with exactly
            the SHA-256 recorded for them - proof it is the same, unchanged
            drive.

        Then reading resumes at the first byte not yet hashed, feeding the
        SAME running MD5/SHA-256.  The linear hashes are a function of the
        byte stream alone, so they are exactly what one uninterrupted read
        would give; the interruption is disclosed in the custody ledger.
        """
        bs = self.block_size
        self._log(f"\n[!] device lost at 0x{lost.offset:X}: {lost.detail}")
        self.ledger.append("device_lost", {
            "path": old.path, "offset": lost.offset, "hashed_up_to": pos,
            "detail": lost.detail, "reconnect_wait_s": self.reconnect_wait_s})
        try:
            old.close()
        except Exception:                                # noqa: BLE001
            pass
        if self.reconnect_wait_s <= 0:
            raise lost
        deadline = time.time() + self.reconnect_wait_s
        warned: set[str] = set()
        while time.time() < deadline:
            for d in self.find_devices():
                if d["size_bytes"] != identity["size_bytes"]:
                    continue
                if identity.get("serial") and d.get("serial") != identity["serial"]:
                    continue
                if not d.get("read_only"):
                    if d["path"] not in warned:
                        warned.add(d["path"])
                        self._log(f"[!] {d['path']} is back but NOT write-blocked - "
                                  f"not opening it; waiting for the kernel ro flag")
                        self.ledger.append("reconnect_waiting_for_write_block",
                                           {"path": d["path"]})
                    continue
                new = BlockDevice(d["path"])
                checks = []
                for i in sorted({0, max(0, pos // bs - 1)}):
                    if i >= len(leaves):
                        continue
                    got = sha256_bytes(new.read_at(i * bs, min(bs, new.size_bytes - i * bs)))
                    checks.append({"block": i, "expected": leaves[i], "got": got,
                                   "match": got == leaves[i]})
                if not checks or not all(c["match"] for c in checks):
                    new.close()
                    self.ledger.append("reconnect_refused", {"path": d["path"],
                                                             "checks": checks})
                    raise DeviceError(
                        f"{d['path']} matches the drive's size/serial but not the blocks "
                        f"already hashed - refusing to continue the pass on it")
                info = new.info()
                event = {"old_path": old.path, "new_path": new.path, "resume_offset": pos,
                         "serial": new.serial, "write_block_method": info.write_block_method,
                         "verified_blocks": [c["block"] for c in checks]}
                self.reconnects.append(event)
                self.ledger.append("device_reconnected", event)
                self._log(f"[+] reconnected as {new.path} ({info.write_block_method}); "
                          f"blocks {event['verified_blocks']} re-verified; resuming at "
                          f"0x{pos:X}")
                return new
            time.sleep(self.reconnect_poll_s)
        raise DeviceError(f"device did not come back write-blocked within "
                          f"{self.reconnect_wait_s:.0f} s") from lost

    def _tap_failed(self, tap, stage: str, exc: Exception) -> None:
        msg = f"{type(exc).__name__}: {exc}"
        self._log(f"[!] inline {tap.name} disabled during {stage}: {msg} - "
                  f"hashing continues unaffected")
        self.tap_results[tap.name] = {"failed": stage, "error": msg}
        self.ledger.append(f"inline_{tap.name}_failed", {"stage": stage, "error": msg})

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

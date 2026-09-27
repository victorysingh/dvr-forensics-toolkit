"""Run a scan tap in its own process, so taps stop waiting for each other.

The one pass is CPU-bound (docs/PERFORMANCE.md): the carvers are Python,
and one process runs them one after another on every block.  They are
independent of each other and of the hashes, so each can run in its own
process while the main process hashes and detects:

    main process    read block -> MD5 + SHA-256, block hash, detection
                              -> copy the block into each tap's shared ring
    one worker/tap  the tap's own prepare / feed / finish, unchanged

The tap's code does not change, so neither does its output: the same
report, byte for byte apart from its timestamp.  Nothing about the evidence
hashes changes either - they never leave the main process.

HOW BLOCKS TRAVEL
-----------------
Not through a pipe: pickling 8 MiB blocks into four queues took the main
process from 69 to 25 MiB/s on its own (measured, taps doing nothing).  Each
tap has a ring of SLOTS block-sized slots in shared memory; the main process
copies a block into a free slot and sends only (offset, slot, length); the
worker copies it out and hands the slot straight back.  A slow tap runs out
of free slots and holds the reader back - memory stays bounded.

  * The worker reopens the device READ-ONLY, only for `prepare` (a tap may
    read an index there).  `feed` gets bytes; `finish` writes files.
  * A tap that fails in its worker is reported at `finish`, and the scan
    completes regardless - the same guarantee as an in-process tap, whose
    failure never touches a hash.

Stdlib only (`multiprocessing`, `multiprocessing.shared_memory`; spawn).
"""

from __future__ import annotations

import importlib
import multiprocessing as mp
import queue
import traceback
from multiprocessing import shared_memory
from typing import Optional

SLOTS = 4                   # blocks in flight per worker: 4 x 8 MiB


def _resolve(factory: str):
    mod, cls = factory.split(":")
    return getattr(importlib.import_module(mod), cls)


def _attach(name: str) -> shared_memory.SharedMemory:
    """Open the main process's ring without adopting it: only the process
    that created it may unlink it."""
    try:
        return shared_memory.SharedMemory(name=name, track=False)      # Python 3.13+
    except TypeError:
        shm = shared_memory.SharedMemory(name=name)
        try:
            from multiprocessing import resource_tracker
            resource_tracker.unregister(shm._name, "shared_memory")      # noqa: SLF001
        except Exception:                                              # noqa: BLE001
            pass
        return shm


def _worker(factory: str, kwargs: dict, path: str, start: int, end: int, q, res, acks) -> None:
    from acquire.device import BlockDevice

    logs: list[str] = []
    try:
        tap = _resolve(factory)(**kwargs)
        with BlockDevice(path) as dev:
            tap.prepare(dev, start, end, log=lambda *a: logs.append(" ".join(map(str, a))))
    except Exception:                                      # noqa: BLE001
        res.put(("error", "prepare: " + traceback.format_exc(limit=3)))
        return
    res.put(("prepared", logs))
    failed: Optional[str] = None
    shm, ss = None, 0
    while True:
        item = q.get()
        kind = item[0]
        if kind == "finish":
            break
        if kind == "ring":
            shm, ss = _attach(item[1]), item[2]
            continue
        if kind == "slot":
            _, offset, slot, n = item
            data = bytes(shm.buf[slot * ss:slot * ss + n])
            acks.put(slot)                      # hand the slot back before the work
        else:                                   # "bytes": a block larger than a slot
            _, offset, data = item
        if failed is None:
            try:
                tap.feed(offset, data)
            except Exception:                              # noqa: BLE001
                failed = f"feed at 0x{offset:X}: " + traceback.format_exc(limit=3)
    if shm is not None:
        shm.close()
    if failed:
        res.put(("error", failed))
        return
    try:
        res.put(("done", tap.finish(item[1], item[2])))
    except Exception:                                      # noqa: BLE001
        res.put(("error", "finish: " + traceback.format_exc(limit=3)))


class ProcessTap:
    """A scan tap that runs in a worker process.  Built from the tap's
    import path ("recover.carver:CarveTap") and keyword arguments, because
    the worker constructs it itself."""

    def __init__(self, factory: str, **kwargs):
        self.factory, self.kwargs = factory, kwargs
        self.name = _resolve(factory).name
        self.proc = None
        self.shm: Optional[shared_memory.SharedMemory] = None
        self.slot_size = 0
        self.free: list[int] = []

    def prepare(self, dev, start: int, end: int, log=print) -> None:
        ctx = mp.get_context("spawn")
        self.q = ctx.Queue()
        self.res = ctx.Queue()
        self.acks = ctx.Queue()
        self.proc = ctx.Process(target=_worker, daemon=True,
                                args=(self.factory, self.kwargs, dev.path, start, end,
                                      self.q, self.res, self.acks))
        self.proc.start()
        kind, payload = self._wait(self.res)
        if kind == "error":
            self.proc.join(5)
            raise RuntimeError(payload)
        for line in payload:
            log(line)
        log(f"[*] {self.name:<8} running in its own process (pid {self.proc.pid})")

    def feed(self, offset: int, data: bytes) -> None:
        n = len(data)
        if self.shm is None:
            self.slot_size = max(n, 1)
            self.shm = shared_memory.SharedMemory(create=True, size=SLOTS * self.slot_size)
            self.free = list(range(SLOTS))
            self.q.put(("ring", self.shm.name, self.slot_size))
        if n > self.slot_size:
            self.q.put(("bytes", offset, data))
            return
        while True:                               # collect slots already handed back
            try:
                self.free.append(self.acks.get_nowait())
            except queue.Empty:
                break
        if not self.free:
            self.free.append(self._wait(self.acks))
        s = self.free.pop()
        self.shm.buf[s * self.slot_size:s * self.slot_size + n] = data
        self.q.put(("slot", offset, s, n))

    def finish(self, out_dir: str, info) -> dict:
        try:
            self.q.put(("finish", out_dir, info))
            kind, payload = self._wait(self.res)
            self.proc.join(30)
        finally:
            if self.shm is not None:
                self.shm.close()
                self.shm.unlink()
                self.shm = None
        if kind == "error":
            raise RuntimeError(payload)
        return payload

    def _wait(self, q):
        """A worker that died outright must not leave the reader waiting
        forever: wait in steps, and check it is still there."""
        while True:
            try:
                return q.get(timeout=5)
            except queue.Empty:
                if not self.proc.is_alive():
                    raise RuntimeError(f"{self.name} worker exited (code {self.proc.exitcode})")


# The taps that do CPU work per block, by the name the scan knows them by.
TAPS = {"carve": "recover.carver:CarveTap", "carve_ps": "recover.pscarve:PsCarveTap",
        "carve_annexb": "recover.annexb:AnnexBTap", "activity": "analyse.activity:ActivityTap"}

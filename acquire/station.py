"""Plug and use: a disk goes in, every step of the problem statement runs.

    sudo python cli.py station --investigator "Your name"

The station waits for a disk to be plugged in, makes sure the kernel will
refuse writes to it, and runs the whole pipeline on it with no further
input: one acquisition pass (hashes, brand, carving, motion), metadata
preserved, the filesystem parsed, deleted footage saved, the timeline built,
faces and objects found, and the report written - the seven stages of
report/pipeline.py, each answering a module of the problem statement.

Every step is the ordinary command an examiner would type (`scan`, `parse`,
`extract-carved`, ...), run as a child process.  So the station adds no new
way to read a disk: each step writes its own custody-ledger entry exactly as
it does by hand, and anything the station did can be done again by hand.

The console never takes part.  It only reads what the station writes:
`<case>/station.json` (which stage is running, what failed or was skipped)
and `<out>/.station/status.json` (waiting, or on which disk).  The console
keeps its rule of never opening an evidence device.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from acquire.device import is_admin, list_physical_drives, mounted_disks
from report.pipeline import STAGES, STATION_DIR, STATION_FILE

IS_WINDOWS = sys.platform == "win32"
#: A detection below this confidence does not choose a parser.
MIN_CONFIDENCE = 0.5
#: Taps run inside the one acquisition pass.  The brand is not known before
#: the pass, so every carver runs: each in its own process (acquire/parallel.py),
#: so on a USB drive the drive, not the CPU, still sets the pace.
SCAN_TAPS = ["--carve", "--carve-ps", "--carve-annexb", "--activity"]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: str, doc: dict) -> None:
    """Whole file or nothing: the console may read it at any moment."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    os.replace(tmp, path)


def _load(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _streams(case_dir: str, report: str) -> int:
    doc = _load(os.path.join(case_dir, "carve", report)) or {}
    s = doc.get("streams")
    return len(s) if isinstance(s, list) else 0


# ---------------------------------------------------------------------------
# What to run after the scan, from what the scan found
# ---------------------------------------------------------------------------
def plan_after_scan(scan: dict, case_dir: str, device: str, ml: bool = True,
                    ml_fps: float = 0.2) -> list[dict]:
    """The commands for stages 2-7, chosen from the scan's report.

    Returns one entry per stage: {"id", "commands": [[arg, ...], ...],
    "skip": reason or ""}.  Pure apart from reading the carve reports in
    `case_dir`, so the choice can be tested without a disk."""
    rep = _load(os.path.join(case_dir, "carve", "carve_report.json")) or {}
    return plan_stages(scan.get("detections") or [], case_dir, device,
                       dhav=_streams(case_dir, "carve_report.json"),
                       ps=_streams(case_dir, "ps_report.json"),
                       es=_streams(case_dir, "annexb_report.json"),
                       indexed=bool(rep.get("index_used_for_labels")), ml=ml, ml_fps=ml_fps)


def plan_stages(detections: list[dict], case_dir: str, device: str, dhav: int = 0,
                ps: int = 0, es: int = 0, indexed: bool = False, ml: bool = True,
                ml_fps: float = 0.2) -> list[dict]:
    """plan_after_scan, from what the scan found rather than its files: the
    brand detections, how many DHAV, MPEG-PS and raw H.264/H.265 streams were
    carved, and whether a DHAV index labelled them.  Wholly pure, so the
    console can show what the station would run for each brand."""
    dets = [d for d in detections if d.get("confidence", 0) >= MIN_CONFIDENCE]
    vendors = {d.get("vendor") for d in dets}
    top = dets[0] if dets else None
    dev, out = ["--device", device], ["--out", case_dir]

    parse: list[list[str]] = []
    if top and top.get("parser_available"):
        # CP Plus boards are Dahua-built and write Dahua's DHFS (viewer/guide.py)
        vendor = "Dahua" if top["vendor"] == "CP Plus" else top["vendor"]
        parse.append(["parse", *dev, "--vendor", vendor, *out])
    if "Hikvision" in vendors:
        if ps:
            parse.append(["label-ps", *dev, *out])       # cameras from a surviving index
        parse.append(["hik-log", *dev, *out])            # the recorder's own system log

    recover: list[list[str]] = []
    if dhav:
        # With an index, what it no longer lists is the deleted footage; with
        # none, every carved stream is all there is.
        label = "outside_index" if indexed else "all"
        recover.append(["extract-carved", *dev, *out, "--format", "dhav", "--label", label])
    if ps:
        recover.append(["extract-carved", *dev, *out, "--format", "ps"])
    if es and not (dhav or ps):
        # raw H.264/H.265 only when no container format was found: the last resort
        recover.append(["extract-carved", *dev, *out, "--format", "annexb"])

    return [
        {"id": "preserve", "commands": [["preserve", *dev, *out]], "skip": ""},
        {"id": "parse", "commands": parse,
         "skip": "" if parse else "no brand matched with a parser - the footage is "
                                  "recovered by carving instead"},
        {"id": "recover", "commands": recover,
         "skip": "" if recover else "no footage was carved from this disk"},
        {"id": "timeline", "commands": [["timeline", *out]], "skip": ""},
        # analyse-video reads every clip extract-carved saves: DHAV, MPEG-PS,
        # and raw H.264/H.265 when that is all the disk gave
        {"id": "ml", "commands": [["analyse-video", *out, "--fps", f"{ml_fps:g}"]]
         if ml and recover else [],
         "skip": "" if ml and recover else
                 ("turned off (--no-ml)" if not ml else "no recovered clips to look at")},
        {"id": "report", "commands": [["report", *out]], "skip": ""},
    ]



# ---------------------------------------------------------------------------
# What the station runs, brand by brand
# ---------------------------------------------------------------------------
#: Which of the scan's carvers finds a brand's footage, from the brand's scan
#: option in the Start here guide (viewer/guide.py).  The station runs every
#: carver anyway; this is the one that finds something on that brand's disk.
CARVED_BY = {"--carve": "dhav", "--carve-ps": "ps", "--carve-annexb": "es"}

#: Each command the station may run, in plain words.
SAYS = {
    "parse": "the recorder's index: its recordings, cameras and times",
    "label-ps": "cameras named from what is left of the index",
    "hik-log": "the recorder's own system log",
    ("extract-carved", "dhav"): "DHAV clips the index no longer lists: the deleted footage",
    ("extract-carved", "ps"): "MPEG-PS clips, each with the recorder's clock",
    ("extract-carved", "annexb"): "raw H.264/H.265 clips, without dates or cameras",
    "analyse-video": "people, faces and vehicles in every recovered clip",
}

NOT_CARVED = ("none of the scan's carvers reads this brand's footage yet: the "
              "index lists the recordings, and Start here has the commands")


def _say(cmd: list[str]) -> dict:
    """A command as the console shows it: its plain words, and the command
    without the disk and case folder, which every command takes."""
    short, it = [], iter(cmd)
    for a in it:
        if a in ("--device", "--out"):
            next(it, None)
        else:
            short.append(a)
    fmt = cmd[cmd.index("--format") + 1] if "--format" in cmd else ""
    return {"cmd": " ".join(short), "says": SAYS.get((cmd[0], fmt)) or SAYS.get(cmd[0], "")}


def brand_plans(brands: list[dict], parsers: set[str], ml: bool = True) -> list[dict]:
    """For each brand of the Start here guide (viewer.guide.brand_guide), what
    the station runs after the scan on that brand's disk.

    Made by plan_stages itself, on the detection a disk of that brand gives
    and the footage its carver finds, so the console shows the station's own
    choice rather than a claim written beside it.  Only the stages that
    differ by brand are kept: the scan, preserving metadata, the timeline and
    the report run on every disk."""
    rows = []
    for b in brands:
        vendor, fmt = b["vendor"], CARVED_BY.get(b.get("flags", ""))
        # A brand the vendor matrix does not know ("Other / not sure") is a
        # disk no detector claims.  CP Plus is parsed as Dahua (plan_stages).
        dets = [{"vendor": vendor, "confidence": 1.0, "parser_available":
                 ("Dahua" if vendor == "CP Plus" else vendor) in parsers}] if b.get("status") else []
        steps = plan_stages(dets, "CASE", "DISK", indexed=True, ml=ml, **({fmt: 1} if fmt else {}))
        stages = []
        for st in steps:
            if st["id"] not in ("parse", "recover", "ml"):
                continue
            skip = NOT_CARVED if st["id"] == "recover" and not fmt else st["skip"]
            stages.append({"id": st["id"], "runs": [_say(c) for c in st["commands"]],
                           "skip": skip})
        rows.append({"vendor": vendor, "source": b.get("source", ""),
                     "status": b.get("status", ""), "media": b.get("media", ""),
                     "stages": stages})
    return rows

def case_name(prefix: str, disk: dict) -> str:
    """CASE-<serial>, so the same disk plugged in again finds its own case."""
    serial = re.sub(r"[^A-Za-z0-9_-]+", "", disk.get("serial") or "")
    if not serial:
        base = os.path.basename(disk.get("path", "")) or "disk"
        serial = re.sub(r"[^A-Za-z0-9_-]+", "", os.path.splitext(base)[0]) or "disk"
    return f"{prefix}-{serial}"


def disk_key(disk: dict) -> str:
    """One physical disk across replugs: its serial and size, not its path."""
    return f"{disk.get('serial') or disk.get('path')}:{disk.get('size_bytes')}"


# ---------------------------------------------------------------------------
# Write blocking (Linux): the kernel's own read-only flag on the whole disk
# ---------------------------------------------------------------------------
def _sysfs_ro(path: str) -> Optional[bool]:
    name = os.path.basename(os.path.realpath(path))
    try:
        with open(os.path.join("/sys/class/block", name, "ro"), "r") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return None


def ensure_write_block(path: str, set_ro: bool = True) -> dict:
    """Make the kernel refuse writes to `path`, and say what held.

    Not a hardware write blocker: the SOP's hardware blocker or the udev rule
    (`writeblock-rule`) is stronger, because it is in force before anything on
    the machine sees the disk.  The station sets the flag only where nothing
    has set it yet, and refuses the disk if the flag will not stick."""
    if not path.startswith("/dev/") or IS_WINDOWS:
        return {"ok": True, "method": "read-only handle" if IS_WINDOWS else "image file",
                "set_by_station": False}
    before = _sysfs_ro(path)
    if before:
        return {"ok": True, "method": "kernel ro flag (already set)", "set_by_station": False}
    if not set_ro:
        return {"ok": False, "set_by_station": False,
                "why": f"{path} is writable and --no-setro was given: write-block it "
                       f"(sudo blockdev --setro {path}) and plug it in again"}
    try:
        subprocess.run(["blockdev", "--setro", path], check=True, capture_output=True,
                       timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "set_by_station": False,
                "why": f"could not set {path} read-only ({exc})"}
    after = _sysfs_ro(path)
    if not after:
        return {"ok": False, "set_by_station": True,
                "why": f"{path} still reads writable after blockdev --setro"}
    return {"ok": True, "method": "kernel ro flag (set by the station)", "set_by_station": True}


# ---------------------------------------------------------------------------
# The station
# ---------------------------------------------------------------------------
class Station:
    """Waits for a disk and runs every stage on it.

    `command` turns a CLI argument list into the process to start; tests give
    it the same interpreter and this repo's cli.py, as the default does."""

    def __init__(self, out_root: str, investigator: str, organization: str = "",
                 case_prefix: str = "CASE", ml: bool = True, ml_fps: float = 0.2,
                 set_ro: bool = True,
                 reconnect_wait: float = 30, poll_s: float = 2.0, quiet: bool = False,
                 command: Optional[Callable[[list[str]], list[str]]] = None,
                 list_disks: Callable[[], list[dict]] = list_physical_drives):
        self.out_root = os.path.abspath(out_root)
        self.investigator = investigator
        self.organization = organization
        self.case_prefix = case_prefix
        self.ml = ml
        self.ml_fps = ml_fps
        self.set_ro = set_ro
        self.reconnect_wait = reconnect_wait
        self.poll_s = poll_s
        self.quiet = quiet
        self.command = command or default_command
        self.list_disks = list_disks
        self.started = utc()
        self.status_path = os.path.join(self.out_root, STATION_DIR, "status.json")
        self.status: dict = {}

    # -- status the console reads ------------------------------------------
    def _say(self, msg: str, end: str = "\n") -> None:
        if not self.quiet:
            print(msg, end=end, flush=True)

    def beat(self, **change) -> None:
        self.status.update(change)
        self.status.update({"pid": os.getpid(), "host": socket.gethostname(),
                            "started_utc": self.started, "heartbeat": time.time(),
                            "investigator": self.investigator})
        _write_json(self.status_path, self.status)

    # -- finding disks ------------------------------------------------------
    def candidates(self) -> list[dict]:
        """Attached disks that could be evidence: not the workstation's own."""
        system = mounted_disks() if not IS_WINDOWS else set()
        return [d for d in self.list_disks()
                if "error" not in d and d.get("path") not in system
                and d.get("size_bytes")]

    def watch(self, once: bool = False) -> int:
        """Wait for disks plugged in after the station started; run each."""
        present = {disk_key(d): d for d in self.candidates()}
        if present:
            self._say("  already attached, so not taken as plugged in (use --device "
                      "to take one):")
            for d in present.values():
                self._say(f"    {d['path']}  {d.get('model', '')}  {d.get('serial', '')}")
        handled = set(present)
        self._say("\n  waiting for a disk ... (Ctrl-C stops the station)")
        self.beat(state="waiting", message="waiting for a disk", device=None, case=None)
        try:
            while True:
                now = {disk_key(d): d for d in self.candidates()}
                handled &= set(now)               # unplugged: a replug counts again
                fresh = [k for k in now if k not in handled]
                if fresh:
                    time.sleep(self.poll_s)       # let udev finish naming it
                    disk = next((d for d in self.candidates()
                                 if disk_key(d) == fresh[0]), None)
                    handled.add(fresh[0])
                    if disk:
                        self.run(disk)
                        if once:
                            return 0
                    self._say("\n  waiting for a disk ...")
                    self.beat(state="waiting", message="waiting for a disk")
                else:
                    self.beat()
                time.sleep(self.poll_s)
        except KeyboardInterrupt:
            self._say("\n  station stopped")
            self.beat(state="stopped", message="stopped by the examiner")
            return 0

    # -- one disk -------------------------------------------------------------
    def run(self, disk: dict) -> int:
        """Every stage on one disk.  Returns 0 when the acquisition finished."""
        path = disk["path"]
        case = case_name(self.case_prefix, disk)
        case_dir = os.path.join(self.out_root, case)
        dev = {k: disk.get(k) for k in ("path", "model", "serial", "size_bytes", "bus_type")}
        self._say(f"\n  disk      {path}  {disk.get('model', '')}  {disk.get('serial', '')}")
        self._say(f"  case      {case}  ({case_dir})")

        old = _load(os.path.join(case_dir, STATION_FILE)) or {}
        if os.path.exists(os.path.join(case_dir, "scan_report.json")):
            msg = f"{path} was already acquired as {case}; nothing to do"
            self._say(f"  {msg}")
            self.beat(state="waiting", message=msg, device=dev, case=case)
            return 0
        resume = os.path.exists(os.path.join(case_dir, "scan_state.json"))

        wb = ensure_write_block(path, self.set_ro)
        if not wb["ok"]:
            self._say(f"  [!] refused: {wb['why']}")
            self.beat(state="refused", message=wb["why"], device=dev, case=None)
            return 2
        self._say(f"  write     blocked - {wb['method']}")
        if not IS_WINDOWS and path.startswith("/dev/") and not is_admin() \
                and not os.access(path, os.R_OK):
            why = "the station needs root to read a disk: run it with sudo"
            self._say(f"  [!] {why}")
            self.beat(state="refused", message=why, device=dev, case=None)
            return 2

        run = {"device": dev, "investigator": self.investigator,
               "organization": self.organization, "write_block": wb,
               "started_utc": old.get("started_utc") or utc(), "ended_utc": None,
               "outcome": "running",
               "stages": [{"id": s["id"], "state": "pending"} for s in STAGES]}
        record = os.path.join(case_dir, STATION_FILE)
        os.makedirs(case_dir, exist_ok=True)
        _write_json(record, run)
        self.beat(state="working", message=f"working on {path}", device=dev, case=case)

        stage = {s["id"]: s for s in run["stages"]}
        scan = ["scan", "--device", path, "--case", case, "--investigator", self.investigator,
                "--out", case_dir, "--reconnect-wait", str(self.reconnect_wait), *SCAN_TAPS]
        if self.organization:
            scan += ["--organization", self.organization]
        if resume:
            scan.append("--resume")
            self._say("  resuming the acquisition this disk started before")
        ok = self._stage(record, run, stage["scan"], [scan], case_dir)
        report = _load(os.path.join(case_dir, "scan_report.json"))
        if not ok or not report:
            run.update(outcome="failed", ended_utc=utc())
            _write_json(record, run)
            self._hand_back(case_dir)
            self.beat(state="waiting", message=f"acquisition of {path} did not finish; "
                      "plug it in again to resume", case=case)
            return 3

        for step in plan_after_scan(report, case_dir, path, self.ml, self.ml_fps):
            st = stage[step["id"]]
            if not step["commands"]:
                st.update(state="skipped", note=step["skip"])
                _write_json(record, run)
                self._say(f"  -  {self._title(st['id'])}: skipped - {step['skip']}")
                continue
            self._stage(record, run, st, step["commands"], case_dir)

        failed = [s["id"] for s in run["stages"] if s["state"] == "failed"]
        run.update(outcome="done" if not failed else "done with failures", ended_utc=utc())
        _write_json(record, run)
        self._hand_back(case_dir)
        self._say(f"  finished  {case}: " + ("every stage ran" if not failed
                                             else f"failed: {', '.join(failed)}"))
        self.beat(state="waiting", message=f"finished {case}", case=case)
        return 0

    @staticmethod
    def _title(sid: str) -> str:
        return next(s["title"] for s in STAGES if s["id"] == sid)

    def _stage(self, record: str, run: dict, st: dict, commands: list[list[str]],
               case_dir: str) -> bool:
        """Run one stage's commands in order; the stage fails if any fails.
        `analyse-video` exits 2 when its optional layer is missing: skipped."""
        n = [s["id"] for s in STAGES].index(st["id"]) + 1
        title = self._title(st["id"])
        st.update(state="running", started_utc=utc(), commands=[" ".join(c) for c in commands])
        _write_json(record, run)
        log = os.path.join(case_dir, "station.log")
        codes = []
        for args in commands:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(f"\n=== {utc()}  {' '.join(args)}\n")
                fh.flush()
                proc = subprocess.Popen(self.command(args), stdout=fh,
                                        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
                try:
                    while proc.poll() is None:
                        self._progress(n, title, case_dir, st["id"])
                        self.beat()
                        try:
                            proc.wait(timeout=self.poll_s)
                        except subprocess.TimeoutExpired:
                            pass
                except KeyboardInterrupt:
                    proc.terminate()
                    proc.wait()
                    st.update(state="failed", ended_utc=utc(),
                              note="stopped by the examiner; plug the disk in again to resume")
                    run.update(outcome="stopped", ended_utc=utc())
                    _write_json(record, run)
                    raise
            codes.append(proc.returncode)
            if proc.returncode != 0:
                break
        st["exit_codes"] = codes
        st["ended_utc"] = utc()
        if codes and codes[-1] == 2 and commands[len(codes) - 1][0] == "analyse-video":
            st.update(state="skipped", note="the optional analytics layer is not installed "
                                            "(ffmpeg, numpy, onnxruntime: analytics/README.md)")
        elif all(c == 0 for c in codes):
            st["state"] = "done"
        else:
            st.update(state="failed",
                      note=f"`{' '.join(commands[len(codes) - 1][:1])}` exited "
                           f"{codes[-1]} - see station.log in the case folder")
        _write_json(record, run)
        mark = {"done": "+", "skipped": "-", "failed": "!"}[st["state"]]
        self._say(f"\r  {mark}  [{n}/7] {title}: {st['state']}"
                  + (f" - {st['note']}" if st.get("note") else "") + " " * 20)
        return st["state"] != "failed"

    def _progress(self, n: int, title: str, case_dir: str, sid: str) -> None:
        line = f"  >  [{n}/7] {title}"
        if sid == "scan":
            state = _load(os.path.join(case_dir, "scan_state.json")) or {}
            ident = state.get("identity", {})
            size = ident.get("size_bytes") or 0
            if size:
                frac = state.get("blocks_done", 0) * ident.get("block_size", 0) / size
                line += f"  {100 * min(frac, 1):5.1f}% read"
        self._say(line + " " * 10, end="\r")

    def _hand_back(self, path: str) -> None:
        """Under sudo, give the case back to the examiner who ran sudo, so the
        console and later commands can use it without root."""
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if IS_WINDOWS or not uid or not hasattr(os, "chown"):
            return
        for root, dirs, files in os.walk(path):
            for name in [root] + [os.path.join(root, x) for x in dirs + files]:
                try:
                    os.chown(name, int(uid), int(gid or uid))
                except OSError:
                    pass
        try:
            os.chown(os.path.dirname(self.status_path), int(uid), int(gid or uid))
            os.chown(self.status_path, int(uid), int(gid or uid))
        except OSError:
            pass


def default_command(args: list[str]) -> list[str]:
    """The same tool, as a child: the packaged executable, or this cli.py."""
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    cli = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cli.py")
    return [sys.executable, "-u", cli, *args]

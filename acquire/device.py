"""Read-only raw block device access.

SAFETY CONTRACT - the whole project rests on this file:

  * Handles are opened GENERIC_READ only.  There is no write path in this
    module, not behind a flag, not behind a confirmation.  A write to the
    evidence drive destroys the deleted-footage carve and the s.63
    admissibility argument at the same time.
  * On Windows the enclosure has no hardware write-blocker, so the read-only
    handle IS the write-block.  We record that honestly in DeviceInfo as
    "software:read-only-handle" rather than claiming hardware blocking.
  * Raw device reads must be sector-aligned in both offset and length.  All
    alignment is handled here so callers never have to think about it.

Reading a raw PhysicalDrive path requires Administrator on Windows.
"""

from __future__ import annotations

import ctypes
import os
import platform
from ctypes import wintypes
from typing import Iterator, Optional

from core.contract import DeviceInfo

IS_WINDOWS = platform.system() == "Windows"

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400

BUS_TYPES = {
    0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA",
    6: "Fibre", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA",
    12: "SD", 13: "MMC", 14: "Virtual", 15: "FileBackedVirtual", 17: "NVMe",
}


class DeviceError(Exception):
    pass


class PermissionNeeded(DeviceError):
    """Raised when the read failed purely for lack of Administrator."""


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _Win32:
    """Thin ctypes wrapper. Kept local so the rest of the tool stays portable."""

    def __init__(self):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.CreateFileW = k32.CreateFileW
        self.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                     wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
        self.CreateFileW.restype = wintypes.HANDLE

        self.ReadFile = k32.ReadFile
        self.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                  wintypes.LPVOID]
        self.ReadFile.restype = wintypes.BOOL

        self.SetFilePointerEx = k32.SetFilePointerEx
        self.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                          ctypes.POINTER(ctypes.c_longlong),
                                          wintypes.DWORD]
        self.SetFilePointerEx.restype = wintypes.BOOL

        self.DeviceIoControl = k32.DeviceIoControl
        self.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                         wintypes.LPVOID, wintypes.DWORD,
                                         wintypes.LPVOID, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD),
                                         wintypes.LPVOID]
        self.DeviceIoControl.restype = wintypes.BOOL

        self.CloseHandle = k32.CloseHandle
        self.CloseHandle.argtypes = [wintypes.HANDLE]
        self.CloseHandle.restype = wintypes.BOOL


_w32: Optional[_Win32] = _Win32() if IS_WINDOWS else None


class BlockDevice:
    """Read-only view of a physical drive or a disk image file.

    Accepts either a raw device path or an ordinary image file, so every
    downstream engine works identically on live hardware and on a fixture.
    """

    def __init__(self, path: str, sector_size: int = 0):
        self.path = path
        self._handle = None
        self._fh = None
        self.is_raw = self._looks_raw(path)
        self.sector_size = sector_size or 512
        self.size_bytes = 0
        self.model = ""
        self.serial = ""
        self.bus_type = ""
        self.removable = False
        self._open()

    @staticmethod
    def _looks_raw(path: str) -> bool:
        p = path.lower()
        return p.startswith("\\\\.\\") or p.startswith("/dev/")

    # -- lifecycle ---------------------------------------------------------
    def _open(self) -> None:
        if self.is_raw and IS_WINDOWS:
            h = _w32.CreateFileW(self.path, GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 None, OPEN_EXISTING, 0, None)
            if h == INVALID_HANDLE_VALUE or h is None:
                err = ctypes.get_last_error()
                if err == 5:
                    raise PermissionNeeded(
                        f"Access denied opening {self.path}. Raw device reads "
                        f"require Administrator - relaunch elevated.")
                if err == 2:
                    raise DeviceError(
                        f"{self.path} does not exist (device not attached?)")
                raise DeviceError(f"CreateFileW failed on {self.path}: WinError {err}")
            self._handle = h
            self._probe_windows()
        else:
            try:
                self._fh = open(self.path, "rb", buffering=0)
            except PermissionError as exc:
                raise PermissionNeeded(f"Permission denied on {self.path}: {exc}") from exc
            except FileNotFoundError as exc:
                raise DeviceError(f"{self.path} not found") from exc
            if self.is_raw:
                self._fh.seek(0, os.SEEK_END)
                self.size_bytes = self._fh.tell()
                self._fh.seek(0)
            else:
                self.size_bytes = os.path.getsize(self.path)
                self.model = "disk image file"

    def _probe_windows(self) -> None:
        # exact byte length
        buf = ctypes.c_longlong(0)
        ret = wintypes.DWORD(0)
        if _w32.DeviceIoControl(self._handle, IOCTL_DISK_GET_LENGTH_INFO,
                                None, 0, ctypes.byref(buf), 8,
                                ctypes.byref(ret), None):
            self.size_bytes = buf.value

        # logical sector size from drive geometry.  DISK_GEOMETRY_EX starts
        # with DISK_GEOMETRY, whose BytesPerSector field sits at offset 20.
        geo = (ctypes.c_ubyte * 32)()
        if _w32.DeviceIoControl(self._handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                None, 0, ctypes.byref(geo), 32,
                                ctypes.byref(ret), None):
            bps = int.from_bytes(bytes(geo[20:24]), "little")
            if bps in (512, 1024, 2048, 4096):
                self.sector_size = bps

        self._probe_descriptor()

    def _probe_descriptor(self) -> None:
        """STORAGE_DEVICE_DESCRIPTOR gives model, serial and bus type."""
        query = (ctypes.c_ubyte * 12)()          # zeroed = StorageDeviceProperty
        out = (ctypes.c_ubyte * 1024)()
        ret = wintypes.DWORD(0)
        if not _w32.DeviceIoControl(self._handle, IOCTL_STORAGE_QUERY_PROPERTY,
                                    ctypes.byref(query), 12,
                                    ctypes.byref(out), 1024,
                                    ctypes.byref(ret), None):
            return
        raw = bytes(out)

        def _str_at(off_pos: int) -> str:
            off = int.from_bytes(raw[off_pos:off_pos + 4], "little")
            if off == 0 or off >= len(raw):
                return ""
            end = raw.find(b"\x00", off)
            return raw[off:end if end != -1 else len(raw)].decode("latin-1").strip()

        self.removable = bool(raw[8])
        self.bus_type = BUS_TYPES.get(raw[28], f"Unknown({raw[28]})")
        vendor = _str_at(12)
        product = _str_at(16)
        self.serial = _str_at(24)
        self.model = " ".join(x for x in (vendor, product) if x)

    def close(self) -> None:
        if self._handle is not None:
            _w32.CloseHandle(self._handle)
            self._handle = None
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "BlockDevice":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- reading -----------------------------------------------------------
    def read_at(self, offset: int, length: int) -> bytes:
        """Read `length` bytes at `offset`. Callers need not align; we widen
        the request to sector boundaries and slice the result back down."""
        if self._handle is not None:
            ss = self.sector_size
            start = (offset // ss) * ss
            end = ((offset + length + ss - 1) // ss) * ss
            if self.size_bytes:
                end = min(end, self.size_bytes)
            raw = self._raw_read(start, end - start)
            return raw[offset - start: offset - start + length]
        self._fh.seek(offset)
        return self._fh.read(length)

    def _raw_read(self, offset: int, length: int) -> bytes:
        if self._handle is not None:
            newpos = ctypes.c_longlong(0)
            if not _w32.SetFilePointerEx(self._handle, ctypes.c_longlong(offset),
                                         ctypes.byref(newpos), 0):
                raise DeviceError(f"seek to {offset} failed: "
                                  f"WinError {ctypes.get_last_error()}")
            buf = ctypes.create_string_buffer(length)
            got = wintypes.DWORD(0)
            if not _w32.ReadFile(self._handle, buf, length,
                                 ctypes.byref(got), None):
                raise DeviceError(f"read {length}B at {offset} failed: "
                                  f"WinError {ctypes.get_last_error()}")
            return buf.raw[:got.value]
        self._fh.seek(offset)
        return self._fh.read(length)

    def read_blocks(self, block_size: int, start: int = 0,
                    end: Optional[int] = None
                    ) -> Iterator[tuple[int, bytes, Optional[str]]]:
        """Stream the device as (offset, data, error) triples.

        A read error does NOT abort the scan - we fall back to sector-by-sector
        reads to isolate exactly which sectors are bad, zero-fill only those,
        and report them.  Silently skipping bad sectors would shift every
        downstream offset and corrupt the provenance record.
        """
        end = self.size_bytes if end is None else min(end, self.size_bytes)
        ss = self.sector_size
        block_size = max(ss, (block_size // ss) * ss)
        off = (start // ss) * ss
        while off < end:
            want = min(block_size, end - off)
            try:
                data = self._raw_read(off, want)
                if len(data) < want:
                    data += b"\x00" * (want - len(data))
                yield off, data, None
            except Exception as exc:                     # noqa: BLE001
                data, bad = self._read_degraded(off, want)
                yield off, data, f"{bad} bad sector(s): {exc}"
            off += want

    def _read_degraded(self, offset: int, length: int) -> tuple[bytes, int]:
        ss = self.sector_size
        out = bytearray()
        bad = 0
        for s in range(offset, offset + length, ss):
            n = min(ss, offset + length - s)
            try:
                chunk = self._raw_read(s, n)
                out += chunk + b"\x00" * (n - len(chunk))
            except Exception:                            # noqa: BLE001
                out += b"\x00" * n
                bad += 1
        return bytes(out), bad

    # -- metadata ----------------------------------------------------------
    def info(self) -> DeviceInfo:
        return DeviceInfo(
            path=self.path,
            size_bytes=self.size_bytes,
            sector_size=self.sector_size,
            model=self.model,
            serial=self.serial,
            bus_type=self.bus_type,
            removable=self.removable,
            write_blocked=True,
            write_block_method=("software:read-only-handle"
                                if self.is_raw else "n/a:image-file"),
        )


def _read_sysfs(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return default


def list_block_devices_linux() -> list[dict]:
    """Enumerate via /sys/block. Pure reads of sysfs - touches no device node,
    so it is safe to run before write-blocking is in place."""
    found: list[dict] = []
    base = "/sys/block"
    if not os.path.isdir(base):
        return found
    for name in sorted(os.listdir(base)):
        if name.startswith(("loop", "ram", "zram", "dm-", "md")):
            continue
        d = os.path.join(base, name)
        sectors = int(_read_sysfs(os.path.join(d, "size"), "0") or 0)
        log_bs = int(_read_sysfs(os.path.join(d, "queue/logical_block_size"),
                                 "512") or 512)
        size = sectors * 512               # sysfs 'size' is always 512B units
        model = _read_sysfs(os.path.join(d, "device/model"))
        vendor = _read_sysfs(os.path.join(d, "device/vendor"))
        serial = (_read_sysfs(os.path.join(d, "device/serial"))
                  or _read_sysfs(os.path.join(d, "serial")))
        found.append({
            "index": len(found),
            "path": f"/dev/{name}",
            "model": " ".join(x for x in (vendor, model) if x),
            "serial": serial,
            "bus_type": "USB" if "usb" in os.path.realpath(d) else "",
            "size_bytes": size,
            "sector_size": log_bs,
            "removable": _read_sysfs(os.path.join(d, "removable")) == "1",
            "size_gb": round(size / 1024**3, 2),
            # Linux exposes the kernel's own read-only flag - this is the one
            # authoritative answer to "is write-blocking actually on?"
            "read_only": _read_sysfs(os.path.join(d, "ro")) == "1",
        })
    return found


def list_physical_drives(max_index: int = 16) -> list[dict]:
    """Enumerate physical drives. Read-only and harmless on both platforms."""
    found = []
    if not IS_WINDOWS:
        return list_block_devices_linux()
    for i in range(max_index):
        path = f"\\\\.\\PhysicalDrive{i}"
        try:
            with BlockDevice(path) as dev:
                found.append({
                    "index": i, "path": path, "model": dev.model,
                    "serial": dev.serial, "bus_type": dev.bus_type,
                    "size_bytes": dev.size_bytes, "sector_size": dev.sector_size,
                    "removable": dev.removable,
                    "size_gb": round(dev.size_bytes / 1024**3, 2),
                })
        except PermissionNeeded:
            found.append({"index": i, "path": path, "error": "needs Administrator"})
        except DeviceError:
            continue
    return found


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n} B"

"""Running outside programs (ffmpeg, ffprobe, tesseract) with a time limit.

Evidence can be damaged, by accident or on purpose, and a decoder fed a
malformed stream can hang instead of failing.  Without a limit the tool would
hang with it, and the examiner would be left with a frozen window and no
record of why.  So every call the tool makes to an outside program goes
through one of the two functions here:

  run          a program that runs to completion (a probe, one OCR, one
               export).  Past its time limit it is killed, and the caller gets
               an ordinary failed result, marked `timed_out`, that it reports
               like any other failure.

  read_chunks  a program the tool reads from as it runs (a decoder streaming
               frames).  A long recording can take any length of time, so the
               limit is on silence instead: if one chunk takes longer than
               `stall_s`, the program is killed and the stream ends there.

Standard library only.
"""

from __future__ import annotations

import subprocess
import threading
from typing import IO, Iterator

TIMED_OUT = 124            # the exit status `timeout` uses; kept for a killed program
PROBE_S = 60               # ffprobe, `-version`: answers at once when it works
IMAGE_S = 60               # one image in or out (a thumbnail, one OCR)
CLIP_S = 600               # a clip read or written once (an export, a sample of frames)
STREAM_S = 3600            # a whole stream decoded (decode checks, cross-checks)
STALL_S = 120              # a streaming decoder silent for this long is stuck


def run(cmd: list[str], timeout: float = CLIP_S, check: bool = False,
        **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with a time limit.  On time-out the program is killed
    and the result has returncode TIMED_OUT and `timed_out` set, so a caller
    that already handles a failed run handles this one too.  With check=True
    a time-out raises CalledProcessError, as any other failure would."""
    try:
        result = subprocess.run(cmd, timeout=timeout, check=check, **kwargs)
        result.timed_out = False
        return result
    except subprocess.TimeoutExpired as exc:
        empty = "" if kwargs.get("text") else b""
        note = f"{cmd[0]} did not finish within {timeout:g} s and was stopped"
        result = subprocess.CompletedProcess(
            cmd, TIMED_OUT, exc.stdout if exc.stdout is not None else empty,
            (exc.stderr or empty) + (note if kwargs.get("text") else note.encode()))
        result.timed_out = True
        if check:
            raise subprocess.CalledProcessError(TIMED_OUT, cmd, result.stdout,
                                                result.stderr) from exc
        return result


def read_chunks(proc: subprocess.Popen, size: int, stall_s: float = STALL_S) -> Iterator[bytes]:
    """Fixed-size chunks from proc.stdout until it ends or runs short.  If one
    chunk takes longer than `stall_s`, the program is killed: the read then
    returns short and the stream ends, as it would at the end of the file."""
    out: IO[bytes] = proc.stdout
    while True:
        timer = threading.Timer(stall_s, proc.kill)
        timer.start()
        try:
            buf = out.read(size)
        finally:
            timer.cancel()
        if len(buf) < size:
            return
        yield buf

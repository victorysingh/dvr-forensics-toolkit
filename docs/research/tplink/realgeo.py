"""TP-Link VIGI at the firmware's own geometry, end to end through the CLI.

A sparse image laid out as a 1 TB VIGI disk would be - the format sector at
512 MiB, the database area at 0x23200000 (128 MiB for a 1 TB disk), data
zones of 1 GiB from 0x33200000 - holding real video: 8 s of x264 (camera 0,
zone 0) and 8 s of x265 (camera 1, zone 3), each packed into the recorder's
GOPs (32-byte frame headers, key-frame table).  Then `cli.py parse` and
`cli.py extract` read it as they would a seized drive, ffmpeg decodes what
comes out, and the output is compared byte for byte with what went in.

Research script, not part of the tool; needs ffmpeg with libx264/libx265.
The layout values are the firmware's (plugins/tplink.py); the video and the
database rows are ours (tests/synth_tplink.py).

    python docs/research/tplink/realgeo.py WORKDIR
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, ROOT)
from plugins import tplink as T  # noqa: E402
from tests import synth_tplink as ST  # noqa: E402

DISK = 1_000_204_886_016           # a 1 TB drive's size, as the format sector records it
AREA = T.db_size_for(DISK)          # 128 MiB
DZ = T.DB_AREA_AT + 2 * AREA        # 0x33200000
FPS, SECONDS = 25, 8
CAMERAS = [  # (event, channel, zone, codec, encoder args)
    (1, 0, 0, "h264", ["-c:v", "libx264", "-profile:v", "baseline", "-g", "25", "-bf", "0",
                       "-s", "1280x720"]),
    (4, 1, 3, "h265", ["-c:v", "libx265", "-x265-params", "keyint=25:min-keyint=25:bframes=0:log-level=0",
                       "-s", "640x360"]),
]


def nals(stream: bytes) -> list[bytes]:
    """NAL units of an Annex-B stream, start codes removed."""
    out, i = [], stream.find(b"\x00\x00\x01")
    while i >= 0:
        j = stream.find(b"\x00\x00\x01", i + 3)
        body = stream[i + 3:j if j >= 0 else len(stream)]
        if j >= 0 and body.endswith(b"\x00"):
            body = body.rstrip(b"\x00")         # the next start code's leading zero
        out.append(body)
        i = j
    return out


def access_units(stream: bytes, codec: str) -> list[list[bytes]]:
    """One list of NALs per frame: a frame starts at a parameter set, SEI or
    delimiter that follows a slice, or at a slice that follows a slice
    (one slice per frame, as these encoders were told)."""
    def vcl(n):
        return (n[0] & 0x1F) in range(1, 6) if codec == "h264" else ((n[0] >> 1) & 0x3F) < 32
    aus, cur, last_vcl = [], [], False
    for n in nals(stream):
        if cur and last_vcl:
            aus.append(cur)
            cur = []
        cur.append(n)
        last_vcl = vcl(n)
    if cur:
        aus.append(cur)
    return aus


def gops(aus: list[list[bytes]], codec: str, t0_us: int) -> list[tuple[bytes, int, int, int]]:
    """(GOP bytes, frames, first time, last time) per 25 frames."""
    out = []
    for g in range(0, len(aus), FPS):
        data, times = bytearray(), []
        for k, au in enumerate(aus[g:g + FPS]):
            payload = b"".join(T.START4 + n for n in au)
            t = t0_us + (g + k) * 40_000
            head = bytearray(T.FRAME_HEAD)
            struct.pack_into("<QI", head, 0, t, len(payload))
            head[0x0D] = 0 if k == 0 else 1
            head[0x10] = 0 if codec == "h264" else 1
            data += head + payload + bytes(-len(payload) % 8)
            times.append(t)
        data += struct.pack("<II", 0, 0)
        out.append((bytes(data), len(times), times[0], times[-1]))
    return out


def sector(data: bytes) -> bytes:
    s = bytearray(T.FORMAT_SECTOR)
    s[:len(data)] = data
    struct.pack_into("<I", s, T.FORMAT_CRC_AT, zlib.crc32(bytes(s[:T.FORMAT_CRC_AT])))
    return bytes(s)


def main(work: str) -> int:
    os.makedirs(work, exist_ok=True)
    img = os.path.join(work, "vigi_1tb_layout.img")
    if os.path.exists(img):
        os.remove(img)
    open(img, "wb").close()
    subprocess.run(["fsutil", "sparse", "setflag", img], check=False, capture_output=True)
    truth = {}
    with open(img, "r+b") as fh:
        def put(off, data):
            fh.seek(off)
            fh.write(data)
        tag = T.TAG + b" 2.2.3"
        fmt = bytearray(0x94)
        fmt[:len(tag)] = tag
        struct.pack_into("<IQII", fmt, 0x80, T.FMT_MARKER, DISK, T.ZONE_BYTES, 0x08000000)
        put(T.FORMAT_AT, sector(bytes(fmt)))
        put(T.FORMAT_AT + T.AREA_INFO_AT, sector(struct.pack("<QQ", T.DB_AREA_AT + T.AREA_HEAD,
                                                             AREA - T.AREA_HEAD)))
        put(T.DB_AREA_AT + T.AREA_HEAD, ST.tpfile_head() + ST.database())
        for ev, ch, zone, codec, enc in CAMERAS:
            src = os.path.join(work, f"cam{ch}.{codec}")
            subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i",
                            f"testsrc2=size=1280x720:rate={FPS}:duration={SECONDS}", *enc,
                            "-f", codec if codec == "h264" else "hevc", src], check=True)
            aus = access_units(open(src, "rb").read(), codec)
            expect = b"".join(T.START4 + n for au in aus for n in au)
            base, off, index = DZ + zone * T.ZONE_BYTES, T.ZONE_INDEX_BYTES, []
            s0 = ST.T0 + ch * 5
            for k, (data, frames, t_first, t_last) in enumerate(gops(aus, codec, s0 * 1_000_000)):
                put(base + off, data)
                index.append(ST.entry(zone, ev, s0 + k, s0 + k + 1, 0, off, len(data), frames))
                off += len(data) + (-len(data) % 4096)
            put(base, b"".join(index))
            truth[f"tpl-e{ev:06d}-main"] = {"frames": len(aus), "gops": len(index), "codec": codec,
                                            "sha256": hashlib.sha256(expect).hexdigest(),
                                            "zone": zone, "zone_at": base}
        fh.truncate(DZ + 4 * T.ZONE_BYTES)
    case = os.path.join(work, "case")
    py = sys.executable
    parse = subprocess.run([py, os.path.join(ROOT, "cli.py"), "parse", "--device", img,
                            "--vendor", "TP-Link", "--out", case], capture_output=True, text=True)
    print(parse.stdout[-3000:])
    for rid, t in truth.items():
        ex = subprocess.run([py, os.path.join(ROOT, "cli.py"), "extract", "--device", img,
                             "--vendor", "TP-Link", "--recording", rid, "--out", case],
                            capture_output=True, text=True)
        out = os.path.join(case, "recordings", f"{rid}.{t['codec']}")
        if not os.path.exists(out):
            cands = [os.path.join(dp, f) for dp, _, fs in os.walk(case) for f in fs
                     if f.startswith(rid) and f.endswith(t["codec"])]
            out = cands[0] if cands else out
        got = open(out, "rb").read() if os.path.exists(out) else b""
        dec = subprocess.run(["ffmpeg", "-v", "error", "-f", "h264" if t["codec"] == "h264" else "hevc",
                              "-i", out, "-f", "framemd5", "-"], capture_output=True, text=True)
        t.update(extracted=os.path.basename(out), identical=hashlib.sha256(got).hexdigest() == t["sha256"],
                 decoded_frames=sum(1 for l in dec.stdout.splitlines() if l and not l.startswith("#")),
                 decode_errors=dec.stderr.strip()[:300], extract_rc=ex.returncode,
                 extract_tail=ex.stdout[-600:])
    print(json.dumps(truth, indent=1))
    json.dump(truth, open(os.path.join(work, "realgeo.json"), "w"), indent=1)
    return 0 if all(t["identical"] and t["decoded_frames"] == t["frames"] for t in truth.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))

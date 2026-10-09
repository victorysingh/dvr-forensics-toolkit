"""Start here: from a recorder's brand to a case on screen.

A newcomer picks the brand on the recorder's label and gets three things:
what the tool can honestly do for that brand, the steps from a drive in hand
to an opened case, and the options to add for that brand.  The UI's "Start
here" page (ui/src/screens/StartHere.jsx) renders this; nothing in it is
written twice.

Picking a brand does not tell the tool anything.  The scan scores every known
vendor from the disk itself, so a CP Plus label on a Dahua-built board, or a
wrong guess, changes nothing; the choice only sets what to expect and which
options to add.  The status shown for each brand comes from the same vendor
matrix the Vendors screen uses (report/case.py), so the guide can never claim
more than the weakest evidence behind a parser.
"""

from __future__ import annotations

from report.case import vendor_matrix

#: The same for every brand.  `{flags}` is where a brand's scan options go.
STEPS = [
    {"title": "Take the disk out",
     "what": "Power the recorder off and take its disk out. If it still runs, "
             "photograph its time settings next to a phone clock first: that is "
             "what later turns the recorder's clock into UTC. Never put the disk "
             "back in the recorder.",
     "cmd": ""},
    {"title": "Connect it read-only",
     "what": "Plug the disk in through a USB-SATA bridge (or a hardware write "
             "blocker), find it, and make the kernel refuse writes to it. The "
             "last command must print 1.",
     "cmd": "python cli.py devices\nsudo blockdev --setro /dev/sdX\nblockdev --getro /dev/sdX"},
    {"title": "One scan",
     "what": "One read of the whole disk: MD5 and SHA-256, the brand detected from "
             "the disk, the custody ledger, and footage recovered in the same "
             "pass. A 1 TB disk takes about 11 hours over USB 2.",
     "cmd": "python cli.py scan --device /dev/sdX --case CASE-001 "
            "--investigator \"Your name\"{flags}"},
    {"title": "Open it here",
     "what": "Start the console on the folder the scan wrote to. The case appears "
             "on the home page; its Vendors screen shows what was detected and how "
             "sure the detector is.",
     "cmd": "python cli.py serve --out out"},
]

#: Per brand: the scan options, what to run after the scan, and what to expect.
#: Keep `note` to what has been shown (docs/STATUS.md, VALIDATION_REPORT.md).
#: `source` is the brand card's one line: the real drive the parser has read,
#: or, with no real drive yet, what it was written from.  Whether a real drive
#: was read is not decided here but by the vendor matrix's `media`.
BRANDS = [
    {"vendor": "Dahua", "source": "read on two real drives (DHFS 4.1)",
     "flags": "--carve",
     "after": ["python cli.py parse --vendor Dahua --device /dev/sdX --out out/CASE-001",
               "python cli.py extract-carved --device /dev/sdX --out out/CASE-001"],
     "note": "DHFS 4.1 read from two real drives. --carve recovers footage outside "
             "every index (deleted or overwritten) in the same pass."},
    {"vendor": "CP Plus", "source": "read on the team's own CP Plus drive",
     "flags": "--carve",
     "after": ["python cli.py parse --vendor Dahua --device /dev/sdX --out out/CASE-001",
               "python cli.py extract-carved --device /dev/sdX --out out/CASE-001"],
     "note": "CP Plus recorders are Dahua-built and write Dahua's DHFS, so they are "
             "parsed as Dahua. Read from the team's own CP Plus drive."},
    {"vendor": "Hikvision", "source": "read on a real DS-7B08HUHI-K1's footage",
     "flags": "--carve-ps",
     "after": ["python cli.py parse --vendor Hikvision --device /dev/sdX --out out/CASE-001",
               "python cli.py hik-log --device /dev/sdX --out out/CASE-001"],
     "note": "Footage dated from Hikvision's HK stream maps, even under a drive "
             "another recorder reformatted; hik-log reads the recorder's own "
             "system log."},
    {"vendor": "Honeywell", "source": "written from published research (DFRWS 2026)",
     "flags": "--carve-annexb",
     "after": ["python cli.py parse --vendor Honeywell --device /dev/sdX --out out/CASE-001",
               "python cli.py parse --vendor Honeywell --device /dev/sdX --remnants"],
     "note": "Parser written from published research (Yoon & Hwang, DFRWS USA "
             "2026); never run on a real Honeywell disk. --carve-annexb recovers "
             "the raw video regardless."},
    {"vendor": "TP-Link", "source": "written from TP-Link's VIGI firmware",
     "flags": "--carve-annexb",
     "after": ["python cli.py parse --vendor TP-Link --device /dev/sdX --out out/CASE-001"],
     "note": "Written from TP-Link's firmware; no real disk read yet. The index is "
             "read when it is not encrypted; the footage itself comes from "
             "--carve-annexb, without dates or cameras."},
    {"vendor": "Godrej", "source": "written from Qualvision's firmware (SeeThru)",
     "flags": "--carve-annexb",
     "after": ["python cli.py parse --vendor Godrej --device /dev/sdX --out out/CASE-001"],
     "note": "Godrej's SeeThru recorders run Qualvision's software; parser written "
             "from that firmware, no real disk read yet. A disk without the QVEX "
             "head is a different maker: --carve-annexb still recovers the video."},
    {"vendor": "Uniview", "source": "written from Uniview's own storage driver",
     "flags": "",
     "after": ["python cli.py parse --vendor Uniview --device /dev/sdX --out out/CASE-001",
               "python cli.py parse --vendor Uniview --device /dev/sdX --remnants"],
     "note": "Written from Uniview's own storage driver; no real disk read yet. "
             "--remnants finds footage the index no longer lists."},
    {"vendor": "Matrix", "source": "written from Matrix's own documents",
     "flags": "",
     "after": ["python cli.py parse --vendor Matrix --device /dev/sdX --out out/CASE-001",
               "python cli.py extract --vendor Matrix --device /dev/sdX --out out/CASE-001 "
               "--recording <id from parse>"],
     "note": "Written from Matrix's own documents; no real disk read yet. Recordings "
             "come out as stored (.stm); Matrix's Device Player converts them."},
    {"vendor": "Other / not sure", "source": "scan anyway: the disk itself names the brand",
     "flags": "--carve-annexb",
     "after": ["python cli.py survey --device /dev/sdX",
               "python cli.py extract-carved --device /dev/sdX --out out/CASE-001 "
               "--format annexb"],
     "note": "Scan anyway: every known vendor is scored from the disk, so the "
             "label does not matter. HeimVision is also parsed (from a real NIST "
             "image). For anything else, --carve-annexb recovers standard "
             "H.264/H.265 with no dates or cameras, and survey maps the unknown "
             "format for a new plugin."},
]


def brand_guide() -> dict:
    """STEPS, and BRANDS each with its status from the vendor matrix."""
    matrix = {v["vendor"]: v for v in vendor_matrix()}
    brands = []
    for b in BRANDS:
        v = matrix.get(b["vendor"], {})
        brands.append(dict(b, status=v.get("parser_status", ""),
                           media=v.get("media", ""), family=v.get("family", "")))
    return {"steps": STEPS, "brands": brands}

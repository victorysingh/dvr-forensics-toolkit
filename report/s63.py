"""A draft certificate under section 63(4)(c) of the Bharatiya Sakshya
Adhiniyam, 2023, filled from what the case recorded - and nothing else.

The Supreme Court held in Arjun Panditrao Khotkar v. Kailash Kushanrao
Gorantyal (2020) that the certificate for an electronic record is mandatory
where the original is not produced; the BSA carries that forward in s.63,
and its Schedule sets the form: Part A by the party producing the record,
Part B by an expert, each stating the hash value(s) and the algorithm.

WHAT THIS FILLS, AND WHAT IT NEVER DOES
---------------------------------------
It fills the facts the tool itself recorded, each traced to its source in
the case: the device type (DVR), the recorder's and the drive's make, model
and serial, and the hash values with their algorithms, plus a hash report
to enclose.  It never makes a statement that belongs to a person: who owned,
maintained, managed or operated the device, that it was working properly,
the declarant's name, residence, signature, date, time and place.  Those
stay blank for the party and the expert to complete, or are filled only
from what they typed on the command line.

It is a DRAFT for the party or the expert to complete and sign.  The
wording was checked word for word on 29 Sep 2026 against the Schedule as
published in the Gazette of India Extraordinary, Part II Section 1, No. 55
of 25 Dec 2023 (CG-DL-E-25122023-250882, pp. 46-47; the PDF is digitally
signed by the Government of India Press), in the copy the Ministry of Home
Affairs hosts (mha.gov.in/sites/default/files/2024-04/
250882_english_01042024_0.pdf, SHA-256 13e2b6eb...039de239).  The layout
follows the printed form: tick boxes after each source and before each
algorithm, the algorithms one to a line.  The earlier wording, taken from a
bare-act site, matched; only punctuation (":—") and line breaks changed.

Stdlib only.  Reads the case directory; writes nothing itself.
"""

from __future__ import annotations

import html
import json
import os
from typing import Optional

RULE = "report.s63.v2"
WORDING_SOURCE = ("The Schedule [See section 63(4)(c)], Bharatiya Sakshya Adhiniyam 2023 (No. 47 "
                  "of 2023), Gazette of India Extraordinary, Part II Sec. 1, No. 55, 25 Dec 2023, "
                  "pp. 46-47 (CG-DL-E-25122023-250882); checked word for word 29 Sep 2026")
SOURCES = ["Computer / Storage Media", "DVR", "Mobile", "Flash Drive", "CD/DVD", "Server",
           "Cloud", "Other"]
ALGORITHMS = ["SHA1", "SHA256", "MD5"]
ROLES = ["Owned", "Maintained", "Managed", "Operated"]


def _load(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _manifest_paths(case_dir: str) -> list[str]:
    """Extraction manifests in the case folder and one folder down: `extract
    --out` may point at a subfolder (USER_MANUAL 3.4: `--out clips/`)."""
    if not os.path.isdir(case_dir):
        return []
    out = []
    for name in sorted(os.listdir(case_dir)):
        path = os.path.join(case_dir, name)
        if name.endswith(".manifest.json"):
            out.append(name)
        elif os.path.isdir(path) and name != "carve":         # carve/ has its own lists
            try:
                out += [f"{name}/{n}" for n in sorted(os.listdir(path))
                        if n.endswith(".manifest.json")]
            except OSError:
                continue
    return out


def _same_device(a: str, b: str) -> bool:
    norm = lambda p: os.path.normcase(os.path.normpath(p.replace("\\", "/")))
    return norm(a) == norm(b)


def _artefacts(case_dir: str, device: str = "", notes: Optional[list] = None) -> list[dict]:
    """Every file the case produced as footage, with the SHA-256 its own
    manifest recorded - the "electronic record/output" a court would see.
    Footage whose manifest names another source device than the case's scan
    is left out, and said so: it is not this drive's record."""
    out = []
    for manifest, sub in (("carve/extracted.json", "carve/streams"),
                          ("carve/ps_extracted.json", "carve/ps_streams"),
                          ("carve/es_extracted.json", "carve/es_streams")):
        m = _load(os.path.join(case_dir, manifest))
        for sid, v in sorted(((m or {}).get("streams") or {}).items()):
            files = v.get("files") or {v.get("file", sid): v}
            for name, f in files.items():
                if f.get("sha256"):
                    out.append({"record": f"{sub}/{name}", "bytes": f.get("bytes"),
                                "sha256": f["sha256"], "source": manifest})
    for name in _manifest_paths(case_dir):
        m = _load(os.path.join(case_dir, name)) or {}
        src = m.get("source_device") or ""
        if device and src and not _same_device(src, device):
            if notes is not None:
                notes.append(f"{name}: footage from {src}, not the scanned device - not "
                             "certified with this drive.")
            continue
        folder = name.rsplit("/", 1)[0] + "/" if "/" in name else ""
        outs = m.get("outputs") or ({m["output"]["file"]: m["output"]} if m.get("output") else {})
        for fname, f in outs.items():
            if f.get("sha256"):
                out.append({"record": folder + fname, "bytes": f.get("bytes"),
                            "sha256": f["sha256"], "source": name})
    return out


def build(case_dir: str, part: str = "B", declarant: Optional[dict] = None,
          records: str = "drive") -> dict:
    """The certificate as data: every pre-filled value with where it came from."""
    scan = _load(os.path.join(case_dir, "scan_report.json")) or {}
    rec = (_load(os.path.join(case_dir, "device_record.json")) or {}).get("observations", [])
    unit = rec[-1] if rec else {}
    dev = scan.get("device") or {}
    # A whole-drive hash only if it covers the whole drive - checked on the
    # hash itself, so a triage pass recorded before scanner.py said so is
    # caught too.
    hashes = {h["algorithm"]: h for h in scan.get("hashes", [])
              if h.get("scope") == "full_device" and dev.get("size_bytes")
              and h.get("length") == dev["size_bytes"]}
    complete = (scan.get("stats") or {}).get("complete_pass") and bool(hashes)
    notes, values, algos = [], [], set()

    if records in ("drive", "both"):
        if not complete:
            notes.append("The acquisition pass was not complete, so no whole-drive hash exists "
                         "to certify. Complete the pass before certifying the drive.")
        else:
            for a in ("sha256", "md5"):
                if a in hashes:
                    values.append({"record": "whole drive", "algorithm": a.upper(),
                                   "value": hashes[a]["value"], "bytes": hashes[a].get("length"),
                                   "source": "scan_report.json (single read-only pass)"})
                    algos.add(a.upper())
    if records in ("footage", "both"):
        arts = _artefacts(case_dir, (scan.get("device") or {}).get("path", ""), notes)
        if not arts:
            notes.append("No extracted footage with a recorded SHA-256 was found in the case.")
        for x in arts:
            values.append({"record": x["record"], "algorithm": "SHA256", "value": x["sha256"],
                           "bytes": x["bytes"], "source": x["source"]})
            algos.add("SHA256")

    ident = unit.get("identified") or {}
    recorder = " ".join(x for x in (ident.get("vendor"), unit.get("model")) if x) or None
    fields = {
        "source_ticks": ["DVR"],
        "other": None,
        "make_model": "; ".join(x for x in (
            f"recorder {recorder}" if recorder else None,
            f"drive {dev.get('model')}" if dev.get("model") and dev.get("model") != "disk image file" else None)
            if x) or None,
        "color": None,
        "serial": "; ".join(x for x in (
            f"recorder {unit['serial']}" if unit.get("serial") else None,
            f"drive {dev['serial']}" if dev.get("serial") else None) if x) or None,
        "ids": None,
        "other_information": (
            f"Case {(scan.get('case') or {}).get('case_id', '')}; drive of {dev.get('size_bytes', 0):,} "
            f"bytes acquired read-only ({dev.get('write_block_method', '')}) on "
            f"{dev.get('acquired_utc', '')}; block Merkle root "
            f"{scan.get('merkle_root', '')}; custody ledger head {scan.get('ledger_head', '')}"
            if scan else None),
        "hash_values": values,
        "algorithm_ticks": sorted(algos),
        "roles_ticked": [],                    # never ticked by the tool
    }
    provenance = {
        "source_ticks": "the evidence is a DVR/NVR hard disk (the case exists because of it)",
        "make_model": "device_record.json (examiner's reading of the unit) and scan_report.json "
                      "(the drive as the OS reported it)",
        "serial": "device_record.json and scan_report.json",
        "other_information": "scan_report.json",
        "hash_values": "see each value's source",
    }
    d = declarant or {}
    return {"rule": RULE, "wording_source": WORDING_SOURCE, "part": part.upper(),
            "status": "draft", "fields": fields, "provenance": provenance,
            "declarant": {k: d.get(k) or None for k in
                          ("name", "relation", "address", "designation", "date", "time", "place")},
            "left_to_the_declarant": [
                "name, relation, residence or employment, signature",
                "date (DD/MM/YYYY), time (IST, 24-hour), place",
                "Part A only: Owned / Maintained / Managed / Operated by me, and the statements "
                "that the device was under lawful control and working properly",
                "colour and IMEI/UIN/UID/MAC/Cloud ID of the device, which the tool did not record"],
            "notes": notes}


# ---------------------------------------------------------------------------
def form_words(text: str) -> list[str]:
    """The words of a certificate form - a rendered draft (HTML) or the
    Gazette's text - with blanks, tick boxes, markup and spacing removed, so
    the two can be compared word for word."""
    import re
    s = text.split("<h2 style='break-before:page'>Hash report", 1)[0]
    if "THE SCHEDULE" in s:
        s = s[s.index("THE SCHEDULE"):]
    s = re.sub(r"</?(i|b)>", "", s)                 # inline styling joins, it does not split
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s).replace("☐", " ").replace("☑", " ").replace(" ", " ")
    s = re.sub(r"_+", " ", s)
    s = re.sub(r"\s+([,.)])", r"\1", s)
    return s.split()


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _blank(v, width: int = 16) -> str:
    return f"<u>&nbsp;{_e(v)}&nbsp;</u>" if v else "_" * width


def _tick(on: bool) -> str:
    return "&#9745;" if on else "&#9744;"


def render(cert: dict) -> str:
    f, d, part = cert["fields"], cert["declarant"], cert["part"]
    vals = f["hash_values"]
    inline = "; ".join(f"{v['algorithm']} {v['value']}" for v in vals[:2])
    if len(vals) > 2:
        inline += f"; and {len(vals) - 2} more in the enclosed hash report"
    p: list[str] = []
    add = p.append
    add("<div class='box warn'><b>DRAFT, generated from the case record.</b> "
        f"Wording: {_e(cert['wording_source'])}. The tool filled only facts it recorded "
        "(sources in the enclosed report); every statement that belongs to a person is left "
        "for that person.</div>")
    for n in cert["notes"]:
        add(f"<div class='box bad'>{_e(n)}</div>")
    # The form as printed in the Gazette (pp. 46-47): its words, its line
    # breaks, a box after each source and before each algorithm.
    add("<p style='text-align:center'>THE SCHEDULE</p>")
    add("<p style='text-align:center'>[<i>See</i> section 63(<i>4</i>)(<i>c</i>)]</p>")
    add("<p style='text-align:center'><b>CERTIFICATE</b></p>")
    who = "Party" if part == "A" else "Expert"
    add(f"<p style='text-align:center'>PART {part}</p>"
        f"<p style='text-align:center'>(To be filled by the {who})</p>")
    add(f"<p>I, {_blank(d['name'])} (Name), Son/daughter/spouse of {_blank(d['relation'])} "
        f"residing/employed at {_blank(d['address'], 24)} do hereby solemnly affirm and "
        f"sincerely state and submit as follows:—</p>")
    if part == "A":
        add("<p>I have produced electronic record/output of the digital record taken from the "
            "following device/digital record source (tick mark):—</p>")
    else:
        add("<p>The produced electronic record/output of the digital record are obtained from "
            "the following device/digital record source (tick mark):—</p>")
    add("<p>" + " &nbsp; ".join(f"{s} {_tick(s in f['source_ticks'])}" for s in SOURCES[:4])
        + "<br>" + " &nbsp; ".join(f"{s} {_tick(s in f['source_ticks'])}" for s in SOURCES[4:])
        + "</p>")
    add(f"<p>Other: {_blank(f['other'], 40)}</p>")
    add(f"<p>Make &amp; Model: {_blank(f['make_model'])} Color: {_blank(f['color'])}<br>"
        f"Serial Number: {_blank(f['serial'])}<br>"
        f"IMEI/UIN/UID/MAC/Cloud ID{_blank(f['ids'], 20)} (as applicable)<br>"
        f"and any other relevant information, if any, about the device/digital "
        f"record{_blank(f['other_information'], 4)}(specify).</p>")
    if part == "A":
        add("<p>The digital device or the digital record source was under the lawful control "
            "for regularly creating, storing or processing information for the purposes of "
            "carrying out regular activities and during this period, the computer or the "
            "communication device was working properly and the relevant information was "
            "regularly fed into the computer during the ordinary course of business. "
            "If the computer/digital device at any point of time was not working properly or "
            "out of operation, then it has not affected the electronic/digital record or its "
            "accuracy. The digital device or the source of the digital record is:—</p>")
        add("<p>" + " &nbsp; ".join(f"{r} {_tick(False)}" for r in ROLES) + "</p>")
        add("<p>by me (select as applicable).</p>")
    add(f"<p>I state that the HASH value/s of the electronic/digital record/s is "
        f"{_blank(inline, 24)}, obtained through the following algorithm:—</p>")
    for a in ALGORITHMS:
        add(f"<p>{_tick(a in f['algorithm_ticks'])} {a}:</p>")
    add(f"<p>{_tick(False)} Other{'_' * 18} (Legally acceptable standard)</p>")
    add("<p>(Hash report to be enclosed with the certificate)</p>")
    add(f"<p style='margin-top:36px;text-align:right'>"
        f"({'Name and signature' if part == 'A' else 'Name, designation and signature'})"
        + (f" &nbsp; {_e(d['name'])}" if d["name"] else "")
        + (f", {_e(d['designation'])}" if d["designation"] and part == "B" else "") + "</p>")
    add(f"<p>Date (DD/MM/YYYY): {_blank(d['date'], 10)}</p>")
    add(f"<p>Time (IST): {_blank(d['time'], 8)}hours (In 24 hours format)</p>")
    add(f"<p>Place: {_blank(d['place'], 12)}</p>")

    add("<h2 style='break-before:page'>Hash report (enclosure)</h2>")
    add("<table><tr><th>Record</th><th>Algorithm</th><th>Value</th><th>Bytes</th>"
        "<th>Source in the case</th></tr>" + "".join(
            f"<tr><td>{_e(v['record'])}</td><td>{_e(v['algorithm'])}</td>"
            f"<td><code>{_e(v['value'])}</code></td><td>{_e(v['bytes'])}</td>"
            f"<td>{_e(v['source'])}</td></tr>" for v in vals) + "</table>")
    add("<h3>Where each pre-filled value came from</h3><table>" + "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k, v in cert["provenance"].items())
        + "</table>")
    add("<h3>Left for the declarant</h3><ul>"
        + "".join(f"<li>{_e(x)}</li>" for x in cert["left_to_the_declarant"]) + "</ul>")
    from report.html import CSS
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>Section 63 certificate (draft), Part {part}</title>"
            f"<style>{CSS}</style></head><body><main>" + "\n".join(p) + "</main></body></html>")

"""The forensic report, as one self-contained HTML file.

No scripts, no external fonts or stylesheets: it opens on an air-gapped
machine, prints cleanly, and its SHA-256 - recorded in the custody ledger
when it is written - covers everything a reader sees.

The report states limitations with the same prominence as findings.  Every
number in it is quoted from a pipeline output that the report cites by hash.
"""

from __future__ import annotations

import html
from typing import Any

from core.contract import utc_now

STATUS_TEXT = {
    "validated": "validated against real media and the recorder's own export",
    "spec_only": "written from published research and real-media observation; not yet "
                 "byte-matched against the recorder's own export",
    "synthetic_only": "tested only against a synthetic fixture",
    "detected_not_parsed": "recognised by signature; no parser",
}


def e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def size(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return ""


def hms(s: float) -> str:
    s = int(s or 0)
    return f"{s // 3600}h {s % 3600 // 60:02d}m {s % 60:02d}s"


def table(headers: list[str], rows: list[list[Any]], cls: str = "") -> str:
    if not rows:
        return "<p class='muted'>None.</p>"
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if isinstance(c, Raw) else e(c)}</td>"
                                    for c in r) + "</tr>" for r in rows)
    return f"<table class='{cls}'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


class Raw(str):
    """Pre-escaped HTML for a table cell."""


def mono(v: Any) -> Raw:
    return Raw(f"<code>{e(v)}</code>")


CSS = """
:root{--ink:#1b1f24;--muted:#5b6470;--line:#d8dde3;--bg:#fff;--accent:#1f4e79;--warn:#8a4b00;--bad:#9b1c1c;--ok:#1d6b3a}
*{box-sizing:border-box}body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);background:var(--bg);margin:0}
main{max-width:1000px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px;padding-bottom:4px;border-bottom:2px solid var(--accent);color:var(--accent)}
h3{font-size:14px;margin:18px 0 6px}
.muted{color:var(--muted)}code{font:12px/1.4 ui-monospace,Consolas,monospace;word-break:break-all}
table{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:13px}
th,td{border:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top}th{background:#f3f5f7}
dl{display:grid;grid-template-columns:220px 1fr;gap:4px 12px;margin:6px 0}dt{color:var(--muted)}dd{margin:0}
.box{border:1px solid var(--line);border-left:4px solid var(--accent);padding:10px 14px;margin:10px 0;background:#f8fafc}
.box.warn{border-left-color:var(--warn);background:#fffaf2}.box.bad{border-left-color:var(--bad);background:#fdf3f3}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}
.pill{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;border:1px solid var(--line)}
footer{margin-top:40px;font-size:12px;color:var(--muted)}
@media print{main{padding:0;max-width:none}h2{break-after:avoid}table{break-inside:auto}tr{break-inside:avoid}}
"""


def render(case: dict, examiner_notes: str = "") -> str:
    s = case.get("scan") or {}
    dev = s.get("device") or {}
    info = s.get("case") or {}
    stats = s.get("stats") or {}
    cust = case.get("custody", {})
    parts: list[str] = []
    add = parts.append

    add(f"<h1>DVR/NVR Forensic Examination Report</h1>")
    add(f"<p class='muted'>Case {e(case.get('case_id'))} &middot; generated {e(utc_now())} "
        f"by {e(s.get('tool', 'ps26150-forensics'))} {e(s.get('tool_version', ''))}</p>")

    # -- summary ---------------------------------------------------------
    add("<h2>1. Summary</h2>")
    hashes = {h["algorithm"]: h for h in s.get("hashes", [])}
    complete = stats.get("complete_pass")
    add("<dl>")
    add(f"<dt>Evidence item</dt><dd>{e(dev.get('path'))} &mdash; {size(dev.get('size_bytes'))}"
        f"{' &mdash; ' + e(dev.get('model')) if dev.get('model') else ''}</dd>")
    add(f"<dt>Acquisition</dt><dd>{'complete single pass' if complete else '<span class=bad>INCOMPLETE pass - no whole-device hash may be quoted</span>'}"
        f", {size(stats.get('bytes_read'))} read, {stats.get('bad_sectors', 0)} unreadable sector(s)</dd>")
    if complete and "sha256" in hashes:
        add(f"<dt>SHA-256 (whole device)</dt><dd>{mono(hashes['sha256']['value'])}</dd>")
        add(f"<dt>MD5 (whole device)</dt><dd>{mono(hashes.get('md5', {}).get('value'))}</dd>")
    add(f"<dt>Block Merkle root</dt><dd>{mono(s.get('merkle_root'))}</dd>")
    v = cust.get("verify", {})
    add(f"<dt>Chain of custody</dt><dd class='{'ok' if v.get('valid') else 'bad'}'>{e(v.get('message'))}</dd>")
    p = case.get("parse")
    if p:
        add(f"<dt>Filesystem</dt><dd>{e(p.get('volume_vendor'))} &mdash; {p['recordings_total']} "
            f"indexed recordings across {len(p['per_camera'])} camera(s)</dd>")
    c = case.get("carve")
    if c:
        add(f"<dt>Footage outside every index</dt><dd>{c['outside_total']} carved stream(s) "
            f"no index record accounts for</dd>")
    add("</dl>")

    # -- evidence and acquisition ----------------------------------------
    add("<h2>2. Evidence and acquisition</h2>")
    add("<dl>")
    for k, label in (("case_id", "Case ID"), ("investigator", "Examiner"),
                     ("organization", "Organisation"), ("opened_utc", "Case opened (UTC)")):
        add(f"<dt>{label}</dt><dd>{e(info.get(k))}</dd>")
    add(f"<dt>Device</dt><dd>{e(dev.get('path'))}, {dev.get('size_bytes', 0):,} bytes, "
        f"{e(dev.get('sector_size'))}-byte sectors</dd>")
    add(f"<dt>Model / serial (as reported)</dt><dd>{e(dev.get('model') or '(not reported by the bridge)')} / "
        f"{e(dev.get('serial') or '(not reported by the bridge)')}</dd>")
    wb = dev.get("write_block_method", "")
    add(f"<dt>Write blocking</dt><dd>{mono(wb)}</dd>")
    add(f"<dt>Throughput</dt><dd>{e(stats.get('throughput_mbps'))} MiB/s over {hms(stats.get('duration_s'))}</dd>")
    add(f"<dt>Examiner notes</dt><dd>{e(info.get('notes'))}</dd>")
    add("</dl>")
    add("<div class='box warn'><b>Write blocking is software, not hardware.</b> "
        + ("The kernel's block-layer read-only flag was set and verified before the device "
           "was opened, and the tool opened it read-only. " if "setro" in wb else
           "The tool opened the device read-only; the kernel read-only flag was not recorded. ")
        + "No hardware write blocker was used; this is stated so that it is not assumed.</div>")
    events = [x for x in cust.get("entries", []) if x["action"] in
              ("device_lost", "device_reconnected", "reconnect_refused",
               "reconnect_waiting_for_write_block")]
    if events:
        add("<h3>Interruptions during acquisition</h3>")
        add("<p>The device dropped off the bus during the pass. Reading resumed only on a "
            "device that was write-blocked, matched the drive's serial and size, and read "
            "back the blocks already hashed with identical SHA-256; the running hashes "
            "continued from the first unhashed byte, so they equal an uninterrupted read.</p>")
        add(table(["Time (UTC)", "Event", "Detail"],
                  [[x["ts_utc"], x["action"],
                    mono(", ".join(f"{k}={v}" for k, v in x["detail"].items()
                                   if k in ("path", "offset", "old_path", "new_path",
                                            "resume_offset", "verified_blocks",
                                            "write_block_method", "detail")))]
                   for x in events]))
    add("<h3>Hashes</h3>")
    add(table(["Algorithm", "Scope", "Value", "Bytes"],
              [[h["algorithm"], h["scope"], mono(h["value"]), f"{h.get('length') or 0:,}"]
               for h in s.get("hashes", [])]))
    add("<p class='muted'>The Merkle root is computed over the SHA-256 of every "
        f"{size(stats.get('blocks_hashed') and stats.get('block_size'))} block. Any extracted "
        "byte range can be proven to come from this device with a short inclusion proof, "
        "without re-reading the device.</p>")
    if s.get("bad_regions"):
        add("<h3>Unreadable regions</h3>")
        add(table(["Offset", "Length", "Error", "Substituted"],
                  [[f"0x{b['offset']:X}", b["length"], b["error"], b["substituted_with"]]
                   for b in s["bad_regions"]]))

    pr = case.get("preserved")
    if pr:
        add("<h3>Preserved filesystem metadata</h3>")
        add(f"<p>The drive's video is not imaged in full; its filesystem structures are "
            f"kept byte-exact as {pr['blocks']} whole scan blocks ({size(pr['bytes_saved'])}), "
            f"each re-verified against the acquisition hash when this report was generated: "
            f"<span class='{'ok' if pr['verify']['ok'] else 'bad'}'>"
            f"{'all verified' if pr['verify']['ok'] else 'VERIFICATION FAILED'}</span> "
            f"({pr['verify']['proven_to_root']} proven to the Merkle root).</p>")
        add(table(["Region", "Offset", "Length", "SHA-256", "Why"],
                  [[r["name"], f"0x{r['start']:X}", size(r["length"]), mono(r["sha256"]), r["why"]]
                   for r in pr["regions"]]))

    # -- device identification -------------------------------------------
    add("<h2>3. Device identification</h2>")
    add("<p>Vendor attribution is a confidence score from signature evidence, never a yes/no. "
        "Every OEM named in the problem statement is listed, including those not found.</p>")
    add(table(["Vendor", "Confidence on this disk", "Filesystem family", "Parser", "Parser status"],
              [[r["vendor"], f"{r['detected_confidence']:.2%}" + (f" ({r['detected_note']})" if r["detected_note"] else ""),
                r["family"], r["parser"] or "none", r["parser_status"]]
               for r in case.get("vendors", [])]))
    for d in s.get("detections", []):
        add(f"<p class='muted'><b>{e(d['vendor'])}</b> evidence: " +
            "; ".join(e(x) for x in d.get("evidence", [])) + "</p>")

    # -- filesystem ------------------------------------------------------
    if p:
        add("<h2>4. Filesystem and recordings</h2>")
        add(f"<p>Parser {mono(p['parser_rule'])}, status <b>{e(p['validation_status'])}</b>: "
            f"{e(STATUS_TEXT.get(p['validation_status'], ''))}.</p>")
        add(table(["", ""], [[a, b] for a, b in p.get("summary", [])]))
        add(table(["Camera", "Indexed recordings"], sorted(p["per_camera"].items())))
        for n in p.get("notes", []):
            add(f"<p class='muted'>&bull; {e(n)}</p>")

    # -- recovery --------------------------------------------------------
    if c:
        add("<h2>5. Recovered footage</h2>")
        st = c.get("stats") or {}
        add(f"<p>Every validated DHAV frame on the drive was carved without using the "
            f"filesystem index ({st.get('frames', 0):,} frames), grouped into streams by "
            f"byte contiguity and stream continuity, and only then labelled against the "
            f"index. Where continuity was ambiguous the carve split rather than guessed "
            f"({st.get('ambiguous_splits', 0)} splits).</p>")
        add(table(["Label", "Streams", "Frames", "Bytes"],
                  [[k, v["streams"], f"{v['frames']:,}", size(v["bytes"])]
                   for k, v in sorted(c["labels"].items())]))
        add("<div class='box'><b>outside_index</b> means no index record accounts for those "
            "frames at their recorded dates: footage the recorder's own index no longer "
            "describes (overwritten, deleted, or from an earlier recording period). Its "
            "camera cannot be established from the frames themselves.</div>")
        add(table(["Stream", "Offset", "Frames", "First frame (recorder clock)", "Duration"],
                  [[r["id"], f"0x{r['offset']:X}", f"{r['frame_count']:,}",
                    r["timestamps"][0]["raw_value"].split(" = ", 1)[-1] if r.get("timestamps") else "",
                    hms(r.get("duration_s"))]
                   for r in c["outside_index"][:100]]))
        if c["outside_total"] > 100:
            add(f"<p class='muted'>&hellip; {c['outside_total'] - 100} more in the carve report "
                f"(SHA-256 {e(c['sha256'])}).</p>")

    # -- timeline --------------------------------------------------------
    t = case.get("timeline")
    if t:
        add("<h2>6. Timeline</h2>")
        add(f"<div class='box'><b>Clock rule:</b> {e(t['clock']['rule'])}"
            + (f"<br><b>Clock error source:</b> {e(t['clock']['drift_source'])}"
               if t['clock'].get('drift_source') else "") + "</div>")
        add(table(["Camera", "Files", "First", "Last", "Covered", "Gaps"],
                  [[k, v["recordings"], v["first_local"], v["last_local"], hms(v["covered_s"]),
                    v["gaps"]] for k, v in sorted(t["cameras"].items())]))
        if t.get("gaps"):
            add("<h3>Recording gaps</h3>")
            add(table(["Camera", "From", "To", "Length", "Shared with"],
                      [[g["camera"], g["start_local"], g["end_local"], hms(g["duration_s"]),
                        ", ".join(g.get("shared_with", [])) or "-"] for g in t["gaps"][:200]]))
        if t.get("correlations"):
            add("<h3>Cross-camera correlation</h3>")
            add(table(["Finding", "From", "To", "Detail"],
                      [[x["kind"], x.get("start_local", ""), x.get("end_local", ""), x["detail"]]
                       for x in t["correlations"][:200]]))
        if t.get("anomalies"):
            add("<h3>Anomalies</h3>")
            add(table(["Kind", "Item", "Detail"],
                      [[x["kind"], x.get("id", x.get("camera", "")), x["detail"]]
                       for x in t["anomalies"][:200]]))
        for n in t.get("notes", []):
            add(f"<p class='muted'>&bull; {e(n)}</p>")

    # -- custody ---------------------------------------------------------
    add("<h2>7. Chain of custody</h2>")
    add(f"<p>Append-only ledger; each entry carries the SHA-256 of the previous one. "
        f"Verification: <span class='{'ok' if v.get('valid') else 'bad'}'>{e(v.get('message'))}</span>. "
        f"Head {mono(cust.get('head'))}.</p>")
    add(table(["#", "Time (UTC)", "Actor", "Action", "Data hash"],
              [[x["seq"], x["ts_utc"], x["actor"], x["action"],
                mono(x["data_hash"][:16] + "…") if x.get("data_hash") else ""]
               for x in cust.get("entries", [])]))

    # -- limitations -----------------------------------------------------
    add("<h2>8. Limitations and validation status</h2>")
    add("<div class='box warn'><ul>"
        "<li>No parser in this report is <b>validated</b>. That status requires a byte-for-byte "
        "match between recovered footage and the recorder's own native export, which has not "
        "been performed.</li>"
        "<li>Recorder timestamps are the device's own wall clock. Conversion to UTC relies on the "
        "zone and clock error stated in section 6; without them no UTC is asserted.</li>"
        "<li>Carved footage outside the index cannot be attributed to a camera from the frame "
        "data alone.</li>"
        "<li>Vendor names for OEM-rebadged recorders (e.g. CP Plus on Dahua DHFS) rest on the "
        "seized unit, not on the platter.</li>"
        "<li>The drive was not imaged in full; the whole-device hashes, per-block hash map and "
        "preserved metadata allow any extracted range to be verified against the original, "
        "which must be retained sealed.</li>"
        "</ul></div>")
    if examiner_notes:
        add(f"<h3>Examiner notes</h3><p>{e(examiner_notes)}</p>")
    add("<h3>Inputs to this report</h3>")
    inputs = dict(case.get("files", {}))
    for k in ("parse", "carve", "timeline"):
        if case.get(k) and case[k].get("sha256"):
            inputs[case[k].get("file", k)] = case[k]["sha256"]
    if pr:
        inputs["preserved/manifest.json"] = pr["manifest_sha256"]
    add(table(["File", "SHA-256"], [[k, mono(v)] for k, v in inputs.items()]))
    add("<footer>Section 63 (Bharatiya Sakshya Adhiniyam, 2023) certificate: the prescribed "
        "format is being confirmed and is not generated by this version.</footer>")

    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Forensic Report {e(case.get('case_id'))}</title><style>{CSS}</style></head>"
            f"<body><main>{''.join(parts)}</main></body></html>")

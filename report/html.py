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

    md = case.get("model")
    if md:
        add("<h3>Recorder model</h3>")
        add("<p>Two sources, kept apart: what the examiner read off the unit, and model-numbered "
            "strings found on the platter. A string on the platter shows the text is on this "
            "disk, not that the disk was seized from that model.</p>")
        if md["observations"]:
            add(table(["Model", "Identified as", "Serial", "Firmware", "Read from", "Photos"],
                      [[o["model"],
                        (f"{o['identified']['vendor']} {o['identified']['kind']}"
                         if o.get("identified") else "unknown numbering"),
                        o.get("serial") or "", o.get("firmware") or "",
                        o.get("read_from") or "",
                        "; ".join(f"{p['file']} {p['sha256'][:16]}…" for p in o.get("photo") or [])]
                       for o in md["observations"]]))
        pl = md.get("platter")
        if pl:
            sr = pl["searched"]
            add(f"<p class='muted'>Platter searched: {size(sr['bytes'])} in {sr['blocks']} blocks "
                f"({e(sr['rule'])}).</p>")
            if pl["candidates"]:
                add(table(["String", "Vendor", "Kind", "Count", "First offset"],
                          [[c["model"], c["vendor"], c["kind"], c["count"],
                            mono(f"0x{c['offsets'][0]:X}")] for c in pl["candidates"][:20]]))
        add(table(["Check", "Verdict", "Detail"],
                  [[c["check"], c["verdict"], c["detail"]] for c in md["checks"]]))

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
        ex = (c.get("extracted") or {}).get("streams", {})
        if ex:
            add("<h3>Recovered footage saved as files</h3>")
            add("<p>Each stream's frames were copied out from its own disk extents, "
                "re-validated frame by frame, and hashed. <code>.dav</code> keeps the "
                "recorder's container; the second file is the bare video stream.</p>")
            add(table(["Stream", "Label", "Frames", "File", "Size", "SHA-256"],
                      [[k, v["label"], f"{v['frames_written']:,}" +
                        ("" if v["frames_match"] else f" (carve: {v['frames_carved']:,})"),
                        fname, size(f["bytes"]), mono(f["sha256"])]
                       for k, v in sorted(ex.items()) for fname, f in v["files"].items()]))
        if c["outside_total"] > 100:
            add(f"<p class='muted'>&hellip; {c['outside_total'] - 100} more in the carve report "
                f"(SHA-256 {e(c['sha256'])}).</p>")

    ps = case.get("ps_carve")
    if ps:
        add("<h2>5b. Recovered MPEG Program Stream footage</h2>")
        add(f"<p>Every MPEG-2 Program Stream pack on the drive was checked by structure — "
            f"accepted only where its packets end exactly on the next pack header — and "
            f"contiguous packs chained into streams, split where the pack clock jumps. No "
            f"filesystem index was used. {ps['streams_total']:,} streams, "
            f"{size(ps['bytes'])}, {hms(ps['duration_s'])} of footage; video "
            f"{', '.join(ps['stream_types']) or '?'}; {ps['hk_streams']:,} carry Hikvision "
            f"'HK' stream-map descriptors.</p>")
        if ps["dated"]:
            add(f"<p>{ps['dated']:,} streams dated from the 'HK' descriptor (the recorder's "
                f"own clock, zone unknown): {e(ps['first_local'])} to {e(ps['last_local'])}.</p>")
            add(table(["Month", "Streams"], sorted(ps["by_month"].items())))
        pl = ps.get("labels")
        if pl:
            add(f"<h3>Cameras from the surviving Hikvision index</h3><p>{pl['index_records']} "
                f"HIKBTREE records survived the reformat ({len(pl['index_headers'])} identical "
                f"copies near the end of the disk). A stream is given a camera only when its "
                f"data block has a record whose window contains the stream's own recorder "
                f"times; older footage left in a reused block is outside_index.</p>")
            add(table(["Label", "Streams"], list(pl["tally"].items())))
        add(table(["Stream", "Camera", "Offset", "Size", "Duration", "From (recorder clock)", "To"],
                  [[r["id"], r.get("label") or "-", f"0x{r['offset']:X}", size(r["bytes"]),
                    hms(r["duration_s"]), r.get("time_first_local") or "-",
                    r.get("time_last_local") or "-"]
                   for r in ps["streams"][:100]]))
        if ps["streams_total"] > 100:
            add(f"<p class='muted'>&hellip; {ps['streams_total'] - 100:,} more in the carve "
                f"report (SHA-256 {e(ps['sha256'])}).</p>")
        pex = (ps.get("extracted") or {}).get("streams", {})
        if pex:
            add(f"<h3>Saved as files ({len(pex):,})</h3><p class='muted'>Each file is the "
                f"stream's bytes copied unmodified — a playable Program Stream.</p>")
            add(table(["Stream", "File", "Size", "SHA-256"],
                      [[k, v["file"], size(v["bytes"]), mono(v["sha256"])]
                       for k, v in sorted(pex.items())[:200]]))

    es = case.get("es_carve")
    if es:
        add("<h2>5c. Raw H.264/H.265 carved without a parser</h2>")
        add(f"<p>The last resort for a recorder whose format has no parser: streams found by "
            f"their parameter sets alone. {es['streams_total']:,} streams, "
            f"{size(es['bytes'])}. Status <b>{e(es['validation_status'])}</b>.</p>")
        add("<p><b>What these are not.</b> They carry no date and no camera. Bytes of the "
            "unknown container sit between their frames: the footage plays, but it is not "
            "the recorder's bitstream byte for byte. Two cameras with identical settings "
            "interleaved on the disk may share a stream.</p>")
        add(table(["Stream", "Codec", "Picture", "Offset", "Size", "Slices", "Keyframes"],
                  [[r["id"], r["codec"], f"{r['width']}x{r['height']}", f"0x{r['offset']:X}",
                    size(r["bytes"]), r["slices"], r["keyframes"]]
                   for r in es["streams"][:100]]))
        ex = (es.get("extracted") or {}).get("streams", {})
        if ex:
            add(table(["Stream", "File", "Size", "SHA-256"],
                      [[k, v["file"], size(v["bytes"]), mono(v["sha256"])]
                       for k, v in sorted(ex.items())[:200]]))

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
        if t.get("index_coverage"):
            add("<h3>Recorded (per the index) vs recovered (by carving)</h3>")
            add(table(["Camera", "Index blocks", "Recorded from", "to", "Recorded", "Recovered"],
                      [[k, v["blocks"], v["first"], v["last"], hms(v["recorded_s"]),
                        f"{v['recovered_share']:.1%}" if v.get("recovered_share") is not None else "-"]
                       for k, v in t["index_coverage"].items()]))
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

    a = case.get("activity")
    if a:
        add("<h2>6a. Motion activity — lead, not evidence</h2>")
        add("<div class='box warn'>Computed from compressed frame sizes (P-frame bytes per "
            "camera per minute); no video was decoded. P-frames also grow with low-light "
            "noise, lighting changes, infrared switching, rain and camera shake. A peak "
            "marks footage worth reviewing. It is <b>not</b> evidence that anything "
            "happened.</div>")
        add(table(["Camera", "Minutes", "Median P-frame bytes / minute"],
                  [[k, v["minutes"], size(v["median_p_bytes_per_minute"])]
                   for k, v in sorted(a["cameras"].items())]))
        if a["multi_camera_peaks"]:
            add("<h3>Minutes with peaks on several cameras</h3><p class='muted'>Seen from "
                "several viewpoints at once — or a recorder-wide cause such as a lighting "
                "or infrared change. Stated as a coincidence, not an explanation.</p>")
            add(table(["Minute (recorder clock)", "Cameras", "Local index"],
                      [[x["minute"], ", ".join(x["cameras"]),
                        ", ".join(f"{k} {v:.1f}x" for k, v in x["local_indices"].items())]
                       for x in a["multi_camera_peaks"][:50]]))
        add(f"<h3>Strongest peaks ({a['peaks_total']} camera-minutes at "
            f"&ge; {a['peak_factor']}x the surrounding hour)</h3>")
        add(table(["Camera", "Minute (recorder clock)", "Local index", "vs whole period"],
                  [[p["camera"], p["minute"], f"{p['local_index']:.1f}x",
                    f"{p['index']:.1f}x" if p.get("index") is not None else "-"]
                   for p in a["peaks"][:25]]))

    an = case.get("analytics")
    if an:
        add("<h2>6b. Video analytics — leads, not evidence</h2>")
        add("<div class='box warn'>Optional layer, run on extracted clips: face "
            "<b>detection</b> (no identification — there is no face recognition in this "
            "tool) and object detection. Scores are the models' own confidence, not the "
            "probability a detection is correct. Each row is a moment to review in the "
            "footage itself.</div>")
        add(table(["Model", "Licence", "SHA-256"],
                  [[m["name"], m["license"], mono(m["sha256"])] for m in an["models"].values()]))
        add(f"<p>{an['clips']} clips, {an['frames_analysed']:,} frames analysed. Frames with: "
            + (", ".join(f"{e(k)} {v}" for k, v in sorted(an["totals"].items())) or "none")
            + ".</p>")
        add(table(["Clip", "Offset in clip (s)", "Detections"],
                  [[h["clip"], h["t_s"], ", ".join(f"{d['label']} {d['score']:.2f}"
                                                  for d in h["detections"])]
                   for h in an["top"][:30]]))

    osd = case.get("osd")
    if osd:
        s = osd["summary"]
        lay = osd.get("layout") or {}
        add("<h2>6c. Burned-in OSD — camera titles and the recorder's clock</h2>")
        add("<div class='box warn'>Optional layer. A title here is <b>OCR of pixels</b>, not a "
            "decoded field: it is the channel name the recorder painted into the picture, read "
            "by a machine, and it carries the share of sampled frames that agreed. It names a "
            "camera and identifies no person. Confirm any label in the frame itself.</div>")
        add(f"<p>{s.get('streams_named_by_the_picture', 0)} of {s.get('streams', 0)} streams "
            f"were named by the picture, from {osd.get('frames_per_stream')} sampled frames each"
            + (f"; the title reads in the <b>{e((lay.get('title') or {}).get('band', '?'))}</b> "
               f"band and the clock in the <b>{e((lay.get('clock') or {}).get('band', '?'))}</b> "
               "band of this recorder's picture" if lay else "") + ".</p>")
        if s.get("titles"):
            add(table(["Title read from the picture", "Streams"],
                      [[k, v] for k, v in s["titles"].items()]))
        add("<h3>Clock in the picture vs the date in the container</h3>")
        add("<p>Both are the recorder's own wall clock reached by different routes, so they "
            "should agree. A disagreement means one of the two is wrong, and this does not "
            "decide which. Neither is UTC: see section 6 for the clock model.</p>")
        add("<p>" + (", ".join(f"{e(k)}: {v}" for k, v in s.get("clock_checks", {}).items())
                     or "nothing compared") + ".</p>")
        if osd.get("clock_disagreements"):
            add(table(["Clip", "Picture − container (s)", "Detail"],
                      [[d["clip"], f"{d['offset_s']:+.0f}" if d.get("offset_s") is not None else "-",
                        d.get("detail") or ""] for d in osd["clock_disagreements"]]))
        if osd.get("named"):
            add(table(["Clip", "Title", "Confidence", "Frames agreeing", "Clock check"],
                      [[n["clip"], n["title"], f"{n['confidence']:.2f}", n["frames"],
                        n.get("clock") or "-"] for n in osd["named"][:30]]))

    rl = case.get("recorder_log")
    if rl:
        s, m = rl["summary"], rl.get("master") or {}
        add("<h2>6d. The recorder's own log</h2>")
        add(f"<p>The recorder's system log, read from the log area its master sector names "
            f"(0x{rl['log_area'][0]:X}-0x{rl['log_area'][1]:X}; master copy at "
            f"0x{m.get('offset', 0):X}, <code>{e(m.get('fs_version', ''))}</code>, initialised "
            f"{e(rl.get('init_time_local') or '?')}). {s['records']:,} records, "
            f"{e(s['first_local'])} to {e(s['last_local'])}; {s['defined_by_the_sdk']:,} carry a "
            f"code Hikvision's SDK names, the rest are reported as undefined. Status "
            f"<b>{e(rl.get('status') or '')}</b>. {e(rl.get('time_basis') or '')}.</p>")
        add(table(["Master-sector check", "Result"],
                  [[c["check"] + (f" ({c['detail']})" if c.get("detail") else ""),
                    {True: "agrees", False: "DIFFERS", None: "not checked"}[c["ok"]]]
                   for c in rl.get("checks", [])]))
        cv = rl.get("clock_vs_footage")
        if cv:
            add(f"<div class='box'><b>Which clock the log keeps:</b> {e(cv['verdict'])} - "
                f"{cv['followed_by_a_stream']} of {cv['power_on_records']} power-on records are "
                f"followed by a new stream within {cv['window_s']} s at no shift, "
                f"{cv['next_best']} at the best other half-hour shift.</div>")
        p = s.get("power", {})
        add(f"<p><b>Power:</b> {p.get('power on', 0)} power-on, {p.get('abnormal shutdown', 0)} "
            f"abnormal shutdown, {p.get('power off', 0)} orderly power-off.</p>")
        tl = case.get("timeline") or {}
        cuts = [x for x in tl.get("correlations", []) if x["kind"] == "power_cut"]
        quiet = [x for x in tl.get("correlations", []) if x["kind"] == "silence_not_in_log"]
        if cuts or quiet:
            add(f"<p>{len(cuts)} of {len(cuts) + len(quiet)} periods in which every camera was "
                f"silent for over a minute, inside the log's period, are explained by a logged "
                f"power cut (section 6).</p>")
            add(table(["Every camera silent from", "to", "Length", "Power-on logged",
                       "Abnormal shutdown logged"],
                      [[x["start_local"], x["end_local"], hms(x["duration_s"]),
                        x.get("power_on_local") or "not in the log",
                        x.get("abnormal_shutdown_local") or "-"] for x in (cuts + quiet)[:100]]))
        if s.get("user_actions"):
            add("<h3>Actions by a named user</h3>")
            add(table(["Time (recorder clock)", "User", "Action"],
                      [[a["time_local"], a["user"], a["type"]] for a in s["user_actions"][:200]]))
        add(table(["Event", "Records"], [[k, f"{v:,}"] for k, v in
                                          list(s.get("by_type", {}).items())[:15]]))
        for n in rl.get("notes", []):
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
        "data alone: the DHAV channel byte is 0 for every camera. Where the recorder burned the "
        "channel title into the picture, section 6c reads it — as a lead from OCR, never as a "
        "decoded field.</li>"
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
    if c and c.get("extracted"):
        inputs["carve/extracted.json"] = c["extracted"]["sha256"]
    if a:
        inputs["activity.json"] = a["sha256"]
    if an:
        inputs["analytics/analytics.json"] = an["sha256"]
    if osd:
        inputs["analytics/osd.json"] = osd["sha256"]
    if ps:
        inputs["carve/ps_report.json"] = ps["sha256"]
        if ps.get("labels"):
            inputs["carve/ps_labels.json"] = ps["labels"]["sha256"]
        if ps.get("extracted"):
            inputs["carve/ps_extracted.json"] = ps["extracted"]["sha256"]
    add(table(["File", "SHA-256"], [[k, mono(v)] for k, v in inputs.items()]))
    add("<footer>Section 63 (Bharatiya Sakshya Adhiniyam, 2023) certificate: a draft of Part A "
        "or Part B, filled from this case's own hashes and device record, is produced by "
        "<code>cli.py certificate</code>; its wording is to be checked against the Gazette "
        "text before use.</footer>")

    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Forensic Report {e(case.get('case_id'))}</title><style>{CSS}</style></head>"
            f"<body><main>{''.join(parts)}</main></body></html>")


def render_combined(view: dict) -> str:
    """The combined view across recorders, as a page for the demo.

    Deliberately not a forensic report: it cites each case's report rather
    than restating it, and its first statement is always whether these
    recorders may be read on one axis at all.
    """
    ax = view.get("axis", {})
    shared = ax.get("shared")
    parts: list[str] = []
    add = parts.append

    add(f"<h1>{e(view.get('title') or 'Combined view')}</h1>")
    add(f"<p class='muted'>{len(view.get('cases', []))} recorders &middot; generated "
        f"{e(view.get('generated_utc') or utc_now())}</p>")

    add(f"<div class='box {'' if shared else 'warn'}'><b>"
        f"{'One UTC axis' if shared else 'Separate axes — these recorders are not aligned'}"
        f".</b> {e((ax.get('reason') or '')[:1].upper() + (ax.get('reason') or '')[1:])}</div>")
    if ax.get("needs"):
        add("<p><b>To place these recorders on one axis, each of these is needed:</b></p><ul>"
            + "".join(f"<li>{e(n)}</li>" for n in ax["needs"]) + "</ul>")
    if ax.get("caveats"):
        add("<p class='muted'><b>Caveats:</b></p><ul class='muted'>"
            + "".join(f"<li>{e(n)}</li>" for n in ax["caveats"]) + "</ul>")

    t = view.get("totals", {})
    add("<h2>1. Across the case</h2>")
    add(table(["Recorders", "Lanes", "Events", "Hours recovered", "Acquired", "Gaps", "Anomalies"],
              [[t.get("recorders"), t.get("lanes"), f"{t.get('events', 0):,}",
                f"{t.get('hours_recovered', 0):,.1f}", size(t.get("bytes_acquired")),
                t.get("gaps"), t.get("anomalies")]]))
    add("<p class='muted'>Totals add up what was recovered from several devices. They "
        "summarise the case, not anything that happened at the premises.</p>")

    add("<h2>2. The recorders</h2>")
    add(table(["Case", "Device", "Serial", "Size", "Complete pass", "Lanes", "Events",
               "Span (recorder clock)", "Span (UTC)"],
              [[c["case_id"], c["device"].get("model") or c["device"].get("path") or "-",
                c["device"].get("serial") or "-", size(c["device"].get("size_bytes")),
                "yes" if c.get("complete_pass") else "NO",
                len(c["lanes"]), f"{c['events']:,}",
                f"{c['span_local']['first'] or '?'} → {c['span_local']['last'] or '?'}",
                (f"{c['span_utc']['first']} → {c['span_utc']['last']}"
                 if c["span_utc"]["first"] else "not asserted")]
               for c in view.get("cases", [])]))

    for c in view.get("cases", []):
        add(f"<h3>{e(c['case_id'])} — lanes</h3>")
        add(f"<p class='muted'>Clock: {e((c.get('clock') or {}).get('rule'))}</p>")
        add(table(["Lane", "Recordings", "First (recorder clock)", "Last", "Hours", "Gaps"],
                  [[name, v["recordings"], v["first_local"], v["last_local"],
                    f"{v['hours']:,.1f}", v["gaps"]]
                   for name, v in c["lanes"].items()]))

    add("<h2>3. Recorders running at the same time</h2>")
    if not shared:
        add("<p class='muted'>Not determined: the recorders are on separate axes, so no "
            "statement about simultaneity is available. See the top of this page.</p>")
    elif not view.get("overlaps"):
        add("<p class='muted'>No two recorders hold footage covering the same period.</p>")
    else:
        add(table(["Recorders", "From (UTC)", "To (UTC)", "Duration"],
                  [[" + ".join(o["cases"]), o["from_utc"], o["to_utc"],
                    f"{o['duration_s'] / 3600:,.1f} h"] for o in view["overlaps"]]))
        add("<p class='muted'>That two recorders were both running is a fact about the "
            "premises. What either of them saw is not decided here.</p>")

    add("<h2>4. Notes and inputs</h2>")
    add("<div class='box warn'><ul>"
        + "".join(f"<li>{e(n)}</li>" for n in view.get("notes", [])) + "</ul></div>")
    add(table(["Case timeline", "SHA-256"],
              [[k, mono(v)] for k, v in (view.get("inputs") or {}).items()]))
    add("<footer>This page cites each case's own report and timeline; it restates "
        "nothing. Each recorder's findings, hashes and chain of custody live in that "
        "case's report.</footer>")

    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{e(view.get('title') or 'Combined view')}</title>"
            f"<style>{CSS}</style></head>"
            f"<body><main>{''.join(parts)}</main></body></html>")

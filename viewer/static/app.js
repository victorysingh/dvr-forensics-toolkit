"use strict";
// PS26150 UI - a read-only viewer over the pipeline's outputs.  Every value
// shown is quoted from a file the pipeline wrote; nothing is computed here
// that the report does not also state.

const $ = (s, r = document) => r.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const size = (n) => {
  n = Number(n || 0);
  for (const u of ["B", "KB", "MB", "GB", "TB"]) {
    if (n < 1024 || u === "TB") return u === "B" ? `${n} B` : `${n.toFixed(2)} ${u}`;
    n /= 1024;
  }
};
const hms = (s) => { s = Math.round(s || 0); return `${Math.floor(s / 3600)}h ${String(Math.floor(s % 3600 / 60)).padStart(2, "0")}m`; };
const pill = (s) => `<span class="pill s-${esc(s || "none")}">${esc(s || "none")}</span>`;
const hex = (n) => "0x" + Number(n || 0).toString(16).toUpperCase();
const localOf = (claim) => (claim?.raw_value || "").split(" = ").pop().replace(" recorder-local", "");

const state = { cases: [], caseId: null, case: null, vendors: null, tab: "overview", tlFull: false, timer: null };

async function api(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

function table(headers, rows, scroll = false) {
  if (!rows.length) return `<p class="muted">None.</p>`;
  const t = `<table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  return scroll ? `<div class="scroll">${t}</div>` : t;
}

// ---------------------------------------------------------------- pipeline
function renderPipeline() {
  const c = state.case || {};
  const scan = c.scan, prog = c.in_progress;
  const st = (cond, part) => (cond ? "done" : part ? "part" : "");
  const stages = [
    ["Acquire", scan ? `hashed ${size(scan.stats?.bytes_read)}` : prog ? `${(prog.fraction * 100).toFixed(1)}% read` : "not started",
      scan ? (scan.stats?.complete_pass ? "done" : "part") : prog ? "run" : ""],
    ["Identify", scan?.detections?.length ? `${scan.detections[0].vendor} ${(scan.detections[0].confidence * 100).toFixed(1)}%` : "with acquisition",
      scan ? "done" : prog ? "run" : ""],
    ["Parse", c.parse ? `${c.parse.recordings_total} recordings` : "pending", st(c.parse)],
    ["Recover", c.carve ? `${c.carve.outside_total} outside index` : prog ? "carving inline" : "pending",
      c.carve ? "done" : prog ? "run" : ""],
    ["Timeline", c.timeline ? `${Object.keys(c.timeline.cameras || {}).length} cameras` : "pending", st(c.timeline)],
    ["Report", scan ? "ready to generate" : "needs acquisition", scan ? "done" : ""],
    ["Analytics", c.activity ? `motion: ${c.activity.peaks_total} peaks (lead)` : "motion from frame sizes; AI add-on pending",
      c.activity ? "part" : "addon"],
  ];
  $("#pipeline").innerHTML = stages.map(([t, d, cls], i) =>
    `<div class="stage ${cls}"><div class="t">${i + 1}. ${t}</div><div class="d">${esc(d)}</div></div>`).join("");
}

// ---------------------------------------------------------------- overview
function viewOverview() {
  const c = state.case;
  if (!c) return `<p class="muted">No cases in out/. Run <code>cli.py scan</code> first.</p>`;
  const s = c.scan, p = c.in_progress;
  let h = "";
  if (!s && p) {
    const left = p.size_bytes - p.bytes_done;
    h += `<h2>Acquisition in progress</h2><div class="card">
      <div class="k">single read-only pass: hashing + inline carve</div>
      <div class="progress"><i style="width:${(p.fraction * 100).toFixed(2)}%"></i></div>
      <div>${size(p.bytes_done)} of ${size(p.size_bytes)} (${(p.fraction * 100).toFixed(2)}%) · ${size(left)} left · updated ${esc(p.updated_utc)}</div>
      <p class="muted">Whole-device MD5/SHA-256 exist only once the single pass completes. This view refreshes automatically.</p></div>`;
  }
  const hs = Object.fromEntries((s?.hashes || []).map((x) => [x.algorithm, x.value]));
  const top = (s?.detections || [])[0];
  h += `<h2>Case ${esc(c.case_id || c.id)}</h2><div class="grid">
    <div class="card"><div class="k">Evidence</div><div class="v">${size(s?.device?.size_bytes || p?.size_bytes)}</div>
      <p class="muted">${esc(s?.device?.path || "")}</p></div>
    <div class="card"><div class="k">Write blocking</div><div class="v small"><code>${esc(s?.device?.write_block_method || c.custody?.entries?.[0]?.detail?.write_block_method || "-")}</code></div>
      <p class="muted">software write block; no hardware blocker claimed</p></div>
    <div class="card"><div class="k">Chain of custody</div><div class="v small ${c.custody?.verify?.valid ? "ok" : "bad"}">${esc(c.custody?.verify?.message)}</div>
      <p class="muted">${c.custody?.entries?.length || 0} ledger entries</p></div>
    <div class="card"><div class="k">Vendor</div><div class="v">${esc(top ? top.vendor : "-")}</div>
      <p class="muted">${top ? `${(top.confidence * 100).toFixed(2)}% signature confidence · ${pill(top.validation_status)}` : "pending acquisition"}</p></div>
    <div class="card"><div class="k">Indexed recordings</div><div class="v">${c.parse ? c.parse.recordings_total.toLocaleString() : "-"}</div>
      <p class="muted">${c.parse ? Object.entries(c.parse.per_camera).map(([k, v]) => `${k}: ${v}`).join(" · ") : "run parse"}</p></div>
    <div class="card"><div class="k">Footage outside every index</div><div class="v">${c.carve ? c.carve.outside_total : "-"}</div>
      <p class="muted">${c.carve ? `${(c.carve.stats?.frames || 0).toLocaleString()} frames carved without the index` : "carved during acquisition"}</p></div>
  </div>`;
  if (s) {
    h += `<h2>Integrity</h2><div class="card"><dl class="kv">
      <dt>SHA-256 (whole device)</dt><dd><code>${esc(s.stats?.complete_pass ? hs.sha256 : "not quotable - incomplete pass")}</code></dd>
      <dt>MD5 (whole device)</dt><dd><code>${esc(s.stats?.complete_pass ? hs.md5 : "-")}</code></dd>
      <dt>Block Merkle root</dt><dd><code>${esc(s.merkle_root)}</code></dd>
      <dt>Blocks / bad sectors</dt><dd>${s.stats?.blocks_hashed?.toLocaleString()} × ${size(s.stats?.block_size)} · ${s.stats?.bad_sectors} unreadable</dd>
      ${c.preserved ? `<dt>Preserved metadata</dt><dd>${c.preserved.blocks} blocks (${size(c.preserved.bytes_saved)}) · <span class="${c.preserved.verify.ok ? "ok" : "bad"}">${c.preserved.verify.ok ? "re-verified against the acquisition" : "VERIFICATION FAILED"}</span></dd>` : ""}
    </dl></div>`;
  }
  return h;
}

// ---------------------------------------------------------------- vendors
function viewVendors() {
  const v = state.vendors;
  if (!v) return `<p class="muted">Loading…</p>`;
  const onCase = Object.fromEntries((state.case?.vendors || []).map((r) => [r.vendor, r]));
  let h = `<h2>OEM coverage - all eight vendors named in the problem statement</h2>
    <div class="note">Detection runs for every vendor on every disk. A parser exists where the platter's structures are understood; its status is the <b>weakest</b> evidence behind it. No vendor is shown as supported beyond what has been demonstrated.</div>
    <div class="grid">`;
  for (const r of v.vendors) {
    const conf = onCase[r.vendor]?.detected_confidence || 0;
    h += `<div class="card vcard">
      <div class="hd"><span class="vn">${esc(r.vendor)}</span>${pill(r.parser_status)}</div>
      <div class="row">Family <b>${esc(r.family)}</b></div>
      <div class="row">Parser <b>${esc(r.parser || "none - plugin slot open")}</b> · ${r.signatures} signature(s)</div>
      <div class="row">Real media <b>${esc(r.media)}</b></div>
      <div class="row">On this case <b>${state.case?.scan ? (conf * 100).toFixed(2) + "%" : "-"}</b>${onCase[r.vendor]?.detected_note ? ` · ${esc(onCase[r.vendor].detected_note)}` : ""}</div>
      <div class="meter"><i style="width:${(conf * 100).toFixed(1)}%"></i></div>
      <div class="row">${esc(r.basis)}</div></div>`;
  }
  h += `</div><h2>Adding a vendor - the plug-in pipeline</h2><div class="flow">`;
  v.onboarding.forEach((s, i) => {
    h += `<div class="st"><div class="n">step ${i + 1} · <code>${esc(s.tool)}</code></div><div class="h">${esc(s.step)}</div>
      <p>${esc(s.what)}</p>${pill(s.state.startsWith("built") ? "spec_only" : "detected_not_parsed").replace(/>[^<]*</, `>${esc(s.state)}<`)}</div>`;
  });
  const pl = v.plugins;
  h += `</div><h2>Plugins</h2><div class="card"><dl class="kv">
    <dt>Parsers registered</dt><dd>${pl.registered.map(esc).join(", ") || "none"}</dd>
    <dt>Drop-in folder</dt><dd><code>${esc(pl.plugin_dir)}</code></dd>
    <dt>Drop-ins loaded</dt><dd>${Object.keys(pl.dropped_in).length ? Object.entries(pl.dropped_in).map(([f, m]) => `<code>${esc(f)}</code> → ${esc(m.vendors.join(", ") || "signatures only")}`).join("<br>") : "none yet - copy <code>plugins/_template.py</code> to start one"}</dd>
    ${Object.keys(pl.errors).length ? `<dt>Failed to load</dt><dd class="bad">${Object.entries(pl.errors).map(([f, e]) => `${esc(f)}: ${esc(e)}`).join("<br>")}</dd>` : ""}
  </dl></div>`;
  return h;
}

// ---------------------------------------------------------------- acquisition
function viewAcq() {
  const c = state.case, s = c?.scan;
  let h = "";
  if (s) {
    const d = s.device;
    h += `<h2>Evidence device</h2><div class="card"><dl class="kv">
      <dt>Path</dt><dd><code>${esc(d.path)}</code></dd>
      <dt>Size</dt><dd>${Number(d.size_bytes).toLocaleString()} bytes (${size(d.size_bytes)}), ${d.sector_size}-byte sectors</dd>
      <dt>Model / serial</dt><dd>${esc(d.model || "(not reported by bridge)")} / ${esc(d.serial || "(not reported by bridge)")}</dd>
      <dt>Write blocking</dt><dd><code>${esc(d.write_block_method)}</code></dd>
      <dt>Examiner</dt><dd>${esc(s.case?.investigator)} ${s.case?.organization ? "· " + esc(s.case.organization) : ""}</dd>
      <dt>Notes</dt><dd>${esc(s.case?.notes)}</dd>
      <dt>Throughput</dt><dd>${s.stats?.throughput_mbps} MiB/s over ${hms(s.stats?.duration_s)}</dd>
    </dl></div><h2>Hashes</h2>` +
      table(["Algorithm", "Scope", "Value"], s.hashes.map((x) => [esc(x.algorithm), esc(x.scope), `<code>${esc(x.value)}</code>`]));
  }
  if (c?.preserved) {
    h += `<h2>Preserved filesystem metadata</h2><div class="note">The video is not imaged in full; every filesystem structure is kept as whole scan blocks that re-verify against the acquisition's Merkle root.</div>` +
      table(["Region", "Offset", "Length", "SHA-256", "Why"], c.preserved.regions.map((r) =>
        [esc(r.name), hex(r.start), size(r.length), `<code>${esc(r.sha256.slice(0, 24))}…</code>`, esc(r.why)]));
  }
  const cu = c?.custody;
  h += `<h2>Chain of custody <span class="${cu?.verify?.valid ? "ok" : "bad"}">· ${esc(cu?.verify?.message)}</span></h2>` +
    table(["#", "Time (UTC)", "Actor", "Action", "Detail", "Entry hash"], (cu?.entries || []).map((e) =>
      [e.seq, esc(e.ts_utc), esc(e.actor), `<b>${esc(e.action)}</b>`,
        `<code>${esc(JSON.stringify(e.detail).slice(0, 180))}</code>`, `<code>${esc(e.entry_hash.slice(0, 16))}…</code>`]), true);
  return h;
}

// ---------------------------------------------------------------- filesystem
function viewFs() {
  const p = state.case?.parse;
  if (!p) return `<p class="muted">No filesystem parse for this case yet (<code>cli.py parse --vendor Dahua --device … --out …</code>).</p>`;
  let h = `<h2>${esc(p.volume_vendor || p.vendor)} ${pill(p.validation_status)}</h2>
    <div class="card"><dl class="kv">${p.summary.map(([a, b]) => `<dt>${esc(a)}</dt><dd>${esc(b)}</dd>`).join("")}</dl></div>`;
  h += `<h2>Recordings (${p.recordings_total.toLocaleString()} indexed${p.recordings_total > p.recordings.length ? `, first ${p.recordings.length} shown` : ""})</h2>` +
    table(["ID", "Camera", "Start (recorder clock)", "End", "Duration", "Codec", "Offset", "Confidence"], p.recordings.map((r) => {
      const idx = r.timestamps.filter((t) => t.source === "index");
      return [`<code>${esc(r.id)}</code>`, esc(r.camera_id), esc(localOf(idx[0])), esc(localOf(idx[1])), hms(r.duration_s),
        esc(r.codec || "-"), `<code>${hex(r.offset)}</code>`, r.confidence.toFixed(2)];
    }), true);
  if (p.notes.length) h += `<h2>Parser notes</h2>` + p.notes.map((n) => `<div class="note">${esc(n)}</div>`).join("");
  h += `<h2>Field provenance</h2>` + table(["Structure", "Field", "Offset", "Source", "Citation"], p.field_provenance.map((f) =>
    [esc(f.struct), esc(f.field), hex(f.offset), pill(f.implies_status).replace(/>[^<]*</, `>${esc(f.source)}<`), esc(f.citation)]), true);
  return h;
}

// ---------------------------------------------------------------- recovered
function viewRec() {
  const c = state.case?.carve, p = state.case?.parse;
  if (!c && !p?.remnants_total && !state.case?.ps_carve && !state.case?.analytics && !state.case?.osd) return `<p class="muted">${state.case?.in_progress ? "Carving is running inside the acquisition pass; results appear when it completes." : "No recovery results for this case yet."}</p>`;
  let h = "";
  if (c && c.stats?.frames) {
    h += `<h2>Indexless carve ${pill(c.validation_status)}</h2>
      <div class="note">Every validated DHAV frame was carved <b>without</b> the filesystem index, then labelled against it. <b>outside_index</b> = footage the recorder's own index no longer accounts for (overwritten, deleted, or from an earlier period). Its camera cannot be established from the frames alone.</div>` +
      table(["Label", "Streams", "Frames", "Bytes"], Object.entries(c.labels).sort().map(([k, v]) =>
        [k === "outside_index" ? `<b class="warn">${k}</b>` : esc(k), v.streams, v.frames.toLocaleString(), size(v.bytes)]));
    h += `<h2>Footage outside every index (${c.outside_total})</h2>` +
      table(["Stream", "Offset", "Frames", "First frame (recorder clock)", "Last frame", "Duration", "Confidence"], c.outside_index.map((r) =>
        [`<code>${esc(r.id)}</code>`, `<code>${hex(r.offset)}</code>`, r.frame_count.toLocaleString(), esc(localOf(r.timestamps[0])),
          esc(localOf(r.timestamps[1])), hms(r.duration_s), r.confidence.toFixed(2)]), true);
  }
  const ps = state.case?.ps_carve;
  if (ps) {
    h += `<h2>MPEG Program Stream footage ${pill(ps.validation_status)}</h2>
      <div class="note">Carved by structure, without any filesystem index — the route to footage left under a reformatted drive. ${ps.hk_streams.toLocaleString()} of ${ps.streams_total.toLocaleString()} streams carry Hikvision "HK" stream-map descriptors; where present, the recorder's clock is read from them.</div>
      <p class="muted">${ps.streams_total.toLocaleString()} streams · ${size(ps.bytes)} · ${hms(ps.duration_s)} · ${esc(ps.stream_types.join(", "))}${ps.dated ? ` · dated ${esc(ps.first_local)} → ${esc(ps.last_local)}` : ""}</p>` +
      (ps.labels ? `<p class="muted">Cameras from ${ps.labels.index_records} surviving HIKBTREE records: ${Object.entries(ps.labels.tally).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}</p>` : "") +
      table(["Stream", "Camera", "Offset", "Size", "Duration", "From (recorder clock)", "To"], ps.streams.map((r) =>
        [`<code>${esc(r.id)}</code>`, esc(r.label || "-"), `<code>${hex(r.offset)}</code>`, size(r.bytes), hms(r.duration_s),
          esc(r.time_first_local || "-"), esc(r.time_last_local || "-")]), true);
  }
  const an = state.case?.analytics;
  if (an) {
    h += `<h2>Faces and objects in recovered clips <span class="pill s-synthetic_only">lead, not evidence</span></h2>
      <div class="note warn">Face <b>detection</b> only — nobody is identified. Scores are the models' own confidence. Each item is a moment to review in the footage.</div>
      <p class="muted">${an.clips} clips, ${an.frames_analysed.toLocaleString()} frames analysed · frames with: ${Object.entries(an.totals).map(([k, v]) => `${esc(k)} ${v}`).join(", ") || "none"}</p>`;
    if (an.thumbnails.length) {
      h += `<div class="grid">${an.thumbnails.map((t) => `<div class="card"><img src="/thumb/${encodeURIComponent(state.case.id)}/${encodeURIComponent(t.file)}" alt="${esc(t.clip)} at ${t.t_s}s" style="width:100%;border-radius:6px"><p class="muted">${esc(t.clip)} · ${t.t_s}s</p></div>`).join("")}</div>`;
    }
  }
  const osd = state.case?.osd;
  if (osd) {
    const s = osd.summary || {}, lay = osd.layout || {};
    h += `<h2>Camera names read from the picture <span class="pill s-synthetic_only">lead, not evidence</span></h2>
      <div class="note warn">OCR of the burned-in OSD — the channel title the recorder painted into the frame. This is the only camera attribution left for footage no index accounts for, and it is <b>pixels read by a machine</b>, not a decoded field: each label carries the share of sampled frames that agreed. It names a camera and identifies nobody.</div>
      <p class="muted">${s.streams_named_by_the_picture || 0} of ${s.streams || 0} streams named${lay.title ? ` · title in the <b>${esc(lay.title.band)}</b> band, clock in the <b>${esc((lay.clock || {}).band || "-")}</b> band` : ""} · ${Object.entries(s.titles || {}).map(([k, v]) => `${esc(k)} ${v}`).join(" · ") || "no titles read"}</p>
      <p class="muted">Clock in the picture vs the date in the container: ${Object.entries(s.clock_checks || {}).map(([k, v]) => `${esc(k)} ${v}`).join(" · ") || "nothing compared"}. Both are the recorder's own clock by different routes; a disagreement says one is wrong, not which.</p>` +
      table(["Stream", "Title read", "Confidence", "Frames agreeing", "Clock check", "Picture − container (s)"], (osd.named || []).map((r) =>
        [`<code>${esc(r.clip)}</code>`, esc(r.title), r.confidence.toFixed(2), esc(r.frames),
          r.clock === "disagrees" ? `<b class="warn">${esc(r.clock)}</b>` : esc(r.clock || "-"),
          r.offset_s === null || r.offset_s === undefined ? "-" : (r.offset_s > 0 ? "+" : "") + r.offset_s.toFixed(0)]), true);
  }
  if (p?.remnants_total) {
    h += `<h2>Remnants in reused clusters (${p.remnants_total})</h2><div class="note">Older footage found by the index-guided parser at the tail of clusters since reassigned to a newer recording.</div>` +
      table(["ID", "Offset", "Frames", "First frame (recorder clock)", "Duration"], p.remnants.map((r) =>
        [`<code>${esc(r.id)}</code>`, `<code>${hex(r.offset)}</code>`, r.frame_count.toLocaleString(), esc(localOf(r.timestamps[0])), hms(r.duration_s)]), true);
  }
  return h;
}

// ---------------------------------------------------------------- timeline
function viewTl() {
  const t = state.case?.timeline;
  if (!t) return `<p class="muted">No timeline yet (<code>cli.py timeline --out … --tz-offset 330</code>).</p>`;
  let h = `<h2>Camera timeline</h2><div class="note"><b>Clock:</b> ${esc(t.clock.rule)}${t.clock.drift_source ? `<br><b>Clock error:</b> ${esc(t.clock.drift_source)}` : ""}</div>
    <div class="tl-wrap"><div class="tl-ctl">
      <button id="tl-idx" class="${state.tlFull ? "" : "on"}">Indexed period</button>
      <button id="tl-all" class="${state.tlFull ? "on" : ""}">Everything (incl. old footage)</button>
      <span class="muted">${t.counts.indexed} indexed · ${t.counts.unindexed} unindexed · ${t.counts.remnant} remnant</span></div>
      <div id="tl-svg"></div>
      <div class="legend"><span><i style="background:var(--cam1)"></i>indexed recording</span><span><i style="background:var(--gap)"></i>gap (no indexed footage)</span>
      <span><i style="background:var(--unidx)"></i>unindexed / remnant footage</span></div></div>`;
  h += `<h2>Per camera</h2>` + table(["Camera", "Files", "First", "Last", "Covered", "Gaps"], Object.entries(t.cameras).map(([k, v]) =>
    [esc(k), v.recordings, esc(v.first_local), esc(v.last_local), hms(v.covered_s), v.gaps]));
  h += `<h2>Cross-camera correlation</h2>` + table(["Finding", "From", "To", "Detail"], (t.correlations || []).map((x) =>
    [esc(x.kind), esc(x.start_local), esc(x.end_local), esc(x.detail)]), true);
  h += `<h2>Anomalies</h2>` + table(["Kind", "Item", "Detail"], (t.anomalies || []).map((x) =>
    [esc(x.kind), esc(x.id || x.camera), esc(x.detail)]), true);
  h += t.notes.map((n) => `<div class="note">${esc(n)}</div>`).join("");
  const a = state.case?.activity;
  if (a) {
    h += `<h2>Motion activity <span class="pill s-synthetic_only">lead, not evidence</span></h2>
      <div class="note warn">From compressed frame sizes (P-frame bytes per camera per minute); no video decoded. Low-light noise, lighting or infrared changes, rain and camera shake also raise it. A peak marks footage to review.</div>`;
    h += `<h3>Minutes with peaks on several cameras</h3>` + table(["Minute (recorder clock)", "Cameras", "Local index"],
      a.multi_camera_peaks.map((x) => [esc(x.minute), esc(x.cameras.join(", ")),
        esc(Object.entries(x.local_indices).map(([k, v]) => `${k} ${v.toFixed(1)}x`).join(", "))]), true);
    h += `<h3>Strongest peaks (${a.peaks_total} camera-minutes)</h3>` + table(["Camera", "Minute", "Local index", "vs whole period"],
      a.peaks.slice(0, 50).map((p) => [esc(p.camera), esc(p.minute), p.local_index.toFixed(1) + "x",
        p.index == null ? "-" : p.index.toFixed(1) + "x"]), true);
  }
  return h;
}

function drawTimeline() {
  const t = state.case?.timeline, host = $("#tl-svg");
  if (!t || !host) return;
  const P = (s) => new Date(s.replace(" ", "T") + "Z").getTime();
  const ev = t.events.filter((e) => e.start_local && e.end_local);
  const idx = ev.filter((e) => e.kind === "indexed");
  const span = (list) => [Math.min(...list.map((e) => P(e.start_local))), Math.max(...list.map((e) => P(e.end_local)))];
  let [t0, t1] = span(state.tlFull || !idx.length ? ev : idx);
  if (!(t1 > t0)) t1 = t0 + 3600e3;
  const cams = Object.keys(t.cameras).sort();
  const lanes = [...cams, "other footage"];
  const W = Math.max(host.clientWidth || 900, 700), L = 110, R = 12, laneH = 26, top = 22;
  const H = top + lanes.length * laneH + 24;
  const x = (ms) => L + (Math.min(Math.max(ms, t0), t1) - t0) / (t1 - t0) * (W - L - R);
  const colors = ["var(--cam1)", "var(--cam2)", "var(--cam3)", "var(--cam4)"];
  let g = "";
  const ticks = 6;
  for (let i = 0; i <= ticks; i++) {
    const ms = t0 + (t1 - t0) * i / ticks, xx = x(ms);
    const d = new Date(ms).toISOString().replace("T", " ").slice(0, 16);
    g += `<line x1="${xx}" x2="${xx}" y1="${top - 4}" y2="${H - 20}" stroke="var(--line)"/>` +
      `<text x="${xx}" y="${H - 6}" text-anchor="${i === 0 ? "start" : i === ticks ? "end" : "middle"}">${d}</text>`;
  }
  lanes.forEach((ln, i) => {
    const y = top + i * laneH;
    g += `<text x="0" y="${y + 16}">${esc(ln)}</text><rect x="${L}" y="${y + 3}" width="${W - L - R}" height="${laneH - 8}" fill="var(--panel2)" rx="3"/>`;
  });
  const inView = (e) => P(e.end_local) >= t0 && P(e.start_local) <= t1;
  for (const e of ev.filter(inView)) {
    const lane = e.kind === "indexed" ? cams.indexOf(e.camera) : lanes.length - 1;
    if (lane < 0) continue;
    const y = top + lane * laneH + 3, x0 = x(P(e.start_local)), w = Math.max(1.5, x(P(e.end_local)) - x0);
    const fill = e.kind === "indexed" ? colors[lane % colors.length] : "var(--unidx)";
    g += `<rect x="${x0}" y="${y}" width="${w}" height="${laneH - 8}" fill="${fill}" opacity="${e.kind === "indexed" ? 0.85 : 0.9}"><title>${esc(e.id)} · ${esc(e.camera)}\n${esc(e.start_local)} → ${esc(e.end_local)}${e.start_utc ? `\nUTC ${esc(e.start_utc)}` : ""}</title></rect>`;
  }
  for (const gp of (t.gaps || [])) {
    const lane = cams.indexOf(gp.camera);
    if (lane < 0 || P(gp.end_local) < t0 || P(gp.start_local) > t1) continue;
    const y = top + lane * laneH + 3, x0 = x(P(gp.start_local));
    g += `<rect x="${x0}" y="${y}" width="${Math.max(2, x(P(gp.end_local)) - x0)}" height="${laneH - 8}" fill="var(--gap)"><title>gap ${esc(gp.start_local)} → ${esc(gp.end_local)} (${hms(gp.duration_s)})</title></rect>`;
  }
  host.innerHTML = `<svg width="${W}" height="${H}" role="img" aria-label="camera timeline">${g}</svg>`;
  $("#tl-idx").onclick = () => { state.tlFull = false; render(); };
  $("#tl-all").onclick = () => { state.tlFull = true; render(); };
}

// ---------------------------------------------------------------- report
function viewReport() {
  const c = state.case;
  if (!c?.scan) return `<p class="muted">The report is generated once the acquisition pass completes - without a whole-device hash there is nothing to anchor it.</p>`;
  const u = `/report/${encodeURIComponent(c.id)}`;
  return `<h2>Forensic report</h2><p><a class="btn" href="${u}" target="_blank" rel="noopener">Open / print</a>
    <span class="muted"> · to record a report in the custody ledger, write it with <code>cli.py report --out ${esc(c.dir)}</code></span></p>
    <iframe class="report" src="${u}" title="forensic report"></iframe>`;
}

// ---------------------------------------------------------------- shell
const VIEWS = { overview: viewOverview, vendors: viewVendors, acq: viewAcq, fs: viewFs, rec: viewRec, tl: viewTl, report: viewReport };

function render() {
  renderPipeline();
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === state.tab));
  $("#view").innerHTML = VIEWS[state.tab]();
  if (state.tab === "tl") drawTimeline();
}

async function loadCase(id) {
  state.caseId = id;
  try { state.case = id ? await api(`/api/case/${encodeURIComponent(id)}`) : null; }
  catch (e) { state.case = null; $("#view").innerHTML = `<p class="bad">${esc(e.message)}</p>`; return; }
  try { localStorage.setItem("ps26150.case", id); } catch (_) { /* storage blocked */ }
  clearTimeout(state.timer);
  if (state.case?.in_progress) state.timer = setTimeout(() => loadCase(id), 5000);
  if (state.tab !== "report" || !state.timer) render();
  else renderPipeline();
}

async function init() {
  document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => { state.tab = b.dataset.tab; render(); });
  window.addEventListener("resize", () => state.tab === "tl" && drawTimeline());
  [state.cases, state.vendors] = await Promise.all([api("/api/cases"), api("/api/vendors")]);
  const sel = $("#case");
  sel.innerHTML = state.cases.map((c) => `<option value="${esc(c.id)}">${esc(c.id)}${c.complete ? "" : ` (acquiring ${(c.progress * 100).toFixed(1)}%)`}</option>`).join("");
  let saved = null;
  try { saved = localStorage.getItem("ps26150.case"); } catch (_) { /* storage blocked */ }
  const hp = new URLSearchParams(location.hash.slice(1));
  if (hp.get("case")) saved = hp.get("case");
  if (VIEWS[hp.get("tab")]) state.tab = hp.get("tab");
  const pick = state.cases.find((c) => c.id === saved) ? saved : state.cases.find((c) => !c.complete)?.id || state.cases[0]?.id;
  if (pick) sel.value = pick;
  sel.onchange = () => loadCase(sel.value);
  await loadCase(pick || null);
  render();
}

init().catch((e) => { $("#view").innerHTML = `<p class="bad">${esc(e.message)}</p>`; });

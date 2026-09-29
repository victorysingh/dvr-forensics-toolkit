// Evidence and acquisition (UI_PLAN 6.2): how the image was taken, what it
// hashed to, and what the block map says about the platter.
//
// The disk map itself lands in P3 with the /blockmap route; what is here now
// is the device record, the hashes with their scope, the scan statistics and
// the entropy-vs-video verdict from regions.json.
"use strict";

import { bytes, num, pct, hash, esc, empty, dur, pill, dataTable } from "../ui.js";

export function evidence(c) {
  const s = c.scan;
  if (!s) {
    return c.in_progress
      ? `<div class="card"><h3>Acquisition in progress</h3>
           <div class="bar"><i style="width:${pct(c.in_progress.fraction)}"></i></div>
           <p class="muted" style="margin-top:9px">${bytes(c.in_progress.bytes_done)} of ${
             bytes(c.in_progress.size_bytes)} read — updated ${
             esc(c.in_progress.updated_utc)} UTC</p></div>`
      : empty("No acquisition for this case.", `cli.py scan --device <dev> --out ${c.id}`);
  }

  const d = s.device || {};
  const st = s.stats || {};

  const device = `<section class="panel"><h2>Device</h2><div class="card"><div class="dl">
    <dt>Path</dt><dd class="mono">${esc(d.path)}</dd>
    <dt>Model</dt><dd>${esc(d.model || "—")}</dd>
    <dt>Serial</dt><dd>${esc(d.serial || "—")}</dd>
    <dt>Size</dt><dd>${bytes(d.size_bytes)} <span class="muted">(${num(d.size_bytes)} bytes)</span></dd>
    <dt>Sector size</dt><dd>${num(d.sector_size)} B</dd>
    <dt>Bus</dt><dd>${esc(d.bus_type || "—")}</dd>
    <dt>Write block</dt><dd>${esc(d.write_block_method || "—")}</dd>
  </div></div></section>`;

  const hashes = `<section class="panel"><h2>Hashes
    <span class="hint">scope is part of the claim — a triage hash covers only what was read</span></h2>
    <div class="card"><div class="dl">
      ${(s.hashes || []).map((h) => `
        <dt>${esc(h.algorithm.toUpperCase())}</dt>
        <dd>${hash(h.value, 12)}
          <div class="muted" style="font-size:11.5px">${esc(h.scope)} &middot;
            offset ${num(h.offset)} &middot; ${bytes(h.length)} &middot;
            ${esc(h.computed_utc || "")}</div></dd>`).join("")}
      ${s.merkle_root ? `<dt>Merkle root</dt><dd>${hash(s.merkle_root, 12)}
        <div class="muted" style="font-size:11.5px">root of the per-block hash tree in
          blockmap.jsonl</div></dd>` : ""}
    </div></div></section>`;

  const scan = `<section class="panel"><h2>Scan</h2><div class="grid">
    <div class="card kpi"><div class="label">Bytes read</div>
      <div class="value">${bytes(st.bytes_read)}</div>
      <div class="sub">${num(st.blocks_hashed)} blocks of ${bytes(st.block_size)}</div></div>
    <div class="card kpi"><div class="label">Throughput</div>
      <div class="value">${Number(st.throughput_mbps || 0).toFixed(2)}</div>
      <div class="sub">MB/s over ${dur(st.duration_s)}</div></div>
    <div class="card kpi"><div class="label">Bad sectors</div>
      <div class="value" style="${st.bad_sectors ? "color:var(--danger)" : ""}">${
        num(st.bad_sectors)}</div>
      <div class="sub">${st.bad_sectors ? "see bad regions below" : "none encountered"}</div></div>
    <div class="card kpi"><div class="label">Pass</div>
      <div class="value" style="font-size:19px">${
        st.complete_pass ? "complete" : "partial (triage)"}</div>
      <div class="sub">${st.complete_pass
        ? "every block of the device was read"
        : "only the region above was read"}</div></div>
  </div></section>`;

  /* ---------------------------------------------------------- regions */
  const r = c.regions;
  const regions = r ? `<section class="panel"><h2>Entropy vs video structure
    <span class="hint">from regions.json &middot; rule ${esc(r.rule)}</span></h2>
    <div class="card">
      <p style="margin:0 0 11px"><b>${esc(r.verdict)}</b></p>
      <div class="dl">
        ${Object.entries(r.counts || {}).map(([k, v]) =>
          `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${num(v)} block(s)</dd>`).join("")}
        <dt>Written blocks</dt><dd>${num(r.written_blocks)}</dd>
        <dt>Flagged</dt><dd>${num(r.flagged_blocks)} (${pct(r.flagged_share)})</dd>
      </div>
      <p class="muted" style="font-size:12px;margin:11px 0 0">
        A block that is incompressible but carries no video structure is the
        signature an encrypted region would leave. Counting them is how this
        tool can say "nothing here looks encrypted" without guessing.</p>
    </div></section>` : "";

  /* ---------------------------------------------------------- bad regions */
  const bad = (s.bad_regions || []).length ? (() => {
    const t = dataTable(s.bad_regions, [
      { key: "offset", label: "Offset", cls: "num", sort: "num",
        render: (x) => `0x${Number(x.offset || 0).toString(16).toUpperCase()}` },
      { key: "length", label: "Length", cls: "num", sort: "num",
        render: (x) => bytes(x.length) },
      { key: "error", label: "Error" },
    ], { search: false });
    return { html: `<section class="panel"><h2 style="color:var(--danger)">Bad regions</h2>
      ${t.html()}</section>`, bind: t.bind };
  })() : null;

  /* ---------------------------------------------------------- codec */
  const cp = c.codec_profile;
  const codec = cp ? `<section class="panel"><h2>Codec profile
    <span class="hint">from codec_profile.json</span></h2>
    <div class="card"><div class="dl">${Object.entries(cp).map(([k, v]) =>
      `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${
        typeof v === "object" ? `<span class="mono">${esc(JSON.stringify(v))}</span>` : esc(v)
      }</dd>`).join("")}</div></div></section>` : "";

  /* ---------------------------------------------------------- preserved */
  const p = c.preserved;
  const preserved = p ? `<section class="panel"><h2>Preserved metadata</h2>
    <div class="card"><div class="dl">
      <dt>Blocks</dt><dd>${num(p.blocks)} &middot; ${bytes(p.bytes_saved)}</dd>
      <dt>All blocks match</dt><dd>${p.all_blocks_match
        ? '<span style="color:var(--validated)">yes</span>'
        : '<span style="color:var(--danger)">NO</span>'}</dd>
      <dt>Merkle root</dt><dd>${hash(p.merkle_root, 10)}</dd>
      <dt>Manifest</dt><dd>${hash(p.manifest_sha256, 10)}</dd>
    </div></div></section>` : "";

  const html = device + hashes + scan + regions + codec + preserved + (bad ? bad.html : "");
  return { html, bind: (root) => { if (bad) bad.bind(root); } };
}

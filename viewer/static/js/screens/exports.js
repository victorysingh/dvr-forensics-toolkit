// Reports and exports (UI_PLAN 6.9).
//
// The full artefact list with sizes and hashes needs load_case's `artifacts`
// key, which is P2 server work.  Until then this screen shows what the case
// view already carries: the rendered report, and the hashes of the files the
// pipeline has written.
"use strict";

import { esc, hash, empty, num, bytes } from "../ui.js";
import { api } from "../api.js";

export function exports(c) {
  const parts = [];

  /* ---------------------------------------------------------- report */
  parts.push(`<section class="panel"><h2>Report</h2>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
        <div>
          <div style="font-weight:640">Examiner's HTML report</div>
          <div class="muted" style="font-size:12px">Rendered from this case on demand,
            with every status and citation the screens show.</div>
        </div>
        ${c.scan
          ? `<a class="badge ok" href="${esc(api.reportUrl(c.id))}" target="_blank"
               rel="noopener">Open report ↗</a>`
          : '<span class="badge">needs acquisition</span>'}
      </div>
    </div></section>`);

  /* ---------------------------------------------------------- files */
  const files = c.files || {};
  const known = [
    ["scan_report.json", "Acquisition report — device, hashes, detections, statistics"],
    ["blockmap.jsonl", "Per-block hash, entropy and start-code map"],
    ["custody_ledger.jsonl", "The custody chain"],
  ];
  const rows = known.filter(([n]) => files[n]).map(([n, d]) => `
    <tr><td><span class="mono">${esc(n)}</span>
        <div class="muted" style="font-size:11.5px">${esc(d)}</div></td>
      <td>${hash(files[n], 10)}</td></tr>`).join("");

  parts.push(`<section class="panel">
    <h2>Case files <span class="hint">SHA-256 of what the pipeline wrote</span></h2>
    ${rows ? `<div class="tablewrap"><div class="tscroll"><table>
      <thead><tr><th class="nosort">File</th><th class="nosort">SHA-256</th></tr></thead>
      <tbody>${rows}</tbody></table></div></div>`
      : empty("No case files recorded.")}
  </section>`);

  /* ------------------------------------------------- derived artefacts */
  const derived = [
    c.parse && [c.parse.file, c.parse.sha256, "Filesystem index parse"],
    c.carve && ["carve/carve_report.json", c.carve.sha256, "Carve report"],
    c.carve?.extracted && ["carve/extracted.json", c.carve.extracted.sha256, "Extraction manifest"],
    c.es_carve && ["carve/annexb_report.json", c.es_carve.sha256, "Raw H.264/H.265 carve"],
    c.ps_carve && ["carve/ps_report.json", c.ps_carve.sha256, "Hikvision PS carve"],
    c.timeline && ["timeline.json", c.timeline.sha256, "Timeline"],
    c.activity && ["activity.json", c.activity.sha256, "Motion activity"],
    c.analytics && ["analytics/analytics.json", c.analytics.sha256, "AI leads"],
    c.osd && ["analytics/osd.json", c.osd.sha256, "OSD titles read from the picture"],
    c.recorder_log && ["hik_log.json", c.recorder_log.sha256, "Recorder system log"],
  ].filter(Boolean);

  if (derived.length) {
    parts.push(`<section class="panel"><h2>Stage outputs</h2>
      <div class="tablewrap"><div class="tscroll"><table>
        <thead><tr><th class="nosort">File</th><th class="nosort">What it is</th>
          <th class="nosort">SHA-256</th></tr></thead>
        <tbody>${derived.map(([n, h, d]) => `
          <tr><td class="mono">${esc(n)}</td><td>${esc(d)}</td><td>${hash(h, 10)}</td></tr>`
        ).join("")}</tbody></table></div></div></section>`);
  }

  /* ---------------------------------------------------------- pending */
  parts.push(`<section class="panel">
    <h2>Court and interchange exports</h2>
    <div class="card">
      <p class="muted" style="font-size:12.5px;margin:0 0 9px">
        The s.63 certificate, CASE/UCO JSON-LD and NIST CCTV export are written
        into the case folder by their own commands. Listing them here with their
        sizes and hashes needs the <code>artifacts</code> key from
        <code>load_case</code> — that is P2 server work in the plan, not yet built.</p>
      <div class="dl" style="font-size:12px">
        <dt>s.63 certificate</dt><dd><code>cli.py certificate --out ${esc(c.id)} --part B</code></dd>
        <dt>CASE/UCO</dt><dd><code>cli.py case-export --out ${esc(c.id)}</code></dd>
        <dt>NIST CCTV</dt><dd><code>cli.py export-nist --out ${esc(c.id)}</code></dd>
      </div>
    </div></section>`);

  return parts.join("");
}

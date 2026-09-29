// Dashboard: the whole case in one look (UI_PLAN 6.1).
//
// Every KPI names the file it was read from.  Nothing on this screen is
// computed from anything but load_case's own numbers.
"use strict";

import { bytes, num, pct, kpi, hash, pill, esc, empty, dur, clockTime } from "../ui.js";
import { linkTo } from "../router.js";

export function dashboard(c) {
  if (!c.scan && !c.in_progress) {
    return empty("This case has no acquisition yet.",
                 `cli.py scan --device <dev> --out ${c.id}`);
  }

  const s = c.scan;
  const cam = c.parse ? Object.keys(c.parse.per_camera || {}).length
                      : Object.keys(c.timeline?.cameras || {}).length;
  const carve = c.carve || {};
  const tot = Object.values(carve.labels || {}).reduce(
    (a, v) => ({ streams: a.streams + v.streams, frames: a.frames + v.frames,
                 bytes: a.bytes + v.bytes }), { streams: 0, frames: 0, bytes: 0 });

  const det = s?.detections?.[0];
  const ver = c.custody?.verify || {};
  const an = c.analytics;

  const cards = [];

  cards.push(kpi({
    label: "Device",
    value: bytes(s?.device?.size_bytes || c.in_progress?.size_bytes),
    sub: s ? (s.stats?.complete_pass
                ? "complete pass — every block hashed"
                : `triage — ${bytes(s.stats?.bytes_read)} read`)
           : `acquiring — ${pct(c.in_progress.fraction)} read`,
    src: "scan_report.json",
  }));

  if (det) {
    cards.push(kpi({
      label: "Vendor",
      value: det.vendor,
      sub: `${pct(det.confidence)} confidence &middot; ${pill(det.validation_status)}`,
      src: "scan_report.json",
    }));
  }

  cards.push(kpi({
    label: "Recordings",
    value: c.parse ? c.parse.recordings_total : 0,
    sub: c.parse ? `${cam} camera${cam === 1 ? "" : "s"} in the index`
                 : "filesystem not parsed",
    src: c.parse ? c.parse.file : "parse_*.json",
  }));

  cards.push(kpi({
    label: "Footage recovered",
    value: tot.streams,
    sub: `${num(tot.frames)} frames &middot; ${bytes(tot.bytes)}`,
    src: "carve/carve_report.json",
  }));

  if (carve.labels?.outside_index) {
    const o = carve.labels.outside_index;
    cards.push(kpi({
      label: "Outside the index",
      value: o.streams,
      sub: `${num(o.frames)} frames the recorder's own index no longer lists`,
      src: "carve/carve_report.json",
    }));
  }

  if (c.timeline) {
    const n = c.timeline.counts || {};
    cards.push(kpi({
      label: "Timeline",
      value: (n.indexed || 0) + (n.unindexed || 0) + (n.remnant || 0),
      sub: `${n.indexed || 0} indexed &middot; ${n.unindexed || 0} unindexed &middot; ${
        (c.timeline.gaps || []).length} gap(s)`,
      src: "timeline.json",
    }));
  }

  if (an) {
    cards.push(kpi({
      label: "AI leads",
      lead: true,
      value: Object.values(an.totals || {}).reduce((a, b) => a + b, 0),
      sub: `${an.clips} clip(s) &middot; ${num(an.frames_analysed)} frames analysed`,
      src: "analytics/analytics.json",
    }));
  }

  cards.push(kpi({
    label: "Custody",
    value: (c.custody?.entries || []).length,
    sub: ver.valid
      ? '<span style="color:var(--validated)">chain intact ✓</span>'
      : `<span style="color:var(--danger)">${esc(ver.message || "chain broken")}</span>`,
    src: "custody_ledger.jsonl",
  }));

  /* ---------------------------------------------------------- header */
  const ci = s?.case || {};
  const head = `<section class="panel"><div class="card">
    <div class="dl">
      <dt>Case ID</dt><dd>${esc(c.case_id || c.id)}</dd>
      <dt>Investigator</dt><dd>${esc(ci.investigator || "—")}</dd>
      <dt>Organisation</dt><dd>${esc(ci.organization || "—")}</dd>
      <dt>Device</dt><dd class="mono">${esc(s?.device?.path || "—")}</dd>
      <dt>Model</dt><dd>${esc(s?.device?.model || "—")}${
        s?.device?.serial ? ` &middot; serial ${esc(s.device.serial)}` : ""}</dd>
      <dt>Acquired</dt><dd>${esc(s?.generated_utc || "—")} <span class="muted">UTC</span></dd>
      <dt>Tool</dt><dd>${esc(s?.tool || "")} ${esc(s?.tool_version || "")}</dd>
    </div>
  </div></section>`;

  /* ---------------------------------------------------------- cameras */
  const cams = c.parse?.per_camera || {};
  const camPanel = Object.keys(cams).length ? `
    <section class="panel"><h2>Cameras <span class="hint">recordings per camera,
      from ${esc(c.parse.file)}</span></h2>
      <div class="grid">${Object.entries(cams).map(([k, v], i) => `
        <div class="card"><div class="label muted">${esc(k)}</div>
          <div style="font-size:20px;font-weight:640">${num(v)}</div>
          <div class="bar" style="margin-top:7px"><i style="width:${
            (v / Math.max(...Object.values(cams)) * 100).toFixed(0)}%;background:var(--cam${
            (i % 8) + 1})"></i></div>
        </div>`).join("")}</div>
    </section>` : "";

  /* ---------------------------------------------------------- carve labels */
  const lab = carve.labels || {};
  const labPanel = Object.keys(lab).length ? `
    <section class="panel"><h2>Recovered streams by label
      <span class="hint">from carve/carve_report.json</span></h2>
      <div class="tablewrap"><div class="tscroll"><table>
        <thead><tr><th class="nosort">Label</th><th class="nosort">Streams</th>
          <th class="nosort">Frames</th><th class="nosort">Bytes</th></tr></thead>
        <tbody>${Object.entries(lab).sort((a, b) => b[1].frames - a[1].frames).map(([k, v]) => `
          <tr><td>${k === "outside_index"
              ? '<b style="color:var(--synthetic_only)">outside_index</b>'
              : esc(k)}</td>
            <td class="num">${num(v.streams)}</td>
            <td class="num">${num(v.frames)}</td>
            <td class="num">${bytes(v.bytes)}</td></tr>`).join("")}</tbody>
      </table></div></div>
      ${lab.outside_index ? `<p class="muted" style="font-size:12.5px;margin-top:8px">
        <b>outside_index</b> is footage found on the platter that the recorder's own
        index no longer accounts for — deleted or overwritten entries, recovered in
        the same read pass.</p>` : ""}
    </section>` : "";

  /* ---------------------------------------------------------- hashes */
  const hashes = (s?.hashes || []).length ? `
    <section class="panel"><h2>Acquisition hashes
      <span class="hint">click any value to copy</span></h2>
      <div class="card"><div class="dl">
        ${s.hashes.map((h) => `<dt>${esc(h.algorithm.toUpperCase())}</dt>
          <dd>${hash(h.value, 10)} <span class="muted">${esc(h.scope)}</span></dd>`).join("")}
        ${s.merkle_root ? `<dt>Merkle root</dt><dd>${hash(s.merkle_root, 10)}
          <span class="muted">per-block tree</span></dd>` : ""}
      </div></div>
    </section>` : "";

  return `<div class="grid">${cards.join("")}</div>
    ${head}${camPanel}${labPanel}${hashes}`;
}

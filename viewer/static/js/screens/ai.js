// AI leads (UI_PLAN 6.7).
//
// Ground rule 1: every screen that shows a model's output carries the "lead,
// not evidence" banner and the models' hashes.  The banner is rendered first
// and unconditionally - including on the empty state, so that a case with no
// analytics still teaches the reader what this screen would have meant.
"use strict";

import { esc, num, empty, pill, hash, dataTable, leadBanner } from "../ui.js";
import { api } from "../api.js";

export function ai(c) {
  const an = c.analytics;
  if (!an) {
    return leadBanner() + empty(
      "No analytics have been run for this case.",
      `cli.py analyse-video --out ${c.id} --fps 1`);
  }

  const parts = [];
  const binds = [];
  const models = an.models || {};

  parts.push(leadBanner(
    `Models: ${Object.entries(models).map(([k, v]) =>
      `${esc(k)} <span class="mono">${esc(String(v?.sha256 || v).slice(0, 12))}…</span>`
    ).join(" &middot; ") || "not recorded"}`));

  /* ---------------------------------------------------------- totals */
  const totals = an.totals || {};
  parts.push(`<section class="panel"><div class="grid">
    ${Object.entries(totals).map(([k, v]) => `
      <div class="card kpi"><div class="label">${esc(k.replace(/_/g, " "))}</div>
        <div class="value lead">${num(v)}</div>
        <div class="sub">frames</div></div>`).join("")}
    <div class="card kpi"><div class="label">Frames analysed</div>
      <div class="value">${num(an.frames_analysed)}</div>
      <div class="sub">${num(an.clips)} clip(s)</div></div>
  </div>
  <div class="card" style="margin-top:12px"><div class="dl">
    <dt>Status</dt><dd>${pill(an.status)}</dd>
    <dt>Thresholds</dt><dd class="mono">${esc(JSON.stringify(an.thresholds || {}))}</dd>
    ${an.tiling ? `<dt>Tiling</dt><dd class="mono">${esc(JSON.stringify(an.tiling))}</dd>` : ""}
    <dt>Report</dt><dd>${hash(an.sha256, 10)}</dd>
  </div></div></section>`);

  /* ---------------------------------------------------------- thumbnails */
  const thumbs = an.thumbnails || [];
  if (thumbs.length) {
    parts.push(`<section class="panel">
      <h2>Detections <span class="hint">boxes are drawn by the detector, on recovered frames</span></h2>
      <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(190px,1fr))">
        ${thumbs.map((t) => `
          <div class="card" style="padding:0;overflow:hidden">
            <img src="${esc(api.thumbUrl(c.id, t.file || t.name || ""))}" alt="${
              esc(t.label || "detection")}" loading="lazy"
              style="width:100%;display:block;aspect-ratio:16/9;object-fit:cover">
            <div style="padding:8px 10px">
              <div style="font-size:12px;font-weight:600;color:var(--lead)">${
                esc(t.label || "—")}${t.score
                  ? ` <span class="mono">${(t.score * 100).toFixed(0)}%</span>` : ""}</div>
              <div class="muted mono" style="font-size:10.5px;word-break:break-all">${
                esc(t.clip || "")}</div>
            </div>
          </div>`).join("")}
      </div></section>`);
  }

  /* ---------------------------------------------------------- top hits */
  const top = an.top || [];
  if (top.length) {
    const rows = top.map((h) => ({
      clip: h.clip ?? "", frame: h.frame ?? h.frame_index ?? 0,
      labels: (h.detections || []).map((d) => d.label).join(", "),
      best: Math.max(...(h.detections || [{ score: 0 }]).map((d) => d.score || 0)),
      count: (h.detections || []).length,
    }));
    const tb = dataTable(rows, [
      { key: "clip", label: "Clip", cls: "mono" },
      { key: "frame", label: "Frame", cls: "num", sort: "num", render: (r) => num(r.frame) },
      { key: "labels", label: "Labels",
        render: (r) => `<span style="color:var(--lead)">${esc(r.labels)}</span>` },
      { key: "count", label: "Boxes", cls: "num", sort: "num" },
      { key: "best", label: "Top score", cls: "num", sort: "num",
        render: (r) => `${(r.best * 100).toFixed(1)}%` },
    ], { page: 100, sort: "best", dir: -1 });
    parts.push(`<section class="panel">
      <h2>Highest-scoring frames
        <span class="hint">a score is the model's confidence, not a probability the lead is right</span></h2>
      ${tb.html()}</section>`);
    binds.push(tb.bind);
  }

  if ((an.notes || []).length) {
    parts.push(`<section class="panel"><h2>Notes</h2><div class="card">
      <ul style="margin:0;padding-left:19px;font-size:12.5px;line-height:1.8">
        ${an.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div></section>`);
  }

  return { html: parts.join(""), bind: (root) => binds.forEach((b) => b(root)) };
}

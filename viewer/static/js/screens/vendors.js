// Vendor identification (UI_PLAN 6.3): the eight PS vendors, what this disk
// actually showed, and what we can honestly parse.
//
// `parser_status` is the weakest evidence behind the parser, never better -
// so it is shown on every card, not only the winner's.
"use strict";

import { pct, esc, pill, confBar, empty, num } from "../ui.js";

export function vendors(c, vendorInfo) {
  const rows = c.vendors || [];
  if (!rows.length) return empty("No vendor matrix available.");

  const det = c.scan?.detections || [];
  const top = det[0];

  /* ---------------------------------------------------------- the winner */
  const winner = top ? `<section class="panel">
    <h2>Detected on this disk</h2>
    <div class="card" style="border-color:color-mix(in srgb,var(--accent) 45%,var(--line))">
      <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap">
        <div style="font-size:24px;font-weight:650">${esc(top.vendor)}</div>
        <div style="font-size:19px;color:var(--accent);font-family:var(--mono)">${
          pct(top.confidence)}</div>
        ${pill(top.validation_status)}
        ${top.parser_available
          ? '<span class="badge ok"><span class="dot"></span>parser available</span>'
          : '<span class="badge">no parser</span>'}
      </div>
      <p class="muted" style="font-size:12.5px;margin:9px 0 11px">
        ${num(top.hit_count)} signature hit(s) across the scanned region.
        Confidence is the detector's own score, not a probability of guilt.</p>
      <h3 style="margin-bottom:7px">Evidence strings</h3>
      <ul class="mono" style="margin:0;padding-left:19px;font-size:12px;line-height:1.75">
        ${(top.evidence || []).map((e) => `<li>${esc(e)}</li>`).join("")}
      </ul>
    </div>
  </section>` : `<section class="panel">${
    empty("No vendor signature matched this disk.",
          "cli.py survey --device <dev> --out " + c.id)}</section>`;

  /* ---------------------------------------------------------- all eight */
  const cards = rows.map((v) => {
    const hit = v.detected_confidence > 0;
    return `<div class="card" style="${hit
      ? "border-color:color-mix(in srgb,var(--accent) 40%,var(--line))" : ""}">
      <div style="display:flex;justify-content:space-between;align-items:start;gap:9px">
        <div style="font-weight:640;font-size:15px">${esc(v.vendor)}</div>
        ${pill(v.parser_status)}
      </div>
      <div class="muted" style="font-size:12px;margin:3px 0 9px">${esc(v.family)}</div>
      ${hit ? confBar(v.detected_confidence)
            : '<div class="muted" style="font-size:12px">not detected on this disk</div>'}
      ${v.detected_note ? `<div class="muted" style="font-size:11.5px;margin-top:5px">${
        esc(v.detected_note)}</div>` : ""}
      <div class="dl" style="margin-top:11px;font-size:11.5px">
        <dt>Parser</dt><dd>${v.parser ? esc(v.parser) : '<span class="muted">none</span>'}</dd>
        <dt>Signatures</dt><dd>${num(v.signatures)}</dd>
        <dt>Media held</dt><dd>${esc(v.media)}</dd>
      </div>
      ${v.basis ? `<details style="margin-top:9px">
        <summary class="muted" style="font-size:11.5px;cursor:pointer">Basis</summary>
        <div class="muted" style="font-size:11.5px;margin-top:5px">${esc(v.basis)}</div>
      </details>` : ""}
    </div>`;
  }).join("");

  const matrix = `<section class="panel">
    <h2>The eight PS vendors <span class="hint">coverage, and what each claim rests on</span></h2>
    <div class="cases">${cards}</div>
  </section>`;

  /* ---------------------------------------------------------- onboarding */
  const ob = vendorInfo?.onboarding || [];
  const onboarding = ob.length ? `<section class="panel">
    <h2>Onboarding a new vendor <span class="hint">unknown disk → parsed footage</span></h2>
    <div class="grid">${ob.map((s, i) => `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div style="font-weight:640">${i + 1}. ${esc(s.step)}</div>
          <span class="badge">${esc(s.state)}</span>
        </div>
        <div class="muted" style="font-size:12px;margin:6px 0 7px">${esc(s.what)}</div>
        <code>${esc(s.tool)}</code>
      </div>`).join("")}</div>
  </section>` : "";

  /* ---------------------------------------------------------- plugins */
  const p = vendorInfo?.plugins;
  const plugins = p ? `<section class="panel"><h2>Parsers loaded</h2>
    <div class="card"><div class="dl">
      <dt>Registered</dt><dd>${(p.registered || []).map((x) =>
        `<span class="badge">${esc(x)}</span>`).join(" ") || "—"}</dd>
      <dt>Dropped in</dt><dd>${(p.dropped_in || []).length
        ? (p.dropped_in).map((x) => `<span class="badge">${esc(x)}</span>`).join(" ")
        : '<span class="muted">none</span>'}</dd>
      <dt>Plugin folder</dt><dd class="mono">${esc(p.plugin_dir || "")}</dd>
      ${(p.errors || []).length ? `<dt style="color:var(--danger)">Errors</dt>
        <dd style="color:var(--danger)">${(p.errors).map(esc).join("<br>")}</dd>` : ""}
    </div></div>
  </section>` : "";

  return winner + matrix + onboarding + plugins;
}

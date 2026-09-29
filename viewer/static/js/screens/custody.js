// Chain of custody (UI_PLAN 6.8): the ledger, drawn as the hash chain it is.
//
// The verdict at the top is not a stored field - report/case.py re-runs
// ledger.verify() on every load.  What this screen shows is therefore the
// result of a check made just now, not a claim the file makes about itself.
"use strict";

import { esc, hash, empty, num, dataTable } from "../ui.js";

// A ledger detail is whatever the stage recorded: a scalar, a hash, or a
// nested object such as the carve label tally or the timeline's clock rule.
// Nested values are printed as compact JSON rather than stringified, which
// is what turned them into "[object Object]".
const isHash = (v) => typeof v === "string" && /^[0-9a-f]{64}$/i.test(v);

function detailValue(v) {
  if (v === null || v === undefined || v === "") return '<span class="muted">—</span>';
  if (isHash(v)) return hash(v, 8);
  if (typeof v !== "object") return `<span class="mono">${esc(v)}</span>`;
  if (Array.isArray(v)) {
    if (!v.length) return '<span class="muted">none</span>';
    return v.map((x) => typeof x === "object"
      ? `<div class="mono">${esc(JSON.stringify(x))}</div>`
      : `<span class="badge">${esc(x)}</span>`).join(" ");
  }
  return `<div class="dl" style="font-size:11px;margin-top:2px">${
    Object.entries(v).map(([k, val]) =>
      `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${detailValue(val)}</dd>`).join("")}</div>`;
}

export function custody(c) {
  const cu = c.custody || {};
  const entries = cu.entries || [];
  if (!entries.length) {
    return empty("This case has no custody ledger.",
                 `cli.py scan --device <dev> --out ${c.id}`);
  }
  const v = cu.verify || {};

  const verdict = `<section class="panel"><div class="card" style="border-color:${
    v.valid ? "color-mix(in srgb,var(--validated) 50%,var(--line))"
            : "color-mix(in srgb,var(--danger) 50%,var(--line))"}">
    <div style="display:flex;align-items:center;gap:13px;flex-wrap:wrap">
      <div style="font-size:27px;color:${v.valid ? "var(--validated)" : "var(--danger)"}">${
        v.valid ? "✓" : "✗"}</div>
      <div>
        <div style="font-size:18px;font-weight:640;color:${
          v.valid ? "var(--validated)" : "var(--danger)"}">${
          v.valid ? "Chain intact" : "Chain BROKEN"}</div>
        <div class="muted" style="font-size:12.5px">${esc(v.message || "")}</div>
      </div>
      <button class="icon-btn" id="reverify" title="Re-fetch the case and re-run the check"
        style="margin-left:auto;width:auto;padding:0 13px">Re-verify</button>
    </div>
    <div class="dl" style="margin-top:13px">
      <dt>Entries</dt><dd>${num(entries.length)}</dd>
      <dt>Head</dt><dd>${hash(cu.head, 12)}</dd>
    </div>
    <p class="muted" style="font-size:12px;margin:11px 0 0">
      Each entry hashes its own contents and its predecessor's hash. Changing
      any entry after the fact changes every hash after it, which is what
      makes this checkable rather than merely written down.</p>
  </div></section>`;

  /* ---------------------------------------------------------- the chain */
  const chain = `<section class="panel"><h2>Ledger
    <span class="hint">oldest first &middot; times are UTC, as recorded</span></h2>
    <ol class="chain">${entries.map((e) => {
      const det = e.detail && typeof e.detail === "object" ? e.detail : null;
      return `<li${v.valid ? "" : ' class="broken"'}>
        <div class="act">${e.seq != null ? `<span class="muted">${esc(e.seq)}.</span> ` : ""}${
          esc(String(e.action || "").replace(/_/g, " "))}</div>
        <div class="meta">${esc(e.ts_utc || "")} <span class="muted">UTC</span> &middot; ${
          esc(e.actor || "")}${e.case_id ? ` &middot; ${esc(e.case_id)}` : ""}</div>
        ${det ? `<div class="det"><div class="dl" style="font-size:11.5px">${
          Object.entries(det).map(([k, val]) =>
            `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${detailValue(val)}</dd>`
          ).join("")}</div></div>`
          : e.detail ? `<div class="det">${esc(e.detail)}</div>` : ""}
        <div class="meta" style="margin-top:5px">
          entry ${hash(e.entry_hash, 7)} ← prev ${hash(e.prev_hash, 7)}${
          e.data_hash ? ` &middot; data ${hash(e.data_hash, 7)}` : ""}</div>
      </li>`;
    }).join("")}</ol>
  </section>`;

  return verdict + chain;
}

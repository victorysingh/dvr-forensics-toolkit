// Shared components and formatters.  Built once here, used by every screen,
// so a status pill or a hash chip looks and behaves the same everywhere.
"use strict";

/* ------------------------------------------------------------ escaping */
// Everything interpolated into HTML goes through esc().  Case data is read
// off a disk under examination: filenames, OSD titles and vendor strings are
// attacker-influenced input and are never trusted as markup.
export const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ------------------------------------------------------------ formatters */
export function bytes(n) {
  n = Number(n || 0);
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
  return i === 0 ? `${n} B` : `${n.toFixed(n < 10 ? 2 : 1)} ${u[i]}`;
}

export const num = (n) => Number(n || 0).toLocaleString("en-US");

export function dur(s) {
  s = Math.round(Number(s) || 0);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${s}s`;
}

export const pct = (f) => `${(Number(f || 0) * 100).toFixed(1)}%`;
export const hex = (n) => "0x" + Number(n || 0).toString(16).toUpperCase();

// Recorder-clock times are shown exactly as stored.  We never re-parse them
// into a Date and re-render: that would silently move them into the
// browser's zone, which is the one lie this product must not tell.
export const clockTime = (s) => (s ? String(s).replace("T", " ").replace("Z", "") : "—");

// A carved stream has no flat local-time field: it carries a list of time
// claims, each holding the decoded value inside `raw_value`, shaped
// "0x6A026000 = 2026-08-01 06:00:00 recorder-local".  Taking the string the
// decoder wrote - rather than re-deriving one - keeps the screen honest
// about which claim it is showing.
export function claimLocal(claim) {
  if (!claim || !claim.raw_value) return "";
  return String(claim.raw_value).split(" = ").pop().replace(" recorder-local", "").trim();
}

// The first time claim on a carved recording, if it made one at all.
export const firstLocal = (rec) => claimLocal((rec && rec.timestamps || [])[0]);

/* ------------------------------------------------------------ components */
export const pill = (s) =>
  `<span class="pill s-${esc(s || "none")}">${esc(s || "none")}</span>`;

// A hash chip: short on screen, full on hover, whole value copied on click.
export function hash(v, len = 6) {
  if (!v) return '<span class="muted">--</span>';
  const s = String(v);
  const short = s.length > len * 2 ? `${s.slice(0, len)}…${s.slice(-4)}` : s;
  return `<span class="hash" data-copy="${esc(s)}" title="${esc(s)}">${esc(short)}</span>`;
}

export function kpi({ label, value, sub, src, lead }) {
  return `<div class="card kpi">
    <div class="label">${esc(label)}</div>
    <div class="value${lead ? " lead" : ""}" ${
      typeof value === "number" ? `data-count="${value}"` : ""}>${
      typeof value === "number" ? num(value) : esc(value)}</div>
    ${sub ? `<div class="sub">${sub}</div>` : ""}
    ${src ? `<div class="src">from ${esc(src)}</div>` : ""}
  </div>`;
}

export const confBar = (f) =>
  `<span class="conf"><span class="bar"><i style="width:${(Number(f || 0) * 100).toFixed(
    1)}%"></i></span><span class="pct">${pct(f)}</span></span>`;

// An empty state always says which command would fill it: a blank panel that
// explains itself is the difference between "broken" and "not run yet".
export const empty = (what, how) =>
  `<div class="empty"><div class="what">${esc(what)}</div>${
    how ? `<div>Run <code>${esc(how)}</code></div>` : ""}</div>`;

export const skeleton = (rows = 4) =>
  `<div class="card">${Array.from({ length: rows },
    (_, i) => `<div class="skel" style="width:${90 - i * 13}%;margin:9px 0"></div>`).join("")}</div>`;

export const leadBanner = (extra = "") =>
  `<div class="lead-banner"><span class="mark">◆</span><div class="txt">
    <b>Leads, not evidence.</b> These boxes come from an object detector run
    over recovered frames. This is <b>detection, not recognition</b>: nothing
    here identifies a person. Treat every row as a pointer for an examiner to
    check by eye.${extra ? `<div class="muted" style="margin-top:5px">${extra}</div>` : ""}
  </div></div>`;

export const clockBanner = (rule) =>
  `<div class="clock-banner"><b>Recorder clock.</b> ${esc(
    rule || "Times are the recorder's own clock, not converted to UTC: the recorder's zone was not stated.")}</div>`;

/* ------------------------------------------------------------ data table */
/* Search, sort and pagination over a column spec.  Columns:
 *   { key, label, cls?, sort?: "num"|"str"|false, render?: (row) => html }
 * Rows beyond `page` are never put in the DOM, which is what keeps a
 * 2,000-stream drive responsive.
 */
let tableSeq = 0;

export function dataTable(rows, cols, opts = {}) {
  const id = `t${++tableSeq}`;
  const page = opts.page || 100;
  const state = { q: "", sort: opts.sort || null, dir: opts.dir || 1, at: 0 };
  const searchable = opts.search !== false;

  const text = (r) => cols.map((c) => String(r[c.key] ?? "")).join(" ").toLowerCase();

  function view() {
    let out = rows;
    if (state.q) out = out.filter((r) => text(r).includes(state.q));
    if (state.sort) {
      const c = cols.find((x) => x.key === state.sort);
      const nu = c && c.sort === "num";
      out = out.slice().sort((a, b) => {
        const x = a[state.sort], y = b[state.sort];
        if (nu) return (Number(x || 0) - Number(y || 0)) * state.dir;
        return String(x ?? "").localeCompare(String(y ?? "")) * state.dir;
      });
    }
    return out;
  }

  function html() {
    const all = view();
    const slice = all.slice(state.at, state.at + page);
    const head = cols.map((c) => {
      const on = state.sort === c.key;
      const sortable = c.sort !== false;
      return `<th class="${sortable ? "" : "nosort"}" ${
        sortable ? `data-sort="${esc(c.key)}"` : ""}>${esc(c.label)}${
        on ? `<span class="arrow">${state.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`;
    }).join("");
    const body = slice.map((r) =>
      `<tr>${cols.map((c) =>
        `<td class="${esc(c.cls || "")}">${c.render ? c.render(r) : esc(r[c.key])}</td>`
      ).join("")}</tr>`).join("");
    const pages = Math.ceil(all.length / page) || 1;
    const at = Math.floor(state.at / page) + 1;
    return `<div class="tablewrap" id="${id}">
      ${searchable || opts.tools ? `<div class="tabletools">
        ${searchable ? `<input type="search" placeholder="Search…" data-q value="${esc(state.q)}">` : ""}
        ${opts.tools || ""}
        <span class="count">${num(all.length)} row${all.length === 1 ? "" : "s"}${
          all.length !== rows.length ? ` of ${num(rows.length)}` : ""}</span>
      </div>` : ""}
      <div class="tscroll"><table>
        <thead><tr>${head}</tr></thead><tbody>${body}</tbody>
      </table></div>
      ${pages > 1 ? `<div class="pager">
        <button data-pg="-1" ${state.at === 0 ? "disabled" : ""}>Prev</button>
        <span>page ${at} of ${pages}</span>
        <button data-pg="1" ${state.at + page >= all.length ? "disabled" : ""}>Next</button>
      </div>` : ""}
    </div>`;
  }

  // Re-render in place.  The wrapper keeps its id, so repeated redraws after
  // a sort or a page step do not detach the listeners bound by bind().
  function redraw(root) {
    const el = root.querySelector(`#${id}`);
    if (!el) return;
    const tmp = document.createElement("div");
    tmp.innerHTML = html();
    el.replaceWith(tmp.firstElementChild);
    bind(root);
  }

  function bind(root) {
    const el = root.querySelector(`#${id}`);
    if (!el) return;
    const q = el.querySelector("[data-q]");
    if (q) {
      q.addEventListener("input", () => {
        state.q = q.value.trim().toLowerCase();
        state.at = 0;
        redraw(root);
        const again = root.querySelector(`#${id} [data-q]`);
        if (again) { again.focus(); again.setSelectionRange(again.value.length, again.value.length); }
      });
    }
    el.querySelectorAll("th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const k = th.dataset.sort;
        state.dir = state.sort === k ? -state.dir : 1;
        state.sort = k;
        redraw(root);
      });
    });
    el.querySelectorAll("[data-pg]").forEach((b) => {
      b.addEventListener("click", () => {
        state.at = Math.max(0, state.at + Number(b.dataset.pg) * page);
        redraw(root);
      });
    });
  }

  return { html, bind };
}

/* ------------------------------------------------------------ toast */
export function toast(msg) {
  let host = document.getElementById("toasts");
  if (!host) {
    host = document.createElement("div");
    host.id = "toasts";
    document.body.appendChild(host);
  }
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => t.remove(), 2200);
}

/* Click-to-copy for every hash chip on the page.  One delegated listener on
 * document, installed once, rather than one per chip per render. */
export function installCopy() {
  document.addEventListener("click", (e) => {
    const el = e.target.closest("[data-copy]");
    if (!el) return;
    const v = el.dataset.copy;
    const done = () => toast("Copied to clipboard");
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(v).then(done, () => fallback(v, done));
    } else {
      fallback(v, done);
    }
  });
}

// http://127.0.0.1 is not a secure context in every browser, so the async
// clipboard API may be unavailable.  Fall back to a scratch textarea.
function fallback(v, done) {
  const ta = document.createElement("textarea");
  ta.value = v;
  ta.style.cssText = "position:fixed;opacity:0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); done(); } catch { /* nothing else to try */ }
  ta.remove();
}

/* Count KPI numbers up on first paint.  Skipped entirely when the viewer
 * asked for reduced motion. */
export function animateCounts(root) {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  root.querySelectorAll("[data-count]").forEach((el) => {
    const to = Number(el.dataset.count);
    if (!isFinite(to) || to <= 0) return;
    const t0 = performance.now(), ms = 520;
    (function step(now) {
      const k = Math.min(1, (now - t0) / ms);
      el.textContent = num(Math.round(to * (1 - Math.pow(1 - k, 3))));
      if (k < 1) requestAnimationFrame(step);
    })(t0);
  });
}

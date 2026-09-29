// The shell: top bar, sidebar, pipeline stepper, routing and case loading.
//
// A screen is a pure function of the case view: it returns HTML, or
// { html, bind } when it needs to wire listeners after paint.  Nothing here
// fetches on a screen's behalf, so adding a screen means adding one entry to
// SCREENS and one file under screens/.
"use strict";

import { api } from "./api.js";
import { parseHash, linkTo, go, onRoute } from "./router.js";
import { esc, bytes, pct, num, skeleton, empty, installCopy, animateCounts, toast } from "./ui.js";

import { dashboard } from "./screens/dashboard.js";
import { evidence } from "./screens/evidence.js";
import { vendors } from "./screens/vendors.js";
import { recordings } from "./screens/recordings.js";
import { recovered } from "./screens/recovered.js";
import { timeline } from "./screens/timeline.js";
import { ai } from "./screens/ai.js";
import { custody } from "./screens/custody.js";
import { exports as exportsScreen } from "./screens/exports.js";

const SCREENS = [
  { id: "dashboard",  label: "Dashboard",  ico: "▦", render: dashboard },
  { id: "evidence",   label: "Evidence",   ico: "▤", render: evidence },
  { id: "vendors",    label: "Vendors",    ico: "◈", render: vendors },
  { id: "recordings", label: "Recordings", ico: "≡", render: recordings },
  { id: "recovered",  label: "Recovered",  ico: "▶", render: recovered },
  { id: "timeline",   label: "Timeline",   ico: "⏱", render: timeline },
  { id: "ai",         label: "AI leads",   ico: "◆", render: ai },
  { id: "custody",    label: "Custody",    ico: "⛓", render: custody },
  { id: "exports",    label: "Exports",    ico: "⤓", render: exportsScreen },
];

const state = { cases: [], caseId: null, case: null, vendorInfo: null, screen: "dashboard" };

/* ------------------------------------------------------------ theme */
function initTheme() {
  let t = null;
  try { t = localStorage.getItem("ps26150-theme"); } catch { /* private mode */ }
  if (t) document.documentElement.dataset.theme = t;
}
function toggleTheme() {
  const now = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = now;
  try { localStorage.setItem("ps26150-theme", now); } catch { /* nothing to do */ }
}

/* ------------------------------------------------------------ chrome */
function renderTopbar() {
  const c = state.case;
  const ver = c?.custody?.verify;
  const live = c?.in_progress;
  const bar = document.getElementById("topbar");
  if (!bar) return;
  bar.innerHTML = `
    <div class="brand"><span class="logo">◧</span>
      <span>PS26150<span class="sub"> &middot; DVR/NVR forensics</span></span></div>
    ${state.cases.length ? `<select class="case-switch" id="caseSwitch" aria-label="Case">
      <option value="">All cases…</option>
      ${state.cases.map((x) => `<option value="${esc(x.id)}" ${
        x.id === state.caseId ? "selected" : ""}>${esc(x.id)}${
        x.case_id ? ` · ${esc(x.case_id)}` : ""}</option>`).join("")}
    </select>` : ""}
    <span class="spacer"></span>
    ${live ? `<span class="badge live"><span class="dot"></span>LIVE ${
      pct(live.fraction)}</span>` : ""}
    ${ver ? `<span class="badge ${ver.valid ? "ok" : "bad"}"><span class="dot"></span>${
      ver.valid ? "chain intact" : "chain broken"}</span>` : ""}
    <span class="badge" title="The UI binds 127.0.0.1, never opens an evidence device, and never writes">
      offline · read-only</span>
    ${c?.scan ? `<a class="badge" href="${esc(api.reportUrl(c.id))}" target="_blank"
      rel="noopener">Report ↗</a>` : ""}
    <button class="icon-btn" id="themeBtn" title="Toggle theme (t)">◑</button>`;

  const sw = document.getElementById("caseSwitch");
  if (sw) sw.addEventListener("change", () => go(sw.value || null, state.screen));
  document.getElementById("themeBtn").addEventListener("click", toggleTheme);
}

function renderSidebar() {
  const nav = document.getElementById("sidebar");
  if (!nav) return;
  if (!state.caseId) { nav.innerHTML = ""; return; }
  nav.innerHTML = SCREENS.map((s, i) => `
    <a href="${linkTo(state.caseId, s.id)}" class="${s.id === state.screen ? "on" : ""}">
      <span class="ico">${s.ico}</span><span class="label">${esc(s.label)}</span>
      <span class="key">${i + 1}</span></a>`).join("");
}

// The stepper is a claim about what has run, so each stage reads its state
// from the case itself rather than from a stored progress field.
function renderStepper() {
  const host = document.getElementById("stepper");
  if (!host) return;
  const c = state.case;
  if (!c) { host.innerHTML = ""; return; }
  const s = c.scan, p = c.in_progress;
  const det = s?.detections?.[0];
  const stages = [
    ["Acquire", "evidence",
      s ? `hashed ${bytes(s.stats?.bytes_read)}` : p ? `${pct(p.fraction)} read` : "not run",
      s ? (s.stats?.complete_pass ? "done" : "part") : p ? "run" : ""],
    ["Identify", "vendors",
      det ? `${det.vendor} ${pct(det.confidence)}` : s ? "no match" : "not run",
      det ? "done" : s ? "part" : ""],
    ["Parse", "recordings",
      c.parse ? `${num(c.parse.recordings_total)} recordings` : "not run", c.parse ? "done" : ""],
    ["Recover", "recovered",
      c.carve ? `${num(c.carve.outside_total)} outside index` : "not run", c.carve ? "done" : ""],
    ["Timeline", "timeline",
      c.timeline ? `${num(Object.keys(c.timeline.cameras || {}).length)} cameras` : "not run",
      c.timeline ? "done" : ""],
    ["AI", "ai", c.analytics ? `${num(c.analytics.clips)} clips` : "not run",
      c.analytics ? "done" : ""],
    ["Report", "exports", s ? "ready" : "needs acquisition", s ? "done" : ""],
  ];
  host.innerHTML = stages.map(([t, screen, d, cls]) => `
    <button class="step ${cls}" data-go="${screen}">
      <div class="t">${esc(t)}</div><div class="d">${esc(d)}</div></button>`).join("");
  host.querySelectorAll("[data-go]").forEach((b) =>
    b.addEventListener("click", () => go(state.caseId, b.dataset.go)));
}

/* ------------------------------------------------------------ cases home */
function casesHome() {
  if (!state.cases.length) {
    return empty("No cases in this folder.",
                 "cli.py serve --out <folder that holds case folders>");
  }
  return `<h1 style="font-size:19px;margin:0 0 14px">Cases</h1>
  <div class="cases">${state.cases.map((c) => `
    <a class="case-card" href="${linkTo(c.id, "dashboard")}">
      <div class="id">${esc(c.id)}</div>
      <div class="dev">${esc(c.device || "—")}</div>
      <div class="dl" style="font-size:12px">
        <dt>Case ID</dt><dd>${esc(c.case_id || "—")}</dd>
        <dt>Size</dt><dd>${bytes(c.size_bytes)}</dd>
      </div>
      ${c.complete ? "" : `<div style="margin-top:10px">
        <div class="bar"><i style="width:${pct(c.progress)}"></i></div>
        <div class="muted" style="font-size:11px;margin-top:4px">acquiring — ${
          pct(c.progress)}</div></div>`}
      <div class="stages">
        <span class="${c.complete ? "has" : ""}">scan</span>
        <span class="${c.has_parse ? "has" : ""}">parse</span>
        <span class="${c.has_carve ? "has" : ""}">carve</span>
        <span class="${c.has_timeline ? "has" : ""}">timeline</span>
      </div>
    </a>`).join("")}</div>`;
}

/* ------------------------------------------------------------ render */
async function render() {
  const main = document.getElementById("main");
  if (!main) return;

  if (!state.caseId) {
    state.case = null;
    renderTopbar(); renderSidebar(); renderStepper();
    main.innerHTML = casesHome();
    return;
  }

  // Only refetch when the case actually changed: switching screens inside a
  // case must not re-hash every file the view cites.
  if (!state.case || state.case.id !== state.caseId) {
    main.innerHTML = skeleton(5);
    try {
      state.case = await api.case(state.caseId);
    } catch (e) {
      state.case = null;
      main.innerHTML = empty(`Could not load case ${state.caseId}.`, "");
      renderTopbar(); renderSidebar();
      return;
    }
  }

  const screen = SCREENS.find((s) => s.id === state.screen) || SCREENS[0];
  renderTopbar(); renderSidebar(); renderStepper();

  let out;
  try {
    out = screen.render(state.case, state.vendorInfo);
  } catch (e) {
    out = `<div class="empty"><div class="what">This screen failed to render.</div>
      <div class="mono" style="margin-top:7px">${esc(e && e.message)}</div></div>`;
  }
  if (typeof out === "string") {
    main.innerHTML = out;
  } else {
    main.innerHTML = out.html;
    if (out.bind) out.bind(main);
  }
  main.scrollTop = 0;
  animateCounts(main);

  const rv = document.getElementById("reverify");
  if (rv) {
    rv.addEventListener("click", async () => {
      state.case = await api.case(state.caseId);
      toast("Custody chain re-verified");
      render();
    });
  }
}

/* ------------------------------------------------------------ keyboard */
function initKeys() {
  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "select" || tag === "textarea" || e.metaKey || e.ctrlKey) return;
    if (e.key === "t") { toggleTheme(); return; }
    if (e.key === "/") {
      const q = document.querySelector("[data-q]");
      if (q) { e.preventDefault(); q.focus(); }
      return;
    }
    const n = Number(e.key);
    if (n >= 1 && n <= SCREENS.length && state.caseId) go(state.caseId, SCREENS[n - 1].id);
  });
}

/* ------------------------------------------------------------ boot */
async function boot() {
  initTheme();
  installCopy();
  initKeys();

  try {
    [state.cases, state.vendorInfo] = await Promise.all([api.cases(), api.vendors()]);
  } catch (e) {
    document.getElementById("main").innerHTML =
      `<div class="empty"><div class="what">The viewer could not reach its own server.</div>
       <div class="mono" style="margin-top:7px">${esc(e && e.message)}</div></div>`;
    return;
  }

  onRoute((r) => {
    // An unknown case in the URL falls back to the home rather than 404ing:
    // a stale link from a previous session should still land somewhere real.
    state.caseId = state.cases.some((c) => c.id === r.caseId) ? r.caseId : null;
    state.screen = SCREENS.some((s) => s.id === r.screen) ? r.screen : "dashboard";
    render();
  });
}

boot();

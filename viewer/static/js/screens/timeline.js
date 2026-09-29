// Timeline (UI_PLAN 6.6).
//
// The zoomable canvas is P3.  What is here now is the clock rule - which is
// not decoration but the one statement that stops a reader assuming UTC -
// plus the per-camera spans, gaps, anomalies and recorder-log events.
"use strict";

import { esc, num, empty, dur, clockTime, dataTable, clockBanner, pill } from "../ui.js";

export function timeline(c) {
  const t = c.timeline;
  if (!t) {
    return empty("No timeline has been built for this case.",
                 `cli.py timeline --out ${c.id}`);
  }

  const parts = [];
  const binds = [];

  parts.push(clockBanner(t.clock?.rule));

  const n = t.counts || {};
  const cams = t.cameras || {};
  parts.push(`<section class="panel"><div class="grid">
    <div class="card kpi"><div class="label">Indexed</div>
      <div class="value">${num(n.indexed)}</div>
      <div class="sub">listed by the recorder's index</div></div>
    <div class="card kpi"><div class="label">Unindexed</div>
      <div class="value" style="color:var(--synthetic_only)">${num(n.unindexed)}</div>
      <div class="sub">recovered, not in the index</div></div>
    <div class="card kpi"><div class="label">Remnants</div>
      <div class="value">${num(n.remnant)}</div>
      <div class="sub">index entries with no footage</div></div>
    <div class="card kpi"><div class="label">Gaps</div>
      <div class="value" style="${(t.gaps || []).length ? "color:var(--danger)" : ""}">${
        num((t.gaps || []).length)}</div>
      <div class="sub">periods with no footage on any camera</div></div>
  </div></section>`);

  /* ---------------------------------------------------------- cameras */
  if (Object.keys(cams).length) {
    const rows = Object.entries(cams).map(([k, v]) => ({
      camera: k,
      first: v.first_local ?? v.first ?? "",
      last: v.last_local ?? v.last ?? "",
      events: v.events ?? v.count ?? 0,
      covered: v.covered_s ?? 0,
    }));
    const tb = dataTable(rows, [
      { key: "camera", label: "Camera" },
      { key: "first", label: "First (recorder clock)", render: (r) => clockTime(r.first) },
      { key: "last", label: "Last (recorder clock)", render: (r) => clockTime(r.last) },
      { key: "events", label: "Events", cls: "num", sort: "num", render: (r) => num(r.events) },
      { key: "covered", label: "Covered", cls: "num", sort: "num", render: (r) => dur(r.covered) },
    ], { search: false });
    parts.push(`<section class="panel"><h2>Cameras</h2>${tb.html()}</section>`);
    binds.push(tb.bind);
  } else {
    parts.push(`<section class="panel"><h2>Cameras</h2>${
      empty("The timeline has no per-camera spans — nothing here was attributed to a camera.",
            `cli.py parse --device <dev> --out ${c.id}`)}</section>`);
  }

  /* ---------------------------------------------------------- events */
  /* The zoomable lanes are P3.  Until then the events themselves are the
   * timeline: each one says whether an index accounted for it, and what its
   * time rests on (`time_basis`), which is the part a lane cannot show. */
  const events = t.events || [];
  if (events.length) {
    const tb = dataTable(events.map((e) => ({
      id: e.id ?? "", kind: e.kind ?? "", camera: e.camera ?? "",
      start: e.start_local ?? "", end: e.end_local ?? "",
      secs: e.duration_s ?? 0, basis: e.time_basis ?? "",
      conf: e.confidence ?? 0, note: e.note ?? "",
    })), [
      { key: "id", label: "ID" },
      { key: "kind", label: "Kind", render: (r) => r.kind === "indexed"
        ? `<span style="color:var(--validated)">${esc(r.kind)}</span>`
        : `<span style="color:var(--synthetic_only)">${esc(r.kind)}</span>` },
      { key: "camera", label: "Camera" },
      { key: "start", label: "Start (recorder clock)", render: (r) => clockTime(r.start) },
      { key: "end", label: "End (recorder clock)", render: (r) => clockTime(r.end) },
      { key: "secs", label: "Duration", cls: "num", sort: "num", render: (r) => dur(r.secs) },
      { key: "basis", label: "Time basis" },
      { key: "conf", label: "Confidence", cls: "num", sort: "num",
        render: (r) => `${(r.conf * 100).toFixed(0)}%` },
      { key: "note", label: "Note" },
    ], { page: 100 });
    parts.push(`<section class="panel">
      <h2>Events <span class="hint">${num(events.length)} on the timeline &middot;
        "time basis" says what each time rests on</span></h2>
      ${tb.html()}</section>`);
    binds.push(tb.bind);
  }

  /* ---------------------------------------------------------- gaps */
  if ((t.gaps || []).length) {
    const tb = dataTable(t.gaps.map((g) => ({
      from: g.from_local ?? g.from ?? "", to: g.to_local ?? g.to ?? "",
      secs: g.seconds ?? g.duration_s ?? 0, camera: g.camera_id ?? "all",
    })), [
      { key: "from", label: "From (recorder clock)", render: (r) => clockTime(r.from) },
      { key: "to", label: "To (recorder clock)", render: (r) => clockTime(r.to) },
      { key: "secs", label: "Length", cls: "num", sort: "num", render: (r) => dur(r.secs) },
      { key: "camera", label: "Camera" },
    ], { search: false, page: 60 });
    parts.push(`<section class="panel">
      <h2 style="color:var(--danger)">Gaps
        <span class="hint">a gap is an absence of footage, not proof of deletion</span></h2>
      ${tb.html()}</section>`);
    binds.push(tb.bind);
  }

  /* ---------------------------------------------------------- anomalies */
  if ((t.anomalies || []).length) {
    parts.push(`<section class="panel"><h2>Anomalies</h2><div class="card">
      <ul style="margin:0;padding-left:19px;font-size:12.5px;line-height:1.8">
        ${t.anomalies.map((a) => `<li>${esc(
          typeof a === "string" ? a : a.detail || JSON.stringify(a))}</li>`).join("")}
      </ul></div></section>`);
  }

  /* ---------------------------------------------- recorder log events */
  const ev = t.recorder_events || [];
  if (ev.length) {
    const tb = dataTable(ev.map((e) => ({
      time: e.time_local ?? e.local ?? "", type: e.type ?? "", detail: e.detail ?? "",
    })), [
      { key: "time", label: "Time (recorder clock)", render: (r) => clockTime(r.time) },
      { key: "type", label: "Event" },
      { key: "detail", label: "Detail" },
    ], { page: 100 });
    parts.push(`<section class="panel">
      <h2>Recorder log <span class="hint">the recorder's own account of itself</span></h2>
      ${tb.html()}</section>`);
    binds.push(tb.bind);
  }

  /* ---------------------------------------------------------- activity */
  const act = c.activity;
  if (act) {
    parts.push(`<section class="panel">
      <h2>Motion activity <span class="hint">activity.json &middot; ${pill(act.status)}
        &middot; from frame sizes, not pixels</span></h2>
      <div class="grid">
        <div class="card kpi"><div class="label">Peaks</div>
          <div class="value">${num(act.peaks_total)}</div>
          <div class="sub">above ${esc(act.peak_factor)}× the median</div></div>
        <div class="card kpi"><div class="label">Cameras</div>
          <div class="value">${num(Object.keys(act.cameras || {}).length)}</div>
          <div class="sub">with minute-level data</div></div>
      </div>
      <p class="muted" style="font-size:12px;margin:10px 0 0">
        ${esc(act.rule || "")} A P-frame spike means the picture changed a lot, which
        usually means motion — it is a pointer, not a detection.</p>
    </section>`);
  }

  return { html: parts.join(""), bind: (root) => binds.forEach((b) => b(root)) };
}

// Recordings (UI_PLAN 6.4): what the recorder's own filesystem index lists.
//
// The field-provenance table is the point of this screen: it shows that every
// field above was read from a documented offset, and cites the source.
"use strict";

import { esc, num, bytes, hex, empty, pill, dataTable, clockTime, dur } from "../ui.js";

export function recordings(c) {
  const p = c.parse;
  if (!p) {
    return empty("The filesystem index has not been parsed for this case.",
                 `cli.py parse --device <dev> --out ${c.id}`);
  }

  const cams = p.per_camera || {};
  const head = `<section class="panel">
    <h2>${esc(p.vendor || "Parsed")} index
      <span class="hint">${esc(p.file)} &middot; ${pill(p.validation_status)}</span></h2>
    <div class="grid">
      <div class="card kpi"><div class="label">Recordings</div>
        <div class="value">${num(p.recordings_total)}</div>
        <div class="sub">${Object.keys(cams).length} camera(s)</div></div>
      <div class="card kpi"><div class="label">Remnants</div>
        <div class="value">${num(p.remnants_total)}</div>
        <div class="sub">index entries with no live recording</div></div>
      ${p.parser_rule ? `<div class="card kpi"><div class="label">Parser rule</div>
        <div class="value" style="font-size:15px">${esc(p.parser_rule)}</div></div>` : ""}
    </div>
    ${(p.summary || []).length ? `<div class="card" style="margin-top:12px">
      <h3>Volume</h3><ul style="margin:0;padding-left:19px;font-size:12.5px">${
        p.summary.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : ""}
  </section>`;

  const camPanel = Object.keys(cams).length ? `<section class="panel"><h2>Per camera</h2>
    <div class="grid">${Object.entries(cams).map(([k, v], i) => `
      <div class="card"><div class="label muted">${esc(k)}</div>
        <div style="font-size:21px;font-weight:640">${num(v)}</div>
        <div class="bar" style="margin-top:7px"><i style="width:${
          (v / Math.max(...Object.values(cams)) * 100).toFixed(0)
        }%;background:var(--cam${(i % 8) + 1})"></i></div></div>`).join("")}</div>
  </section>` : "";

  /* ---------------------------------------------------------- recordings */
  const recs = (p.recordings || []).map((r) => ({
    id: r.id ?? "", camera: r.camera_id ?? "",
    start: r.start_time_local ?? r.start_time ?? "",
    end: r.end_time_local ?? r.end_time ?? "",
    secs: r.duration_s ?? 0, codec: r.codec ?? "",
    offset: r.offset ?? 0, length: r.length ?? 0,
    conf: r.confidence ?? "",
  }));
  const tbl = dataTable(recs, [
    { key: "id", label: "ID" },
    { key: "camera", label: "Camera" },
    { key: "start", label: "Start (recorder clock)", render: (r) => clockTime(r.start) },
    { key: "end", label: "End (recorder clock)", render: (r) => clockTime(r.end) },
    { key: "secs", label: "Duration", cls: "num", sort: "num", render: (r) => dur(r.secs) },
    { key: "codec", label: "Codec" },
    { key: "offset", label: "Offset", cls: "num", sort: "num", render: (r) => hex(r.offset) },
    { key: "length", label: "Size", cls: "num", sort: "num", render: (r) => bytes(r.length) },
  ], { page: 100 });

  const recPanel = `<section class="panel">
    <h2>Recordings <span class="hint">times are the recorder's own clock${
      p.recordings_total > recs.length
        ? ` &middot; first ${num(recs.length)} of ${num(p.recordings_total)}` : ""}</span></h2>
    ${recs.length ? tbl.html() : empty("The index lists no recordings.")}
  </section>`;

  /* ---------------------------------------------------- field provenance */
  const fp = p.field_provenance || [];
  const fpTbl = fp.length ? dataTable(fp.map((x) => ({
    structure: x.structure ?? "", field: x.field ?? "",
    offset: x.offset ?? 0, source: x.source ?? "", citation: x.citation ?? "",
  })), [
    { key: "structure", label: "Structure" },
    { key: "field", label: "Field" },
    { key: "offset", label: "Offset", cls: "num", sort: "num", render: (r) => hex(r.offset) },
    { key: "source", label: "Source" },
    { key: "citation", label: "Citation" },
  ], { page: 60 }) : null;

  const fpPanel = fpTbl ? `<section class="panel">
    <h2>Field provenance <span class="hint">every field above, and where its offset came from</span></h2>
    ${fpTbl.html()}
  </section>` : "";

  const notes = [...(p.notes || []), ...(p.errors || [])].length ? `
    <section class="panel"><h2>Parser notes</h2><div class="card">
      ${(p.notes || []).map((n) => `<div style="font-size:12.5px">${esc(n)}</div>`).join("")}
      ${(p.errors || []).map((n) =>
        `<div style="font-size:12.5px;color:var(--danger)">${esc(n)}</div>`).join("")}
    </div></section>` : "";

  return {
    html: head + camPanel + recPanel + fpPanel + notes,
    bind: (root) => { if (recs.length) tbl.bind(root); if (fpTbl) fpTbl.bind(root); },
  };
}

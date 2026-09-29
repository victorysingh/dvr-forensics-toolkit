// Recovered footage (UI_PLAN 6.5): what came off the platter, including the
// footage the recorder's own index no longer accounts for.
//
// The video player lands in P3 with the /file route and Range support.  Raw
// elementary streams (.h264/.h265/.dav) cannot play in a browser at all, so
// they are listed with the command that makes a playable copy rather than a
// dead play button.
"use strict";

import { esc, num, bytes, hex, empty, pill, dataTable, clockTime, dur,
         hash as hashChip, firstLocal } from "../ui.js";

export function recovered(c) {
  const parts = [];
  const binds = [];

  const carve = c.carve;
  const es = c.es_carve;
  const ps = c.ps_carve;

  if (!carve && !es && !ps) {
    return empty("No carving has been run for this case.",
                 `cli.py carve --device <dev> --out ${c.id}`);
  }

  /* ---------------------------------------------------------- summary */
  if (carve) {
    const lab = carve.labels || {};
    const st = carve.stats || {};
    parts.push(`<section class="panel">
      <h2>Carve summary <span class="hint">carve/carve_report.json &middot; ${
        pill(carve.validation_status)}</span></h2>
      <div class="grid">
        <div class="card kpi"><div class="label">Streams kept</div>
          <div class="value">${num(st.streams_kept ?? carve.outside_total)}</div>
          <div class="sub">${num(st.frames)} frames carved</div></div>
        <div class="card kpi"><div class="label">Outside the index</div>
          <div class="value" style="color:var(--synthetic_only)">${num(carve.outside_total)}</div>
          <div class="sub">no index entry accounts for these</div></div>
        <div class="card kpi"><div class="label">Region scanned</div>
          <div class="value" style="font-size:17px">${bytes(
            (st.region_end || 0) - (st.region_start || 0))}</div>
          <div class="sub">${hex(st.region_start)} → ${hex(st.region_end)}</div></div>
      </div>
      <p class="muted" style="font-size:12.5px;margin:11px 0 0">
        <b>Outside the index</b> means the frames are on the platter but the
        recorder's index no longer lists them — typically footage that was
        deleted or rotated past. Recovering it needs no parser, which is why it
        works on vendors this tool cannot yet parse.</p>
    </section>`);

    const rows = Object.entries(lab).map(([k, v]) => ({
      label: k, streams: v.streams, frames: v.frames, size: v.bytes,
    })).sort((a, b) => b.frames - a.frames);
    const t = dataTable(rows, [
      { key: "label", label: "Index label",
        render: (r) => r.label === "outside_index"
          ? '<b style="color:var(--synthetic_only)">outside_index</b>' : esc(r.label) },
      { key: "streams", label: "Streams", cls: "num", sort: "num", render: (r) => num(r.streams) },
      { key: "frames", label: "Frames", cls: "num", sort: "num", render: (r) => num(r.frames) },
      { key: "size", label: "Bytes", cls: "num", sort: "num", render: (r) => bytes(r.size) },
    ], { search: false });
    parts.push(`<section class="panel"><h2>By label</h2>${t.html()}</section>`);
    binds.push(t.bind);
  }

  /* ---------------------------------------------- outside-index streams */
  if (carve?.outside_index?.length) {
    const rows = carve.outside_index.map((r) => ({
      id: r.id ?? "", camera: r.camera_id ?? "",
      start: firstLocal(r), secs: r.duration_s ?? 0,
      frames: r.frame_count ?? 0, size: r.length ?? 0,
      offset: r.offset ?? 0, codec: r.codec || "—",
      conf: r.confidence ?? 0, state: r.state ?? "",
    }));
    const t = dataTable(rows, [
      { key: "id", label: "ID" },
      { key: "camera", label: "Camera" },
      { key: "start", label: "Start (recorder clock)",
        render: (r) => r.start ? esc(r.start) : '<span class="muted">no time claim</span>' },
      { key: "secs", label: "Duration", cls: "num", sort: "num", render: (r) => dur(r.secs) },
      { key: "frames", label: "Frames", cls: "num", sort: "num", render: (r) => num(r.frames) },
      { key: "size", label: "Size", cls: "num", sort: "num", render: (r) => bytes(r.size) },
      { key: "offset", label: "Offset", cls: "num", sort: "num", render: (r) => hex(r.offset) },
      { key: "state", label: "State" },
      { key: "conf", label: "Confidence", cls: "num", sort: "num",
        render: (r) => `${(r.conf * 100).toFixed(0)}%` },
    ], { page: 100 });
    parts.push(`<section class="panel">
      <h2>Streams outside the index <span class="hint">${num(carve.outside_total)} total</span></h2>
      ${t.html()}</section>`);
    binds.push(t.bind);
  }

  /* ---------------------------------------------------------- extracted */
  const ex = carve?.extracted;
  if (ex?.streams && Object.keys(ex.streams).length) {
    // `files` is a map of written filename -> { bytes, sha256 }: one carved
    // stream can be written out in more than one container.
    const rows = Object.entries(ex.streams).map(([k, v]) => ({
      id: k, label: v.label ?? "", codec: v.codec ?? "",
      written: v.frames_written ?? 0, carved: v.frames_carved ?? 0,
      match: v.frames_match, files: v.files || {},
      names: Object.keys(v.files || {}).join(" "),
    }));
    const t = dataTable(rows, [
      { key: "id", label: "Stream" },
      { key: "label", label: "Label" },
      { key: "codec", label: "Codec" },
      { key: "written", label: "Written", cls: "num", sort: "num", render: (r) => num(r.written) },
      { key: "carved", label: "Carved", cls: "num", sort: "num", render: (r) => num(r.carved) },
      { key: "match", label: "Frames match", render: (r) => r.match
        ? '<span style="color:var(--validated)">yes</span>'
        : '<span style="color:var(--danger)">NO</span>' },
      { key: "names", label: "Files written", render: (r) =>
        Object.entries(r.files).map(([n, f]) =>
          `<div style="margin-bottom:3px"><span class="mono">${esc(n)}</span>
            <span class="muted">${bytes(f.bytes)}</span> ${hashChip(f.sha256, 6)}</div>`
        ).join("") || '<span class="muted">—</span>' },
    ], { page: 60 });
    parts.push(`<section class="panel">
      <h2>Extracted files <span class="hint">written out of the image, frame counts re-checked</span></h2>
      ${t.html()}
      <p class="muted" style="font-size:12px;margin:9px 0 0">
        Raw <code>.h264</code>, <code>.h265</code> and <code>.dav</code> streams do not
        play in a browser. Make a playable, hashed copy with
        <code>cli.py export-nist --out ${esc(c.id)}</code>.</p>
    </section>`);
    binds.push(t.bind);
  }

  /* ------------------------------------------------- annex-b / ps carves */
  if (es) {
    parts.push(`<section class="panel">
      <h2>Raw H.264/H.265 streams <span class="hint">carve/annexb_report.json &middot; ${
        pill(es.validation_status)}</span></h2>
      <div class="grid">
        <div class="card kpi"><div class="label">Streams</div>
          <div class="value">${num(es.streams_total)}</div>
          <div class="sub">${bytes(es.bytes)}</div></div>
      </div></section>`);
  }
  if (ps) {
    parts.push(`<section class="panel">
      <h2>Hikvision PS streams <span class="hint">carve/ps_report.json &middot; ${
        pill(ps.validation_status)}</span></h2>
      <div class="grid">
        <div class="card kpi"><div class="label">Streams</div>
          <div class="value">${num(ps.streams_total)}</div>
          <div class="sub">${bytes(ps.bytes)} &middot; ${dur(ps.duration_s)}</div></div>
        <div class="card kpi"><div class="label">Dated</div>
          <div class="value">${num(ps.dated)}</div>
          <div class="sub">${clockTime(ps.first_local)} → ${clockTime(ps.last_local)}</div></div>
      </div></section>`);
  }

  /* ---------------------------------------------------------- OSD titles */
  const osd = c.osd;
  if (osd?.named?.length) {
    const t = dataTable(osd.named.map((x) => ({
      clip: x.clip, title: x.title, conf: x.confidence,
      frames: x.frames, clock: x.clock ?? "", offset: x.offset_s ?? "",
    })), [
      { key: "clip", label: "Clip", cls: "mono" },
      { key: "title", label: "Camera title (read from the picture)" },
      { key: "conf", label: "Confidence", cls: "num", sort: "num",
        render: (r) => `${(r.conf * 100).toFixed(0)}%` },
      { key: "frames", label: "Frames agreeing", cls: "num" },
      { key: "clock", label: "Clock" },
    ], { page: 60 });
    parts.push(`<section class="panel">
      <h2>Camera titles from the burned-in OSD
        <span class="hint">analytics/osd.json &middot; ${pill(osd.status)}</span></h2>
      ${t.html()}</section>`);
    binds.push(t.bind);
  }

  return { html: parts.join(""), bind: (root) => binds.forEach((b) => b(root)) };
}

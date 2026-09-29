// Recovered footage (UI_PLAN 6.5): what came off the platter, including the
// footage the recorder's own index no longer accounts for.
//
// The video player lands in P3 with the /file route and Range support.  Raw
// elementary streams cannot play in a browser at all, so they are listed
// with the command that makes a playable copy rather than a dead button.
import { Section, Card, Pill, Empty, DataTable, Kpi, Hash, Code } from "../components/index.jsx";
import { num, bytes, hex, dur, pct0, firstLocal, clockTime } from "../lib/format.js";

export default function Recovered({ c }) {
  const carve = c.carve, es = c.es_carve, ps = c.ps_carve;
  if (!carve && !es && !ps) {
    return <Empty what="No carving has been run for this case."
      how={`cli.py carve --device <dev> --out ${c.id}`} />;
  }

  const labels = carve?.labels || {};
  const st = carve?.stats || {};
  const ex = carve?.extracted;

  return (
    <>
      {carve && (
        <>
          <Section title="Carve summary"
            hint={<>carve/carve_report.json &middot; <Pill status={carve.validation_status} /></>}>
            <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
              <Kpi label="Streams kept" value={st.streams_kept ?? carve.outside_total}
                sub={`${num(st.frames)} frames carved`} src="carve/carve_report.json" />
              <Kpi label="Outside the index" value={carve.outside_total}
                sub="no index entry accounts for these" src="carve/carve_report.json" />
              <Kpi label="Region scanned"
                value={bytes((st.region_end || 0) - (st.region_start || 0))}
                sub={`${hex(st.region_start)} → ${hex(st.region_end)}`}
                src="carve/carve_report.json" />
            </div>
            <p className="dim text-[12.5px] mt-3">
              <b>Outside the index</b> means the frames are on the platter but the
              recorder's index no longer lists them &mdash; typically footage that was
              deleted or rotated past. Recovering it needs no parser, which is why it
              works on vendors this tool cannot yet parse.
            </p>
          </Section>

          <Section title="By label">
            <DataTable search={false}
              rows={Object.entries(labels).map(([k, v]) => ({
                __k: k, label: k, streams: v.streams, frames: v.frames, size: v.bytes,
              })).sort((a, b) => b.frames - a.frames)}
              cols={[
                { key: "label", label: "Index label", render: (r) =>
                  r.label === "outside_index"
                    ? <b className="text-synthetic">outside_index</b> : r.label },
                { key: "streams", label: "Streams", cls: "text-right font-mono", sort: "num",
                  render: (r) => num(r.streams) },
                { key: "frames", label: "Frames", cls: "text-right font-mono", sort: "num",
                  render: (r) => num(r.frames) },
                { key: "size", label: "Bytes", cls: "text-right font-mono", sort: "num",
                  render: (r) => bytes(r.size) },
              ]} />
          </Section>
        </>
      )}

      {(carve?.outside_index || []).length > 0 && (
        <Section title="Streams outside the index" hint={`${num(carve.outside_total)} total`}>
          <DataTable
            rows={carve.outside_index.map((r, i) => ({
              __k: i,
              id: r.id ?? "", camera: r.camera_id ?? "",
              start: firstLocal(r), secs: r.duration_s ?? 0,
              frames: r.frame_count ?? 0, size: r.length ?? 0,
              offset: r.offset ?? 0, state: r.state ?? "", conf: r.confidence ?? 0,
            }))}
            cols={[
              { key: "id", label: "ID" },
              { key: "camera", label: "Camera" },
              { key: "start", label: "Start (recorder clock)", render: (r) =>
                r.start || <span className="dim">no time claim</span> },
              { key: "secs", label: "Duration", cls: "text-right font-mono", sort: "num",
                render: (r) => dur(r.secs) },
              { key: "frames", label: "Frames", cls: "text-right font-mono", sort: "num",
                render: (r) => num(r.frames) },
              { key: "size", label: "Size", cls: "text-right font-mono", sort: "num",
                render: (r) => bytes(r.size) },
              { key: "offset", label: "Offset", cls: "text-right font-mono", sort: "num",
                render: (r) => hex(r.offset) },
              { key: "state", label: "State" },
              { key: "conf", label: "Confidence", cls: "text-right font-mono", sort: "num",
                render: (r) => pct0(r.conf) },
            ]} />
        </Section>
      )}

      {ex?.streams && Object.keys(ex.streams).length > 0 && (
        <Section title="Extracted files"
          hint="written out of the image, frame counts re-checked">
          <DataTable page={60}
            rows={Object.entries(ex.streams).map(([k, v]) => ({
              __k: k, id: k, label: v.label ?? "", codec: v.codec ?? "",
              written: v.frames_written ?? 0, carved: v.frames_carved ?? 0,
              match: v.frames_match,
              // `files` is a map of written filename -> { bytes, sha256 }: one
              // carved stream can be written out in more than one container.
              files: v.files || {},
              names: Object.keys(v.files || {}).join(" "),
            }))}
            cols={[
              { key: "id", label: "Stream" },
              { key: "label", label: "Label" },
              { key: "codec", label: "Codec" },
              { key: "written", label: "Written", cls: "text-right font-mono", sort: "num",
                render: (r) => num(r.written) },
              { key: "carved", label: "Carved", cls: "text-right font-mono", sort: "num",
                render: (r) => num(r.carved) },
              { key: "match", label: "Frames match", render: (r) => r.match
                ? <span className="text-validated">yes</span>
                : <span className="text-danger">NO</span> },
              { key: "names", label: "Files written", render: (r) =>
                Object.entries(r.files).map(([n, f]) => (
                  <div key={n} className="mb-0.5">
                    <span className="font-mono">{n}</span>{" "}
                    <span className="dim">{bytes(f.bytes)}</span>{" "}
                    <Hash value={f.sha256} len={6} />
                  </div>
                )) },
            ]} />
          <p className="dim text-[12px] mt-2">
            Raw <Code>.h264</Code>, <Code>.h265</Code> and <Code>.dav</Code> streams do not
            play in a browser. Make a playable, hashed copy with{" "}
            <Code>{`cli.py export-nist --out ${c.id}`}</Code>.
          </p>
        </Section>
      )}

      {es && (
        <Section title="Raw H.264/H.265 streams"
          hint={<>carve/annexb_report.json &middot; <Pill status={es.validation_status} /></>}>
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
            <Kpi label="Streams" value={es.streams_total} sub={bytes(es.bytes)}
              src="carve/annexb_report.json" />
          </div>
        </Section>
      )}

      {ps && (
        <Section title="Hikvision PS streams"
          hint={<>carve/ps_report.json &middot; <Pill status={ps.validation_status} /></>}>
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
            <Kpi label="Streams" value={ps.streams_total}
              sub={`${bytes(ps.bytes)} · ${dur(ps.duration_s)}`} src="carve/ps_report.json" />
            <Kpi label="Dated" value={ps.dated}
              sub={`${clockTime(ps.first_local)} → ${clockTime(ps.last_local)}`}
              src="carve/ps_report.json" />
          </div>
        </Section>
      )}

      {(c.osd?.named || []).length > 0 && (
        <Section title="Camera titles from the burned-in OSD"
          hint={<>analytics/osd.json &middot; <Pill status={c.osd.status} /></>}>
          <DataTable page={60}
            rows={c.osd.named.map((x, i) => ({ ...x, __k: i }))}
            cols={[
              { key: "clip", label: "Clip", cls: "font-mono" },
              { key: "title", label: "Camera title (read from the picture)" },
              { key: "confidence", label: "Confidence", cls: "text-right font-mono", sort: "num",
                render: (r) => pct0(r.confidence) },
              { key: "frames", label: "Frames agreeing", cls: "text-right font-mono" },
              { key: "clock", label: "Clock" },
            ]} />
        </Section>
      )}
    </>
  );
}

// Recordings (UI_PLAN 6.4): what the recorder's own filesystem index lists.
//
// The field-provenance table is the point of this screen: it shows that
// every field above was read from a documented offset, and cites the source.
import { Section, Card, DL, Pill, Empty, DataTable, Kpi } from "../components/index.jsx";
import { num, bytes, hex, dur, clockTime, camColor } from "../lib/format.js";

export default function Recordings({ c }) {
  const p = c.parse;
  const hik = c.ps_carve?.labels;
  if (!p && hik) {
    // Say where the index went, rather than send the examiner to a command
    // that, on a reformatted disk, finds an empty index.
    return <Empty what={`No filesystem parse report. The recorder's HIKBTREE index
      (${num(hik.index_records)} records) was read while labelling the carved streams:
      the labelled streams are on Recovered, and their times on Timeline.`} />;
  }
  if (!p) {
    return <Empty what="The filesystem index has not been parsed for this case."
      how={`cli.py parse --device <dev> --out ${c.id}`} />;
  }

  const cams = p.per_camera || {};
  const recs = (p.recordings || []).map((r, i) => ({
    __k: i,
    id: r.id ?? "", camera: r.camera_id ?? "",
    start: r.start_time_local ?? r.start_time ?? "",
    end: r.end_time_local ?? r.end_time ?? "",
    secs: r.duration_s ?? 0, codec: r.codec ?? "",
    offset: r.offset ?? 0, length: r.length ?? 0,
  }));

  return (
    <>
      <Section title={`${p.vendor || "Parsed"} index`}
        hint={<>{p.file} &middot; <Pill status={p.validation_status} /></>}>
        <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
          <Kpi label="Recordings" value={p.recordings_total}
            sub={`${Object.keys(cams).length} camera(s)`} src={p.file} />
          <Kpi label="Remnants" value={p.remnants_total}
            sub="index entries with no live recording" src={p.file} />
          {p.parser_rule && (
            <Kpi label="Parser rule" value={p.parser_rule} src={p.file} />
          )}
        </div>
        {(p.summary || []).length > 0 && (
          <Card className="mt-3">
            <h3 className="dim text-[13px] uppercase font-semibold mb-2">Volume</h3>
            {/* the parser writes [key, value] pairs; an empty key continues the row above */}
            <div className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5 text-[12.5px]">
              {p.summary.map((x, i) => {
                const [k, v] = Array.isArray(x) ? x : ["", x];
                return [<span key={`k${i}`} className="dim">{k}</span>,
                        <span key={`v${i}`}>{v}</span>];
              })}
            </div>
          </Card>
        )}
      </Section>

      {Object.keys(cams).length > 0 && (
        <Section title="Per camera">
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(180px,1fr))]">
            {Object.entries(cams).map(([k, v], i) => (
              <Card key={k}>
                <div className="dim text-[11.5px]">{k}</div>
                <div className="text-xl font-semibold">{num(v)}</div>
                <div className="panel-2 h-1.5 rounded-full overflow-hidden mt-2">
                  <i className="block h-full rounded-full"
                    style={{ width: `${(v / Math.max(...Object.values(cams))) * 100}%`,
                             background: camColor(i) }} />
                </div>
              </Card>
            ))}
          </div>
        </Section>
      )}

      <Section title="Recordings"
        hint={`times are the recorder's own clock${
          p.recordings_total > recs.length
            ? ` · first ${num(recs.length)} of ${num(p.recordings_total)}` : ""}`}>
        {recs.length ? (
          <DataTable rows={recs} cols={[
            { key: "id", label: "ID" },
            { key: "camera", label: "Camera" },
            { key: "start", label: "Start (recorder clock)", render: (r) => clockTime(r.start) },
            { key: "end", label: "End (recorder clock)", render: (r) => clockTime(r.end) },
            { key: "secs", label: "Duration", cls: "text-right font-mono", sort: "num",
              render: (r) => dur(r.secs) },
            { key: "codec", label: "Codec" },
            { key: "offset", label: "Offset", cls: "text-right font-mono", sort: "num",
              render: (r) => hex(r.offset) },
            { key: "length", label: "Size", cls: "text-right font-mono", sort: "num",
              render: (r) => bytes(r.length) },
          ]} />
        ) : <Empty what="The index lists no recordings." />}
      </Section>

      {(p.field_provenance || []).length > 0 && (
        <Section title="Field provenance"
          hint="every field above, and where its offset came from">
          <DataTable page={60}
            rows={p.field_provenance.map((x, i) => ({ ...x, __k: i }))}
            cols={[
              { key: "structure", label: "Structure" },
              { key: "field", label: "Field" },
              { key: "offset", label: "Offset", cls: "text-right font-mono", sort: "num",
                render: (r) => hex(r.offset) },
              { key: "source", label: "Source" },
              { key: "citation", label: "Citation" },
            ]} />
        </Section>
      )}

      {[...(p.notes || []), ...(p.errors || [])].length > 0 && (
        <Section title="Parser notes">
          <Card>
            {(p.notes || []).map((n, i) => <div key={i} className="text-[12.5px]">{n}</div>)}
            {(p.errors || []).map((n, i) =>
              <div key={i} className="text-[12.5px] text-danger">{n}</div>)}
          </Card>
        </Section>
      )}
    </>
  );
}

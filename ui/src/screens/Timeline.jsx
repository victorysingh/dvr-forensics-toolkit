// Timeline (UI_PLAN 6.6).
//
// The zoomable canvas is P3.  What is here now is the clock rule - not
// decoration, but the one statement that stops a reader assuming UTC - plus
// the per-camera spans, gaps, events and recorder-log entries.
import { Section, Card, Pill, Empty, DataTable, Kpi, ClockBanner } from "../components/index.jsx";
import { num, dur, clockTime, pct0 } from "../lib/format.js";

export default function Timeline({ c }) {
  const t = c.timeline;
  if (!t) {
    return <Empty what="No timeline has been built for this case."
      how={`cli.py timeline --out ${c.id}`} />;
  }

  const n = t.counts || {};
  const cams = t.cameras || {};
  const gaps = t.gaps || [];
  const events = t.events || [];
  const act = c.activity;

  return (
    <>
      <ClockBanner rule={t.clock?.rule} />

      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
        <Kpi label="Indexed" value={n.indexed || 0}
          sub="listed by the recorder's index" src="timeline.json" />
        <Kpi label="Unindexed" value={n.unindexed || 0}
          sub="recovered, not in the index" src="timeline.json" />
        <Kpi label="Remnants" value={n.remnant || 0}
          sub="index entries with no footage" src="timeline.json" />
        <Kpi label="Gaps" value={gaps.length}
          sub={`periods a camera has no footage · ${gaps.filter((g) => g.system_wide).length} on every camera`}
          src="timeline.json" />
      </div>

      <Section title="Cameras">
        {Object.keys(cams).length ? (
          <DataTable search={false}
            rows={Object.entries(cams).map(([k, v]) => ({
              __k: k, camera: k,
              first: v.first_local ?? v.first ?? "",
              last: v.last_local ?? v.last ?? "",
              recordings: v.recordings ?? 0,
              covered: v.covered_s ?? 0,
            }))}
            cols={[
              { key: "camera", label: "Camera" },
              { key: "first", label: "First (recorder clock)", render: (r) => clockTime(r.first) },
              { key: "last", label: "Last (recorder clock)", render: (r) => clockTime(r.last) },
              { key: "recordings", label: "Indexed recordings", cls: "text-right font-mono",
                sort: "num", render: (r) => num(r.recordings) },
              { key: "covered", label: "Covered", cls: "text-right font-mono", sort: "num",
                render: (r) => dur(r.covered) },
            ]} />
        ) : (
          <Empty what="The timeline has no per-camera spans — nothing here was attributed to a camera."
            how={`cli.py parse --device <dev> --out ${c.id}`} />
        )}
      </Section>

      {gaps.length > 0 && (
        <Section title={<span className="text-danger">Gaps</span>}
          hint="a gap is an absence of footage, not proof of deletion">
          <DataTable search={false} page={60}
            rows={gaps.map((g, i) => ({
              __k: i,
              from: g.start_local ?? "", to: g.end_local ?? "",
              secs: g.duration_s ?? 0,
              camera: g.system_wide ? "all" : [g.camera, ...(g.shared_with || [])].join(", "),
            }))}
            cols={[
              { key: "from", label: "From (recorder clock)", render: (r) => clockTime(r.from) },
              { key: "to", label: "To (recorder clock)", render: (r) => clockTime(r.to) },
              { key: "secs", label: "Length", cls: "text-right font-mono", sort: "num",
                render: (r) => dur(r.secs) },
              { key: "camera", label: "Camera" },
            ]} />
        </Section>
      )}

      {/* The zoomable lanes are P3.  Until then the events are the timeline:
          each one says whether an index accounted for it, and what its time
          rests on - which a lane cannot show. */}
      {events.length > 0 && (
        <Section title="Events"
          hint={`${num(events.length)} of ${num((n.indexed || 0) + (n.unindexed || 0) + (n.remnant || 0))} shown · "time basis" says what each time rests on`}>
          <DataTable
            rows={events.map((e, i) => ({
              __k: i,
              id: e.id ?? "", kind: e.kind ?? "", camera: e.camera ?? "",
              start: e.start_local ?? "", end: e.end_local ?? "",
              secs: e.duration_s ?? 0, basis: e.time_basis ?? "",
              conf: e.confidence ?? 0, note: e.note ?? "",
            }))}
            cols={[
              { key: "id", label: "ID" },
              { key: "kind", label: "Kind", render: (r) => (
                <span className={r.kind === "indexed" ? "text-validated" : "text-synthetic"}>
                  {r.kind}</span>) },
              { key: "camera", label: "Camera" },
              { key: "start", label: "Start (recorder clock)", render: (r) => clockTime(r.start) },
              { key: "end", label: "End (recorder clock)", render: (r) => clockTime(r.end) },
              { key: "secs", label: "Duration", cls: "text-right font-mono", sort: "num",
                render: (r) => dur(r.secs) },
              { key: "basis", label: "Time basis" },
              { key: "conf", label: "Confidence", cls: "text-right font-mono", sort: "num",
                render: (r) => pct0(r.conf) },
              { key: "note", label: "Note" },
            ]} />
        </Section>
      )}

      {(t.anomalies || []).length > 0 && (
        <Section title="Anomalies">
          <Card>
            <ul className="list-disc pl-5 text-[12.5px] space-y-1">
              {t.anomalies.map((a, i) => (
                <li key={i}>{typeof a === "string" ? a : a.detail || JSON.stringify(a)}</li>
              ))}
            </ul>
          </Card>
        </Section>
      )}

      {(t.recorder_events || []).length > 0 && (
        <Section title="Recorder log" hint="the recorder's own account of itself">
          <DataTable
            rows={t.recorder_events.map((e, i) => ({
              __k: i,
              time: e.time_local ?? e.local ?? "", type: e.type ?? "", detail: e.detail ?? "",
            }))}
            cols={[
              { key: "time", label: "Time (recorder clock)", render: (r) => clockTime(r.time) },
              { key: "type", label: "Event" },
              { key: "detail", label: "Detail" },
            ]} />
        </Section>
      )}

      {act && (
        <Section title="Motion activity"
          hint={<>activity.json &middot; <Pill status={act.status} /> &middot; from frame sizes, not pixels</>}>
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
            <Kpi label="Peaks" value={act.peaks_total}
              sub={`above ${act.peak_factor}× the median`} src="activity.json" />
            <Kpi label="Cameras" value={Object.keys(act.cameras || {}).length}
              sub="with minute-level data" src="activity.json" />
          </div>
          <p className="dim text-[12px] mt-2.5">
            {act.rule} A P-frame spike means the picture changed a lot, which usually
            means motion &mdash; it is a pointer, not a detection.
          </p>
        </Section>
      )}
    </>
  );
}

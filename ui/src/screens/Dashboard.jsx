// Dashboard: the whole case in one look (UI_PLAN 6.1).
//
// Every KPI names the file it was read from.  Nothing here is computed from
// anything but load_case's own numbers.
import { Kpi, Section, Card, DL, Pill, Hash, Empty } from "../components/index.jsx";
import { bytes, num, pct, camColor, plural, utcTime } from "../lib/format.js";

export default function Dashboard({ c }) {
  if (!c.scan && !c.in_progress) {
    return <Empty what="This case has no acquisition yet."
      how={`cli.py scan --device <dev> --out ${c.id}`} />;
  }

  const s = c.scan;
  const carve = c.carve || {};
  const labels = carve.labels || {};
  const tot = Object.values(labels).reduce(
    (a, v) => ({ streams: a.streams + v.streams, frames: a.frames + v.frames,
                 bytes: a.bytes + v.bytes }), { streams: 0, frames: 0, bytes: 0 });
  // A Hikvision disk carries MPEG-PS, not DHAV, and its index is read while the
  // carved streams are labelled (carve/hik_index.json), not by `parse`.
  const ps = !tot.streams && c.ps_carve ? c.ps_carve : null;
  const hikIndex = !c.parse && ps?.labels ? ps.labels : null;
  // channel 255 marks a block reserved at format time, not a camera (hikbtree.py)
  const hikCams = Object.keys(hikIndex?.index_channels || {}).filter((k) => k !== "255").length;

  const det = s?.detections?.[0];
  const ver = c.custody?.verify || {};
  const an = c.analytics;
  const cams = c.parse?.per_camera || {};
  const camCount = Object.keys(cams).length
    || Object.keys(c.timeline?.cameras || {}).length;
  const tl = c.timeline?.counts || {};
  const ci = s?.case || {};

  return (
    <>
      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
        <Kpi label="Device"
          value={bytes(s?.device?.size_bytes || c.in_progress?.size_bytes)}
          sub={s ? (s.stats?.complete_pass
                ? "complete pass — every block hashed"
                : `triage — ${bytes(s.stats?.bytes_read)} read`)
              : `acquiring — ${pct(c.in_progress.fraction)} read`}
          src="scan_report.json" />

        {det && (
          <Kpi label="Vendor" value={det.vendor}
            sub={<>{pct(det.confidence)} confidence &middot;{" "}
              <Pill status={det.validation_status} /></>}
            src="scan_report.json" />
        )}

        {hikIndex ? (
          <Kpi label="Index records" value={hikIndex.index_records}
            sub={`HIKBTREE records, ${hikCams} camera channel${hikCams === 1 ? "" : "s"} · read while labelling`}
            src="carve/hik_index.json" />
        ) : (
          <Kpi label="Recordings" value={c.parse ? c.parse.recordings_total : 0}
            sub={c.parse ? `${camCount} camera${camCount === 1 ? "" : "s"} in the index`
                         : "filesystem not parsed"}
            src={c.parse ? c.parse.file : "parse_*.json"} />
        )}

        {ps ? (
          <Kpi label="Footage recovered" value={ps.streams_total}
            sub={`MPEG-PS streams · ${bytes(ps.bytes)}`}
            src="carve/ps_report.json" />
        ) : (
          <Kpi label="Footage recovered" value={tot.streams}
            sub={`${num(tot.frames)} frames · ${bytes(tot.bytes)}`}
            src="carve/carve_report.json" />
        )}

        {labels.outside_index && (
          <Kpi label="Outside the index" value={labels.outside_index.streams}
            sub={`${num(labels.outside_index.frames)} frames the recorder's own index no longer lists`}
            src="carve/carve_report.json" />
        )}

        {c.timeline && (
          <Kpi label="Timeline"
            value={(tl.indexed || 0) + (tl.unindexed || 0) + (tl.remnant || 0)}
            sub={`${num(tl.indexed)} indexed · ${num(tl.unindexed)} unindexed · ${
              plural((c.timeline.gaps || []).length, "gap")}`}
            src="timeline.json" />
        )}

        {an && (
          <Kpi label="AI leads" lead
            value={Object.values(an.totals || {}).reduce((a, b) => a + b, 0)}
            sub={`${plural(an.clips, "clip")} · ${num(an.frames_analysed)} frames analysed`}
            src="analytics/analytics.json" />
        )}

        <Kpi label="Custody" value={(c.custody?.entries || []).length}
          sub={ver.valid
            ? <span className="text-validated">chain intact &#10003;</span>
            : <span className="text-danger">{ver.message || "chain broken"}</span>}
          src="custody_ledger.jsonl" />
      </div>

      <Section>
        <Card>
          <DL rows={[
            ["Case ID", c.case_id || c.id],
            ["Investigator", ci.investigator || "—"],
            ["Organisation", ci.organization || "—"],
            ["Device", <span className="font-mono break-all">{s?.device?.path || "—"}</span>],
            ["Model", s?.device?.model || "—"],
            ["Acquired", <>{utcTime(s?.generated_utc)} <span className="dim">UTC</span></>],
            ["Tool", `${s?.tool || ""} ${s?.tool_version || ""}`],
          ]} />
        </Card>
      </Section>

      {camCount > 0 && Object.keys(cams).length > 0 && (
        <Section title="Cameras" hint={`recordings per camera, from ${c.parse.file}`}>
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

      {Object.keys(labels).length > 0 && (
        <Section title="Recovered streams by label" hint="from carve/carve_report.json">
          <div className="panel overflow-hidden">
            <table className="w-full border-collapse text-[12.5px]">
              <thead><tr>
                {["Label", "Streams", "Frames", "Bytes"].map((h, i) => (
                  <th key={h} className={`dim font-semibold text-[11px] uppercase tracking-wide
                    px-2.5 py-1.5 hairline border-b ${i ? "text-right" : "text-left"}`}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {Object.entries(labels).sort((a, b) => b[1].frames - a[1].frames)
                  .map(([k, v]) => (
                  <tr key={k}>
                    <td className="px-2.5 py-1.5 hairline border-b">
                      {k === "outside_index"
                        ? <b className="text-synthetic">outside_index</b> : k}
                    </td>
                    <td className="px-2.5 py-1.5 hairline border-b text-right font-mono">
                      {num(v.streams)}</td>
                    <td className="px-2.5 py-1.5 hairline border-b text-right font-mono">
                      {num(v.frames)}</td>
                    <td className="px-2.5 py-1.5 hairline border-b text-right font-mono">
                      {bytes(v.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {labels.outside_index && (
            <p className="dim text-[12.5px] mt-2">
              <b>outside_index</b> is footage found on the platter that the recorder's own
              index no longer accounts for &mdash; deleted or overwritten entries, recovered
              in the same read pass.
            </p>
          )}
        </Section>
      )}

      {(s?.hashes || []).length > 0 && (
        <Section title="Acquisition hashes" hint="click any value to copy">
          <Card>
            <DL rows={[
              ...s.hashes.map((h) => [
                h.algorithm.toUpperCase(),
                <><Hash value={h.value} len={10} /> <span className="dim">{h.scope}</span></>,
              ]),
              s.merkle_root && ["Merkle root",
                <><Hash value={s.merkle_root} len={10} />{" "}
                  <span className="dim">per-block tree</span></>],
            ]} />
          </Card>
        </Section>
      )}
    </>
  );
}

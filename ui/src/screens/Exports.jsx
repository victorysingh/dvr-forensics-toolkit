// Reports and exports (UI_PLAN 6.9).
//
// Shows what the case view carries: the rendered report, and the hashes of
// what the pipeline wrote.  Court exports are written by their own commands.
import { Section, Card, DL, Hash, Code, Empty } from "../components/index.jsx";
import { api } from "../lib/api.js";

export default function Exports({ c }) {
  const files = c.files || {};

  const known = [
    ["scan_report.json", "Acquisition report — device, hashes, detections, statistics"],
    ["blockmap.jsonl", "Per-block hash, entropy and start-code map"],
    ["custody_ledger.jsonl", "The custody chain"],
  ].filter(([n]) => files[n]);

  const derived = [
    c.parse && [c.parse.file, c.parse.sha256, "Filesystem index parse"],
    c.carve && ["carve/carve_report.json", c.carve.sha256, "Carve report"],
    c.carve?.extracted && ["carve/extracted.json", c.carve.extracted.sha256, "Extraction manifest"],
    c.es_carve && ["carve/annexb_report.json", c.es_carve.sha256, "Raw H.264/H.265 carve"],
    c.ps_carve && ["carve/ps_report.json", c.ps_carve.sha256, "Hikvision PS carve"],
    c.timeline && ["timeline.json", c.timeline.sha256, "Timeline"],
    c.activity && ["activity.json", c.activity.sha256, "Motion activity"],
    c.analytics && ["analytics/analytics.json", c.analytics.sha256, "AI leads"],
    c.osd && ["analytics/osd.json", c.osd.sha256, "OSD titles read from the picture"],
    c.recorder_log && ["hik_log.json", c.recorder_log.sha256, "Recorder system log"],
  ].filter(Boolean);

  return (
    <>
      <Section title="Report">
        <Card>
          <div className="flex justify-between items-center gap-3 flex-wrap">
            <div>
              <div className="font-semibold">Examiner's HTML report</div>
              <div className="dim text-[12px]">
                Rendered from this case on demand, with every status and citation
                the screens show.
              </div>
            </div>
            {c.scan ? (
              <a href={api.reportUrl(c.id)} target="_blank" rel="noopener"
                className="border border-validated/45 text-validated rounded-full px-3 py-1
                  text-[11.5px] whitespace-nowrap">Open report &#8599;</a>
            ) : (
              <span className="hairline border rounded-full px-3 py-1 text-[11.5px] dim">
                needs acquisition</span>
            )}
          </div>
        </Card>
      </Section>

      <Section title="Case files" hint="SHA-256 of what the pipeline wrote">
        {known.length ? (
          <div className="panel overflow-hidden">
            <table className="w-full border-collapse text-[12.5px]">
              <thead><tr>
                {["File", "SHA-256"].map((h) => (
                  <th key={h} className="dim font-semibold text-[11px] uppercase tracking-wide
                    px-2.5 py-1.5 hairline border-b text-left">{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {known.map(([n, d]) => (
                  <tr key={n}>
                    <td className="px-2.5 py-1.5 hairline border-b">
                      <span className="font-mono">{n}</span>
                      <div className="dim text-[11.5px]">{d}</div>
                    </td>
                    <td className="px-2.5 py-1.5 hairline border-b align-top">
                      <Hash value={files[n]} len={10} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty what="No case files recorded." />}
      </Section>

      {derived.length > 0 && (
        <Section title="Stage outputs">
          <div className="panel overflow-hidden">
            <table className="w-full border-collapse text-[12.5px]">
              <thead><tr>
                {["File", "What it is", "SHA-256"].map((h) => (
                  <th key={h} className="dim font-semibold text-[11px] uppercase tracking-wide
                    px-2.5 py-1.5 hairline border-b text-left">{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {derived.map(([n, h, d]) => (
                  <tr key={n}>
                    <td className="px-2.5 py-1.5 hairline border-b font-mono">{n}</td>
                    <td className="px-2.5 py-1.5 hairline border-b">{d}</td>
                    <td className="px-2.5 py-1.5 hairline border-b"><Hash value={h} len={10} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      <Section title="Court and interchange exports">
        <Card>
          <p className="dim text-[12.5px] mb-2.5">
            The s.63 certificate, CASE/UCO JSON-LD and NIST CCTV export are written into
            the case folder by their own commands, each recorded in the custody ledger
            with its hash.
          </p>
          <DL rows={[
            ["s.63 certificate", <Code>{`cli.py certificate --out ${c.id} --part B`}</Code>],
            ["CASE/UCO", <Code>{`cli.py case-export --out ${c.id}`}</Code>],
            ["NIST CCTV", <Code>{`cli.py export-nist --out ${c.id}`}</Code>],
          ]} />
        </Card>
      </Section>
    </>
  );
}

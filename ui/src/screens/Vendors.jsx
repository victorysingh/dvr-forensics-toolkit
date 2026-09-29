// Vendor identification (UI_PLAN 6.3): the eight PS vendors, what this disk
// actually showed, and what we can honestly parse.
//
// `parser_status` is the weakest evidence behind a parser, never better - so
// it sits on every card, not only the winner's.
import { Section, Card, DL, Pill, ConfBar, Empty, Code } from "../components/index.jsx";
import { num, pct } from "../lib/format.js";

export default function Vendors({ c, vendorInfo }) {
  const rows = c.vendors || [];
  if (!rows.length) return <Empty what="No vendor matrix available." />;

  const top = (c.scan?.detections || [])[0];

  return (
    <>
      <Section title="Detected on this disk">
        {top ? (
          <Card className="border-teal-500/45">
            <div className="flex items-baseline gap-3 flex-wrap">
              <div className="text-2xl font-semibold">{top.vendor}</div>
              <div className="text-[19px] text-teal-500 font-mono">{pct(top.confidence)}</div>
              <Pill status={top.validation_status} />
              <span className={`hairline border rounded-full px-2.5 py-1 text-[11.5px]
                ${top.parser_available ? "text-validated border-validated/45" : "dim"}`}>
                {top.parser_available ? "parser available" : "no parser"}
              </span>
            </div>
            <p className="dim text-[12.5px] mt-2 mb-3">
              {num(top.hit_count)} signature hit(s) across the scanned region.
              Confidence is the detector's own score, not a probability of guilt.
            </p>
            <h3 className="dim text-[13px] uppercase font-semibold mb-1.5">Evidence strings</h3>
            <ul className="font-mono text-[12px] leading-relaxed list-disc pl-5 space-y-0.5">
              {(top.evidence || []).map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          </Card>
        ) : (
          <Empty what="No vendor signature matched this disk."
            how={`cli.py survey --device <dev> --out ${c.id}`} />
        )}
      </Section>

      <Section title="The eight PS vendors" hint="coverage, and what each claim rests on">
        <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(290px,1fr))]">
          {rows.map((v) => {
            const hit = v.detected_confidence > 0;
            return (
              <Card key={v.vendor} className={hit ? "border-teal-500/40" : ""}>
                <div className="flex justify-between items-start gap-2">
                  <div className="font-semibold text-[15px]">{v.vendor}</div>
                  <Pill status={v.parser_status} />
                </div>
                <div className="dim text-[12px] mt-0.5 mb-2.5">{v.family}</div>

                {hit ? <ConfBar value={v.detected_confidence} />
                     : <div className="dim text-[12px]">not detected on this disk</div>}

                {v.detected_note && (
                  <div className="dim text-[11.5px] mt-1.5">{v.detected_note}</div>
                )}

                <div className="mt-3">
                  <DL rows={[
                    ["Parser", v.parser || <span className="dim">none</span>],
                    ["Signatures", num(v.signatures)],
                    ["Media held", v.media],
                  ]} />
                </div>

                {v.basis && (
                  <details className="mt-2.5">
                    <summary className="dim text-[11.5px] cursor-pointer">Basis</summary>
                    <div className="dim text-[11.5px] mt-1.5">{v.basis}</div>
                  </details>
                )}
              </Card>
            );
          })}
        </div>
      </Section>

      {(vendorInfo?.onboarding || []).length > 0 && (
        <Section title="Onboarding a new vendor" hint="unknown disk → parsed footage">
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(230px,1fr))]">
            {vendorInfo.onboarding.map((s, i) => (
              <Card key={s.step}>
                <div className="flex justify-between items-center gap-2">
                  <div className="font-semibold">{i + 1}. {s.step}</div>
                  <span className="hairline border rounded-full px-2 py-px text-[10.5px] dim">
                    {s.state}</span>
                </div>
                <div className="dim text-[12px] my-1.5">{s.what}</div>
                <Code>{s.tool}</Code>
              </Card>
            ))}
          </div>
        </Section>
      )}

      {vendorInfo?.plugins && (
        <Section title="Parsers loaded">
          <Card>
            <DL rows={[
              ["Registered", (vendorInfo.plugins.registered || []).join(", ") || "—"],
              ["Dropped in", (vendorInfo.plugins.dropped_in || []).length
                ? vendorInfo.plugins.dropped_in.join(", ")
                : <span className="dim">none</span>],
              ["Plugin folder",
                <span className="font-mono break-all">{vendorInfo.plugins.plugin_dir}</span>],
              (vendorInfo.plugins.errors || []).length > 0 && [
                <span className="text-danger">Errors</span>,
                <span className="text-danger">{vendorInfo.plugins.errors.join("; ")}</span>],
            ]} />
          </Card>
        </Section>
      )}
    </>
  );
}

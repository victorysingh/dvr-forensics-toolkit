// AI leads (UI_PLAN 6.7).
//
// Ground rule 1: every screen showing a model's output carries the "leads,
// not evidence" banner and the models' hashes.  The banner renders first and
// unconditionally - including on the empty state, so a reader who arrives
// before the analytics have run still learns what this screen would mean.
import { useState } from "react";
import { Section, Card, DL, Pill, Empty, DataTable, Kpi, Hash, LeadBanner }
  from "../components/index.jsx";
import { num, pct0 } from "../lib/format.js";
import { api } from "../lib/api.js";

export default function AILeads({ c }) {
  const an = c.analytics;
  const [shot, setShot] = useState(null);

  if (!an) {
    return (
      <>
        <LeadBanner />
        <Empty what="No analytics have been run for this case."
          how={`cli.py analyse-video --out ${c.id} --fps 1`} />
      </>
    );
  }

  const models = an.models || {};
  const totals = an.totals || {};
  const thumbs = an.thumbnails || [];
  const top = an.top || [];

  return (
    <>
      <LeadBanner extra={
        Object.keys(models).length ? (
          <span className="flex flex-wrap gap-x-3 gap-y-1 items-center">
            {Object.entries(models).map(([job, m]) => (
              <span key={job}>
                {job}: <b>{m?.name || String(m)}</b>{" "}
                {m?.sha256 && <Hash value={m.sha256} len={8} />}
              </span>
            ))}
          </span>
        ) : "Models not recorded in this report."
      } />

      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(215px,1fr))]">
        {Object.entries(totals).map(([k, v]) => (
          <Kpi key={k} lead label={k.replace(/_/g, " ")} value={v} sub="frames"
            src="analytics/analytics.json" />
        ))}
        <Kpi label="Frames analysed" value={an.frames_analysed}
          sub={`${num(an.clips)} clip(s)`} src="analytics/analytics.json" />
      </div>

      <Section>
        <Card>
          <DL rows={[
            ["Status", <Pill status={an.status} />],
            ["Thresholds",
              <span className="font-mono break-all">{JSON.stringify(an.thresholds || {})}</span>],
            an.tiling && ["Tiling",
              <span className="font-mono break-all">{JSON.stringify(an.tiling)}</span>],
            ["Report", <Hash value={an.sha256} len={10} />],
          ]} />
        </Card>
      </Section>

      {thumbs.length > 0 && (
        <Section title="Detections"
          hint="boxes are drawn by the detector, on recovered frames">
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(190px,1fr))]">
            {thumbs.map((t, i) => (
              <button key={i} onClick={() => setShot(t)}
                className="panel overflow-hidden p-0 text-left hover:border-lead cursor-pointer">
                <img src={api.thumbUrl(c.id, t.file || t.name || "")}
                  alt={t.label || "detection"} loading="lazy"
                  className="w-full block aspect-video object-cover" />
                <div className="px-2.5 py-2">
                  <div className="text-[12px] font-semibold text-lead">
                    {t.label || "—"}
                    {t.score != null && <span className="font-mono"> {pct0(t.score)}</span>}
                  </div>
                  <div className="dim font-mono text-[10.5px] break-all">{t.clip || ""}</div>
                </div>
              </button>
            ))}
          </div>
        </Section>
      )}

      {top.length > 0 && (
        <Section title="Highest-scoring frames"
          hint="a score is the model's confidence, not a probability the lead is right">
          <DataTable initialSort="best" initialDir={-1}
            rows={top.map((h, i) => ({
              __k: i,
              clip: h.clip ?? "", frame: h.frame ?? h.frame_index ?? 0,
              labels: (h.detections || []).map((d) => d.label).join(", "),
              count: (h.detections || []).length,
              best: Math.max(0, ...(h.detections || []).map((d) => d.score || 0)),
            }))}
            cols={[
              { key: "clip", label: "Clip", cls: "font-mono" },
              { key: "frame", label: "Frame", cls: "text-right font-mono", sort: "num",
                render: (r) => num(r.frame) },
              { key: "labels", label: "Labels",
                render: (r) => <span className="text-lead">{r.labels}</span> },
              { key: "count", label: "Boxes", cls: "text-right font-mono", sort: "num" },
              { key: "best", label: "Top score", cls: "text-right font-mono", sort: "num",
                render: (r) => `${(r.best * 100).toFixed(1)}%` },
            ]} />
        </Section>
      )}

      {(an.notes || []).length > 0 && (
        <Section title="Notes">
          <Card>
            <ul className="list-disc pl-5 text-[12.5px] space-y-1">
              {an.notes.map((n, i) => <li key={i}>{n}</li>)}
            </ul>
          </Card>
        </Section>
      )}

      {shot && <Lightbox t={shot} caseId={c.id} onClose={() => setShot(null)} />}
    </>
  );
}

function Lightbox({ t, caseId, onClose }) {
  return (
    <div onClick={onClose}
      className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-6">
      <div onClick={(e) => e.stopPropagation()} className="panel max-w-4xl w-full overflow-hidden">
        <img src={api.thumbUrl(caseId, t.file || t.name || "")}
          alt={t.label || "detection"} className="w-full block" />
        <div className="p-3.5">
          <DL rows={[
            ["Label", <span className="text-lead font-semibold">{t.label || "—"}</span>],
            t.score != null && ["Score", pct0(t.score)],
            ["Clip", <span className="font-mono break-all">{t.clip || "—"}</span>],
            t.time_local && ["Time (recorder clock)", t.time_local],
          ]} />
          <p className="dim text-[11.5px] mt-2.5">
            A lead for an examiner to check by eye, not an identification.
          </p>
        </div>
      </div>
    </div>
  );
}

// One case, one scroll.
//
// Instead of nine screens named after the pipeline's output files, the case is
// read top to bottom as the argument it is. The platter stays pinned beside
// the text and lights up whatever the section in view is talking about, so a
// claim about "footage the index forgot" is seen at the offsets it was found.
//
// The old screens are not thrown away: each is the "show the evidence" detail
// inside its section, so every table, filter and provenance list still exists
// one disclosure away from the sentence that summarises it.
import { useEffect, useRef, useState, useMemo } from "react";
import { buildSections } from "./sections.jsx";
import PlatterMap from "../components/PlatterMap.jsx";
import { Pill, Hash, Code } from "../components/index.jsx";

import Evidence from "../screens/Evidence.jsx";
import Vendors from "../screens/Vendors.jsx";
import Recordings from "../screens/Recordings.jsx";
import Recovered from "../screens/Recovered.jsx";
import Timeline from "../screens/Timeline.jsx";
import AILeads from "../screens/AILeads.jsx";
import Custody from "../screens/Custody.jsx";
import Exports from "../screens/Exports.jsx";

const DETAIL = {
  evidence: Evidence, vendors: Vendors, recordings: Recordings,
  recovered: Recovered, timeline: Timeline, ai: AILeads,
  custody: Custody, exports: Exports,
};

const TONE = {
  danger: "text-danger", synthetic: "text-synthetic",
  lead: "text-lead", validated: "text-validated",
};

export default function CaseScroll({ c, vendorInfo, reload, toast }) {
  const sections = useMemo(() => buildSections(c), [c]);
  const [active, setActive] = useState(sections[0]?.id);
  const scroller = useRef(null);

  // Which section is being read drives the platter.
  //
  // Done by scroll position rather than IntersectionObserver: the observer
  // reports every section touching the band and the one above the reading
  // line is often still among them, which left the rail an entry behind.
  // "The last heading to have crossed the line" is what a reader means by
  // where they are, and the last section is short enough that it may never
  // reach the line at all - so hitting the bottom selects it outright.
  useEffect(() => {
    const root = scroller.current;
    if (!root) return;

    const pick = () => {
      const els = [...root.querySelectorAll("section[id]")];
      if (!els.length) return;
      const line = root.getBoundingClientRect().top + root.clientHeight * 0.25;

      if (root.scrollTop + root.clientHeight >= root.scrollHeight - 8) {
        setActive(els[els.length - 1].id);
        return;
      }
      let chosen = els[0];
      for (const el of els) {
        if (el.getBoundingClientRect().top <= line) chosen = el;
        else break;
      }
      setActive(chosen.id);
    };

    pick();
    root.addEventListener("scroll", pick, { passive: true });
    return () => root.removeEventListener("scroll", pick);
  }, [sections]);

  const current = sections.find((s) => s.id === active) || sections[0];

  const jump = (id) => {
    const el = scroller.current?.querySelector(`#${CSS.escape(id)}`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[168px_minmax(0,1fr)_auto] gap-6 min-h-0">
      {/* the rail: where you are in the argument */}
      <nav className="hidden lg:block sticky top-4 self-start" aria-label="Sections">
        <ol className="list-none m-0 p-0">
          {sections.map((s, i) => {
            const on = s.id === active;
            return (
              <li key={s.id}>
                <button onClick={() => jump(s.id)}
                  className={`w-full text-left py-1.5 px-2 border-l-2 cursor-pointer
                    text-[12.5px] leading-tight
                    ${on ? "border-l-accent text-accent"
                         : "border-l-line dim hover:text-[color:var(--color-ink)]"}`}>
                  <span className="mono-t text-[10px] opacity-60 mr-1.5">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  {s.rail}
                </button>
              </li>
            );
          })}
        </ol>
      </nav>

      {/* the argument */}
      <div ref={scroller} className="min-w-0 overflow-y-auto pr-1"
        style={{ maxHeight: "calc(100vh - 110px)" }}>
        {sections.map((s, i) => (
          <Section key={s.id} s={s} n={i + 1} c={c}
            vendorInfo={vendorInfo} reload={reload} toast={toast} />
        ))}
        <footer className="dim text-[11.5px] py-10 measure">
          Every figure above is quoted from a file the pipeline wrote, and each
          file's SHA-256 is beside it. Nothing on this page is recomputed from
          anything else.
        </footer>
      </div>

      {/* the platter, pinned, tracking what is being read */}
      <aside className="hidden lg:block sticky top-4 self-start">
        <PlatterMap c={c} highlight={current?.marks || []} />
      </aside>
    </div>
  );
}

function Section({ s, n, c, vendorInfo, reload, toast }) {
  const [open, setOpen] = useState(false);
  const Detail = DETAIL[s.detail];

  return (
    <section id={s.id} className="scroll-mt-4 py-8 border-b hairline last:border-b-0">
      <div className="micro mb-3">
        {String(n).padStart(2, "0")} &nbsp;{s.rail}
      </div>

      <h2 className={`display font-semibold measure mb-3
        ${s.emphasis ? "text-[27px] leading-[1.25]" : "text-[21px] leading-[1.3]"}`}>
        {s.title}
      </h2>

      {s.lead && (
        <p className="measure text-[13.5px] leading-relaxed dim mb-5">{s.lead}</p>
      )}

      {s.absent ? (
        <p className="text-[12.5px] dim mb-4">
          Not run for this case. <Code>{s.absent}</Code>
        </p>
      ) : null}

      {s.figures.length > 0 && (
        <div className="flex flex-wrap gap-x-10 gap-y-4 mb-5">
          {s.figures.map((f, i) => (
            <div key={i}>
              <div className={`figure ${TONE[f.tone] || ""}`}>{f.value}</div>
              <div className="micro mt-1">{f.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* The refusal is a feature, so it is set as loudly as a finding. */}
      {s.refusal && (
        <p className="measure mb-5 pl-3 border-l-2 border-l-synthetic
          text-[13px] text-synthetic">
          {s.refusal}
        </p>
      )}

      {s.strength && (
        <div className="measure mb-5 flex items-start gap-2.5 text-[12.5px]">
          <Pill status={s.strength.status} />
          <span className="dim">{s.strength.note}</span>
        </div>
      )}

      {s.cites?.filter((x) => x.hash).length > 0 && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 mb-4">
          {s.cites.filter((x) => x.hash).map((x) => (
            <span key={x.file} className="micro flex items-center gap-1.5 normal-case">
              <span className="mono-t">{x.file}</span>
              <Hash value={x.hash} len={6} />
            </span>
          ))}
        </div>
      )}

      {Detail && !s.absent && (
        <>
          <button onClick={() => setOpen(!open)}
            className="micro hairline border px-2.5 py-1.5 cursor-pointer
              hover:text-accent hover:border-accent">
            {open ? "− hide the evidence" : "+ show the evidence"}
          </button>
          {open && (
            <div className="mt-5 pt-1">
              <Detail c={c} vendorInfo={vendorInfo} reload={reload} toast={toast} />
            </div>
          )}
        </>
      )}
    </section>
  );
}

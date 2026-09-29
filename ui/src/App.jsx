// The shell: top bar, sidebar, pipeline stepper, routing and case loading.
//
// A screen is a component of the case view and nothing more: it fetches
// nothing itself, so adding a screen means one entry in SCREENS and one file
// under screens/.
import { useState, useEffect, useCallback } from "react";
import { api } from "./lib/api.js";
import { useHashRoute, linkTo, go } from "./lib/useHashRoute.js";
import { bytes, num, pct } from "./lib/format.js";
import { Skeleton, Empty, ToastHost, useToast, DL } from "./components/index.jsx";

import Dashboard from "./screens/Dashboard.jsx";
import Evidence from "./screens/Evidence.jsx";
import Vendors from "./screens/Vendors.jsx";
import Recordings from "./screens/Recordings.jsx";
import Recovered from "./screens/Recovered.jsx";
import Timeline from "./screens/Timeline.jsx";
import AILeads from "./screens/AILeads.jsx";
import Custody from "./screens/Custody.jsx";
import Exports from "./screens/Exports.jsx";

const SCREENS = [
  { id: "dashboard",  label: "Dashboard",  ico: "▦", C: Dashboard },
  { id: "evidence",   label: "Evidence",   ico: "▤", C: Evidence },
  { id: "vendors",    label: "Vendors",    ico: "◈", C: Vendors },
  { id: "recordings", label: "Recordings", ico: "≡", C: Recordings },
  { id: "recovered",  label: "Recovered",  ico: "▶", C: Recovered },
  { id: "timeline",   label: "Timeline",   ico: "⏱", C: Timeline },
  { id: "ai",         label: "AI leads",   ico: "◆", C: AILeads },
  { id: "custody",    label: "Custody",    ico: "⛓", C: Custody },
  { id: "exports",    label: "Exports",    ico: "⤓", C: Exports },
];

export default function App() {
  return <ToastHost><Console /></ToastHost>;
}

function Console() {
  const route = useHashRoute();
  const [cases, setCases] = useState(null);
  const [vendorInfo, setVendorInfo] = useState(null);
  const [caseData, setCaseData] = useState(null);
  const [bootError, setBootError] = useState(null);
  const [loading, setLoading] = useState(false);
  const toast = useToast();

  useEffect(() => {
    Promise.all([api.cases(), api.vendors()])
      .then(([c, v]) => { setCases(c); setVendorInfo(v); })
      .catch((e) => setBootError(e.message));
  }, []);

  // A stale link to a case this folder no longer holds falls back to the
  // home rather than erroring: it should still land somewhere real.
  const caseId = cases && cases.some((c) => c.id === route.caseId) ? route.caseId : null;
  const screen = SCREENS.find((s) => s.id === route.screen) || SCREENS[0];

  const reload = useCallback(() => {
    if (!caseId) return Promise.resolve();
    return api.case(caseId).then(setCaseData);
  }, [caseId]);

  useEffect(() => {
    if (!caseId) { setCaseData(null); return; }
    if (caseData && caseData.id === caseId) return;   // screen change, not case change
    setLoading(true);
    api.case(caseId).then(setCaseData).catch(() => setCaseData(null))
      .finally(() => setLoading(false));
  }, [caseId]);                                        // eslint-disable-line

  useKeyboard(SCREENS, caseId);

  if (bootError) {
    return (
      <Shell>
        <Empty what="The console could not reach its own server." />
        <p className="font-mono text-[12px] mt-2 text-center dim">{bootError}</p>
      </Shell>
    );
  }
  if (!cases) return <Shell><Skeleton rows={5} /></Shell>;

  const Screen = screen.C;
  return (
    <div className="grid grid-rows-[auto_1fr] h-screen">
      <TopBar cases={cases} caseId={caseId} screen={screen.id} c={caseData} />
      <div className="grid grid-cols-[52px_1fr] xl:grid-cols-[208px_1fr] min-h-0">
        <Sidebar caseId={caseId} screen={screen.id} />
        <div className="grid grid-rows-[auto_1fr] min-w-0 min-h-0">
          <Stepper c={caseData} caseId={caseId} />
          <main className="min-w-0 overflow-y-auto px-5 pt-4 pb-10" key={`${caseId}/${screen.id}`}>
            {!caseId ? <CasesHome cases={cases} />
              : loading || !caseData ? <Skeleton rows={5} />
              : <ErrorBoundary name={screen.label}>
                  <Screen c={caseData} vendorInfo={vendorInfo} reload={reload} toast={toast} />
                </ErrorBoundary>}
          </main>
        </div>
      </div>
    </div>
  );
}

const Shell = ({ children }) => (
  <div className="p-5 max-w-3xl mx-auto mt-10">{children}</div>
);

/* ------------------------------------------------------------- top bar */
function TopBar({ cases, caseId, screen, c }) {
  const ver = c?.custody?.verify;
  const live = c?.in_progress;
  return (
    <header className="panel rounded-none border-0 border-b flex items-center gap-3.5 px-4 h-13
      min-h-[52px]">
      <div className="flex items-center gap-2 font-semibold whitespace-nowrap">
        <span className="text-teal-500 text-lg">&#9703;</span>
        <span>PS26150<span className="dim font-normal text-[11px] hidden sm:inline">
          &nbsp;&middot; DVR/NVR forensics</span></span>
      </div>

      <select value={caseId || ""} aria-label="Case"
        onChange={(e) => go(e.target.value || null, screen)}
        className="panel-2 hairline border rounded-lg px-2.5 py-1.5 max-w-[320px] text-sm">
        <option value="">All cases&hellip;</option>
        {cases.map((x) => (
          <option key={x.id} value={x.id}>{x.id}{x.case_id ? ` · ${x.case_id}` : ""}</option>
        ))}
      </select>

      <span className="flex-1" />

      {live && <Badge tone="live">LIVE {pct(live.fraction)}</Badge>}
      {ver && <Badge tone={ver.valid ? "ok" : "bad"}>
        {ver.valid ? "chain intact" : "chain broken"}</Badge>}
      <Badge title="Binds 127.0.0.1, never opens an evidence device, never writes">
        offline &middot; read-only</Badge>
      {c?.scan && (
        <a href={api.reportUrl(c.id)} target="_blank" rel="noopener"
          className="hidden md:inline-flex"><Badge>Report &#8599;</Badge></a>
      )}
      <ThemeToggle />
    </header>
  );
}

function Badge({ children, tone, title }) {
  const tones = {
    ok: "text-validated border-validated/45",
    bad: "text-danger border-danger/45",
    live: "text-accent-dark border-accent-dark/45",
  };
  // `dim` only when there is no tone: its dark-mode rule is a descendant
  // selector, so it outranks a plain text-* utility and would grey out the
  // very colour that carries the meaning.
  return (
    <span title={title}
      className={`border rounded-full px-2.5 py-1 text-[11.5px] whitespace-nowrap
        inline-flex items-center gap-1.5 ${tones[tone] || "hairline dim"}`}>
      {tone && <span className={`w-1.5 h-1.5 rounded-full bg-current
        ${tone === "live" ? "animate-pulse" : ""}`} />}
      {children}
    </span>
  );
}

function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  const flip = () => {
    const now = !dark;
    setDark(now);
    document.documentElement.classList.toggle("dark", now);
    try { localStorage.setItem("ps26150-theme", now ? "dark" : "light"); } catch { /* ignore */ }
  };
  return (
    <button onClick={flip} title="Toggle theme (t)"
      className="hairline border rounded-lg w-8 h-8 dim hover:text-teal-500
        hover:border-teal-500 cursor-pointer">&#9681;</button>
  );
}

/* ------------------------------------------------------------- sidebar */
function Sidebar({ caseId, screen }) {
  if (!caseId) return <nav className="panel rounded-none border-0 border-r" />;
  return (
    <nav className="panel rounded-none border-0 border-r p-2 overflow-y-auto" aria-label="Screens">
      {SCREENS.map((s, i) => {
        const on = s.id === screen;
        return (
          <a key={s.id} href={linkTo(caseId, s.id)}
            className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13.5px]
              justify-center xl:justify-start
              ${on ? "bg-teal-500/15 text-teal-500" : "dim hover:panel-2 hover:text-current"}`}>
            <span className="w-[18px] text-center shrink-0">{s.ico}</span>
            <span className="hidden xl:inline">{s.label}</span>
            <span className="hidden xl:inline ml-auto font-mono text-[10.5px] opacity-50">
              {i + 1}</span>
          </a>
        );
      })}
    </nav>
  );
}

/* ------------------------------------------------------------- stepper */
// Each stage reads its state from the case itself rather than a stored
// progress field, so the strip is a claim about what actually ran.
function Stepper({ c, caseId }) {
  if (!c || !caseId) return null;
  const s = c.scan, p = c.in_progress, det = s?.detections?.[0];
  const stages = [
    ["Acquire", "evidence",
      s ? `hashed ${bytes(s.stats?.bytes_read)}` : p ? `${pct(p.fraction)} read` : "not run",
      s ? (s.stats?.complete_pass ? "done" : "part") : p ? "run" : ""],
    ["Identify", "vendors",
      det ? `${det.vendor} ${pct(det.confidence)}` : s ? "no match" : "not run",
      det ? "done" : s ? "part" : ""],
    ["Parse", "recordings",
      c.parse ? `${num(c.parse.recordings_total)} recordings` : "not run", c.parse ? "done" : ""],
    ["Recover", "recovered",
      c.carve ? `${num(c.carve.outside_total)} outside index` : "not run", c.carve ? "done" : ""],
    ["Timeline", "timeline",
      c.timeline ? `${num(Object.keys(c.timeline.cameras || {}).length)} cameras` : "not run",
      c.timeline ? "done" : ""],
    ["AI", "ai", c.analytics ? `${num(c.analytics.clips)} clips` : "not run",
      c.analytics ? "done" : ""],
    ["Report", "exports", s ? "ready" : "needs acquisition", s ? "done" : ""],
  ];
  const edge = { done: "border-l-validated", part: "border-l-synthetic", run: "border-l-accent-dark" };
  return (
    <nav className="hairline border-b px-5 py-2.5 flex gap-1.5 flex-wrap"
      aria-label="Pipeline stages">
      {stages.map(([t, to, d, cls]) => (
        <button key={t} onClick={() => go(caseId, to)}
          className={`panel border-l-[3px] rounded-lg px-2.5 py-1.5 text-left flex-1
            min-w-[120px] basis-[130px] cursor-pointer hover:border-teal-500
            ${edge[cls] || "border-l-slate-500/40"}`}>
          <div className="text-[12.5px] font-semibold">{t}</div>
          <div className="dim text-[11px]">{d}</div>
        </button>
      ))}
    </nav>
  );
}

/* ---------------------------------------------------------- cases home */
function CasesHome({ cases }) {
  if (!cases.length) {
    return <Empty what="No cases in this folder."
      how="cli.py serve --out <folder that holds case folders>" />;
  }
  return (
    <>
      <h1 className="text-[19px] font-semibold mb-3.5">Cases</h1>
      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(290px,1fr))]">
        {/* finished acquisitions first; an aborted attempt stays listed, since
            it is part of the case's history, but after the ones that count */}
        {[...cases].sort((a, b) => (b.complete - a.complete)).map((c) => (
          <a key={c.id} href={linkTo(c.id, "dashboard")}
            className="panel p-4 hover:border-teal-500 block">
            <div className="text-[17px] font-semibold break-all">{c.id}</div>
            <div className="dim font-mono text-[12px] mt-0.5 mb-2.5 break-all">
              {c.device || "—"}</div>
            <DL rows={[["Case ID", c.case_id || "—"], ["Size", bytes(c.size_bytes)]]} />
            {!c.complete && (
              <div className="mt-2.5">
                <div className="panel-2 h-1.5 rounded-full overflow-hidden">
                  <i className="block h-full bg-teal-500 rounded-full"
                    style={{ width: pct(c.progress) }} />
                </div>
                <div className="dim text-[11px] mt-1">acquiring &mdash; {pct(c.progress)}</div>
              </div>
            )}
            <div className="flex gap-1.5 flex-wrap mt-2.5">
              {[["scan", c.complete], ["parse", c.has_parse],
                ["carve", c.has_carve], ["timeline", c.has_timeline]].map(([k, has]) => (
                <span key={k}
                  className={`hairline border rounded-full px-2 py-px text-[10.5px]
                    ${has ? "text-validated border-validated/45" : "dim"}`}>{k}</span>
              ))}
            </div>
          </a>
        ))}
      </div>
    </>
  );
}

/* ------------------------------------------------------------ keyboard */
function useKeyboard(screens, caseId) {
  useEffect(() => {
    const on = (e) => {
      const tag = (e.target.tagName || "").toLowerCase();
      if (["input", "select", "textarea"].includes(tag) || e.metaKey || e.ctrlKey) return;
      if (e.key === "t") {
        const now = !document.documentElement.classList.contains("dark");
        document.documentElement.classList.toggle("dark", now);
        try { localStorage.setItem("ps26150-theme", now ? "dark" : "light"); } catch { /* ignore */ }
        return;
      }
      if (e.key === "/") {
        const q = document.querySelector("[data-table-search]");
        if (q) { e.preventDefault(); q.focus(); }
        return;
      }
      const n = Number(e.key);
      if (n >= 1 && n <= screens.length && caseId) go(caseId, screens[n - 1].id);
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, [screens, caseId]);
}

/* ------------------------------------------------------ error boundary */
// One screen throwing must not blank the console: the rest of the shell,
// and every other screen, stays reachable.
import { Component } from "react";
class ErrorBoundary extends Component {
  constructor(p) { super(p); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  componentDidUpdate(prev) { if (prev.children !== this.props.children && this.state.err) this.setState({ err: null }); }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div>
        <Empty what={`The ${this.props.name} screen failed to render.`} />
        <p className="font-mono text-[12px] mt-2 text-center text-danger">
          {String(this.state.err.message || this.state.err)}</p>
      </div>
    );
  }
}

// The shell: top bar, sidebar, pipeline stepper, routing and case loading.
//
// A screen is a component of the case view and nothing more: it fetches
// nothing itself, so adding a screen means one entry in SCREENS and one file
// under screens/.
import { useState, useEffect, useCallback } from "react";
import { api } from "./lib/api.js";
import { useHashRoute, linkTo, go } from "./lib/useHashRoute.js";
import { bytes, num, pct } from "./lib/format.js";
import { isDemo } from "./lib/host.js";
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
        <span className="text-accent text-lg">&#9703;</span>
        <span>AnokhiDrishti<span className="dim font-normal text-[11px] hidden sm:inline">
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
      {isDemo()
        ? <Badge tone="warn" title="A public demonstration of the interface, served from static
            snapshots of synthetic cases. Not an evidence workstation, and not real evidence.">
            demo &middot; synthetic data</Badge>
        : <Badge title="Binds 127.0.0.1, never opens an evidence device, never writes">
            offline &middot; read-only</Badge>}
      {c?.scan && (
        <a href={api.reportUrl(c.id)} target="_blank" rel="noopener"
          className="hidden md:inline-flex"><Badge>Report &#8599;</Badge></a>
      )}
      <LookSwitcher />
      <ThemeToggle />
    </header>
  );
}

function Badge({ children, tone, title }) {
  const tones = {
    ok: "text-validated border-validated/45",
    bad: "text-danger border-danger/45",
    live: "text-accent border-accent/45",
    warn: "text-synthetic border-synthetic/45",
  };
  // `dim` only when there is no tone: its dark-mode rule is a descendant
  // selector, so it outranks a plain text-* utility and would grey out the
  // very colour that carries the meaning.
  return (
    <span title={title}
      className={`border rounded-full px-2.5 py-1 text-[11.5px] whitespace-nowrap
        inline-flex items-center gap-1.5 ${tones[tone] || "hairline dim"}`}>
      {tone && tone !== "warn" && <span className={`w-1.5 h-1.5 rounded-full bg-current
        ${tone === "live" ? "animate-pulse" : ""}`} />}
      {children}
    </span>
  );
}

/* Three looks, switchable live. This is evaluation scaffolding: once a
   direction is chosen the other two go, and this becomes one line in
   index.html. Keeping it here means the comparison is made on real screens
   with real case data rather than on mockups. */
export const LOOKS = [
  { id: "instrument", label: "Instrument" },
  { id: "dossier", label: "Dossier" },
  { id: "platter", label: "Platter" },
];

export function setLook(id) {
  document.documentElement.dataset.look = id;
  try { localStorage.setItem("anokhidrishti-look", id); } catch { /* ignore */ }
}

/* Light and dark are per-look palettes, not one inversion (index.css). With
   nothing stored the theme follows the operating system, and choosing here
   pins it — after which the system no longer overrides the choice. */
export function setTheme(t) {
  if (t === "light") document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  try { localStorage.setItem("anokhidrishti-theme", t); } catch { /* ignore */ }
}

export const currentTheme = () =>
  document.documentElement.dataset.theme === "light" ? "light" : "dark";

/* The keyboard shortcuts set the attribute directly, so a control holding
   its own copy would fall out of step the first time one is pressed. Both
   controls read the attribute instead and re-read it whenever it changes. */
function useHtmlAttr(read) {
  const [v, setV] = useState(read);
  useEffect(() => {
    const el = document.documentElement;
    const o = new MutationObserver(() => setV(read()));
    o.observe(el, { attributes: true, attributeFilter: ["data-theme", "data-look"] });
    setV(read());
    return () => o.disconnect();
  }, [read]);
  return v;
}

function ThemeToggle() {
  const theme = useHtmlAttr(currentTheme);
  const flip = () => setTheme(theme === "light" ? "dark" : "light");
  return (
    <button onClick={flip}
      title={`${theme === "light" ? "Dark" : "Light"} mode (press t)`}
      aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
      className="hairline border rounded-[var(--radius-panel)] w-8 h-8 shrink-0
        dim hover:text-accent hover:border-accent cursor-pointer leading-none">
      {theme === "light" ? "◑" : "◐"}
    </button>
  );
}

const readLook = () => document.documentElement.dataset.look || LOOKS[0].id;

function LookSwitcher() {
  const look = useHtmlAttr(readLook);
  return (
    <div className="hairline border rounded-[var(--radius-panel)] flex overflow-hidden"
      title="Visual direction (press l to cycle)">
      {LOOKS.map((l) => (
        <button key={l.id} onClick={() => setLook(l.id)}
          className={`px-2.5 py-1 text-[11px] cursor-pointer micro
            ${l.id === look ? "bg-accent/15 text-accent" : "dim"}`}>
          {l.label}
        </button>
      ))}
    </div>
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
              ${on ? "bg-accent/15 text-accent" : "dim hover:panel-2 hover:text-current"}`}>
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
  const edge = { done: "border-l-validated", part: "border-l-synthetic", run: "border-l-accent" };
  return (
    <nav className="hairline border-b px-5 py-2.5 flex gap-1.5 flex-wrap"
      aria-label="Pipeline stages">
      {stages.map(([t, to, d, cls]) => (
        <button key={t} onClick={() => go(caseId, to)}
          className={`panel border-l-[3px] px-2.5 py-1.5 text-left flex-1
            min-w-[120px] basis-[130px] cursor-pointer hover:border-accent
            ${edge[cls] || "border-l-line"}`}>
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
      {isDemo() && (
        <div className="rounded-xl border border-synthetic/45 bg-synthetic/10 px-3.5 py-3 mb-4
          text-[12.5px]">
          <b className="text-synthetic">Demonstration build.</b> These cases are
          <b> synthetic disks generated for the demo</b> &mdash; not evidence, and not
          vendor samples. The screens are the real interface reading real pipeline
          output; the acquisition, carving and custody chain all ran, on made-up disks.
          The actual tool runs offline on an examiner's own machine and binds the
          loopback interface only.
        </div>
      )}
      <h1 className="text-[19px] font-semibold mb-3.5">Cases</h1>
      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(290px,1fr))]">
        {cases.map((c) => (
          <a key={c.id} href={linkTo(c.id, "dashboard")}
            className="panel p-4 hover:border-accent block">
            <div className="text-[17px] font-semibold">{c.id}</div>
            <div className="dim font-mono text-[12px] mt-0.5 mb-2.5 break-all">
              {c.device || "—"}</div>
            <DL rows={[["Case ID", c.case_id || "—"], ["Size", bytes(c.size_bytes)]]} />
            {!c.complete && (
              <div className="mt-2.5">
                <div className="panel-2 h-1.5 rounded-full overflow-hidden">
                  <i className="block h-full bg-accent rounded-full"
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
      if (e.key === "l") {
        const cur = document.documentElement.dataset.look || LOOKS[0].id;
        const i = LOOKS.findIndex((x) => x.id === cur);
        setLook(LOOKS[(i + 1) % LOOKS.length].id);
        return;
      }
      if (e.key === "t") {
        setTheme(currentTheme() === "light" ? "dark" : "light");
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

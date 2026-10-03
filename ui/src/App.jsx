// The shell: top bar, sidebar, pipeline stepper, routing and case loading.
//
// A screen is a component of the case view and nothing more: it fetches
// nothing itself, so adding a screen means one entry in SCREENS and one file
// under screens/.
import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "./lib/api.js";
import { useHashRoute, linkTo, go } from "./lib/useHashRoute.js";
import { bytes, num, pct } from "./lib/format.js";
import { isDemo } from "./lib/host.js";
import { Skeleton, Empty, ToastHost, useToast, DL } from "./components/index.jsx";
import { ProfileMenu } from "./components/Account.jsx";
import { useTheme, flipTheme } from "./lib/theme.js";

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
  // The screen rail belongs to a case: on the cases home it would list
  // screens that have nothing to show yet, so it only appears once a case is
  // open, and the home takes the full width. On a phone it is a bar along
  // the bottom instead, where a thumb reaches it and it costs no width.
  //
  // h-dvh, not h-screen: on a phone 100vh includes the browser's own
  // toolbars, so the bottom of the console would sit underneath them.
  return (
    <div className="grid grid-rows-[auto_minmax(0,1fr)] grid-cols-[minmax(0,1fr)] h-dvh">
      <TopBar cases={cases} caseId={caseId} screen={screen.id} c={caseData} />
      <div className={`grid min-h-0 ${caseId
        ? `grid-rows-[minmax(0,1fr)_auto] md:grid-rows-[minmax(0,1fr)]
           md:grid-cols-[52px_minmax(0,1fr)] xl:grid-cols-[208px_minmax(0,1fr)]`
        : "grid-cols-[minmax(0,1fr)]"}`}>
        {caseId && <Sidebar caseId={caseId} screen={screen.id} />}
        <div className="grid grid-rows-[auto_minmax(0,1fr)] min-w-0 min-h-0">
          <Stepper c={caseData} caseId={caseId} />
          <main className="min-w-0 overflow-y-auto px-3 sm:px-5 pt-4 pb-10"
            key={`${caseId}/${screen.id}`}>
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
    // On a phone the name shrinks to its mark and the posture badge moves
    // into the profile menu, so the case picker keeps the room it needs.
    <header className="panel rounded-none border-0 border-b flex items-center gap-2 sm:gap-3.5
      px-3 sm:px-4 h-13 min-h-[52px] relative z-30">
      <a href="#/" title="All cases"
        className="flex items-center gap-2 font-semibold whitespace-nowrap shrink-0">
        <span className="text-accent text-lg">&#9703;</span>
        <span className="hidden min-[420px]:inline">AnokhiDrishti<span
          className="dim font-normal text-[11px] hidden lg:inline">
          &nbsp;&middot; DVR/NVR forensics</span></span>
      </a>

      <select value={caseId || ""} aria-label="Case"
        onChange={(e) => go(e.target.value || null, screen)}
        className="panel-2 hairline border rounded-lg px-2.5 py-1.5 w-0 flex-1 sm:flex-none
          sm:w-auto max-w-[320px] min-w-0 text-sm">
        <option value="">All cases&hellip;</option>
        {cases.map((x) => (
          <option key={x.id} value={x.id}>{x.id}{x.case_id ? ` · ${x.case_id}` : ""}</option>
        ))}
      </select>

      <span className="hidden sm:block flex-1" />

      {live && <Badge tone="live">LIVE {pct(live.fraction)}</Badge>}
      {ver && <Badge tone={ver.valid ? "ok" : "bad"}
        title={ver.valid ? "Custody chain intact" : "Custody chain broken"}>
        <span className="hidden min-[400px]:inline">
          {ver.valid ? "chain intact" : "chain broken"}</span></Badge>}
      <span className="hidden lg:inline-flex">
      {isDemo() && cases.length && cases.every((x) => x.synthetic)
        ? <Badge tone="warn" title="A public demonstration of the interface, served from static
            snapshots of synthetic cases. Not an evidence workstation, and not real evidence.">
            demo &middot; synthetic data</Badge>
        : isDemo()
        ? <Badge tone="warn" title="Served over the internet for review, behind sign-in and an
            administrator's approval. The tool itself runs offline on an examiner's machine.">
            hosted &middot; approved access</Badge>
        : <Badge title="Binds 127.0.0.1, never opens an evidence device, never writes">
            offline &middot; read-only</Badge>}
      </span>
      {c?.scan && (
        <a href={api.reportUrl(c.id)} target="_blank" rel="noopener"
          className="hidden md:inline-flex"><Badge>Report &#8599;</Badge></a>
      )}
      <ThemeToggle />
      <ProfileMenu />
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

/* The theme lives in lib/theme.js, so the profile menu can switch it too.
   On a phone the switch is in that menu only; the bar has no room for both. */
function ThemeToggle() {
  const theme = useTheme();
  return (
    <button onClick={flipTheme}
      title={`${theme === "light" ? "Dark" : "Light"} mode (press t)`}
      aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
      className="hairline border rounded-[var(--radius-panel)] w-8 h-8 shrink-0
        dim hover:text-accent hover:border-accent cursor-pointer leading-none
        hidden sm:block">
      {theme === "light" ? "◑" : "◐"}
    </button>
  );
}

/* ------------------------------------------------------------- sidebar */
function Sidebar({ caseId, screen }) {
  // On a phone the bar scrolls sideways; keep the open screen in view.
  const here = useRef(null);
  useEffect(() => {
    here.current?.scrollIntoView?.({ block: "nearest", inline: "center" });
  }, [screen]);
  return (
    <nav className="panel rounded-none border-0 border-t md:border-t-0 md:border-r p-1 md:p-2
      order-last md:order-none flex md:block overflow-x-auto md:overflow-x-visible
      md:overflow-y-auto rail-in"
      aria-label="Screens">
      <a href="#/" title="All cases (Esc)"
        className="flex flex-col md:flex-row items-center gap-0.5 md:gap-2.5 shrink-0
          min-w-[58px] md:min-w-0 px-1.5 md:px-2.5 py-1.5 rounded-lg text-[10.5px]
          md:text-[12.5px] justify-center xl:justify-start dim hover:text-accent">
        <span className="w-[18px] text-center shrink-0 text-[15px] md:text-[length:inherit]">
          &larr;</span>
        <span className="md:hidden xl:inline">All cases</span>
      </a>
      <div className="hidden xl:block px-2.5 pt-1 pb-2.5 mb-1.5 border-b hairline">
        <div className="micro">Case</div>
        <div className="text-[13px] font-semibold break-all leading-snug">{caseId}</div>
      </div>
      {SCREENS.map((s, i) => {
        const on = s.id === screen;
        return (
          <a key={s.id} href={linkTo(caseId, s.id)} ref={on ? here : null}
            aria-current={on ? "page" : undefined} title={s.label}
            className={`flex flex-col md:flex-row items-center gap-0.5 md:gap-2.5 shrink-0
              min-w-[64px] md:min-w-0 px-1.5 md:px-2.5 py-1.5 md:py-2 rounded-lg
              text-[10.5px] md:text-[13.5px] whitespace-nowrap justify-center xl:justify-start
              ${on ? "bg-accent/15 text-accent" : "dim hover:panel-2 hover:text-current"}`}>
            <span className="w-[18px] text-center shrink-0 text-[15px] md:text-[length:inherit]">
              {s.ico}</span>
            <span className="md:hidden xl:inline">{s.label}</span>
            <span className="hidden xl:inline ml-auto font-mono text-[10.5px] dim">
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
  const edge = { done: "var(--color-validated)", part: "var(--color-synthetic)",
                 run: "var(--color-accent)" };
  return (
    // One strip that scrolls sideways on a phone: seven stages wrapped into
    // rows there took a third of the screen before any evidence showed.
    <nav className="hairline border-b px-3 sm:px-5 py-2 sm:py-2.5 flex gap-1.5 overflow-x-auto
      md:flex-wrap md:overflow-x-visible" aria-label="Pipeline stages">
      {stages.map(([t, to, d, cls]) => (
        <button key={t} onClick={() => go(caseId, to)}
          title={`${t}: ${cls === "done" ? "done" : cls === "part" ? "partial"
            : cls === "run" ? "running" : "not run"}`}
          style={{ borderLeft: `3px solid ${edge[cls] || "var(--color-line)"}` }}
          className="panel px-2.5 py-1.5 text-left shrink-0 md:shrink md:flex-1
            min-w-[118px] md:basis-[130px] cursor-pointer hover:border-accent">
          <div className="text-[12.5px] font-semibold">{t}</div>
          <div className="dim text-[11px]">{d}</div>
        </button>
      ))}
    </nav>
  );
}

/* ---------------------------------------------------------- cases home */
// Complete acquisitions are the ones an examiner opens, so they lead, as
// cards naming what the detector found.  An attempt that stopped short stays
// listed - it is part of the case's history - but as a compact row after them.
const STAGES = [["Acquire", "complete"], ["Parse", "has_parse"],
                ["Recover", "has_carve"], ["Timeline", "has_timeline"]];

// A device node reads fine as it is; an image path is long and mostly the
// directory it happens to sit in, so the card shows the file and the full
// path is one hover away.
const shortDevice = (p) => (!p ? "—" : p.startsWith("/dev/") ? p : p.split(/[\\/]/).pop());

function CasesHome({ cases }) {
  const [q, setQ] = useState("");
  if (!cases.length) {
    return <Empty what="No cases in this folder."
      how="cli.py serve --out <folder that holds case folders>" />;
  }
  const needle = q.trim().toLowerCase();
  const shown = cases.filter((c) => !needle || [c.id, c.case_id, c.vendor, c.device]
    .some((v) => String(v || "").toLowerCase().includes(needle)));
  const ready = shown.filter((c) => c.complete);
  const partial = shown.filter((c) => !c.complete).sort((a, b) => b.progress - a.progress);
  const done = cases.filter((c) => c.complete);
  const vendors = [...new Set(done.map((c) => c.vendor).filter(Boolean))];
  return (
    <div className="max-w-[1480px] mx-auto">
      {isDemo() && (
        <div className="rounded-xl border border-synthetic/45 bg-synthetic/10 px-3.5 py-3 mb-4
          text-[12.5px]">
          {cases.every((x) => x.synthetic) ? (<>
            <b className="text-synthetic">Demonstration build.</b> These cases are
            <b> synthetic disks generated for the demo</b> &mdash; not evidence, and not
            vendor samples. The screens are the real interface reading real pipeline
            output; the acquisition, carving and custody chain all ran, on made-up disks.
            The actual tool runs offline on an examiner's own machine and binds the
            loopback interface only.</>) : (<>
            <b className="text-synthetic">Hosted for review, behind approval.</b> The cases
            are the team's own acquisitions of two real DVR drives, as the pipeline
            produced them; any marked <b>synthetic</b> were generated for the demo. The raw
            recovered video stays on the examiner's machine. The tool itself runs offline
            and binds the loopback interface only; this copy is served for review.</>)}
        </div>
      )}
      <div className="flex items-end justify-between gap-x-4 gap-y-3 flex-wrap mb-4">
        <div className="min-w-0">
          <h1 className="display text-[22px] font-semibold">Cases</h1>
          <p className="dim text-[13px] mt-0.5">
            Open a case to examine its evidence, recordings, recovered footage,
            timeline and custody.</p>
        </div>
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)}
          data-table-search placeholder="Filter by case, vendor or device  ( / )"
          aria-label="Filter cases"
          className="panel-2 hairline border rounded-lg px-3 py-1.5 text-sm w-full
            sm:w-[300px]" />
      </div>

      <div className="grid gap-3 grid-cols-2 md:grid-cols-4 mb-6">
        <HomeStat label="Cases" value={num(cases.length)} />
        <HomeStat label="Ready to examine" value={num(done.length)} />
        <HomeStat label="Acquired" value={bytes(done.reduce((s, c) => s + (c.size_bytes || 0), 0))} />
        <HomeStat label="Vendors detected" value={vendors.length ? vendors.join(" · ") : "—"} small />
      </div>

      {!shown.length && <Empty what={`No case matches “${q}”.`} />}

      {ready.length > 0 && (
        <section className="mb-7">
          <h2 className="micro mb-2.5">Ready to examine &middot; {ready.length}</h2>
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(min(300px,100%),1fr))]">
            {ready.map((c) => <CaseCard key={c.id} c={c} />)}
          </div>
        </section>
      )}

      {partial.length > 0 && (
        <section>
          <h2 className="micro mb-1">Incomplete acquisitions &middot; {partial.length}</h2>
          <p className="dim text-[12px] mb-2.5">Did not finish a full pass of the device.
            Kept because each attempt is part of its case's history.</p>
          <div className="grid gap-2">
            {partial.map((c) => (
              <a key={c.id} href={linkTo(c.id, "dashboard")}
                className="panel px-4 py-2.5 flex items-center gap-4 hover:border-accent group">
                <div className="min-w-0 flex-1">
                  <div className="text-[14px] font-semibold break-all group-hover:text-accent">
                    {c.id}</div>
                  <div className="dim font-mono text-[11.5px] truncate" title={c.device}>
                    {shortDevice(c.device)} &middot; {bytes(c.size_bytes)}</div>
                </div>
                <div className="w-[200px] max-w-[40%] shrink-0">
                  <div className="bg-line h-1.5 rounded-full overflow-hidden">
                    <i className="block h-full bg-synthetic rounded-full"
                      style={{ width: pct(c.progress) }} />
                  </div>
                  <div className="dim text-[11px] mt-1">{pct(c.progress)} of the device read</div>
                </div>
              </a>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function HomeStat({ label, value, small }) {
  return (
    <div className="panel px-4 py-3 min-w-0">
      <div className="micro">{label}</div>
      {/* A long value (the vendors) wraps to a second line rather than
          losing its end; a figure steps down a size on a phone. */}
      <div className={small ? "text-[14px] sm:text-[15px] font-semibold mt-1.5 line-clamp-2"
        : "figure figure-fit mt-1 truncate"}
        title={String(value)}>{value}</div>
    </div>
  );
}

function CaseCard({ c }) {
  return (
    // `accent`, not a hardcoded teal: the looks redefine that token, and a
    // fixed colour here would ignore the chosen direction.  `break-all` is
    // setup's fix for a long case id overflowing.
    <a href={linkTo(c.id, "dashboard")} className="panel p-4 hover:border-accent block group">
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="micro truncate">{c.case_id || "no case ID"}</span>
        {c.vendor
          ? <span title="The detector's best match for this disk, with its confidence"
              className="border border-accent/45 text-accent rounded-full px-2 py-px
                text-[10.5px] whitespace-nowrap">
              {c.vendor} &middot; {pct(c.vendor_confidence)}</span>
          : <span className="hairline border dim rounded-full px-2 py-px text-[10.5px]
              whitespace-nowrap">vendor not identified</span>}
      </div>
      {c.synthetic && (
        <div className="text-synthetic font-mono text-[10.5px] uppercase tracking-wide -mt-1 mb-1.5"
          title="Generated for the demo from a made-up disk - not evidence">synthetic disk</div>)}
      <div className="text-[17px] font-semibold break-all group-hover:text-accent">{c.id}</div>
      <div className="dim font-mono text-[12px] mt-0.5 truncate" title={c.device}>
        {bytes(c.size_bytes)} &middot; {shortDevice(c.device)}</div>
      <div className="grid grid-cols-4 gap-1.5 mt-3.5" aria-label="Pipeline stages">
        {STAGES.map(([t, k]) => (
          <div key={t} title={`${t}: ${c[k] ? "done" : "not run"}`}>
            <i className={`block h-1 rounded-full ${c[k] ? "bg-validated" : "bg-line"}`} />
            <div className={`text-[10.5px] mt-1 ${c[k] ? "" : "dim"}`}>{t}</div>
          </div>
        ))}
      </div>
    </a>
  );
}

/* ------------------------------------------------------------ keyboard */
function useKeyboard(screens, caseId) {
  useEffect(() => {
    const on = (e) => {
      const tag = (e.target.tagName || "").toLowerCase();
      if (["input", "select", "textarea"].includes(tag) || e.metaKey || e.ctrlKey) return;
      if (e.key === "t") { flipTheme(); return; }
      if (e.key === "/") {
        const q = document.querySelector("[data-table-search]");
        if (q) { e.preventDefault(); q.focus(); }
        return;
      }
      if (e.key === "Escape" && caseId) { go(null); return; }
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

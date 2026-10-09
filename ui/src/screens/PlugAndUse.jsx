// Plug and use (acquire/station.py): a disk plugged into the workstation runs
// through every stage of the problem statement, and this page follows it live.
//
// The console still opens no device. The station is a separate process,
// started as root, that does the work; this page only reads what it writes,
// through /api/station (report/pipeline.py). It lives at #/plug, like the
// Start here guide at #/start.
import { useState, useEffect, useRef } from "react";
import { api } from "../lib/api.js";
import { linkTo } from "../lib/useHashRoute.js";
import { isDemo } from "../lib/host.js";
import { bytes, dur } from "../lib/format.js";
import { Section, Command, Skeleton } from "../components/index.jsx";

// Under sudo, the Python that has the analytics layer (analytics/README.md):
// root's own python3 usually does not, and faces and objects are then skipped.
const START = 'sudo .venv/bin/python cli.py station --investigator "Your name"';

// How a stage's state reads, its text colour, and the colour of its edge.
const LOOK = {
  done:    ["done",    "text-validated", "var(--color-validated)"],
  running: ["running", "text-accent",    "var(--color-accent)"],
  part:    ["partial", "text-synthetic", "var(--color-synthetic)"],
  failed:  ["failed",  "text-danger",    "var(--color-danger)"],
  skipped: ["skipped", "dim",            "var(--color-line)"],
  pending: ["to do",   "dim",            "var(--color-line)"],
};
const look = (s) => LOOK[s] || LOOK.pending;

const secs = (a, b) => (a ? Math.max(0, ((b ? Date.parse(b) : Date.now()) - Date.parse(a)) / 1000) : null);

export default function PlugAndUse({ cases, onNewCase }) {
  const [view, setView] = useState(null);
  const [err, setErr] = useState(null);
  const known = useRef(new Set());
  known.current = new Set(cases.map((c) => c.id));

  useEffect(() => {
    let alive = true;
    let timer;
    const load = () => api.station().then((v) => {
      if (!alive) return;
      setView(v);
      setErr(null);
      // A case the station just started is not in the console's list yet.
      if ([...v.runs, ...v.examples].some((r) => !known.current.has(r.id))) onNewCase?.();
      // Follow a running station closely; with none, look in now and then, so
      // one started after this page opened still shows up. The hosted copy
      // has no station to wait for.
      if (v.station?.running) timer = setTimeout(load, 2500);
      else if (!isDemo()) timer = setTimeout(load, 10000);
    }, (e) => {
      if (!alive) return;
      setErr(e.message);
      if (!isDemo()) timer = setTimeout(load, 15000);
    });
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, []);                                                // eslint-disable-line

  const byId = Object.fromEntries(cases.map((c) => [c.id, c]));
  const st = view?.station;
  const live = st?.running && st.case ? view.runs.find((r) => r.id === st.case) : null;
  const others = (view?.runs || []).filter((r) => r !== live);
  // Real drives make the examples; generated ones only if there is nothing else.
  const real = (view?.examples || []).filter((r) => !byId[r.id]?.synthetic);
  const examples = real.length ? real : view?.examples || [];
  const module = Object.fromEntries((view?.stages || []).map((s) => [s.id, s.module]));

  return (
    <div className="max-w-[1100px] mx-auto">
      <h1 className="display text-[22px] font-semibold">Plug and use</h1>
      <p className="dim text-[13px] mt-0.5 max-w-[760px]">
        Plug a recorder's disk into the workstation and every step of the problem
        statement runs on it, with no further input: acquisition and hashes, the brand,
        the filesystem, deleted footage, the timeline, faces and objects, and the
        report. This page follows each stage as it runs.</p>
      {isDemo() && (
        <p className="text-[12.5px] mt-3 rounded-lg border border-synthetic/45 bg-synthetic/10
          px-3 py-2 max-w-[760px]">
          This is a copy hosted for review, and a disk is never plugged into a website: the
          station runs on your own forensic workstation, offline. Below, real drives show
          what a finished run produces.</p>
      )}

      {!view && !err && <div className="mt-4"><Skeleton rows={3} /></div>}
      {err && (
        <p className="dim text-[12.5px] mt-4">The station's status did not load ({err}).</p>
      )}
      {view && !isDemo() && <StationPanel st={st} />}

      {live && (
        <Section title={`Now running: ${live.id}`}
          hint={live.started_utc ? `started ${dur(secs(live.started_utc))} ago` : ""}>
          <Stages run={live} module={module} />
          <a href={linkTo(live.id, "dashboard")} className="inline-block mt-2.5 text-[12.5px]
            text-accent hover:underline">Open the case as it fills in &rarr;</a>
        </Section>
      )}

      {others.length > 0 && (
        <Section title="Runs by the station" hint="newest first">
          <RunGrid runs={others} byId={byId} />
        </Section>
      )}

      {examples.length > 0 && (
        <Section title="Examples" hint="finished cases on this console, as the same seven stages">
          <RunGrid runs={examples} byId={byId} />
        </Section>
      )}

      {view?.stages && (
        <Section title="The seven stages" hint="each one a module of problem statement 26150">
          <ol className="grid gap-2 grid-cols-[repeat(auto-fill,minmax(300px,1fr))]">
            {view.stages.map((s, i) => (
              <li key={s.id} className="panel px-3.5 py-3 grid grid-cols-[28px_1fr] gap-x-3">
                <Num n={i + 1} />
                <div className="min-w-0">
                  <div className="font-semibold text-[13.5px]">{s.title}</div>
                  <div className="text-accent text-[11px] mt-px">{s.module}</div>
                  <p className="dim text-[12px] mt-1 leading-relaxed">{s.what}</p>
                </div>
              </li>
            ))}
          </ol>
        </Section>
      )}

      {isDemo() && (
        <Section title="On a workstation" hint="one command, then plug the disk in">
          <Command text={START} />
          <StartNotes />
        </Section>
      )}
    </div>
  );
}

const Num = ({ n }) => (
  <span className="w-7 h-7 rounded-full border border-accent/50 text-accent grid place-items-center
    text-[13px] font-semibold">{n}</span>
);

function StartNotes() {
  return (
    <p className="dim text-[12px] mt-2 leading-relaxed max-w-[820px]">
      Run it from the tool's folder. It waits for a disk plugged in after it starts, sets
      the kernel's read-only flag on it (or refuses it), and names the case after the
      disk's serial; plugging the same disk in again resumes an unfinished scan. With the
      packaged <b>ps26150-dvr.exe</b>, run <code>ps26150-dvr station</code> from an
      elevated prompt, behind a hardware write blocker. <code>--no-ml</code> skips faces
      and objects.</p>
  );
}

/* The station itself: running and waiting, on a disk, refused, or not running. */
function StationPanel({ st }) {
  const dev = st?.device;
  const disk = dev && [dev.model, dev.serial, dev.size_bytes ? bytes(dev.size_bytes) : ""]
    .filter(Boolean).join(" · ");
  if (!st?.running) {
    return (
      <div className="panel px-4 py-3.5 mt-4">
        <div className="font-semibold text-[14px] flex items-center gap-2">
          <span className="w-2 h-2 rounded-full border border-current dim" aria-hidden="true" />
          No station is running on this workstation</div>
        <p className="dim text-[12.5px] mt-1">Start it once, as root. Leave this page open and
          it follows the run.</p>
        <Command text={START} />
        <StartNotes />
        {st && (
          <p className="dim text-[11.5px] mt-2">Last seen {dur(st.heartbeat_age_s)} ago
            {st.message ? `: ${st.message}` : ""}.</p>
        )}
      </div>
    );
  }
  if (st.state === "refused") {
    return (
      <div className="panel px-4 py-3.5 mt-4 border-danger/60">
        <div className="font-semibold text-[14px] text-danger">Refused {dev?.path || "the disk"}</div>
        <p className="text-[12.5px] mt-1">{st.message}</p>
        <p className="dim text-[12px] mt-1">Nothing was read. Fix it, unplug the disk and plug
          it in again; the station is still waiting.</p>
      </div>
    );
  }
  const working = st.state === "working";
  return (
    <div className="panel px-4 py-3.5 mt-4" style={{ borderLeft: "3px solid var(--color-accent)" }}>
      <div className="font-semibold text-[14px] flex items-center gap-2 flex-wrap">
        <span className="w-2 h-2 rounded-full bg-accent animate-pulse" aria-hidden="true" />
        {working ? <>Working on {dev?.path}</> : <>Station running on {st.host}: waiting for a disk</>}
      </div>
      <p className="dim text-[12.5px] mt-1">
        {working
          ? <>{disk}{st.case && <> &middot; case <a className="text-accent hover:underline"
              href={linkTo(st.case, "dashboard")}>{st.case}</a></>}</>
          : <>Plug the disk in through the USB-SATA bridge or the write blocker.
              {st.message && st.message !== "waiting for a disk" && <> Last: {st.message}.</>}</>}
      </p>
      <p className="dim text-[11.5px] mt-1">Investigator {st.investigator} &middot; running
        since {dur(secs(st.started_utc))}</p>
    </div>
  );
}

/* One run, stage by stage, with what each stage found. */
function Stages({ run, module }) {
  return (
    <ol className="grid gap-2">
      {run.stages.map((s, i) => {
        const [word, tone, edge] = look(s.state);
        const took = s.started_utc && s.state !== "pending" ? secs(s.started_utc, s.ended_utc) : null;
        return (
          <li key={s.id} className="panel px-3.5 py-2.5 grid grid-cols-[28px_1fr_auto] gap-x-3
            items-center" style={{ borderLeft: `3px solid ${edge}` }}>
            <Num n={i + 1} />
            <div className="min-w-0">
              <div className="font-semibold text-[13.5px]">{s.title}
                {module[s.id] && <span className="dim text-[11px] font-normal"> &middot; {module[s.id]}</span>}</div>
              {s.result && <div className="dim text-[12px] mt-0.5 break-words">{s.result}</div>}
              {s.state === "running" && s.progress != null && (
                <div className="h-1.5 rounded-full bg-line mt-1.5 overflow-hidden">
                  <i className="block h-full bg-accent rounded-full"
                    style={{ width: `${Math.round(s.progress * 100)}%` }} />
                </div>
              )}
            </div>
            <div className="text-right">
              <div className={`text-[11.5px] font-semibold ${tone}`}>{word}</div>
              {took != null && <div className="dim text-[11px]">{dur(took)}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/* Finished or past runs: a card each, every stage on one line. */
function RunGrid({ runs, byId }) {
  return (
    <div className="grid gap-2.5 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
      {runs.map((r) => {
        const c = byId[r.id];
        const about = [c?.vendor && `detected as ${c.vendor}`, c?.size_bytes && bytes(c.size_bytes),
          r.outcome].filter(Boolean).join(" · ");
        return (
          <a key={r.id} href={linkTo(r.id, "dashboard")}
            className="panel px-3.5 py-3 block hover:border-accent group">
            <div className="flex items-baseline justify-between gap-2">
              <span className="font-semibold text-[13.5px] break-all group-hover:text-accent">{r.id}</span>
              <span className="dim text-[11.5px] whitespace-nowrap">{r.done} of 7 stages</span>
            </div>
            {about && <div className="dim text-[11.5px] mt-0.5">{about}</div>}
            {c?.synthetic && <div className="text-synthetic text-[11px] mt-0.5">generated disk, not evidence</div>}
            <ul className="mt-2.5 grid gap-1">
              {r.stages.map((s) => {
                const [word, tone] = look(s.state);
                return (
                  <li key={s.id} className="grid grid-cols-[62px_1fr] gap-2 text-[12px] leading-snug">
                    <span className={`font-semibold ${tone}`}>{word}</span>
                    <span className="min-w-0"><span>{s.title}</span>
                      {s.result && <span className="dim"> &middot; {s.result}</span>}</span>
                  </li>
                );
              })}
            </ul>
          </a>
        );
      })}
    </div>
  );
}

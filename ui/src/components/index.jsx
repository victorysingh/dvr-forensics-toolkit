// Shared components: built once, used by every screen, so a status pill or
// a hash chip cannot drift between one screen and the next.
import { useState, useMemo, useEffect, useRef, createContext, useContext } from "react";
import { num, bytes, pct0, STATUS_COLOR } from "../lib/format.js";

/* ------------------------------------------------------------- toasts */
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastHost({ children }) {
  const [items, setItems] = useState([]);
  const push = (msg) => {
    const id = Math.random();
    setItems((x) => [...x, { id, msg }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 2200);
  };
  return (
    <ToastCtx.Provider value={push}>
      {children}
      {/* Above the bottom screen bar on a phone. Opaque, because some looks
          draw .panel with no fill and a toast must not show the page through. */}
      <div className="fixed right-3 bottom-[72px] md:right-4 md:bottom-4 z-50 flex flex-col gap-2">
        {items.map((t) => (
          <div key={t.id} style={{ background: "var(--color-surface)" }}
            className="panel border-accent px-3.5 py-2 text-xs shadow-lg shadow-black/30">
            {t.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/* --------------------------------------------------------------- pill */
// `label` puts plain words on the pill where a newcomer reads it; the colour
// still comes from the status, so it agrees with every other screen.
export function Pill({ status, label }) {
  const s = status || "none";
  const color = STATUS_COLOR[s] || "dim";
  return (
    <span className={`inline-block rounded-full border border-current px-2 py-px
      text-[11px] font-semibold whitespace-nowrap ${color}`}>{label || s}</span>
  );
}

/* ---------------------------------------------------------- hash chip */
// Short on screen, full on hover, whole value copied on click.
export function Hash({ value, len = 6 }) {
  const toast = useToast();
  if (!value) return <span className="dim">&mdash;</span>;
  const s = String(value);
  const short = s.length > len * 2 ? `${s.slice(0, len)}…${s.slice(-4)}` : s;

  const copy = async () => {
    // http://127.0.0.1 is not a secure context in every browser, so the
    // async clipboard API can be missing; fall back to a scratch textarea.
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(s);
      } else {
        const ta = document.createElement("textarea");
        ta.value = s;
        ta.style.cssText = "position:fixed;opacity:0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      toast("Copied to clipboard");
    } catch { toast("Could not copy"); }
  };

  return (
    <button onClick={copy} title={s}
      className="panel-2 hairline border rounded-md px-1.5 py-px font-mono text-[11.5px]
        hover:border-accent hover:text-accent cursor-pointer align-middle">
      {short}
    </button>
  );
}

/* ---------------------------------------------------------------- kpi */
export function Kpi({ label, value, sub, src, lead }) {
  // The hook runs unconditionally - passing null for a text value keeps the
  // call order stable when a KPI switches between a number and a string.
  const n = useCountUp(typeof value === "number" ? value : null);
  return (
    <div className="panel p-3.5 min-w-0">
      <div className="micro">{label}</div>
      {/* A word or an identifier can be far wider than a count, so a long
          text value steps down a size and may wrap rather than spill out. */}
      <div className={`font-semibold leading-tight mt-1
        ${typeof value === "string" && value.length > 10
          ? "text-[18px] break-all" : "text-[26px]"}
        ${lead ? "text-lead" : ""}`}>
        {typeof value === "number" ? num(n) : value}
      </div>
      {sub && <div className="dim text-[11.5px] mt-0.5">{sub}</div>}
      {src && <div className="dim font-mono text-[10.5px] mt-1.5">from {src}</div>}
    </div>
  );
}

// Count a KPI up on mount, unless the viewer asked for reduced motion.
// `to` is null when the KPI's value is text, in which case this does nothing.
function useCountUp(to) {
  const [v, setV] = useState(() =>
    window.matchMedia("(prefers-reduced-motion: reduce)").matches ? to : 0);
  useEffect(() => {
    if (to === null) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || to <= 0) {
      setV(to);
      return;
    }
    let raf; const t0 = performance.now(), ms = 520;
    const step = (now) => {
      const k = Math.min(1, (now - t0) / ms);
      setV(Math.round(to * (1 - Math.pow(1 - k, 3))));
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [to]);
  return v;
}

/* -------------------------------------------------------------- panel */
export function Section({ title, hint, children }) {
  return (
    <section className="mt-5">
      {title && (
        <h2 className="text-[15px] font-semibold mb-2.5 flex flex-wrap items-baseline gap-x-2.5">
          {title}{hint && <span className="dim text-[11.5px] font-normal">{hint}</span>}
        </h2>
      )}
      {children}
    </section>
  );
}

export function Card({ children, className = "" }) {
  return <div className={`panel p-3.5 ${className}`}>{children}</div>;
}

/* ------------------------------------------------------- definition list */
export function DL({ rows }) {
  return (
    <dl className="grid grid-cols-[minmax(96px,auto)_minmax(0,1fr)] sm:grid-cols-[minmax(120px,auto)_minmax(0,1fr)]
      gap-x-4 gap-y-1 text-[12.5px]">
      {rows.filter(Boolean).map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="dim">{k}</dt>
          <dd className="m-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/* --------------------------------------------------------- confidence */
export function ConfBar({ value, color }) {
  return (
    <span className="flex items-center gap-2">
      <span className="panel-2 h-1.5 flex-1 min-w-16 rounded-full overflow-hidden">
        <i className="block h-full rounded-full"
          style={{ width: pct0(value), background: color || "var(--color-accent)" }} />
      </span>
      <span className="font-mono text-[11.5px] w-11 text-right">{pct0(value)}</span>
    </span>
  );
}

/* -------------------------------------------------------------- empty */
// An empty state always names the command that would fill it: a blank panel
// that explains itself is the difference between "broken" and "not run".
export function Empty({ what, how }) {
  return (
    <div className="hairline border border-dashed rounded-xl px-5 py-6 text-center dim">
      <div className="text-[13.5px] text-current mb-1">{what}</div>
      {how && <div>Run <Code>{how}</Code></div>}
    </div>
  );
}

export const Code = ({ children }) => (
  <code className="panel-2 hairline border rounded px-1.5 py-px font-mono text-[12px]">
    {children}
  </code>
);

export function Skeleton({ rows = 4 }) {
  return (
    <Card>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="panel-2 h-3 my-2 rounded animate-pulse"
          style={{ width: `${90 - i * 13}%` }} />
      ))}
    </Card>
  );
}

/* ------------------------------------------------------------ banners */
export function LeadBanner({ extra }) {
  return (
    <div className="rounded-xl border border-lead/45 bg-lead/10 px-3.5 py-3 mb-3.5
      flex gap-3 items-start">
      <span className="text-lead font-bold">&#9670;</span>
      <div className="text-[12.5px]">
        <b className="text-lead">Leads, not evidence.</b> These boxes come from an object
        detector run over recovered frames. This is <b className="text-lead">detection,
        not recognition</b>: nothing here identifies a person. Treat every row as a
        pointer for an examiner to check by eye.
        {extra && <div className="dim mt-1">{extra}</div>}
      </div>
    </div>
  );
}

export function ClockBanner({ rule }) {
  return (
    <div className="panel border-l-[3px] border-l-synthetic px-3.5 py-2.5 mb-3 text-[12.5px]">
      <b>Recorder clock.</b>{" "}
      {rule || "Times are the recorder's own clock, not converted to UTC: the recorder's zone was not stated."}
    </div>
  );
}

/* --------------------------------------------------------- data table */
/* Search, sort and pagination over a column spec:
 *   { key, label, cls?, sort?: "num" | false, render?: (row) => node }
 * Rows past the current page are never mounted, which is what keeps a
 * 2,000-stream drive responsive.
 */
export function DataTable({ rows, cols, page = 100, search = true, initialSort, initialDir = 1 }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState(initialSort || null);
  const [dir, setDir] = useState(initialDir);
  const [at, setAt] = useState(0);

  const view = useMemo(() => {
    let out = rows;
    if (q) {
      const needle = q.toLowerCase();
      out = out.filter((r) =>
        cols.map((c) => String(r[c.key] ?? "")).join(" ").toLowerCase().includes(needle));
    }
    if (sort) {
      const c = cols.find((x) => x.key === sort);
      const isNum = c && c.sort === "num";
      out = [...out].sort((a, b) => isNum
        ? (Number(a[sort] || 0) - Number(b[sort] || 0)) * dir
        : String(a[sort] ?? "").localeCompare(String(b[sort] ?? "")) * dir);
    }
    return out;
  }, [rows, cols, q, sort, dir]);

  const slice = view.slice(at, at + page);
  const pages = Math.ceil(view.length / page) || 1;

  const clickSort = (k) => {
    if (sort === k) setDir(-dir); else { setSort(k); setDir(1); }
    setAt(0);
  };

  return (
    <div className="panel overflow-hidden">
      {search && (
        <div className="hairline border-b px-2.5 py-2 flex items-center gap-2 flex-wrap">
          <input type="search" placeholder="Search&hellip;" data-table-search
            value={q} onChange={(e) => { setQ(e.target.value); setAt(0); }}
            className="panel-2 hairline border rounded-md px-2.5 py-1 text-[12.5px]
              outline-none focus:border-accent" />
          <span className="dim text-[11.5px] ml-auto">
            {num(view.length)} row{view.length === 1 ? "" : "s"}
            {view.length !== rows.length && ` of ${num(rows.length)}`}
          </span>
        </div>
      )}
      <div className="max-h-[460px] overflow-auto">
        <table className="w-full border-collapse text-[12.5px]">
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c.key}
                  onClick={c.sort === false ? undefined : () => clickSort(c.key)}
                  className={`sticky top-0 z-10 text-left dim font-semibold text-[11px]
                    uppercase tracking-wide px-2.5 py-1.5 hairline border-b whitespace-nowrap
                    ${c.sort === false ? "" : "cursor-pointer"}`}>
                  {c.label}
                  {sort === c.key && (
                    <span className="text-[9px] ml-1">{dir > 0 ? "▲" : "▼"}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map((r, i) => (
              <tr key={r.__k ?? r.id ?? i} className="hover:bg-[color-mix(in_srgb,var(--color-ink)_7%,transparent)]">
                {cols.map((c) => (
                  <td key={c.key}
                    className={`px-2.5 py-1.5 hairline border-b align-top ${c.cls || ""}`}>
                    {c.render ? c.render(r) : String(r[c.key] ?? "")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="hairline border-t px-2.5 py-1.5 flex items-center justify-end gap-2
          text-[12px] dim">
          <PagerBtn disabled={at === 0} onClick={() => setAt(Math.max(0, at - page))}>Prev</PagerBtn>
          <span>page {Math.floor(at / page) + 1} of {pages}</span>
          <PagerBtn disabled={at + page >= view.length}
            onClick={() => setAt(at + page)}>Next</PagerBtn>
        </div>
      )}
    </div>
  );
}

const PagerBtn = ({ disabled, onClick, children }) => (
  <button disabled={disabled} onClick={onClick}
    className="panel-2 hairline border rounded px-2 py-0.5 text-[12px]
      disabled:opacity-60 disabled:cursor-default cursor-pointer">
    {children}
  </button>
);

/* ------------------------------------------------------------ command */
// A command block with one copy button. Copying is a convenience: a browser
// that refuses the clipboard just leaves the text to be selected by hand.
export function Command({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    try {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }, () => {});
    } catch { /* no clipboard here */ }
  };
  return (
    <div className="relative mt-2">
      <pre className="panel-2 hairline border rounded-lg px-3 py-2 pr-16 font-mono text-[12px]
        overflow-x-auto whitespace-pre">{text}</pre>
      <button type="button" onClick={copy}
        className="absolute top-1.5 right-1.5 hairline border rounded px-2 py-0.5 text-[11px]
          panel hover:border-accent">{copied ? "copied" : "copy"}</button>
    </div>
  );
}

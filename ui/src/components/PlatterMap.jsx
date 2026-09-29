// The drive, drawn to scale, pinned beside the case narrative.
//
// This is the one thing a forensic console has that a dashboard does not: the
// evidence is a physical object with coordinates. An offset is not metadata,
// it is *where something is*. So the map runs offset 0 at the top to the last
// sector at the bottom, every recovered stream sits at its real position, and
// scrolling the argument lights up the part of the platter being discussed.
//
// Positions come from what load_case already returns - carved stream offsets,
// bad regions, the scanned extent. A per-block picture needs the /blockmap
// route (UI_PLAN §8, not built), and when it lands it slots in as another
// band without changing anything here.
import { useMemo } from "react";
import { bytes, hex, num } from "../lib/format.js";

/** Every positioned thing the case knows about, as {id, at, len, kind, label}. */
export function collectMarks(c) {
  const marks = [];
  const push = (id, at, len, kind, label) => {
    if (at == null || !isFinite(at)) return;
    marks.push({ id, at: Number(at), len: Math.max(Number(len) || 0, 1), kind, label });
  };

  for (const r of c.carve?.outside_index || []) {
    push(`carve:${r.id}`, r.offset, r.length, "outside",
         `${r.id} · ${num(r.frame_count)} frames · not in the index`);
  }
  for (const r of c.parse?.recordings || []) {
    push(`rec:${r.id}`, r.offset, r.length, "indexed",
         `${r.id} · ${r.camera_id || "?"} · listed by the index`);
  }
  for (const r of c.es_carve?.streams || []) {
    push(`es:${r.id}`, r.offset, r.bytes, "raw", `${r.id} · raw ${r.codec || "stream"}`);
  }
  for (const r of c.ps_carve?.streams || []) {
    push(`ps:${r.id}`, r.offset, r.bytes, "raw", `${r.id} · PS stream`);
  }
  (c.scan?.bad_regions || []).forEach((b, i) =>
    push(`bad:${i}`, b.offset, b.length, "bad", `bad sector at ${hex(b.offset)}`));

  return marks;
}

const KIND_COLOR = {
  outside: "var(--color-synthetic)",
  indexed: "var(--color-validated)",
  raw: "var(--color-spec)",
  bad: "var(--color-danger)",
};

/* `orient` follows where the map is put, not the other way round. Down a
   pinned column it reads as a drive stood on end; across a full-width
   section it reads as the strip UI_PLAN §6.2 describes, and a tall narrow
   column there would waste the width and say nothing extra. */
export default function PlatterMap({ c, highlight, onPick, orient = "horizontal" }) {
  const size = Number(c.scan?.device?.size_bytes || c.in_progress?.size_bytes || 0);
  const read = Number(c.scan?.stats?.bytes_read || 0);
  const marks = useMemo(() => collectMarks(c), [c]);

  if (!size) return null;

  const vertical = orient === "vertical";
  const pctOf = (n) => `${Math.max(0, Math.min(100, (n / size) * 100))}%`;
  // A stream a few hundred KiB long on a 150 GB drive is invisible at true
  // scale, so marks get a floor of 0.6% and stay findable. The label always
  // states the real length, so nothing is overstated by the drawing.
  const spanOf = (len) => `${Math.max(0.6, (len / size) * 100)}%`;

  const lit = (m) => !highlight || highlight.length === 0 || highlight.includes(m.kind);
  const anyHighlight = highlight && highlight.length > 0;

  // the axis the offset runs along, and the one the drive is thick along
  const at = (n) => (vertical ? { top: pctOf(n) } : { left: pctOf(n) });
  const span = (len) => (vertical ? { height: spanOf(len) } : { width: spanOf(len) });
  const across = vertical ? "left-0 right-0" : "top-0 bottom-0";
  const driveBox = vertical
    ? { width: "3.5rem", height: "clamp(320px, 58vh, 620px)" }
    : { width: "100%", height: "5rem" };

  return (
    <figure className="m-0 select-none">
      <figcaption className="micro mb-2">The platter &middot; {bytes(size)}</figcaption>

      <div className={vertical ? "flex gap-2" : "block"}>
        {/* the drive itself */}
        <div className="relative shrink-0 panel overflow-hidden" style={driveBox}>

          {/* what the scan actually read: a triage pass stops partway */}
          <div className={`absolute ${across} ${vertical ? "top-0" : "left-0"}`}
            style={{
              ...span(read || size),
              background: "color-mix(in srgb, var(--color-ink) 7%, transparent)",
            }} />
          {read > 0 && read < size && (
            <div className={`absolute ${across} border-dashed ${
              vertical ? "border-t" : "border-l"}`}
              style={{ ...at(read), borderColor: "var(--color-ink-dim)" }} />
          )}

          {marks.map((m) => (
            <button key={m.id} title={`${m.label}\n${hex(m.at)} · ${bytes(m.len)}`}
              onClick={() => onPick && onPick(m)}
              className={`absolute ${across} cursor-pointer transition-opacity`}
              style={{
                ...at(m.at),
                ...span(m.len),
                background: KIND_COLOR[m.kind] || "var(--color-ink-dim)",
                opacity: anyHighlight ? (lit(m) ? 1 : 0.15) : 0.85,
              }} />
          ))}
        </div>

        {/* the ruler */}
        <div className={`relative text-[9.5px] mono-t dim ${
          vertical ? "w-16 shrink-0" : "w-full h-4 mt-1"}`}
          style={vertical ? { height: "clamp(320px, 58vh, 620px)" } : undefined}>
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <div key={f} className="absolute"
              style={vertical ? { top: `${f * 100}%`, left: 0 }
                              : { left: `${f * 100}%` }}>
              <span className={`block ${
                vertical ? "-translate-y-1/2"
                  : f === 0 ? "" : f === 1 ? "-translate-x-full" : "-translate-x-1/2"}`}>
                {hex(Math.round(size * f))}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* the key sits in a row when the map lies flat, a column when it stands */}
      <div className={`micro mt-3 leading-relaxed ${
        vertical ? "" : "flex flex-wrap items-center gap-x-5 gap-y-1"}`}>
        {[["indexed", "in the index"], ["outside", "not in the index"],
          ["raw", "raw stream"], ["bad", "bad sector"]]
          .filter(([k]) => marks.some((m) => m.kind === k))
          .map(([k, label]) => (
            <div key={k} className="flex items-center gap-1.5"
              style={{ opacity: lit({ kind: k }) ? 1 : 0.3 }}>
              <span className="w-2 h-2 inline-block shrink-0"
                style={{ background: KIND_COLOR[k] }} />
              {label}
            </div>
          ))}
        {read > 0 && read < size && (
          <div className={`normal-case tracking-normal ${vertical ? "mt-1.5" : ""}`}>
            dashed line: the scan read to here
          </div>
        )}
        {marks.length === 0 && (
          <div className="normal-case tracking-normal">
            nothing positioned on the platter yet
          </div>
        )}
      </div>
    </figure>
  );
}

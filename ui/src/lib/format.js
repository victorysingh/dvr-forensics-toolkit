// Formatters shared by every screen.
//
// React escapes interpolated text for us, so there is no esc() here - the
// one thing that still needs care is time, below.

export function bytes(n) {
  n = Number(n || 0);
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
  return i === 0 ? `${n} B` : `${n.toFixed(n < 10 ? 2 : 1)} ${u[i]}`;
}

export const num = (n) => Number(n || 0).toLocaleString("en-US");

export function dur(s) {
  s = Math.round(Number(s) || 0);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${s}s`;
}

export const pct = (f) => `${(Number(f || 0) * 100).toFixed(1)}%`;
export const pct0 = (f) => `${(Number(f || 0) * 100).toFixed(0)}%`;
export const hex = (n) => "0x" + Number(n || 0).toString(16).toUpperCase();

// Recorder-clock times are printed exactly as they were stored.  They are
// never parsed into a Date and re-formatted: that would quietly move them
// into the viewer's own zone, which is the one lie this product must not
// tell.  An em dash means the pipeline recorded no time, not "midnight".
export const clockTime = (s) => (s ? String(s).replace("T", " ").replace("Z", "") : "—");

// A carved stream has no flat local-time field.  It carries a list of time
// claims, each holding its decoded value inside `raw_value`, shaped
// "0x6A026000 = 2026-08-01 06:00:00 recorder-local".  Showing the string the
// decoder wrote - rather than re-deriving one - keeps the screen honest
// about which claim it is quoting.
export function claimLocal(claim) {
  if (!claim || !claim.raw_value) return "";
  return String(claim.raw_value).split(" = ").pop().replace(" recorder-local", "").trim();
}

export const firstLocal = (rec) => claimLocal(((rec && rec.timestamps) || [])[0]);

export const camColor = (i) => `var(--color-cam-${(i % 8) + 1})`;

// Status -> the Tailwind text colour that names it.  One place, so a pill,
// a bar and a heading can never disagree about what "spec_only" looks like.
export const STATUS_COLOR = {
  validated: "text-validated",
  spec_only: "text-spec",
  synthetic_only: "text-synthetic",
  detected_not_parsed: "text-detected",
};

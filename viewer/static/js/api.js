// Every fetch the UI makes.  All of them are same-origin, relative paths to
// the loopback server: nothing here may ever name an external host.
"use strict";

async function get(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

export const api = {
  cases: () => get("/api/cases"),
  case: (id) => get(`/api/case/${encodeURIComponent(id)}`),
  vendors: () => get("/api/vendors"),
  // A case's newest file mtime, for the auto-refresh poll (P4).
  stamp: (id) => get(`/api/case/${encodeURIComponent(id)}/stamp`),
  reportUrl: (id) => `/report/${encodeURIComponent(id)}`,
  thumbUrl: (id, f) => `/thumb/${encodeURIComponent(id)}/${encodeURIComponent(f)}`,
  fileUrl: (id, rel) =>
    `/file/${encodeURIComponent(id)}/${rel.split("/").map(encodeURIComponent).join("/")}`,
};

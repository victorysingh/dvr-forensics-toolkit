// Every fetch the console makes.  All same-origin, relative to the loopback
// server: no absolute URL and no external host may ever appear here.
async function get(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

export const api = {
  cases: () => get("/api/cases"),
  case: (id) => get(`/api/case/${encodeURIComponent(id)}`),
  vendors: () => get("/api/vendors"),
  stamp: (id) => get(`/api/case/${encodeURIComponent(id)}/stamp`),
  reportUrl: (id) => `/report/${encodeURIComponent(id)}`,
  thumbUrl: (id, f) => `/thumb/${encodeURIComponent(id)}/${encodeURIComponent(f)}`,
  fileUrl: (id, rel) =>
    `/file/${encodeURIComponent(id)}/${String(rel).split("/").map(encodeURIComponent).join("/")}`,
};

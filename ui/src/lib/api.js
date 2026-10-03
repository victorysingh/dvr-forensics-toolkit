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
  me,
};

// Who is signed in (access/routes.py::Gate._me), as one of:
//   { gate: true, user: {...} }   signed in behind serve --require-access
//   { gate: true, user: null }    behind the gate, but the session has ended
//   { gate: false }               no sign-in: the local viewer says so, and
//                                 the static demo has no server at all
async function me() {
  try {
    const r = await fetch("/access/me", { cache: "no-store" });
    if (r.status === 401) return { gate: true, user: null };
    const json = (r.headers.get("content-type") || "").includes("json");
    if (!r.ok || !json) return { gate: false };
    const body = await r.json();
    return body.gate === false ? { gate: false } : { gate: true, user: body };
  } catch {
    return { gate: false };
  }
}

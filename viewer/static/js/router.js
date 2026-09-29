// Hash routing: #/<case>/<screen>, plus #/ for the cases home.
//
// The route is the whole of the UI's navigation state, so any screen can be
// reached by URL alone - which is what makes the demo recording repeatable
// and lets a examiner send a colleague a link to exactly what they saw.
"use strict";

export function parseHash(h = location.hash) {
  const parts = h.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  return { caseId: parts[0] || null, screen: parts[1] || "dashboard" };
}

export const linkTo = (caseId, screen) =>
  `#/${encodeURIComponent(caseId)}/${encodeURIComponent(screen)}`;

export function go(caseId, screen) {
  location.hash = caseId ? linkTo(caseId, screen) : "#/";
}

export function onRoute(fn) {
  window.addEventListener("hashchange", () => fn(parseHash()));
  return fn(parseHash());
}

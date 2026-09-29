import { useState, useEffect } from "react";

// Hash routing: #/<case>/<screen>, and #/ for the cases home.
//
// The route holds all of the console's navigation state, so any screen can
// be reached by URL alone - which is what makes the demo recording
// repeatable and lets an examiner send a colleague exactly what they saw.
export function parseHash(h = location.hash) {
  const parts = h.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  return { caseId: parts[0] || null, screen: parts[1] || "dashboard" };
}

export const linkTo = (caseId, screen) =>
  `#/${encodeURIComponent(caseId)}/${encodeURIComponent(screen)}`;

export const go = (caseId, screen) => {
  location.hash = caseId ? linkTo(caseId, screen) : "#/";
};

export function useHashRoute() {
  const [route, setRoute] = useState(() => parseHash());
  useEffect(() => {
    const on = () => setRoute(parseHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

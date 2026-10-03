import { useState, useEffect } from "react";

/* Light and dark are palettes in index.css, not one inversion. With nothing
   stored the theme follows the operating system, and choosing here pins it
   - after which the system no longer overrides the choice. */
export function setTheme(t) {
  if (t === "light") document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  try { localStorage.setItem("anokhidrishti-theme", t); } catch { /* ignore */ }
}

export const currentTheme = () =>
  document.documentElement.dataset.theme === "light" ? "light" : "dark";

export const flipTheme = () => setTheme(currentTheme() === "light" ? "dark" : "light");

/* The keyboard shortcut sets the attribute directly, so a control holding
   its own copy would fall out of step the first time it is pressed. Every
   control reads the attribute instead and re-reads it whenever it changes. */
export function useTheme() {
  const [v, setV] = useState(currentTheme);
  useEffect(() => {
    const o = new MutationObserver(() => setV(currentTheme()));
    o.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    setV(currentTheme());
    return () => o.disconnect();
  }, []);
  return v;
}

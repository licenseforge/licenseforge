export type ThemeMode = "system" | "light" | "dark";
const key = "lf-theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

export function storedTheme(): ThemeMode {
  try {
    const m = localStorage.getItem(key);
    if (m === "light" || m === "dark") return m;
  } catch {
    // storage blocked: follow the system
  }
  return "system";
}

/** Applies mode to <html> and remembers it; "system" follows the OS live. */
export function applyTheme(mode: ThemeMode) {
  try {
    if (mode === "system") localStorage.removeItem(key);
    else localStorage.setItem(key, mode);
  } catch {
    // not remembered, still applied
  }
  const set = () =>
    document.documentElement.classList.toggle("dark", mode === "dark" || (mode === "system" && media().matches));
  set();
  media().onchange = mode === "system" ? set : null;
}

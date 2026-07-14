export const THEME_STORAGE_KEY = "ah-theme";
export const THEME_CHANGED_EVENT = "autohunter-theme-changed";
export const TOKEN_DIALOG_EVENT = "autohunter-open-token-modal";

export function normalizeTheme(theme) {
  return theme === "light" ? "light" : "dark";
}

export function currentTheme(storage = globalThis.localStorage) {
  return normalizeTheme(storage?.getItem?.(THEME_STORAGE_KEY));
}

export function nextTheme(theme) {
  return normalizeTheme(theme) === "dark" ? "light" : "dark";
}

export function setThemePreference(theme, options = {}) {
  const value = normalizeTheme(theme);
  const root = options.root || globalThis.document?.documentElement;
  const storage = options.storage || globalThis.localStorage;
  root?.setAttribute?.("data-theme", value);
  storage?.setItem?.(THEME_STORAGE_KEY, value);
  if (options.notify !== false) {
    const target = options.target || globalThis.window;
    target?.dispatchEvent?.(new CustomEvent(THEME_CHANGED_EVENT, { detail: { theme: value } }));
  }
  return value;
}

export function requestTokenDialog(reason = "switch", target = globalThis.window) {
  target?.dispatchEvent?.(new CustomEvent(TOKEN_DIALOG_EVENT, { detail: { reason } }));
}

export function shouldLoadSystemSettings(role) {
  return role === "full";
}

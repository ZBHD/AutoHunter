const NAV_ITEMS = Object.freeze([
  { id: "tasks", label: "任务", to: "/", roles: null },
  { id: "missed", label: "疑似", to: "/missed-signals", roles: ["full", "readonly"], badgeKey: "missedPending" },
  { id: "killsweeps", label: "通杀", to: "/killsweeps", roles: ["full", "readonly"], badgeKey: "killsweepFailed" },
  { id: "settings", label: "设置", to: "/settings", roles: null },
]);

const RESTRICTED_READ_ROUTES = ["/missed-signals", "/killsweeps", "/intel", "/vulns", "/runtime-logs"];

export function primaryNavigation(role, counts = {}) {
  return NAV_ITEMS
    .filter((item) => !item.roles || item.roles.includes(role))
    .map((item) => ({
      id: item.id,
      label: item.label,
      to: item.to,
      badge: item.badgeKey ? Math.max(0, Number(counts[item.badgeKey]) || 0) : 0,
    }));
}

export function canAccessRoute(role, path) {
  if (path === "/create") return role === "full";
  if (RESTRICTED_READ_ROUTES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))) {
    return role === "full" || role === "readonly";
  }
  return true;
}

export function isNavigationActive(item, path) {
  if (item.to === "/") return path === "/" || path.startsWith("/task/");
  return path === item.to || path.startsWith(`${item.to}/`);
}

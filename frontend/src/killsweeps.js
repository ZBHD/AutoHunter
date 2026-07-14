export const KILLSWEEP_STATUS = Object.freeze({
  queued: { label: "待触发", tone: "warning" },
  running: { label: "运行中", tone: "running" },
  pending_validation: { label: "待验证", tone: "warning" },
  killsweep: { label: "可通杀", tone: "success" },
  not_killsweep: { label: "不可通杀", tone: "muted" },
  failed: { label: "失败", tone: "danger" },
  invalid: { label: "人工无效", tone: "muted" },
  succeeded: { label: "分析完成", tone: "success" },
  cancelled: { label: "已取消", tone: "muted" },
});

export function killsweepPresentation(status) {
  const value = KILLSWEEP_STATUS[status];
  return value
    ? { key: status, ...value }
    : { key: status || "unknown", label: status || "未知", tone: "muted" };
}

export function killsweepStatCount(stats = {}, key = "total") {
  if (key === "succeeded") {
    return ["pending_validation", "killsweep", "not_killsweep"]
      .reduce((total, status) => total + Math.max(0, Number(stats[status]) || 0), 0);
  }
  return Math.max(0, Number(stats[key]) || 0);
}

export function reanalysisBatchLimit(value = 40) {
  const parsed = Math.floor(Number(value));
  if (!Number.isFinite(parsed)) return 40;
  return Math.min(40, Math.max(1, parsed));
}

export function canReanalyzeKillsweep(item = {}) {
  return item.status === "failed"
    || item.automatic_verdict === "not_killsweep"
    || item.manual_verdict === "invalid";
}

export const KILLSWEEP_PAGE_SIZE = 50;

export function killsweepListParams({
  status = "all",
  manualVerdict = "all",
  q = "",
  page = 0,
  taskId = "",
} = {}) {
  const params = {};
  if (taskId) params.task_id = taskId;
  if (status && status !== "all") params.status = status;
  if (manualVerdict && manualVerdict !== "all") params.manual_verdict = manualVerdict;
  const query = String(q || "").trim();
  if (query) params.q = query;
  params.limit = KILLSWEEP_PAGE_SIZE;
  params.offset = Math.max(0, Math.floor(Number(page) || 0)) * KILLSWEEP_PAGE_SIZE;
  return params;
}

export function intelFiltersForKillsweep(item = {}) {
  const filters = {};
  if (item.task_id) filters.task_id = item.task_id;
  const product = String(item.product_name || item.product_key || "").trim();
  if (product) filters.q = product;
  return filters;
}

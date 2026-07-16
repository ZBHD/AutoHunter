const STATUS_META = {
  ready: { code: "ready", label: "可用", tone: "ok" },
  rate_limited: { code: "rate_limited", label: "限流冷却", tone: "warn" },
  daily_cooldown: { code: "daily_cooldown", label: "额度冷却", tone: "warn" },
  daily_suspended: { code: "daily_suspended", label: "今日暂停", tone: "danger" },
  auth_invalid: { code: "auth_invalid", label: "Key 无效", tone: "danger" },
};

const CATEGORY_LABELS = {
  ok: "正常",
  auth: "Key 无效",
  rate_limit: "请求限流",
  daily_limit: "每日额度",
  endpoint: "地址错误",
  transient: "临时故障",
};

const ENDPOINT_MODE_LABELS = {
  root: "根地址自动拼接",
  api_php: "完整地址",
  exact: "完整地址",
  known: "标准接口",
  fallback: "标准接口回退",
};

export function fofaKeyList(response) {
  if (Array.isArray(response)) return response;
  if (Array.isArray(response?.fofa_keys)) return response.fofa_keys;
  return [];
}

export function isLegacyFofaKey(item) {
  return item?.read_only === true || item?.source === "legacy";
}

export function needsEffectiveFofaKeyReload(response) {
  return fofaKeyList(response).length === 0;
}

export function moveFofaKey(names, index, delta) {
  const ordered = [...names];
  const destination = index + delta;
  if (index < 0 || index >= ordered.length || destination < 0 || destination >= ordered.length) {
    return ordered;
  }
  const [name] = ordered.splice(index, 1);
  ordered.splice(destination, 0, name);
  return ordered;
}

export function isFofaKeyUsable(item = {}, now = Date.now()) {
  if (item.enabled !== true || item.key_set !== true) return false;
  const state = String(item.runtime_state || "ready");
  if (state === "auth_invalid" || state === "daily_suspended") return false;
  if (state === "rate_limited" || state === "daily_cooldown") {
    if (!item.cooldown_until) return false;
    const until = Date.parse(item.cooldown_until);
    return Number.isFinite(until) && until <= Number(now);
  }
  return state === "ready";
}

function normalizedHealthResult(value, fallbackName = "") {
  if (!value || typeof value !== "object") return null;
  const latency = Number(value.latency_ms);
  const status = Number(value.http_status);
  return {
    name: String(value.name || fallbackName).trim() || fallbackName,
    ok: value.ok === true,
    category: String(value.category || (value.ok ? "ok" : "transient")),
    runtime_state: String(value.runtime_state || ""),
    latency_ms: Number.isFinite(latency) && latency >= 0 ? latency : 0,
    error: String(value.error || ""),
    resolved_url: String(value.resolved_url || ""),
    endpoint_mode: String(value.endpoint_mode || ""),
    http_status: Number.isFinite(status) && status > 0 ? status : null,
    cooldown_until: value.cooldown_until || null,
    enabled: value.enabled !== false,
    auto_blocked: value.auto_blocked === true,
    stale: value.stale === true,
  };
}

export function fofaHealthSnapshot(payload = {}) {
  const hasMultiResults = Array.isArray(payload?.fofa_results);
  const results = (hasMultiResults ? payload.fofa_results : [])
    .map((item) => normalizedHealthResult(item))
    .filter((item) => item?.name);
  const legacyResult = normalizedHealthResult(payload?.fofa_result, "FOFA");
  if (!hasMultiResults && legacyResult) results.push(legacyResult);
  return {
    keys: fofaKeyList(payload).map((item) => ({ ...item })),
    results,
    legacy: !hasMultiResults && Boolean(legacyResult),
  };
}

export function fofaKeyStatus(item = {}) {
  if (item.enabled === false) {
    return { code: "manual_disabled", label: "手动停用", tone: "muted" };
  }
  const state = String(item.runtime_state || "ready");
  return STATUS_META[state] || { code: state, label: "状态未知", tone: "muted" };
}

export function categoryLabel(category) {
  const value = String(category || "");
  return CATEGORY_LABELS[value] || value || "未知";
}

export function endpointModeLabel(mode) {
  const value = String(mode || "");
  return ENDPOINT_MODE_LABELS[value] || value || "自动识别";
}

export function cooldownLabel(value, now = Date.now()) {
  if (!value) return "";
  const until = Date.parse(value);
  if (!Number.isFinite(until)) return "";
  const seconds = Math.ceil((until - Number(now)) / 1000);
  if (seconds <= 0) return "冷却已结束";
  if (seconds < 60) return `${seconds} 秒后恢复`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟后恢复`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes ? `${hours} 小时 ${remainingMinutes} 分钟后恢复` : `${hours} 小时后恢复`;
}

export const formatFofaCooldown = cooldownLabel;

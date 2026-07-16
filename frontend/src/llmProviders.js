function normalizedWeight(provider) {
  const weight = Number(provider?.weight);
  return Number.isFinite(weight) && weight > 0 ? weight : 0;
}

function normalizedBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

export function canReuseSavedProviderKey(savedBaseUrl, draftBaseUrl) {
  const saved = normalizedBaseUrl(savedBaseUrl);
  return Boolean(saved) && saved === normalizedBaseUrl(draftBaseUrl);
}

export function isProviderUsable(provider) {
  return provider?.enabled === true && provider?.api_key_set === true;
}

export function isLegacyProvider(provider) {
  return provider?.read_only === true || provider?.source === "legacy";
}

export function providerList(response) {
  if (Array.isArray(response)) return response;
  if (Array.isArray(response?.providers)) return response.providers;
  return [];
}

export function needsEffectiveProviderReload(response) {
  return providerList(response).length === 0;
}

export function weightDistribution(providers = []) {
  const enabled = providers.filter(isProviderUsable);
  const total = enabled.reduce((sum, provider) => sum + normalizedWeight(provider), 0);

  return enabled.map((provider) => ({
    ...provider,
    percentage: total > 0 ? (normalizedWeight(provider) / total) * 100 : 0,
  }));
}

export function moveProvider(names, index, delta) {
  const ordered = [...names];
  const destination = index + delta;
  if (index < 0 || index >= ordered.length || destination < 0 || destination >= ordered.length) {
    return ordered;
  }

  const [name] = ordered.splice(index, 1);
  ordered.splice(destination, 0, name);
  return ordered;
}

export function modelProbePayload({ baseUrl, apiKey, protocol, providerName } = {}) {
  const payload = {
    base_url: String(baseUrl || "").trim(),
    api_key: String(apiKey || "").trim(),
    protocol: protocol || "openai_chat",
  };
  const name = String(providerName || "").trim();
  if (name) payload.provider_name = name;
  return payload;
}

function normalizedHealthResult(value, fallbackName = "") {
  if (!value || typeof value !== "object") return null;
  const latency = Number(value.latency_ms);
  return {
    ...value,
    name: String(value.name || fallbackName).trim() || fallbackName,
    ok: value.ok === true,
    latency_ms: Number.isFinite(latency) && latency >= 0 ? latency : 0,
    error: String(value.error || ""),
    enabled: value.enabled !== false,
    auto_disabled: value.auto_disabled === true,
    stale: value.stale === true,
  };
}

export function providerHealthSnapshot(payload = {}) {
  const results = (Array.isArray(payload?.provider_results) ? payload.provider_results : [])
    .map((item) => normalizedHealthResult(item))
    .filter((item) => item?.name);
  const providers = (Array.isArray(payload?.providers) ? payload.providers : [])
    .map((provider) => ({ ...provider }));
  return { providers, results };
}

export function summarizeHealthCheck(payload = {}) {
  const providerResults = providerHealthSnapshot(payload).results;
  const hasFofaPool = Array.isArray(payload?.fofa_results);
  const fofaResults = (hasFofaPool ? payload.fofa_results : [])
    .map((item) => normalizedHealthResult(item))
    .filter((item) => item?.name);
  const fofaResult = hasFofaPool ? null : normalizedHealthResult(payload?.fofa_result, "FOFA");
  const results = fofaResult ? [...providerResults, fofaResult] : [...providerResults, ...fofaResults];
  return {
    checkedAt: String(payload?.checked_at || ""),
    total: results.length,
    passed: results.filter((item) => item.ok).length,
    failed: results.filter((item) => !item.ok).length,
    autoDisabled: results.filter((item) => item.auto_disabled).length,
    autoBlocked: fofaResults.filter((item) => item.auto_blocked).length,
    stale: payload?.stale === true || results.some((item) => item.stale),
    results,
  };
}

export function markHealthCheckStale(payload) {
  if (!payload || typeof payload !== "object") return null;
  return { ...payload, stale: true };
}

export const LITELLM_DEFAULT_CHECKS = Object.freeze({
  key_leak: true,
  env_leak: true,
  management_exposure: true,
  anonymous_models: true,
  anonymous_inference: true,
});

const DEFAULT_VALIDATION = Object.freeze({
  level: "full",
  max_tokens: 1,
  max_provider_validations_per_cycle: 20,
  max_requests_per_asset_epoch: 24,
});

const DEFAULT_RECHECK = Object.freeze({
  confirmed_seconds: 21_600,
  protected_seconds: 86_400,
  unreachable_seconds: 3_600,
});

const lines = (value) => {
  const values = Array.isArray(value) ? value : String(value || "").split("\n");
  return [...new Set(values.map((item) => String(item || "").trim()).filter(Boolean))];
};

const integer = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const hoursToSeconds = (value, fallback) => {
  const hours = Number(value);
  return Number.isFinite(hours) ? Math.round(hours * 3600) : fallback;
};

export function buildLiteLlmTaskPayload(form = {}) {
  const scopeMode = form.scopeMode || form.scope_mode || "targeted";
  const targetSource = form.target_source || (scopeMode === "global" ? "fofa" : "manual");
  return {
    ...(form.name ? { name: String(form.name) } : {}),
    src_type: "litellm",
    target_source: targetSource,
    vuln_types: [],
    manual_targets: lines(form.manual_targets),
    mode_config: {
      scope_mode: scopeMode,
      scope_anchors: lines(form.scopeAnchors ?? form.scope_anchors),
      enabled_profiles: ["litellm"],
      profile_versions: { litellm: "1" },
      checks: {
        ...LITELLM_DEFAULT_CHECKS,
        ...(form.checks || {}),
      },
      validation: {
        level: form.validationLevel || form.validation_level || DEFAULT_VALIDATION.level,
        max_tokens: integer(form.maxTokens ?? form.max_tokens, DEFAULT_VALIDATION.max_tokens),
        max_provider_validations_per_cycle: integer(
          form.maxProviderValidationsPerCycle ?? form.max_provider_validations_per_cycle,
          DEFAULT_VALIDATION.max_provider_validations_per_cycle,
        ),
        max_requests_per_asset_epoch: integer(
          form.maxRequestsPerAssetEpoch ?? form.max_requests_per_asset_epoch,
          DEFAULT_VALIDATION.max_requests_per_asset_epoch,
        ),
      },
      recheck_intervals: {
        confirmed_seconds: hoursToSeconds(
          form.confirmedRecheckHours,
          DEFAULT_RECHECK.confirmed_seconds,
        ),
        protected_seconds: hoursToSeconds(
          form.protectedRecheckHours,
          DEFAULT_RECHECK.protected_seconds,
        ),
        unreachable_seconds: hoursToSeconds(
          form.unreachableRecheckHours,
          DEFAULT_RECHECK.unreachable_seconds,
        ),
      },
      collection_state: form.collectionState || {},
    },
  };
}

export function validateLiteLlmForm(form = {}) {
  const payload = buildLiteLlmTaskPayload(form);
  const errors = [];
  const mode = payload.mode_config;
  if (mode.scope_mode === "global" && !["fofa", "both"].includes(payload.target_source)) {
    errors.push("全网巡检需要启用自动搜索来源");
  }
  if (
    mode.scope_mode === "targeted"
    && mode.scope_anchors.length === 0
    && payload.manual_targets.length === 0
  ) {
    errors.push("定向巡检至少需要一个范围锚点或手动目标");
  }
  if (!Object.values(mode.checks).some(Boolean)) {
    errors.push("至少启用一个专项检测项");
  }
  const validation = mode.validation;
  if (validation.max_tokens < 1 || validation.max_tokens > 8) {
    errors.push("最小推理 Token 上限需在 1 到 8 之间");
  }
  if (validation.max_requests_per_asset_epoch < 1 || validation.max_requests_per_asset_epoch > 10_000) {
    errors.push("单资产请求预算需在 1 到 10000 之间");
  }
  if (
    validation.max_provider_validations_per_cycle < 0
    || validation.max_provider_validations_per_cycle > 10_000
  ) {
    errors.push("每轮凭据验证上限需在 0 到 10000 之间");
  }
  for (const seconds of Object.values(mode.recheck_intervals)) {
    if (seconds < 0 || seconds > 2_592_000) {
      errors.push("复查周期需在 0 到 720 小时之间");
      break;
    }
  }
  return { valid: errors.length === 0, errors, payload };
}

export function litellmFormFromTask(task = {}) {
  const config = task.mode_config || task.mode_config_json || {};
  const validation = config.validation || {};
  const recheck = config.recheck_intervals || {};
  return {
    scopeMode: config.scope_mode || "targeted",
    scopeAnchors: lines(config.scope_anchors).join("\n"),
    checks: { ...LITELLM_DEFAULT_CHECKS, ...(config.checks || {}) },
    validationLevel: validation.level || DEFAULT_VALIDATION.level,
    maxTokens: integer(validation.max_tokens, DEFAULT_VALIDATION.max_tokens),
    maxProviderValidationsPerCycle: integer(
      validation.max_provider_validations_per_cycle,
      DEFAULT_VALIDATION.max_provider_validations_per_cycle,
    ),
    maxRequestsPerAssetEpoch: integer(
      validation.max_requests_per_asset_epoch,
      DEFAULT_VALIDATION.max_requests_per_asset_epoch,
    ),
    confirmedRecheckHours: (recheck.confirmed_seconds ?? DEFAULT_RECHECK.confirmed_seconds) / 3600,
    protectedRecheckHours: (recheck.protected_seconds ?? DEFAULT_RECHECK.protected_seconds) / 3600,
    unreachableRecheckHours: (recheck.unreachable_seconds ?? DEFAULT_RECHECK.unreachable_seconds) / 3600,
    collectionState: { ...(config.collection_state || {}) },
  };
}

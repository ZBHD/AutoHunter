export function isAutoSource(source) {
  return source === "fofa" || source === "both";
}

export function isManualOnly(source) {
  return source === "manual";
}

export function isSiteSource(source) {
  return source === "site";
}

export function isFofaPoolMode(source, engine) {
  if (!isAutoSource(source)) return false;
  const normalizedEngine = String(engine || "").trim().toLowerCase();
  return !normalizedEngine || normalizedEngine === "fofa";
}

export function fofaKeyPatch({
  initialMode = "global",
  finalMode = "global",
  finalIsFofa = true,
  key = "",
} = {}) {
  const hadTaskOverride = initialMode === "task";
  const finalTaskMode = finalIsFofa && finalMode === "task";
  const normalizedKey = String(key || "").trim();

  if (finalTaskMode && normalizedKey) return { key: normalizedKey };
  if (hadTaskOverride && !finalTaskMode) return { key: null };
  // A global task with no existing override is always a no-op.
  return {};
}

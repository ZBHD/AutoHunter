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

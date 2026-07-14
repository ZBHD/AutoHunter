export function buildListQuery(params = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const entry of value) search.append(key, String(entry));
    } else {
      search.set(key, String(value));
    }
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

export function normalizePage(payload, defaults = {}) {
  const wrapped = payload && !Array.isArray(payload) ? payload : {};
  const items = Array.isArray(payload)
    ? payload
    : Array.isArray(wrapped.items) ? wrapped.items : [];
  const limit = Number.isFinite(Number(wrapped.limit))
    ? Number(wrapped.limit)
    : Number(defaults.limit ?? items.length);
  const offset = Number.isFinite(Number(wrapped.offset))
    ? Number(wrapped.offset)
    : Number(defaults.offset ?? 0);
  const total = Number.isFinite(Number(wrapped.total))
    ? Number(wrapped.total)
    : items.length;
  const hasMore = typeof wrapped.has_more === "boolean"
    ? wrapped.has_more
    : offset + items.length < total;

  return { items, total, limit, offset, hasMore };
}

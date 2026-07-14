export function queueOrderIds(items = []) {
  return items.map((item) => item.id);
}

export function moveQueueTarget(items = [], fromIndex, toIndex) {
  const next = [...items];
  if (
    fromIndex < 0 || fromIndex >= next.length
    || toIndex < 0 || toIndex >= next.length
    || fromIndex === toIndex
  ) return next;
  const [moved] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, moved);
  return next;
}

function fieldValue(item, field) {
  if (field === "priority") return Number(item.priority_score || 0);
  if (field === "created") return Date.parse(item.created_at || "") || 0;
  if (field === "url") return String(item.url || item.host || "").toLowerCase();
  return 0;
}

export function sortQueueTargets(items = [], field = "manual", direction = "desc") {
  if (field === "manual") return [...items];
  const sign = direction === "asc" ? 1 : -1;
  return items
    .map((item, index) => ({ item, index }))
    .sort((left, right) => {
      const a = fieldValue(left.item, field);
      const b = fieldValue(right.item, field);
      const compared = typeof a === "string" ? a.localeCompare(b, "zh-CN") : a - b;
      return compared ? compared * sign : left.index - right.index;
    })
    .map(({ item }) => item);
}

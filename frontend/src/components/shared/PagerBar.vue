<script setup>
import { computed } from "vue";

const props = defineProps({
  total: { type: Number, default: 0 },
  limit: { type: Number, default: 50 },
  offset: { type: Number, default: 0 },
  count: { type: Number, default: 0 },
  loading: { type: Boolean, default: false },
});
const emit = defineEmits(["change"]);

const page = computed(() => Math.floor(props.offset / Math.max(1, props.limit)) + 1);
const pages = computed(() => Math.max(1, Math.ceil(props.total / Math.max(1, props.limit))));
const start = computed(() => props.total ? props.offset + 1 : 0);
const end = computed(() => Math.min(props.total, props.offset + props.count));

function move(delta) {
  const next = Math.max(0, props.offset + delta * props.limit);
  if (next === props.offset || next >= props.total) return;
  emit("change", next);
}
</script>

<template>
  <nav class="operations-pager" aria-label="分页">
    <button type="button" title="上一页" aria-label="上一页"
      :disabled="loading || offset <= 0" @click="move(-1)">‹</button>
    <span>第 {{ page }} / {{ pages }} 页</span>
    <small>{{ start }}-{{ end }} / {{ total }}</small>
    <button type="button" title="下一页" aria-label="下一页"
      :disabled="loading || offset + count >= total" @click="move(1)">›</button>
  </nav>
</template>

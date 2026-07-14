<script setup>
import { computed } from "vue";
import RawEvidenceViewer from "../shared/RawEvidenceViewer.vue";

const props = defineProps({
  caseId: { type: String, required: true },
  events: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
});

const orderedEvents = computed(() => [...props.events].sort((a, b) => {
  const attempt = Number(a.attempt_no || 0) - Number(b.attempt_no || 0);
  if (attempt) return attempt;
  return Number(a.sequence || a.id || 0) - Number(b.sequence || b.id || 0);
}));

function payloadText(payload) {
  if (!payload || (typeof payload === "object" && !Object.keys(payload).length)) return "";
  if (typeof payload === "string") return payload;
  try { return JSON.stringify(payload, null, 2); }
  catch { return String(payload); }
}

function fmtTime(value) {
  return value ? String(value).slice(0, 19).replace("T", " ") : "-";
}
</script>

<template>
  <div class="killsweep-timeline">
    <div v-if="loading" class="operations-empty compact">正在读取时间线…</div>
    <div v-else-if="!orderedEvents.length" class="operations-empty compact">暂无分析时间线</div>
    <article v-for="event in orderedEvents" :key="event.id" class="timeline-event" :class="event.level || 'info'">
      <span class="timeline-marker" aria-hidden="true"></span>
      <div class="timeline-body">
        <header>
          <div>
            <span class="event-kind">{{ event.kind || "event" }}</span>
            <b>{{ event.summary || "分析事件" }}</b>
          </div>
          <time>{{ fmtTime(event.created_at) }}</time>
        </header>
        <details v-if="payloadText(event.payload)" class="event-payload">
          <summary>事件详情</summary>
          <pre>{{ payloadText(event.payload) }}</pre>
        </details>
        <RawEvidenceViewer v-if="event.evidence?.length" context="killsweep"
          :case-id="caseId" :event-id="event.id" :evidence="event.evidence" />
      </div>
    </article>
  </div>
</template>

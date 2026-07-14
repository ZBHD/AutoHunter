<script setup>
import { reactive } from "vue";
import { api } from "../../api.js";

const props = defineProps({
  signalId: { type: String, default: "" },
  caseId: { type: String, default: "" },
  eventId: { type: [String, Number], default: "" },
  context: { type: String, default: "missed" },
  evidence: { type: Array, default: () => [] },
});

const channelState = reactive({});

function stateKey(evidenceId, channel) {
  return `${evidenceId}:${channel}`;
}

function channelsOf(item) {
  const channels = item?.channels;
  if (Array.isArray(channels)) {
    return channels.map((entry) => typeof entry === "string" ? { name: entry } : entry);
  }
  if (channels && typeof channels === "object") {
    return Object.entries(channels).map(([name, metadata]) => ({ name, ...(metadata || {}) }));
  }
  return Object.keys(item?.preview || {}).map((name) => ({ name }));
}

function previewOf(item, channel) {
  const value = item?.preview?.[channel];
  if (typeof value === "string") return value;
  if (value == null) return "";
  try { return JSON.stringify(value, null, 2); }
  catch { return String(value); }
}

function bytesLabel(value) {
  const size = Number(value || 0);
  if (!size) return "";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

async function loadChannel(item, channel) {
  const key = stateKey(item.id, channel.name);
  const existing = channelState[key];
  if (existing?.open) {
    channelState[key] = { ...existing, open: false };
    return;
  }
  if (existing?.content !== undefined) {
    channelState[key] = { ...existing, open: true };
    return;
  }

  channelState[key] = { loading: true, open: true, content: undefined, error: "" };
  try {
    const content = props.context === "killsweep"
      ? await api.killsweepEvidenceContent(props.caseId, props.eventId, item.id, channel.name)
      : await api.missedSignalEvidenceContent(props.signalId, item.id, channel.name);
    channelState[key] = { loading: false, open: true, content: String(content ?? ""), error: "" };
  } catch (error) {
    channelState[key] = {
      loading: false,
      open: true,
      content: undefined,
      error: String(error?.message || error),
    };
  }
}
</script>

<template>
  <div class="raw-evidence-list">
    <div v-if="!evidence.length" class="operations-empty compact">暂无原始证据</div>
    <article v-for="item in evidence" :key="item.id" class="raw-evidence-item">
      <header>
        <div>
          <b>{{ item.source_kind || "原始证据" }}</b>
          <span class="status-chip" :class="item.capture_status">{{ item.capture_status || "complete" }}</span>
        </div>
        <time>{{ item.occurred_at ? String(item.occurred_at).slice(0, 19).replace("T", " ") : "" }}</time>
      </header>
      <div v-if="channelsOf(item).length" class="raw-channel-list">
        <section v-for="channel in channelsOf(item)" :key="channel.name" class="raw-channel">
          <div class="raw-channel-head">
            <span><b>{{ channel.name }}</b><small>{{ bytesLabel(channel.size) }}</small></span>
            <button type="button" class="compact-action" :disabled="channelState[stateKey(item.id, channel.name)]?.loading"
              @click="loadChannel(item, channel)">
              {{ channelState[stateKey(item.id, channel.name)]?.loading ? "加载中…"
                : channelState[stateKey(item.id, channel.name)]?.open ? "收起原值" : "加载原值" }}
            </button>
          </div>
          <pre v-if="previewOf(item, channel.name)" class="evidence-preview">{{ previewOf(item, channel.name) }}</pre>
          <div v-if="channelState[stateKey(item.id, channel.name)]?.open" class="raw-channel-content">
            <p v-if="channelState[stateKey(item.id, channel.name)]?.error" class="operations-error">
              {{ channelState[stateKey(item.id, channel.name)].error }}
            </p>
            <pre v-else-if="channelState[stateKey(item.id, channel.name)]?.content !== undefined">{{ channelState[stateKey(item.id, channel.name)].content || "（空内容）" }}</pre>
          </div>
        </section>
      </div>
    </article>
  </div>
</template>

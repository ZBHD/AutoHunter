<script setup>
import { ref, watch } from "vue";
import { api } from "../../api.js";
import { copyText } from "../../clipboard.js";
import { normalizePage } from "../../listQuery.js";

const props = defineProps({
  taskId: { type: String, required: true },
  active: { type: Boolean, default: false },
  readonly: { type: Boolean, default: false },
});
const emit = defineEmits(["toast"]);
const PAGE_SIZE = 50;
const rows = ref([]);
const total = ref(0);
const offset = ref(0);
const searchDraft = ref("");
const search = ref("");
const status = ref("");
const loading = ref(false);
const exporting = ref(false);
const workingId = ref("");
const error = ref("");

async function load(reset = false) {
  if (!props.active || !props.taskId) return;
  if (reset) offset.value = 0;
  loading.value = true;
  error.value = "";
  try {
    const page = normalizePage(await api.gatewaySecrets(props.taskId, {
      q: search.value,
      status: status.value,
      limit: PAGE_SIZE,
      offset: offset.value,
    }), { limit: PAGE_SIZE, offset: offset.value });
    rows.value = page.items;
    total.value = page.total;
  } catch (cause) {
    error.value = String(cause?.message || cause || "Secret 加载失败").replace(/^\d+\s*/, "");
  } finally {
    loading.value = false;
  }
}

async function applyFilters() {
  search.value = searchDraft.value.trim();
  await load(true);
}

async function copySecret(secret) {
  await copyText(secret.secret_value);
  emit("toast", `已复制 ${secret.secret_name}`);
}

async function revalidate(secret) {
  if (props.readonly || workingId.value) return;
  workingId.value = secret.id;
  try {
    await api.revalidateGatewaySecret(secret.id);
    await load();
  } catch (cause) {
    error.value = String(cause?.message || cause || "重新验证失败").replace(/^\d+\s*/, "");
  } finally {
    workingId.value = "";
  }
}

async function exportSecrets(format) {
  exporting.value = true;
  error.value = "";
  try {
    const payload = await api.gatewaySecretExport(props.taskId, format);
    const content = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
    const blob = new Blob([content], { type: format === "csv" ? "text/csv;charset=utf-8" : "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `litellm-secrets-${props.taskId}.${format}`;
    anchor.click();
    URL.revokeObjectURL(href);
  } catch (cause) {
    error.value = String(cause?.message || cause || "Secret 导出失败").replace(/^\d+\s*/, "");
  } finally {
    exporting.value = false;
  }
}

async function changePage(delta) {
  const next = Math.max(0, offset.value + delta * PAGE_SIZE);
  if (next === offset.value || next >= total.value) return;
  offset.value = next;
  await load();
}

watch(() => [props.active, props.taskId], ([active]) => {
  if (active) load(true);
}, { immediate: true });
</script>

<template>
  <section class="gateway-panel" aria-labelledby="gateway-secrets-title">
    <header class="gateway-panel-head">
      <div><h3 id="gateway-secrets-title">Gateway Secrets</h3><p>显示证据中提取的原值与确定性验证状态</p></div>
      <span>{{ total }} 条</span>
    </header>
    <form class="gateway-toolbar" @submit.prevent="applyFilters">
      <input v-model="searchDraft" aria-label="搜索 Secret" placeholder="搜索变量名、Provider、类型或来源 URL" />
      <select v-model="status" aria-label="Secret 状态" @change="applyFilters">
        <option value="">全部状态</option><option value="pending">待验证</option><option value="valid">有效</option>
        <option value="invalid">无效</option><option value="expired">已过期</option><option value="unknown">未知</option>
      </select>
      <button type="submit">搜索</button>
      <button type="button" :disabled="exporting" @click="exportSecrets('json')">导出 JSON</button>
      <button type="button" :disabled="exporting" @click="exportSecrets('csv')">导出 CSV</button>
    </form>
    <p v-if="error" class="operation-error" role="alert">{{ error }}</p>
    <div v-if="loading" class="operations-empty">正在加载 Secret...</div>
    <div v-else-if="!rows.length" class="operations-empty">没有符合条件的 Secret</div>
    <div v-else class="gateway-secret-list">
      <article v-for="secret in rows" :key="secret.id" class="gateway-secret-row">
        <div class="gateway-secret-head">
          <div><b>{{ secret.secret_name }}</b><small>{{ secret.provider }} · {{ secret.secret_type }}</small></div>
          <span class="status-chip" :class="secret.validation_status">{{ secret.validation_status }}</span>
        </div>
        <code>{{ secret.secret_value }}</code>
        <p>{{ secret.source_url }}<span v-if="secret.source_location"> · {{ secret.source_location }}</span></p>
        <div class="gateway-row-actions">
          <button type="button" @click="copySecret(secret)">复制原值</button>
          <button type="button" :disabled="readonly || workingId === secret.id" @click="revalidate(secret)">{{ workingId === secret.id ? "入队中" : "重新验证" }}</button>
        </div>
      </article>
    </div>
    <footer class="operations-pager">
      <button type="button" :disabled="offset === 0 || loading" @click="changePage(-1)">上一页</button>
      <span>{{ total ? `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)} / ${total}` : "0 / 0" }}</span>
      <span></span>
      <button type="button" :disabled="offset + PAGE_SIZE >= total || loading" @click="changePage(1)">下一页</button>
    </footer>
  </section>
</template>

<script setup>
import { ref, watch } from "vue";
import { api } from "../../api.js";
import { normalizePage } from "../../listQuery.js";

const props = defineProps({ taskId: { type: String, required: true }, active: { type: Boolean, default: false } });
const PAGE_SIZE = 50;
const assets = ref([]);
const assetId = ref("");
const rows = ref([]);
const total = ref(0);
const offset = ref(0);
const loading = ref(false);
const error = ref("");

async function loadAssets() {
  const page = normalizePage(await api.gatewayAssets(props.taskId, { limit: 200, offset: 0 }), { limit: 200 });
  assets.value = page.items;
  if (!assets.value.some((asset) => asset.id === assetId.value)) assetId.value = assets.value[0]?.id || "";
}

async function load(reset = false) {
  if (!props.active || !props.taskId) return;
  if (reset) offset.value = 0;
  loading.value = true;
  error.value = "";
  try {
    if (!assets.value.length) await loadAssets();
    if (!assetId.value) {
      rows.value = [];
      total.value = 0;
      return;
    }
    const page = normalizePage(await api.gatewayObservations(assetId.value, {
      limit: PAGE_SIZE,
      offset: offset.value,
    }), { limit: PAGE_SIZE, offset: offset.value });
    rows.value = page.items;
    total.value = page.total;
  } catch (cause) {
    error.value = String(cause?.message || cause || "探测记录加载失败").replace(/^\d+\s*/, "");
  } finally {
    loading.value = false;
  }
}

async function selectAsset() {
  await load(true);
}

async function changePage(delta) {
  const next = Math.max(0, offset.value + delta * PAGE_SIZE);
  if (next === offset.value || next >= total.value) return;
  offset.value = next;
  await load();
}

watch(() => [props.active, props.taskId], ([active]) => {
  assets.value = [];
  assetId.value = "";
  if (active) load(true);
}, { immediate: true });
</script>

<template>
  <section class="gateway-panel" aria-labelledby="gateway-observations-title">
    <header class="gateway-panel-head">
      <div><h3 id="gateway-observations-title">探测记录</h3><p>按扫描轮次查看 Profile 路由与鉴权变体结论</p></div>
      <span>{{ total }} 条</span>
    </header>
    <div class="gateway-toolbar">
      <select v-model="assetId" aria-label="选择网关资产" @change="selectAsset">
        <option value="" disabled>选择网关资产</option>
        <option v-for="asset in assets" :key="asset.id" :value="asset.id">{{ asset.url }}</option>
      </select>
      <button type="button" :disabled="loading" @click="load()">刷新</button>
    </div>
    <p v-if="error" class="operation-error" role="alert">{{ error }}</p>
    <div v-if="loading" class="operations-empty">正在加载探测记录...</div>
    <div v-else-if="!assetId" class="operations-empty">当前任务还没有网关资产</div>
    <div v-else-if="!rows.length" class="operations-empty">该资产还没有探测记录</div>
    <div v-else class="gateway-table-wrap">
      <table class="gateway-table">
        <thead><tr><th>轮次</th><th>阶段</th><th>Probe</th><th>鉴权变体</th><th>HTTP</th><th>结论</th><th>时间</th></tr></thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id">
            <td>{{ row.scan_epoch }}</td><td>{{ row.stage }}</td><td><code>{{ row.probe_id }}</code></td>
            <td>{{ row.auth_variant }}</td><td>{{ row.status_code }}<small>{{ row.content_type }}</small></td>
            <td><span class="status-chip" :class="row.result">{{ row.result }}</span></td>
            <td>{{ row.observed_at?.slice(0, 19).replace("T", " ") || "-" }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <footer class="operations-pager">
      <button type="button" :disabled="offset === 0 || loading" @click="changePage(-1)">上一页</button>
      <span>{{ total ? `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)} / ${total}` : "0 / 0" }}</span>
      <span></span>
      <button type="button" :disabled="offset + PAGE_SIZE >= total || loading" @click="changePage(1)">下一页</button>
    </footer>
  </section>
</template>

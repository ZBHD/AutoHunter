<script setup>
import { ref, watch } from "vue";
import { api } from "../../api.js";
import { normalizePage } from "../../listQuery.js";

const props = defineProps({
  taskId: { type: String, required: true },
  active: { type: Boolean, default: false },
  readonly: { type: Boolean, default: false },
});

const PAGE_SIZE = 50;
const summary = ref({});
const rows = ref([]);
const total = ref(0);
const offset = ref(0);
const searchDraft = ref("");
const search = ref("");
const loading = ref(false);
const error = ref("");
const workingId = ref("");

async function load(reset = false) {
  if (!props.active || !props.taskId) return;
  if (reset) offset.value = 0;
  loading.value = true;
  error.value = "";
  try {
    const [summaryValue, result] = await Promise.all([
      api.gatewaySummary(props.taskId),
      api.gatewayAssets(props.taskId, { q: search.value, limit: PAGE_SIZE, offset: offset.value }),
    ]);
    const page = normalizePage(result, { limit: PAGE_SIZE, offset: offset.value });
    summary.value = summaryValue || {};
    rows.value = page.items;
    total.value = page.total;
  } catch (cause) {
    error.value = String(cause?.message || cause || "网关资产加载失败").replace(/^\d+\s*/, "");
  } finally {
    loading.value = false;
  }
}

async function applySearch() {
  search.value = searchDraft.value.trim();
  await load(true);
}

async function recheck(asset) {
  if (props.readonly || workingId.value) return;
  workingId.value = asset.id;
  error.value = "";
  try {
    await api.recheckGatewayAsset(asset.id);
    await load();
  } catch (cause) {
    error.value = String(cause?.message || cause || "复查入队失败").replace(/^\d+\s*/, "");
  } finally {
    workingId.value = "";
  }
}

async function changePage(delta) {
  const next = Math.max(0, offset.value + delta * PAGE_SIZE);
  if (next === offset.value || next >= total.value) return;
  offset.value = next;
  await load();
}

function time(value) {
  return value ? String(value).slice(0, 19).replace("T", " ") : "-";
}

watch(() => [props.active, props.taskId], ([active]) => {
  if (active) load(true);
}, { immediate: true });
</script>

<template>
  <section class="gateway-panel" aria-labelledby="gateway-assets-title">
    <header class="gateway-panel-head">
      <div><h3 id="gateway-assets-title">LiteLLM 网关资产</h3><p>按挂载路径独立跟踪指纹、鉴权状态和复查周期</p></div>
      <span>{{ total }} 个资产</span>
    </header>
    <div class="gateway-summary-grid">
      <div><span>已确认</span><b>{{ summary.confirmed_asset_count || 0 }}</b></div>
      <div><span>Secret</span><b>{{ summary.secret_count || 0 }}</b></div>
      <div><span>有效 Secret</span><b>{{ summary.valid_secret_count || 0 }}</b></div>
      <div><span>匿名推理</span><b>{{ summary.anonymous_inference_count || 0 }}</b></div>
    </div>
    <form class="gateway-toolbar" @submit.prevent="applySearch">
      <input v-model="searchDraft" aria-label="搜索网关资产" placeholder="搜索 URL、Profile 或鉴权状态" />
      <button type="submit">搜索</button>
      <button v-if="search" type="button" @click="searchDraft = ''; applySearch()">清空</button>
    </form>
    <p v-if="error" class="operation-error" role="alert">{{ error }}</p>
    <div v-if="loading" class="operations-empty">正在加载网关资产...</div>
    <div v-else-if="!rows.length" class="operations-empty">没有符合条件的网关资产</div>
    <div v-else class="gateway-table-wrap">
      <table class="gateway-table">
        <thead><tr><th>网关</th><th>指纹</th><th>鉴权</th><th>模型</th><th>扫描状态</th><th>下次复查</th><th></th></tr></thead>
        <tbody>
          <tr v-for="asset in rows" :key="asset.id">
            <td><b>{{ asset.url }}</b><small>{{ asset.profile_id }} v{{ asset.profile_version }}</small></td>
            <td><span class="status-chip" :class="asset.fingerprint_status">{{ asset.fingerprint_status }}</span></td>
            <td>{{ asset.auth_state || "unknown" }}</td>
            <td>{{ asset.model_count || 0 }} <small>{{ asset.model_names?.slice(0, 2).join(", ") }}</small></td>
            <td>{{ asset.scan_state }}<small>epoch {{ asset.scan_epoch }}</small></td>
            <td>{{ time(asset.next_scan_at) }}</td>
            <td><button type="button" :disabled="readonly || workingId === asset.id" @click="recheck(asset)">{{ workingId === asset.id ? "入队中" : "立即复查" }}</button></td>
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

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, canWrite } from "../api.js";
import { normalizePage } from "../listQuery.js";
import {
  MISSED_SIGNAL_PAGE_SIZE,
  missedSignalListParams,
  missedSignalPresentation,
  missedSignalSourceLabel,
} from "../missedSignals.js";
import MissedSignalDraftEditor from "../components/missed-signals/MissedSignalDraftEditor.vue";
import PagerBar from "../components/shared/PagerBar.vue";
import RawEvidenceViewer from "../components/shared/RawEvidenceViewer.vue";

const router = useRouter();
const FILTERS = [
  { key: "pending", label: "待复核" },
  { key: "deepening", label: "深挖中" },
  { key: "converted", label: "已转报告" },
  { key: "rejected", label: "已驳回" },
  { key: "all", label: "全部" },
];

const stats = ref({ total: 0, pending: 0, deepening: 0, converted: 0, rejected: 0 });
const rows = ref([]);
const total = ref(0);
const page = ref(0);
const status = ref("pending");
const searchDraft = ref("");
const searchText = ref("");
const loading = ref(true);
const refreshing = ref(false);
const error = ref("");
const selectedId = ref("");
const selectedDetail = ref(null);
const detailLoading = ref(false);
const actionMode = ref("");
const actionText = ref("");
const actionBusy = ref(false);
const toastMsg = ref("");
let searchTimer = null;
let toastTimer = null;
let listVersion = 0;
let detailVersion = 0;

const writable = computed(() => canWrite());
const offset = computed(() => page.value * MISSED_SIGNAL_PAGE_SIZE);
const selected = computed(() => selectedDetail.value);

function toast(message) {
  toastMsg.value = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastMsg.value = ""; }, 2600);
}

function statCount(key) {
  return key === "all" ? Number(stats.value.total || 0) : Number(stats.value[key] || 0);
}

function fmtTime(value) {
  return value ? String(value).slice(0, 19).replace("T", " ") : "-";
}

function riskLabel(item) {
  const labels = { critical: "严重", high: "高风险", medium: "中风险", low: "低风险" };
  return labels[item?.risk_level] || item?.risk_level || "待评级";
}

function sourceLabels(item) {
  return (item?.source_types || []).map(missedSignalSourceLabel).join(" · ") || "未知来源";
}

function dispatchPendingCount() {
  window.dispatchEvent(new CustomEvent("autohunter-operation-counts", {
    detail: { missedPending: Number(stats.value.pending || 0) },
  }));
}

async function loadStats() {
  try {
    stats.value = { ...stats.value, ...(await api.missedSignalStats()) };
    dispatchPendingCount();
  } catch {
    // A list error is shown separately; keep the last valid counters.
  }
}

async function selectSignal(item) {
  const id = typeof item === "string" ? item : item?.id;
  if (!id) {
    selectedId.value = "";
    selectedDetail.value = null;
    return;
  }
  selectedId.value = id;
  actionMode.value = "";
  actionText.value = "";
  const version = ++detailVersion;
  detailLoading.value = true;
  try {
    const detail = await api.missedSignal(id);
    if (version !== detailVersion) return;
    if (!Array.isArray(detail.evidence)) {
      try { detail.evidence = await api.missedSignalEvidence(id); }
      catch { detail.evidence = []; }
    }
    selectedDetail.value = detail;
  } catch (detailError) {
    if (version === detailVersion) {
      selectedDetail.value = null;
      error.value = String(detailError?.message || detailError);
    }
  } finally {
    if (version === detailVersion) detailLoading.value = false;
  }
}

async function loadList() {
  const version = ++listVersion;
  const hadRows = rows.value.length > 0;
  if (!hadRows) loading.value = true;
  else refreshing.value = true;
  error.value = "";
  try {
    const payload = await api.missedSignals(missedSignalListParams({
      status: status.value,
      q: searchText.value,
      page: page.value,
    }));
    if (version !== listVersion) return;
    const normalized = normalizePage(payload, { limit: MISSED_SIGNAL_PAGE_SIZE, offset: offset.value });
    rows.value = normalized.items;
    total.value = normalized.total;
    const current = rows.value.find((item) => item.id === selectedId.value);
    if (current) await selectSignal(current);
    else if (rows.value.length) await selectSignal(rows.value[0]);
    else await selectSignal(null);
  } catch (listError) {
    if (version === listVersion) error.value = String(listError?.message || listError);
  } finally {
    if (version === listVersion) {
      loading.value = false;
      refreshing.value = false;
    }
  }
}

async function refresh() {
  refreshing.value = true;
  await Promise.all([loadStats(), loadList()]);
  refreshing.value = false;
}

function chooseStatus(next) {
  if (status.value === next) return;
  status.value = next;
}

function changePage(nextOffset) {
  page.value = Math.floor(nextOffset / MISSED_SIGNAL_PAGE_SIZE);
  loadList();
}

function openAction(mode) {
  actionMode.value = mode;
  actionText.value = "";
}

async function afterAction(message) {
  actionMode.value = "";
  actionText.value = "";
  toast(message);
  await Promise.all([loadStats(), loadList()]);
}

async function submitDeepen() {
  const directive = actionText.value.trim();
  if (!directive) return;
  actionBusy.value = true;
  try {
    await api.deepenMissedSignal(selectedId.value, { directive });
    await afterAction("定向深挖已排入原任务队列");
  } catch (actionError) {
    error.value = String(actionError?.message || actionError);
  } finally {
    actionBusy.value = false;
  }
}

async function submitReject() {
  const reason = actionText.value.trim();
  if (!reason) return;
  actionBusy.value = true;
  try {
    await api.rejectMissedSignal(selectedId.value, reason);
    await afterAction("疑似记录已驳回");
  } catch (actionError) {
    error.value = String(actionError?.message || actionError);
  } finally {
    actionBusy.value = false;
  }
}

async function restoreSignal() {
  actionBusy.value = true;
  try {
    await api.restoreMissedSignal(selectedId.value);
    await afterAction("疑似记录已恢复到待复核");
  } catch (actionError) {
    error.value = String(actionError?.message || actionError);
  } finally {
    actionBusy.value = false;
  }
}

function openTask(item) {
  if (item?.task_id) router.push(`/task/${item.task_id}`);
}

watch(status, () => {
  page.value = 0;
  loadList();
});
watch(searchDraft, (value) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = value.trim();
    page.value = 0;
    loadList();
  }, 260);
});

onMounted(refresh);
onBeforeUnmount(() => {
  clearTimeout(searchTimer);
  clearTimeout(toastTimer);
});
</script>

<template>
  <section class="view operations-view missed-signals-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>
    <header class="page-head split">
      <div>
        <h2>疑似漏洞池 <span class="intel-chip">SIGNALS</span></h2>
        <p class="page-sub">集中复核尚未形成正式报告的高信号证据，并追踪深挖与转报告历史。</p>
      </div>
      <button type="button" class="head-action" :disabled="refreshing" @click="refresh">
        {{ refreshing ? "刷新中…" : "刷新" }}
      </button>
    </header>

    <div class="operations-stats" aria-label="疑似漏洞统计">
      <button v-for="filter in FILTERS" :key="filter.key" type="button"
        :class="['operation-stat', `tone-${missedSignalPresentation(filter.key).tone}`]"
        :data-active="status === filter.key" @click="chooseStatus(filter.key)">
        <span>{{ filter.label }}</span><b>{{ statCount(filter.key) }}</b>
      </button>
    </div>

    <div class="operations-toolbar">
      <div class="search-box">
        <span aria-hidden="true">⌕</span>
        <input v-model="searchDraft" type="search" aria-label="搜索疑似漏洞"
          placeholder="搜索标题、目标、规则或证据摘要" />
      </div>
      <span class="toolbar-summary">{{ total }} 条 · 每页 {{ MISSED_SIGNAL_PAGE_SIZE }} 条</span>
    </div>

    <p v-if="error" class="operations-error page-error" role="alert">{{ error }}</p>

    <div class="operations-split missed-split">
      <section class="operations-master" aria-label="疑似漏洞列表">
        <div v-if="loading" class="operations-loading">
          <span v-for="n in 7" :key="n" class="operation-row skeleton-hard"></span>
        </div>
        <div v-else-if="!rows.length" class="operations-empty">当前筛选条件下没有疑似记录</div>
        <button v-for="item in rows" v-else :key="item.id" type="button" class="operation-row signal-row"
          :class="{ selected: item.id === selectedId }" @click="selectSignal(item)">
          <span class="row-status status-chip" :class="missedSignalPresentation(item.status).tone">
            {{ missedSignalPresentation(item.status).label }}
          </span>
          <span class="row-content">
            <b>{{ item.title || item.rule_label || "未命名高信号" }}</b>
            <small>{{ item.method || "HTTP" }} · {{ item.endpoint_key || "目标待补充" }}</small>
            <em>{{ item.summary || sourceLabels(item) }}</em>
          </span>
          <span class="row-meta">
            <strong :class="['risk-label', item.risk_level]">{{ riskLabel(item) }}</strong>
            <small>命中 {{ item.hit_count || 1 }} · 证据 {{ item.evidence_count || 0 }}</small>
            <time>{{ fmtTime(item.last_seen_at || item.updated_at) }}</time>
          </span>
        </button>
        <PagerBar :total="total" :limit="MISSED_SIGNAL_PAGE_SIZE" :offset="offset"
          :count="rows.length" :loading="refreshing" @change="changePage" />
      </section>

      <aside class="operations-detail" aria-label="疑似漏洞详情">
        <div v-if="detailLoading" class="operations-empty">正在读取详情…</div>
        <div v-else-if="!selected" class="operations-empty">从左侧选择一条记录查看证据</div>
        <template v-else>
          <header class="detail-head">
            <div>
              <span class="status-chip" :class="missedSignalPresentation(selected.status).tone">
                {{ missedSignalPresentation(selected.status).label }}
              </span>
              <h3>{{ selected.title || selected.rule_label }}</h3>
              <p>{{ selected.method }} {{ selected.endpoint_key }}</p>
            </div>
            <button type="button" class="compact-action" @click="openTask(selected)">进任务</button>
          </header>

          <dl class="detail-facts">
            <div><dt>风险</dt><dd>{{ riskLabel(selected) }} · {{ Number(selected.risk_score || 0).toFixed(1) }}</dd></div>
            <div><dt>来源</dt><dd>{{ sourceLabels(selected) }}</dd></div>
            <div><dt>命中</dt><dd>{{ selected.hit_count || 1 }} 次</dd></div>
            <div><dt>深挖</dt><dd>{{ selected.deepen_count || 0 }} / 10</dd></div>
          </dl>
          <p class="detail-summary">{{ selected.summary || "暂无摘要" }}</p>

          <div v-if="writable" class="detail-actions operation-write">
            <button v-if="selected.status !== 'converted' && selected.status !== 'rejected' && Number(selected.deepen_count || 0) < 10"
              type="button" @click="openAction('deepen')">定向深挖</button>
            <button v-if="selected.status !== 'converted' && selected.status !== 'rejected'"
              type="button" class="danger-action" @click="openAction('reject')">驳回</button>
            <button v-if="selected.status === 'rejected'" type="button" @click="restoreSignal" :disabled="actionBusy">恢复</button>
          </div>
          <form v-if="writable && actionMode" class="inline-action" @submit.prevent="actionMode === 'deepen' ? submitDeepen() : submitReject()">
            <label>{{ actionMode === "deepen" ? "本轮深挖指令" : "驳回原因（必填）" }}
              <textarea v-model="actionText" rows="3" :placeholder="actionMode === 'deepen' ? '说明要验证的接口、参数和证据目标' : '说明不形成报告的判断依据'"></textarea>
            </label>
            <div>
              <button type="button" @click="actionMode = ''">取消</button>
              <button type="submit" class="primary" :disabled="actionBusy || !actionText.trim()">
                {{ actionBusy ? "处理中…" : "确认" }}
              </button>
            </div>
          </form>

          <section class="operation-section">
            <header class="section-head"><div><h4>原始证据</h4><p>按需读取完整请求、响应、命令与输出</p></div></header>
            <RawEvidenceViewer :signal-id="selected.id" :evidence="selected.evidence || []" />
          </section>

          <MissedSignalDraftEditor :signal-id="selected.id" :writable="writable"
            @confirmed="refresh" @toast="toast" />

          <section v-if="selected.events?.length" class="operation-section audit-section">
            <header class="section-head"><div><h4>处理历史</h4><p>状态与人工操作永久保留</p></div></header>
            <ol class="audit-list">
              <li v-for="event in selected.events" :key="event.id">
                <span>{{ event.kind || "状态变更" }}</span>
                <b>{{ event.from_status || "-" }} → {{ event.to_status || selected.status }}</b>
                <p v-if="event.reason">{{ event.reason }}</p>
                <time>{{ fmtTime(event.created_at) }}</time>
              </li>
            </ol>
          </section>
        </template>
      </aside>
    </div>
    <div v-if="toastMsg" class="toast operations-toast">{{ toastMsg }}</div>
  </section>
</template>

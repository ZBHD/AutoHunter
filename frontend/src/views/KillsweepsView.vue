<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, canWrite } from "../api.js";
import { vulnerabilityTypeLabel } from "../vulnerabilityTypes.js";
import {
  KILLSWEEP_PAGE_SIZE,
  canReanalyzeKillsweep,
  intelFiltersForKillsweep,
  killsweepListParams,
  killsweepPresentation,
  killsweepStatCount,
} from "../killsweeps.js";
import { normalizePage } from "../listQuery.js";
import KillsweepTimeline from "../components/killsweeps/KillsweepTimeline.vue";
import PagerBar from "../components/shared/PagerBar.vue";

const router = useRouter();
const STATUS_FILTERS = [
  { key: "all", label: "全部" },
  { key: "queued", label: "待触发" },
  { key: "running", label: "运行中" },
  { key: "succeeded", label: "分析完成" },
  { key: "pending_validation", label: "待验证" },
  { key: "killsweep", label: "可通杀" },
  { key: "not_killsweep", label: "不可通杀" },
  { key: "failed", label: "失败" },
  { key: "cancelled", label: "已取消" },
  { key: "invalid", label: "人工无效" },
];
const MANUAL_LABELS = {
  confirmed: "人工确认通杀",
  not_killsweep: "人工判定不可通杀",
  invalid: "人工无效",
};

const stats = ref({
  total: 0, queued: 0, running: 0, pending_validation: 0,
  killsweep: 0, not_killsweep: 0, failed: 0, cancelled: 0, invalid: 0,
});
const rows = ref([]);
const total = ref(0);
const page = ref(0);
const status = ref("all");
const manualVerdict = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const loading = ref(true);
const refreshing = ref(false);
const error = ref("");
const selectedId = ref("");
const selectedDetail = ref(null);
const events = ref([]);
const detailLoading = ref(false);
const timelineLoading = ref(false);
const reviewVerdict = ref("");
const reviewReason = ref("");
const actionBusy = ref(false);
const batchBusy = ref(false);
const toastMsg = ref("");
let searchTimer = null;
let toastTimer = null;
let listVersion = 0;
let detailVersion = 0;

const writable = computed(() => canWrite());
const offset = computed(() => page.value * KILLSWEEP_PAGE_SIZE);
const selected = computed(() => selectedDetail.value);
const currentFilters = computed(() => {
  const params = killsweepListParams({
    status: status.value,
    manualVerdict: manualVerdict.value,
    q: searchText.value,
    page: 0,
  });
  delete params.limit;
  delete params.offset;
  return params;
});

function toast(message) {
  toastMsg.value = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastMsg.value = ""; }, 2800);
}

function fmtTime(value) {
  return value ? String(value).slice(0, 19).replace("T", " ") : "-";
}

function displayState(item) {
  if (["queued", "running", "failed", "cancelled"].includes(item?.status)) return item.status;
  return item?.automatic_verdict || item?.status || "pending_validation";
}

function autoLabel(item) {
  return killsweepPresentation(item?.automatic_verdict || "pending_validation").label;
}

function manualLabel(value) {
  return MANUAL_LABELS[value] || "未人工评判";
}

function dispatchFailedCount() {
  window.dispatchEvent(new CustomEvent("autohunter-operation-counts", {
    detail: { killsweepFailed: Number(stats.value.failed || 0) },
  }));
}

async function loadStats() {
  try {
    stats.value = { ...stats.value, ...(await api.killsweepStats()) };
    dispatchFailedCount();
  } catch {
    // Keep the last valid counters when only this request fails.
  }
}

async function selectCase(item) {
  const id = typeof item === "string" ? item : item?.id;
  if (!id) {
    selectedId.value = "";
    selectedDetail.value = null;
    events.value = [];
    return;
  }
  selectedId.value = id;
  reviewVerdict.value = "";
  reviewReason.value = "";
  const version = ++detailVersion;
  detailLoading.value = true;
  timelineLoading.value = true;
  try {
    const [detailResult, eventResult] = await Promise.allSettled([
      api.killsweepCase(id),
      api.killsweepEvents(id),
    ]);
    if (version !== detailVersion) return;
    if (detailResult.status === "rejected") throw detailResult.reason;
    selectedDetail.value = detailResult.value;
    events.value = eventResult.status === "fulfilled"
      ? normalizePage(eventResult.value).items
      : [];
  } catch (detailError) {
    if (version === detailVersion) {
      selectedDetail.value = null;
      events.value = [];
      error.value = String(detailError?.message || detailError);
    }
  } finally {
    if (version === detailVersion) {
      detailLoading.value = false;
      timelineLoading.value = false;
    }
  }
}

async function loadList() {
  const version = ++listVersion;
  if (!rows.value.length) loading.value = true;
  else refreshing.value = true;
  error.value = "";
  try {
    const payload = await api.killsweepCases(killsweepListParams({
      status: status.value,
      manualVerdict: manualVerdict.value,
      q: searchText.value,
      page: page.value,
    }));
    if (version !== listVersion) return;
    const normalized = normalizePage(payload, { limit: KILLSWEEP_PAGE_SIZE, offset: offset.value });
    rows.value = normalized.items;
    total.value = normalized.total;
    const current = rows.value.find((item) => item.id === selectedId.value);
    if (current) await selectCase(current);
    else if (rows.value.length) await selectCase(rows.value[0]);
    else await selectCase(null);
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
  if (next === "invalid") {
    status.value = "all";
    manualVerdict.value = "invalid";
  } else {
    manualVerdict.value = "all";
    status.value = next;
  }
  page.value = 0;
  loadList();
}

function filterActive(key) {
  return key === "invalid"
    ? manualVerdict.value === "invalid"
    : manualVerdict.value === "all" && status.value === key;
}

function changePage(nextOffset) {
  page.value = Math.floor(nextOffset / KILLSWEEP_PAGE_SIZE);
  loadList();
}

function changeManualFilter() {
  page.value = 0;
  loadList();
}

function openReview(verdict) {
  reviewVerdict.value = verdict;
  reviewReason.value = "";
}

async function submitReview() {
  if (!selected.value || !reviewVerdict.value) return;
  if (reviewVerdict.value !== "confirmed" && !reviewReason.value.trim()) return;
  actionBusy.value = true;
  try {
    const detail = await api.reviewKillsweep(selected.value.id, {
      verdict: reviewVerdict.value,
      reason: reviewReason.value.trim(),
    });
    selectedDetail.value = detail;
    reviewVerdict.value = "";
    reviewReason.value = "";
    toast("人工评判已保存，自动结论保持不变");
    await Promise.all([loadStats(), loadList()]);
  } catch (actionError) {
    error.value = String(actionError?.message || actionError);
  } finally {
    actionBusy.value = false;
  }
}

async function reanalyzeOne() {
  if (!selected.value || !canReanalyzeKillsweep(selected.value)) return;
  actionBusy.value = true;
  try {
    await api.reanalyzeKillsweep(selected.value.id);
    toast("已追加一次重新分析尝试");
    await refresh();
  } catch (actionError) {
    error.value = String(actionError?.message || actionError);
  } finally {
    actionBusy.value = false;
  }
}

async function reanalyzeCurrentFilter() {
  batchBusy.value = true;
  try {
    const result = await api.reanalyzeKillsweeps({ filters: currentFilters.value });
    toast(`已从当前筛选排入 ${Number(result?.selected_count || 0)} 条重析任务`);
    await refresh();
  } catch (batchError) {
    error.value = String(batchError?.message || batchError);
  } finally {
    batchBusy.value = false;
  }
}

function openTask(selected) {
  router.push(`/task/${selected.task_id}`);
}

function openIntel(item) {
  router.push({ name: "intel", query: intelFiltersForKillsweep(item) });
}

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
  <section class="view operations-view killsweeps-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>
    <header class="page-head split">
      <div>
        <h2>通杀运行中心 <span class="intel-chip">KILLSWEEP</span></h2>
        <p class="page-sub">跨任务审计产品级漏洞分析、验证过程、失败重析和人工结论。</p>
      </div>
      <div class="head-actions">
        <button v-if="writable" type="button" class="head-action primary" :disabled="batchBusy" @click="reanalyzeCurrentFilter">
          {{ batchBusy ? "排队中…" : "重析当前筛选 · 最多 40 条" }}
        </button>
        <button type="button" class="head-action" :disabled="refreshing" @click="refresh">
          {{ refreshing ? "刷新中…" : "刷新" }}
        </button>
      </div>
    </header>

    <div class="operations-stats killsweep-stats" aria-label="通杀状态统计">
      <button v-for="filter in STATUS_FILTERS" :key="filter.key" type="button" class="operation-stat"
        :class="`tone-${killsweepPresentation(filter.key).tone}`" :data-active="filterActive(filter.key)"
        @click="chooseStatus(filter.key)">
        <span>{{ filter.label }}</span>
        <b>{{ killsweepStatCount(stats, filter.key === "all" ? "total" : filter.key) }}</b>
      </button>
    </div>

    <div class="operations-toolbar">
      <div class="search-box">
        <span aria-hidden="true">⌕</span>
        <input v-model="searchDraft" type="search" aria-label="搜索通杀案例"
          placeholder="搜索产品、漏洞、FOFA、任务或失败原因" />
      </div>
      <select v-model="manualVerdict" aria-label="人工结论筛选" @change="changeManualFilter">
        <option value="all">全部人工结论</option>
        <option value="confirmed">人工确认通杀</option>
        <option value="not_killsweep">人工判定不可通杀</option>
        <option value="invalid">人工无效</option>
      </select>
      <span class="toolbar-summary">{{ total }} 条 · 每页 {{ KILLSWEEP_PAGE_SIZE }} 条</span>
    </div>

    <p v-if="error" class="operations-error page-error" role="alert">{{ error }}</p>

    <div class="operations-split killsweep-split">
      <section class="operations-master" aria-label="通杀案例列表">
        <div v-if="loading" class="operations-loading">
          <span v-for="n in 7" :key="n" class="operation-row skeleton-hard"></span>
        </div>
        <div v-else-if="!rows.length" class="operations-empty">当前筛选条件下没有通杀案例</div>
        <button v-for="item in rows" v-else :key="item.id" type="button" class="operation-row killsweep-row"
          :class="{ selected: item.id === selectedId }" @click="selectCase(item)">
          <span class="row-status status-chip" :class="killsweepPresentation(displayState(item)).tone">
            {{ killsweepPresentation(displayState(item)).label }}
          </span>
          <span class="row-content">
            <b>{{ item.product_name || "产品待识别" }}</b>
            <small>{{ item.origin_title || vulnerabilityTypeLabel(item.vuln_type) }}</small>
            <em v-if="item.failure_message">{{ item.failure_message }}</em>
            <em v-else>{{ item.task_name || item.task_id }} · {{ item.fofa_query || "FOFA 语法待生成" }}</em>
          </span>
          <span class="row-meta">
            <strong>{{ item.asset_count || 0 }} 全网 / {{ item.edu_count || 0 }} 教育</strong>
            <small>{{ manualLabel(item.manual_verdict) }}</small>
            <time>{{ fmtTime(item.finished_at || item.updated_at || item.created_at) }}</time>
          </span>
        </button>
        <PagerBar :total="total" :limit="KILLSWEEP_PAGE_SIZE" :offset="offset"
          :count="rows.length" :loading="refreshing" @change="changePage" />
      </section>

      <aside class="operations-detail" aria-label="通杀案例详情">
        <div v-if="detailLoading" class="operations-empty">正在读取案例详情…</div>
        <div v-else-if="!selected" class="operations-empty">从左侧选择一个案例查看完整分析</div>
        <template v-else>
          <header class="detail-head">
            <div>
              <span class="status-chip" :class="killsweepPresentation(displayState(selected)).tone">
                {{ killsweepPresentation(displayState(selected)).label }}
              </span>
              <h3>{{ selected.product_name || "产品待识别" }}</h3>
              <p>{{ selected.origin_title || vulnerabilityTypeLabel(selected.vuln_type) }}</p>
            </div>
            <div class="detail-head-actions">
              <button type="button" class="compact-action" @click="openTask(selected)">进任务</button>
              <button type="button" class="compact-action" @click="openIntel(selected)">查看情报库</button>
            </div>
          </header>

          <div v-if="selected.legacy_without_timeline" class="legacy-notice">旧记录无完整时间线</div>

          <div class="verdict-grid">
            <div>
              <span>自动结论</span>
              <b :class="`tone-text-${killsweepPresentation(selected.automatic_verdict).tone}`">{{ autoLabel(selected) }}</b>
              <small>{{ selected.verified ? `已验证 ${selected.verified_url || "同款站点"}` : "尚无成功验证 URL" }}</small>
            </div>
            <div>
              <span>人工结论</span>
              <b>{{ manualLabel(selected.manual_verdict) }}</b>
              <small>{{ selected.manual_reason || "自动与人工结论并列保留" }}</small>
            </div>
          </div>

          <dl class="detail-facts killsweep-facts">
            <div><dt>全网规模</dt><dd>{{ selected.asset_count || 0 }}</dd></div>
            <div><dt>教育规模</dt><dd>{{ selected.edu_count || 0 }}</dd></div>
            <div><dt>分析尝试</dt><dd>{{ selected.attempt_count || selected.attempts?.length || 0 }}</dd></div>
            <div><dt>可信度</dt><dd>{{ selected.confidence || "待判断" }}</dd></div>
          </dl>

          <section class="operation-section compact-section">
            <header class="section-head"><div><h4>产品与漏洞结论</h4></div></header>
            <dl class="long-facts">
              <div><dt>漏洞说明</dt><dd>{{ selected.vuln_summary || "待补充" }}</dd></div>
              <div><dt>产品指纹</dt><dd><pre>{{ selected.fingerprint || "待补充" }}</pre></dd></div>
              <div><dt>FOFA 查询</dt><dd><code>{{ selected.fofa_query || "待补充" }}</code></dd></div>
              <div v-if="selected.failure_message"><dt>失败原因</dt><dd class="danger-text">{{ selected.failure_kind }} · {{ selected.failure_message }}</dd></div>
              <div v-if="selected.notes"><dt>分析建议</dt><dd>{{ selected.notes }}</dd></div>
            </dl>
          </section>

          <div v-if="writable" class="detail-actions operation-write">
            <button type="button" @click="openReview('confirmed')">确认通杀</button>
            <button type="button" @click="openReview('not_killsweep')">判定不可通杀</button>
            <button type="button" class="danger-action" @click="openReview('invalid')">标记无效</button>
            <button v-if="canReanalyzeKillsweep(selected)" type="button" :disabled="actionBusy" @click="reanalyzeOne">重新分析</button>
          </div>

          <form v-if="writable && reviewVerdict" class="inline-action" @submit.prevent="submitReview">
            <label>人工评判原因{{ reviewVerdict === "confirmed" ? "（可选）" : "（必填）" }}
              <textarea v-model="reviewReason" rows="3" placeholder="记录人工判断依据；否定结论会取消尚未开始的派生目标"></textarea>
            </label>
            <div>
              <button type="button" @click="reviewVerdict = ''">取消</button>
              <button type="submit" class="primary"
                :disabled="actionBusy || (reviewVerdict !== 'confirmed' && !reviewReason.trim())">
                {{ actionBusy ? "保存中…" : "保存人工结论" }}
              </button>
            </div>
          </form>

          <section v-if="selected.attempts?.length" class="operation-section compact-section">
            <header class="section-head"><div><h4>分析尝试</h4><p>重新分析只追加，不覆盖历史</p></div></header>
            <div class="attempt-list">
              <article v-for="attempt in selected.attempts" :key="attempt.id">
                <span class="status-chip" :class="killsweepPresentation(attempt.status).tone">{{ killsweepPresentation(attempt.status).label }}</span>
                <b>第 {{ attempt.attempt_no }} 次 · {{ attempt.trigger || "initial" }}</b>
                <small>{{ killsweepPresentation(attempt.automatic_verdict).label }}</small>
                <time>{{ fmtTime(attempt.finished_at || attempt.created_at) }}</time>
                <p v-if="attempt.error_message">{{ attempt.error_kind }} · {{ attempt.error_message }}</p>
              </article>
            </div>
          </section>

          <section class="operation-section timeline-section">
            <header class="section-head"><div><h4>完整时间线</h4><p>FOFA、HTTP、命令、输出与错误均按原顺序保留</p></div></header>
            <KillsweepTimeline :case-id="selected.id" :events="events" :loading="timelineLoading" />
          </section>

          <section v-if="selected.affected_table?.length" class="operation-section compact-section">
            <header class="section-head"><div><h4>影响明细</h4><p>{{ selected.affected_table.length }} 个已记录目标</p></div></header>
            <div class="affected-table-wrap">
              <table>
                <thead><tr><th>单位</th><th>URL</th><th>状态</th><th>证据</th></tr></thead>
                <tbody>
                  <tr v-for="(asset, index) in selected.affected_table" :key="asset.dedup_key || index">
                    <td>{{ asset.school || "待确认" }}</td><td>{{ asset.url || asset.host }}</td>
                    <td>{{ asset.status || "-" }}</td><td>{{ asset.evidence || "-" }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </template>
      </aside>
    </div>
    <div v-if="toastMsg" class="toast operations-toast">{{ toastMsg }}</div>
  </section>
</template>

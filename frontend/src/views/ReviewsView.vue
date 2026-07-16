<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { api, authRoleRef } from "../api.js";
import ReportDrawer from "../components/ReportDrawer.vue";
import { downloadMarkdownReports, saveMarkdownFile } from "../downloads.js";
import { normalizePage } from "../listQuery.js";
import { buildDownloadReportMd, effectiveSeverity } from "../report.js";
import { vulnerabilityTypeLabel } from "../vulnerabilityTypes.js";

const PAGE_SIZE = 50;
const rows = ref([]);
const tasks = ref([]);
const total = ref(0);
const page = ref(0);
const loading = ref(false);
const error = ref("");
const searchDraft = ref("");
const search = ref("");
const taskId = ref("");
const downloadStatus = ref("");
const selectedIds = ref(new Set());
const selectedRows = ref(new Map());
const downloadScope = ref("filtered");
const downloadWorking = ref(false);
const bulkWorking = ref(false);
const drawerId = ref(null);
const drawerSrcType = ref("");
const toastMsg = ref("");

const writable = computed(() => authRoleRef.value === "full");
const selectedCount = computed(() => selectedIds.value.size);
const allPageSelected = computed(() => (
  rows.value.length > 0 && rows.value.every((row) => selectedIds.value.has(row.id))
));
const pageCount = computed(() => Math.max(1, Math.ceil(total.value / PAGE_SIZE)));

function toast(message) {
  toastMsg.value = message;
  setTimeout(() => {
    if (toastMsg.value === message) toastMsg.value = "";
  }, 2600);
}

async function notifyReviewCount() {
  try {
    const stats = await api.globalReviewStats();
    window.dispatchEvent(new CustomEvent("autohunter-operation-counts", {
      detail: { reviewPending: Number(stats?.pending ?? 0) },
    }));
  } catch {
    // Keep the global badge unchanged when a filtered list refresh fails to read stats.
  }
}

async function load(reset = false) {
  if (reset) page.value = 0;
  loading.value = true;
  error.value = "";
  try {
    const response = await api.globalReviewQueue(search.value || undefined, {
      task_id: taskId.value,
      download_status: downloadStatus.value,
      limit: PAGE_SIZE,
      offset: page.value * PAGE_SIZE,
    });
    const normalized = normalizePage(response, { limit: PAGE_SIZE, offset: page.value * PAGE_SIZE });
    rows.value = normalized.items;
    total.value = Number(response?.total ?? normalized.total ?? 0);
    void notifyReviewCount();
  } catch (cause) {
    error.value = String(cause?.message || cause || "复审队列加载失败").replace(/^\d+\s*/, "");
  } finally {
    loading.value = false;
  }
}

async function applySearch() {
  search.value = searchDraft.value.trim();
  await load(true);
}

function rememberSelection(row, selected) {
  const ids = new Set(selectedIds.value);
  const cache = new Map(selectedRows.value);
  if (selected) {
    ids.add(row.id);
    cache.set(row.id, row);
  } else {
    ids.delete(row.id);
    cache.delete(row.id);
  }
  selectedIds.value = ids;
  selectedRows.value = cache;
  if (ids.size) downloadScope.value = "selected";
}

function toggleSelection(row) {
  rememberSelection(row, !selectedIds.value.has(row.id));
}

function togglePageSelection() {
  const select = !allPageSelected.value;
  for (const row of rows.value) rememberSelection(row, select);
}

function clearSelection() {
  selectedIds.value = new Set();
  selectedRows.value = new Map();
  downloadScope.value = "filtered";
}

async function fetchFilteredRows() {
  const output = [];
  let offset = 0;
  for (;;) {
    const response = await api.globalReviewQueue(search.value || undefined, {
      task_id: taskId.value,
      download_status: downloadStatus.value,
      limit: 200,
      offset,
    });
    const normalized = normalizePage(response, { limit: 200, offset });
    output.push(...normalized.items);
    if (!normalized.hasMore || !normalized.items.length) break;
    offset += normalized.items.length;
  }
  return output;
}

async function downloadReports() {
  if (downloadWorking.value) return;
  downloadWorking.value = true;
  try {
    const source = downloadScope.value === "selected"
      ? [...selectedRows.value.values()]
      : await fetchFilteredRows();
    if (!source.length) return;
    const details = [];
    for (const row of source) details.push(await api.finding(row.id));
    const downloaded = [];
    await downloadMarkdownReports(details, {
      render: (finding) => buildDownloadReportMd(finding),
      save: async (file) => {
        saveMarkdownFile(file);
        downloaded.push(file.finding);
      },
    });
    const byTask = new Map();
    for (const finding of downloaded) {
      if (!byTask.has(finding.task_id)) byTask.set(finding.task_id, []);
      byTask.get(finding.task_id).push(finding.id);
    }
    await Promise.all([...byTask].map(([id, findingIds]) => api.markFindingsDownloaded(id, findingIds)));
    clearSelection();
    await load();
    toast(`已下载 ${downloaded.length} 份 Markdown 报告`);
  } catch (cause) {
    toast(`下载失败：${cause?.message || cause}`);
  } finally {
    downloadWorking.value = false;
  }
}

async function applyBulkDecision(status) {
  if (!writable.value || !selectedCount.value || bulkWorking.value) return;
  const label = status === "passed" ? "通过" : "不通过";
  if (!window.confirm(`确认将已选 ${selectedCount.value} 项批量标记为${label}？`)) return;
  let notes = "";
  if (status === "rejected") {
    const input = window.prompt("批量不通过备注（可留空）", "");
    if (input === null) return;
    notes = input.trim();
  }
  bulkWorking.value = true;
  let completed = 0;
  try {
    for (const id of selectedIds.value) {
      await api.userReview(id, { user_status: status, ...(notes ? { user_notes: notes } : {}) });
      completed += 1;
    }
    clearSelection();
    await load();
    window.dispatchEvent(new CustomEvent("autohunter-refresh-operation-counts"));
    toast(`已批量${label} ${completed} 项`);
  } catch (cause) {
    await load();
    toast(`已处理 ${completed} 项，随后失败：${cause?.message || cause}`);
  } finally {
    bulkWorking.value = false;
  }
}

function openReview(row) {
  drawerId.value = row.id;
  drawerSrcType.value = row.task_src_type || "";
}

async function onDrawerUpdated() {
  drawerId.value = null;
  await load();
  window.dispatchEvent(new CustomEvent("autohunter-refresh-operation-counts"));
}

async function changePage(delta) {
  const next = Math.min(pageCount.value - 1, Math.max(0, page.value + delta));
  if (next === page.value) return;
  page.value = next;
  await load();
}

watch([taskId, downloadStatus], () => load(true));

onMounted(async () => {
  const [taskRows] = await Promise.allSettled([api.listTasks(), load(true)]);
  if (taskRows.status === "fulfilled") tasks.value = taskRows.value || [];
});
</script>

<template>
  <div class="page operations-view reviews-view">
    <div class="page-head">
      <div>
        <h2>全局复审</h2>
        <p class="page-sub">集中处理所有任务中等待人工裁决的漏洞</p>
      </div>
      <div class="review-summary"><b>{{ total }}</b><span>待复审</span></div>
    </div>

    <form class="operations-toolbar review-toolbar" @submit.prevent="applySearch">
      <div class="search-box"><span>⌕</span><input v-model="searchDraft" placeholder="搜索标题、URL、单位、类型或任务" /></div>
      <select v-model="taskId" aria-label="按任务筛选">
        <option value="">全部任务</option>
        <option v-for="task in tasks" :key="task.id" :value="task.id">{{ task.name }}</option>
      </select>
      <button type="submit">搜索</button>
      <button v-if="search" type="button" class="ghost" @click="searchDraft = ''; applySearch()">清空</button>
    </form>

    <section class="review-workbench">
      <header class="review-command-bar">
        <div class="review-status-tabs" role="tablist" aria-label="下载状态">
          <button type="button" :class="{ active: downloadStatus === '' }" @click="downloadStatus = ''">全部</button>
          <button type="button" :class="{ active: downloadStatus === 'pending' }" @click="downloadStatus = 'pending'">未下载</button>
          <button type="button" :class="{ active: downloadStatus === 'downloaded' }" @click="downloadStatus = 'downloaded'">已下载</button>
        </div>
        <button type="button" class="ghost" :disabled="!rows.length" @click="togglePageSelection">
          {{ allPageSelected ? "取消全选当前页" : "全选当前页" }}
        </button>
        <span v-if="selectedCount" class="selected-summary">已选 {{ selectedCount }} 项</span>
        <button v-if="selectedCount" type="button" class="ghost" @click="clearSelection">清空选择</button>
        <span class="grow"></span>
        <label><input v-model="downloadScope" type="radio" value="selected" :disabled="!selectedCount" /> 已选项</label>
        <label><input v-model="downloadScope" type="radio" value="filtered" /> 当前筛选结果</label>
        <button type="button" :disabled="downloadWorking || (downloadScope === 'selected' ? !selectedCount : !total)" @click="downloadReports">
          {{ downloadWorking ? "下载中…" : "批量下载 Markdown" }}
        </button>
        <div v-if="writable" class="review-bulk-actions">
          <button type="button" class="approve" :disabled="!selectedCount || bulkWorking" @click="applyBulkDecision('passed')">批量通过</button>
          <button type="button" class="reject" :disabled="!selectedCount || bulkWorking" @click="applyBulkDecision('rejected')">批量不通过</button>
        </div>
      </header>

      <p v-if="error" class="review-error" role="alert">{{ error }}</p>
      <div v-if="loading" class="operations-loading">正在加载复审队列…</div>
      <div v-else-if="!rows.length" class="operations-empty">当前没有符合条件的待复审漏洞</div>
      <div v-else class="global-review-list">
        <article v-for="row in rows" :key="row.id" class="global-review-row" :class="{ selected: selectedIds.has(row.id) }">
          <label class="review-check" @click.stop>
            <input type="checkbox" :checked="selectedIds.has(row.id)" :aria-label="`选择 ${row.title}`" @change="toggleSelection(row)" />
          </label>
          <span class="sev-pill" :class="effectiveSeverity(row)">{{ effectiveSeverity(row) }}</span>
          <button type="button" class="global-review-open" @click="openReview(row)">
            <span class="global-review-main">
              <b>{{ row.title }}</b>
              <small>{{ vulnerabilityTypeLabel(row.vuln_type) }} · {{ row.target_url }}</small>
              <em>{{ row.owner || "归属待确认" }}</em>
            </span>
            <span class="global-review-task">
              <b>{{ row.task_name }}</b>
              <small>{{ row.downloaded ? "已下载" : "未下载" }}</small>
            </span>
            <span class="score">{{ row.review?.score ?? "-" }}</span>
          </button>
        </article>
      </div>

      <footer class="operations-pager review-pager">
        <button type="button" aria-label="上一页" :disabled="page === 0 || loading" @click="changePage(-1)">‹</button>
        <span>第 {{ page + 1 }} / {{ pageCount }} 页</span>
        <small>{{ total }} 条待复审</small>
        <button type="button" aria-label="下一页" :disabled="page + 1 >= pageCount || loading" @click="changePage(1)">›</button>
      </footer>
    </section>

    <ReportDrawer v-if="drawerId" :finding-id="drawerId" mode="review" :src-type="drawerSrcType"
      @close="drawerId = null" @updated="onDrawerUpdated" @toast="toast" />
    <div v-if="toastMsg" class="operations-toast">{{ toastMsg }}</div>
  </div>
</template>

<style scoped>
.reviews-view{max-width:1180px}.review-summary{display:grid;justify-items:end;gap:2px}.review-summary b{color:var(--warn);font-size:28px;font-variant-numeric:tabular-nums}.review-summary span{color:var(--muted);font-size:11px}.review-toolbar .search-box{flex:1}.review-toolbar select{min-width:180px}.review-workbench{overflow:hidden;border:1px solid var(--border);border-radius:8px;background:var(--surface)}.review-command-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px;border-bottom:1px solid var(--border-soft);background:var(--nav)}.review-command-bar label{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:11px;white-space:nowrap}.selected-summary{color:var(--accent);font-size:11px;font-variant-numeric:tabular-nums}.review-bulk-actions{display:flex;gap:6px}.review-bulk-actions .approve{border-color:color-mix(in srgb,var(--ok) 45%,var(--border));color:var(--ok)}.review-bulk-actions .reject{border-color:color-mix(in srgb,var(--danger) 45%,var(--border));color:var(--danger)}.review-error{margin:10px;padding:10px;border:1px solid color-mix(in srgb,var(--danger) 35%,var(--border));border-radius:6px;color:var(--danger)}.operations-loading{min-height:160px;place-items:center;color:var(--muted)}.global-review-list{display:grid}.global-review-row{display:grid;grid-template-columns:28px 72px minmax(0,1fr);align-items:center;gap:10px;min-height:82px;padding:10px 12px;border-bottom:1px solid var(--border-soft);background:var(--surface)}.global-review-row:last-child{border-bottom:0}.global-review-row:hover,.global-review-row.selected{background:var(--surface-2)}.global-review-row.selected{box-shadow:inset 3px 0 var(--accent)}.global-review-open{display:grid;grid-template-columns:minmax(0,1fr) 180px 48px;align-items:center;gap:12px;min-width:0;width:100%;padding:0;border:0;background:transparent;color:inherit;text-align:left}.global-review-open:hover{border-color:transparent;background:transparent}.global-review-main,.global-review-task{display:grid;gap:3px;min-width:0}.global-review-main b,.global-review-main small,.global-review-main em{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.global-review-main b{font-size:13px}.global-review-main small{color:var(--ink-2);font-size:11px}.global-review-main em{color:var(--muted);font-size:10.5px;font-style:normal}.global-review-task{justify-items:end;text-align:right}.global-review-task b{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}.global-review-task small{color:var(--muted);font-size:10px}.global-review-row .score{justify-self:end}.review-pager{border-top:1px solid var(--border-soft)}
@media(max-width:760px){.reviews-view{padding-inline:12px}.review-toolbar{align-items:stretch;flex-wrap:wrap}.review-toolbar .search-box{flex-basis:100%}.review-toolbar select{flex:1;min-width:0}.review-command-bar{align-items:stretch}.review-command-bar>.grow{display:none}.review-command-bar>button,.review-bulk-actions{flex:1}.review-command-bar>button,.review-bulk-actions button{min-height:44px}.review-bulk-actions button{flex:1}.global-review-row{grid-template-columns:28px 58px minmax(0,1fr)}.global-review-open{grid-template-columns:minmax(0,1fr) 42px}.global-review-task{grid-column:1/-1;justify-items:start;text-align:left}.global-review-main b,.global-review-main small,.global-review-main em{white-space:normal;overflow-wrap:anywhere}}
</style>

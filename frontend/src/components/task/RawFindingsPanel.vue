<script setup>
import { nextTick, ref, watch } from "vue";
import { api } from "../../api.js";
import { normalizePage } from "../../listQuery.js";
import { buildReportMd, effectiveSeverity } from "../../report.js";
import { downloadMarkdownReports, saveMarkdownFile } from "../../downloads.js";

const props = defineProps({ taskId: { type: String, required: true } });
const emit = defineEmits(["open-finding", "toast"]);
const PAGE_SIZE = 50;

const rows = ref([]);
const total = ref(0);
const offset = ref(0);
const searchDraft = ref("");
const search = ref("");
const loading = ref(false);
const error = ref("");
const downloadOpen = ref(false);
const downloadScope = ref("all");
const downloadWorking = ref(false);
const downloadProgress = ref({ current: 0, total: 0, stage: "" });
const cancelDownload = ref(false);
const downloadTrigger = ref(null);
const downloadDialog = ref(null);
let downloadReturnFocus = null;

async function openDownload() {
  downloadReturnFocus = document.activeElement;
  downloadOpen.value = true;
  await nextTick();
  downloadDialog.value?.focus();
}

function restoreDownloadFocus() {
  const target = downloadReturnFocus?.isConnected ? downloadReturnFocus : downloadTrigger.value;
  downloadReturnFocus = null;
  void nextTick(() => target?.focus());
}

function finishCloseDownload() {
  downloadOpen.value = false;
  restoreDownloadFocus();
}

function closeDownload() {
  if (downloadWorking.value) {
    cancelDownload.value = true;
    return;
  }
  finishCloseDownload();
}

function trapDownloadFocus(event) {
  const dialog = downloadDialog.value;
  if (!dialog) return;
  const focusable = [...dialog.querySelectorAll(
    'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]',
  )].filter((element) => element.getClientRects().length > 0);
  if (!focusable.length) {
    event.preventDefault();
    dialog.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

async function load(reset = false) {
  if (!props.taskId) return;
  if (reset) offset.value = 0;
  loading.value = true;
  error.value = "";
  try {
    const page = normalizePage(await api.rawFindings(props.taskId, {
      q: search.value,
      limit: PAGE_SIZE,
      offset: offset.value,
    }), { limit: PAGE_SIZE, offset: offset.value });
    rows.value = page.items;
    total.value = page.total;
  } catch (cause) {
    error.value = String(cause?.message || cause || "原始发现加载失败").replace(/^\d+\s*/, "");
  } finally {
    loading.value = false;
  }
}

async function applySearch() {
  search.value = searchDraft.value.trim();
  await load(true);
}

async function changePage(delta) {
  const next = Math.max(0, offset.value + delta * PAGE_SIZE);
  if (next === offset.value || next >= total.value) return;
  offset.value = next;
  await load();
}

async function fetchDownloadRows() {
  const compact = [];
  let cursor = 0;
  const q = downloadScope.value === "filtered" ? search.value : "";
  for (;;) {
    if (cancelDownload.value) throw new Error("下载已取消");
    const page = normalizePage(await api.rawFindings(props.taskId, {
      q,
      limit: PAGE_SIZE,
      offset: cursor,
    }), { limit: PAGE_SIZE, offset: cursor });
    compact.push(...page.items);
    downloadProgress.value = { current: compact.length, total: page.total, stage: "正在读取报告列表" };
    if (!page.hasMore || !page.items.length) break;
    cursor += page.items.length;
  }
  return compact;
}

async function startDownload() {
  downloadWorking.value = true;
  cancelDownload.value = false;
  error.value = "";
  try {
    const compact = await fetchDownloadRows();
    downloadProgress.value = { current: 0, total: compact.length, stage: "正在读取完整报告" };
    const details = [];
    for (let index = 0; index < compact.length; index += 1) {
      if (cancelDownload.value) throw new Error("下载已取消");
      details.push(await api.finding(compact[index].id));
      downloadProgress.value = { current: index + 1, total: compact.length, stage: "正在读取完整报告" };
    }
    downloadProgress.value = { current: 0, total: details.length, stage: "正在下载独立 Markdown" };
    await downloadMarkdownReports(details, {
      render: (finding) => buildReportMd(finding),
      save: async (file) => {
        if (cancelDownload.value) throw new Error("下载已取消");
        saveMarkdownFile(file);
        downloadProgress.value = {
          current: downloadProgress.value.current + 1,
          total: details.length,
          stage: "正在下载独立 Markdown",
        };
      },
    });
    emit("toast", `已下载 ${details.length} 份独立 Markdown 报告`);
    finishCloseDownload();
  } catch (cause) {
    const message = String(cause?.message || cause || "下载失败").replace(/^\d+\s*/, "");
    if (message !== "下载已取消") error.value = message;
    else {
      emit("toast", message);
      finishCloseDownload();
    }
  } finally {
    downloadWorking.value = false;
  }
}

watch(() => props.taskId, () => load(true), { immediate: true });
</script>

<template>
  <section class="raw-findings-panel" aria-labelledby="raw-findings-title">
    <header class="raw-head">
      <div><h3 id="raw-findings-title">原始发现</h3><p>当前有效 Finding，点击条目查看完整漏洞报告</p></div>
      <div class="raw-head-actions">
        <span>{{ total }} 份报告</span>
        <button ref="downloadTrigger" type="button" :disabled="!total" @click="openDownload">下载报告</button>
      </div>
    </header>
    <form class="raw-search" @submit.prevent="applySearch">
      <input v-model="searchDraft" aria-label="搜索原始发现" placeholder="搜索标题、URL、类型、单位、正文或审核备注" />
      <button type="submit">搜索</button>
      <button v-if="search" type="button" class="ghost" @click="searchDraft = ''; applySearch()">清空</button>
    </form>
    <p v-if="error" class="raw-error" role="alert">{{ error }}</p>
    <div v-if="loading" class="raw-empty">正在加载原始发现...</div>
    <div v-else-if="!rows.length" class="raw-empty">没有符合条件的原始发现</div>
    <div v-else class="raw-list">
      <button v-for="finding in rows" :key="finding.id" type="button" class="raw-row" @click="emit('open-finding', finding.id)">
        <span class="raw-severity" :class="effectiveSeverity(finding)">{{ effectiveSeverity(finding) || finding.severity_claimed || "-" }}</span>
        <span class="raw-main"><b>{{ finding.title }}</b><small>{{ finding.vuln_type }} · {{ finding.target_url }}</small></span>
        <span class="raw-time">{{ finding.created_at?.slice(0, 19).replace("T", " ") || "-" }}</span>
      </button>
    </div>
    <footer class="raw-pager">
      <button type="button" :disabled="offset === 0 || loading" @click="changePage(-1)">上一页</button>
      <span>{{ total ? `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)} / ${total}` : "0 / 0" }}</span>
      <button type="button" :disabled="offset + PAGE_SIZE >= total || loading" @click="changePage(1)">下一页</button>
    </footer>

    <div v-if="downloadOpen" class="download-mask" @click.self="closeDownload">
      <section ref="downloadDialog" class="download-dialog" role="dialog" aria-modal="true"
        aria-labelledby="download-title" aria-describedby="download-description" tabindex="-1"
        @keydown.escape.prevent="closeDownload" @keydown.tab="trapDownloadFocus">
        <h4 id="download-title">下载独立 Markdown 报告</h4>
        <p id="download-description">浏览器会依次下载每份报告，首次使用可能需要允许多个文件下载。</p>
        <label><input v-model="downloadScope" type="radio" value="all" :disabled="downloadWorking" /> 当前任务全部原始发现</label>
        <label><input v-model="downloadScope" type="radio" value="filtered" :disabled="downloadWorking" /> 当前搜索结果{{ search ? `（${search}）` : "（未设置关键词，等同全部）" }}</label>
        <div v-if="downloadWorking" class="download-progress">
          <span>{{ downloadProgress.stage }}</span>
          <b>{{ downloadProgress.current }} / {{ downloadProgress.total }}</b>
          <progress :value="downloadProgress.current" :max="Math.max(1, downloadProgress.total)"></progress>
        </div>
        <footer>
          <button type="button" class="ghost" @click="closeDownload">{{ downloadWorking ? "取消下载" : "关闭" }}</button>
          <button type="button" :disabled="downloadWorking" @click="startDownload">开始下载</button>
        </footer>
      </section>
    </div>
  </section>
</template>

<style scoped>
.raw-findings-panel{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:16px}.raw-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.raw-head h3{margin:0;font-size:16px}.raw-head p{margin:5px 0 0;color:var(--muted);font-size:13px}.raw-head-actions{display:flex;align-items:center;gap:12px}.raw-head-actions span{color:var(--muted);font-variant-numeric:tabular-nums}.raw-search{display:flex;gap:8px;margin:14px 0}.raw-search input{flex:1;min-width:0}.raw-search button{min-height:44px}.raw-error{color:var(--danger);padding:10px;border:1px solid color-mix(in srgb,var(--danger) 35%,transparent);border-radius:6px}.raw-empty{padding:32px;text-align:center;color:var(--muted)}.raw-list{display:grid;gap:8px}.raw-row{display:grid;grid-template-columns:72px minmax(0,1fr) 156px;gap:12px;align-items:center;text-align:left;padding:13px;border:1px solid var(--border);background:var(--surface-2);border-radius:7px;color:inherit}.raw-row:hover,.raw-row:focus-visible{border-color:var(--accent)}.raw-severity{font-size:12px;font-weight:700}.raw-main{min-width:0}.raw-main b,.raw-main small{display:block;overflow-wrap:anywhere}.raw-main small,.raw-time{color:var(--muted);font-size:12px}.raw-time{text-align:right;font-variant-numeric:tabular-nums}.raw-pager{display:flex;justify-content:center;align-items:center;gap:14px;margin-top:14px}.raw-pager span{font-variant-numeric:tabular-nums;color:var(--muted)}.download-mask{position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.62);display:grid;place-items:center;padding:16px}.download-dialog{width:min(520px,100%);overscroll-behavior:contain;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;box-shadow:0 20px 60px rgba(0,0,0,.35)}.download-dialog h4{margin:0 0 6px}.download-dialog>p{color:var(--muted);font-size:13px}.download-dialog>label{display:flex;align-items:center;gap:9px;padding:10px 0}.download-progress{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:12px}.download-progress progress{grid-column:1/-1;width:100%}.download-dialog footer{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}.download-dialog button{min-height:44px}
@media(max-width:700px){.raw-findings-panel{padding:12px}.raw-findings-panel button{min-height:44px}.raw-head{display:grid}.raw-head-actions{justify-content:space-between}.raw-search{flex-wrap:wrap}.raw-search input{flex-basis:100%}.raw-row{grid-template-columns:60px minmax(0,1fr)}.raw-time{display:none}}
</style>

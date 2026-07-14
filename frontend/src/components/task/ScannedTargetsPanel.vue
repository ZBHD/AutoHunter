<script setup>
import { ref, watch } from "vue";
import { api } from "../../api.js";
import { normalizePage } from "../../listQuery.js";
import { isCurrentTargetDetail } from "../../taskViews.js";

const props = defineProps({ taskId: { type: String, required: true } });
const emit = defineEmits(["open-finding"]);

const PAGE_SIZE = 50;
const rows = ref([]);
const total = ref(0);
const offset = ref(0);
const searchDraft = ref("");
const search = ref("");
const loading = ref(false);
const error = ref("");
const expandedId = ref("");
const detail = ref(null);
const detailLoading = ref(false);
let detailVersion = 0;

async function load(reset = false) {
  if (!props.taskId) return;
  if (reset) offset.value = 0;
  loading.value = true;
  error.value = "";
  try {
    const page = normalizePage(await api.terminalTargets(props.taskId, {
      q: search.value,
      limit: PAGE_SIZE,
      offset: offset.value,
    }), { limit: PAGE_SIZE, offset: offset.value });
    rows.value = page.items;
    total.value = page.total;
  } catch (cause) {
    error.value = String(cause?.message || cause || "目标加载失败").replace(/^\d+\s*/, "");
  } finally {
    loading.value = false;
  }
}

async function applySearch() {
  search.value = searchDraft.value.trim();
  detailVersion += 1;
  expandedId.value = "";
  detail.value = null;
  detailLoading.value = false;
  await load(true);
}

async function toggleTarget(target) {
  if (expandedId.value === target.id) {
    detailVersion += 1;
    expandedId.value = "";
    detail.value = null;
    detailLoading.value = false;
    return;
  }
  const version = ++detailVersion;
  expandedId.value = target.id;
  detail.value = null;
  detailLoading.value = true;
  try {
    const value = await api.targetDetail(props.taskId, target.id);
    if (isCurrentTargetDetail(version, detailVersion, target.id, expandedId.value)) {
      detail.value = value;
    }
  } catch (cause) {
    if (isCurrentTargetDetail(version, detailVersion, target.id, expandedId.value)) {
      error.value = String(cause?.message || cause || "目标详情加载失败").replace(/^\d+\s*/, "");
    }
  } finally {
    if (isCurrentTargetDetail(version, detailVersion, target.id, expandedId.value)) {
      detailLoading.value = false;
    }
  }
}

function verdictLabel(row) {
  if (row.verdict === "found") return "发现漏洞";
  if (row.verdict === "no_vuln") return "未发现漏洞";
  if (row.verdict === "error") return "扫描异常";
  if (row.status === "skipped") return "已跳过";
  return row.verdict || row.status || "已完成";
}

async function changePage(delta) {
  const next = Math.max(0, offset.value + delta * PAGE_SIZE);
  if (next === offset.value || next >= total.value) return;
  offset.value = next;
  detailVersion += 1;
  expandedId.value = "";
  detail.value = null;
  detailLoading.value = false;
  await load();
}

watch(() => props.taskId, () => {
  detailVersion += 1;
  expandedId.value = "";
  detail.value = null;
  detailLoading.value = false;
  load(true);
}, { immediate: true });
</script>

<template>
  <section class="task-operation-panel" aria-labelledby="scanned-targets-title">
    <header class="operation-head">
      <div>
        <h3 id="scanned-targets-title">已扫目标</h3>
        <p>包含有洞、无洞、异常和跳过的全部终态目标</p>
      </div>
      <span class="operation-total">{{ total }} 个目标</span>
    </header>

    <form class="operation-search" @submit.prevent="applySearch">
      <input v-model="searchDraft" aria-label="搜索已扫目标" placeholder="搜索 URL、Host、单位、状态或结论" />
      <button type="submit">搜索</button>
      <button v-if="search" type="button" class="ghost" @click="searchDraft = ''; applySearch()">清空</button>
    </form>

    <p v-if="error" class="operation-error" role="alert">{{ error }}</p>
    <div v-if="loading" class="operation-empty">正在加载目标...</div>
    <div v-else-if="!rows.length" class="operation-empty">没有符合条件的已扫目标</div>
    <div v-else class="operation-list">
      <article v-for="row in rows" :key="row.id" class="target-operation-row" :class="{ open: expandedId === row.id }">
        <button type="button" class="target-summary" :aria-expanded="expandedId === row.id" @click="toggleTarget(row)">
          <span class="status-mark" :class="`status-${row.status}`"></span>
          <span class="target-primary">
            <b>{{ row.host || row.url }}</b>
            <small>{{ row.url }}</small>
          </span>
          <span class="target-source">{{ row.source || "-" }}</span>
          <span class="target-verdict">{{ verdictLabel(row) }}</span>
          <span class="target-findings"><b>{{ row.finding_count ?? 0 }}</b> 发现</span>
          <span class="target-chevron" aria-hidden="true">{{ expandedId === row.id ? "−" : "+" }}</span>
        </button>

        <div v-if="expandedId === row.id" class="target-audit">
          <div v-if="detailLoading" class="operation-empty compact">正在加载审计信息...</div>
          <template v-else-if="detail">
            <dl class="target-facts">
              <div><dt>归属</dt><dd>{{ detail.school || detail.org || "待确认" }}</dd></div>
              <div><dt>IP</dt><dd>{{ detail.ip || "-" }}</dd></div>
              <div><dt>重试</dt><dd>{{ detail.retry_count ?? 0 }}</dd></div>
              <div><dt>深挖</dt><dd>{{ detail.deepen_count ?? 0 }}</dd></div>
              <div><dt>完成时间</dt><dd>{{ detail.updated_at?.slice(0, 19).replace("T", " ") || "-" }}</dd></div>
            </dl>
            <p v-if="detail.dead_reason || detail.last_error" class="target-reason">
              {{ detail.dead_reason || detail.last_error }}
            </p>
            <div class="linked-findings">
              <span>关联发现</span>
              <p v-if="!detail.findings?.length">该目标没有当前有效的原始发现</p>
              <button v-for="finding in detail.findings" :key="finding.id" type="button" @click="emit('open-finding', finding.id)">
                <span>{{ finding.severity_claimed || "-" }}</span>
                <b>{{ finding.title }}</b>
                <small>{{ finding.vuln_type }}</small>
              </button>
            </div>
          </template>
        </div>
      </article>
    </div>

    <footer class="operation-pager">
      <button type="button" :disabled="offset === 0 || loading" @click="changePage(-1)">上一页</button>
      <span>{{ total ? `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)} / ${total}` : "0 / 0" }}</span>
      <button type="button" :disabled="offset + PAGE_SIZE >= total || loading" @click="changePage(1)">下一页</button>
    </footer>
  </section>
</template>

<style scoped>
.task-operation-panel{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:16px}.operation-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.operation-head h3{margin:0;font-size:16px}.operation-head p{margin:5px 0 0;color:var(--muted);font-size:13px}.operation-total{font-variant-numeric:tabular-nums;color:var(--accent);white-space:nowrap}.operation-search{display:flex;gap:8px;margin:14px 0}.operation-search input{flex:1;min-width:0}.operation-search button{min-height:44px}.operation-error{color:var(--danger);padding:10px;border:1px solid color-mix(in srgb,var(--danger) 35%,transparent);border-radius:6px}.operation-empty{padding:32px;text-align:center;color:var(--muted)}.operation-empty.compact{padding:16px}.operation-list{display:grid;gap:8px}.target-operation-row{border:1px solid var(--border);border-radius:7px;background:var(--surface-2)}.target-summary{width:100%;display:grid;grid-template-columns:10px minmax(220px,1fr) 90px 110px 82px 28px;align-items:center;gap:12px;padding:13px;text-align:left;background:transparent;border:0;color:inherit}.target-primary{min-width:0}.target-primary b,.target-primary small{display:block;overflow-wrap:anywhere}.target-primary small{margin-top:3px;color:var(--muted);font-size:12px}.status-mark{width:8px;height:8px;border-radius:50%;background:var(--muted)}.status-done{background:var(--ok)}.status-dead{background:var(--danger)}.status-skipped{background:var(--warn)}.target-source,.target-verdict,.target-findings{font-size:12px;color:var(--muted)}.target-findings b{color:var(--ink)}.target-chevron{text-align:center;font-size:18px}.target-audit{border-top:1px solid var(--border);padding:14px}.target-facts{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin:0}.target-facts div{background:var(--surface);padding:10px;border-radius:6px}.target-facts dt{color:var(--muted);font-size:11px}.target-facts dd{margin:4px 0 0;overflow-wrap:anywhere}.target-reason{font-size:13px;color:var(--warn)}.linked-findings{display:grid;gap:7px;margin-top:12px}.linked-findings>span{font-size:12px;color:var(--muted)}.linked-findings>p{margin:0;color:var(--muted)}.linked-findings button{display:grid;grid-template-columns:60px minmax(0,1fr) 120px;gap:10px;text-align:left;align-items:center}.linked-findings small{color:var(--muted)}.operation-pager{display:flex;justify-content:center;align-items:center;gap:14px;margin-top:14px}.operation-pager span{font-variant-numeric:tabular-nums;color:var(--muted)}
@media(max-width:760px){.task-operation-panel{padding:12px}.task-operation-panel button{min-height:44px}.target-summary{grid-template-columns:10px minmax(0,1fr) 28px}.target-source,.target-verdict{display:none}.target-findings{text-align:right}.target-facts{grid-template-columns:repeat(2,minmax(0,1fr))}.linked-findings button{grid-template-columns:54px minmax(0,1fr)}.linked-findings small{display:none}.operation-search{flex-wrap:wrap}.operation-search input{flex-basis:100%}}
</style>

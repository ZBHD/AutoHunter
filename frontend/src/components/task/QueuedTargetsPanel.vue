<script setup>
import { computed, onUnmounted, ref, watch } from "vue";
import { api } from "../../api.js";
import { moveQueueTarget, queueOrderIds, sortQueueTargets } from "../../queuedTargets.js";

const props = defineProps({
  taskId: { type: String, required: true },
  active: { type: Boolean, default: false },
  readonly: { type: Boolean, default: false },
  progress: { type: Object, default: () => ({ total: 0, resolved: 0, percent: 0 }) },
});
const emit = defineEmits(["count"]);

const items = ref([]);
const loading = ref(false);
const saving = ref(false);
const deleting = ref(false);
const error = ref("");
const notice = ref("");
const sortField = ref("manual");
const sortDirection = ref("desc");
const dragIndex = ref(-1);
const deleteTarget = ref(null);
let loadVersion = 0;
let pollTimer = null;
let observedTaskId = "";

const progressPercent = computed(() => Math.max(0, Math.min(100, Number(props.progress.percent || 0))));
const canWrite = computed(() => !props.readonly && !saving.value && !deleting.value);

function errorMessage(err) {
  const raw = String(err?.message || err || "操作失败").replace(/^\d+\s*/, "").trim();
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed.detail === "string" ? parsed.detail : raw;
  } catch {
    return raw;
  }
}

function applyPayload(payload) {
  items.value = Array.isArray(payload) ? payload : (payload?.items || []);
  emit("count", Number(payload?.total ?? items.value.length));
}

async function loadQueue({ silent = false } = {}) {
  if (!props.active || !props.taskId || saving.value || deleting.value || dragIndex.value >= 0) return;
  const version = ++loadVersion;
  if (!silent) loading.value = true;
  error.value = "";
  try {
    const payload = await api.queuedTargets(props.taskId);
    if (version === loadVersion && props.active) applyPayload(payload);
  } catch (err) {
    if (version === loadVersion) error.value = errorMessage(err);
  } finally {
    if (version === loadVersion) loading.value = false;
  }
}

async function persistOrder(next, successMessage) {
  if (!canWrite.value || next.length !== items.value.length) return;
  const previous = items.value;
  items.value = next;
  saving.value = true;
  error.value = "";
  notice.value = "";
  try {
    const payload = await api.orderQueuedTargets(props.taskId, queueOrderIds(next));
    applyPayload(payload);
    notice.value = successMessage;
  } catch (err) {
    items.value = previous;
    const message = errorMessage(err);
    saving.value = false;
    await loadQueue({ silent: true });
    error.value = message;
  } finally {
    saving.value = false;
  }
}

async function applySort() {
  if (sortField.value === "manual") {
    await loadQueue();
    return;
  }
  const next = sortQueueTargets(items.value, sortField.value, sortDirection.value);
  await persistOrder(next, "排序已保存");
}

async function toggleSortDirection() {
  if (sortField.value === "manual") return;
  sortDirection.value = sortDirection.value === "asc" ? "desc" : "asc";
  await applySort();
}

async function move(index, delta) {
  const targetIndex = index + delta;
  if (!canWrite.value || targetIndex < 0 || targetIndex >= items.value.length) return;
  sortField.value = "manual";
  await persistOrder(moveQueueTarget(items.value, index, targetIndex), "顺序已保存");
}

function startDrag(index, event) {
  if (!canWrite.value) {
    event.preventDefault();
    return;
  }
  dragIndex.value = index;
  event.dataTransfer.effectAllowed = "move";
  event.dataTransfer.setData("text/plain", items.value[index].id);
}

async function dropAt(index) {
  const fromIndex = dragIndex.value;
  dragIndex.value = -1;
  if (fromIndex < 0 || fromIndex === index) return;
  sortField.value = "manual";
  await persistOrder(moveQueueTarget(items.value, fromIndex, index), "顺序已保存");
}

function endDrag() {
  dragIndex.value = -1;
}

async function confirmDelete() {
  const target = deleteTarget.value;
  if (!target || !canWrite.value) return;
  deleting.value = true;
  error.value = "";
  notice.value = "";
  let failure = "";
  try {
    await api.deleteQueuedTarget(props.taskId, target.id);
    deleteTarget.value = null;
  } catch (err) {
    failure = errorMessage(err);
    deleteTarget.value = null;
  } finally {
    deleting.value = false;
  }
  await loadQueue({ silent: true });
  if (failure) error.value = failure;
  else notice.value = "目标已从队列删除";
}

function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(() => loadQueue({ silent: true }), 4000);
}

watch(
  () => [props.active, props.taskId],
  ([active]) => {
    clearInterval(pollTimer);
    pollTimer = null;
    loadVersion += 1;
    loading.value = false;
    if (props.taskId !== observedTaskId) {
      observedTaskId = props.taskId;
      items.value = [];
      error.value = "";
      notice.value = "";
      emit("count", null);
    }
    if (active) {
      loadQueue();
      startPolling();
    }
  },
  { immediate: true },
);

onUnmounted(() => clearInterval(pollTimer));
</script>

<template>
  <section class="queued-targets-panel" aria-labelledby="queued-targets-title">
    <header class="queue-head">
      <div>
        <h3 id="queued-targets-title">FOFA 执行队列</h3>
        <div class="queue-progress-copy">
          <span>当前进度</span>
          <b>{{ progress.resolved || 0 }} / {{ progress.total || 0 }}</b>
          <strong>{{ progressPercent }}%</strong>
        </div>
      </div>
      <div class="queue-tools">
        <select v-model="sortField" aria-label="队列排序方式" :disabled="!canWrite" @change="applySort">
          <option value="manual">当前执行顺序</option>
          <option value="priority">目标优先级</option>
          <option value="created">发现时间</option>
          <option value="url">目标地址</option>
        </select>
        <button type="button" class="queue-icon-btn" :disabled="!canWrite || sortField === 'manual'"
          :aria-label="sortDirection === 'asc' ? '切换为降序' : '切换为升序'"
          :title="sortDirection === 'asc' ? '降序' : '升序'" @click="toggleSortDirection">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h13M3 12h9M3 18h5"/><path d="m17 15 3 3 3-3M20 6v12"/></svg>
        </button>
        <button type="button" class="queue-icon-btn" :disabled="loading || saving" aria-label="刷新队列"
          title="刷新" @click="loadQueue()">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v6h-6"/></svg>
        </button>
        <span class="queue-total">{{ items.length }} 项</span>
      </div>
    </header>

    <div class="queue-progress-track" role="progressbar" aria-label="任务当前进度"
      :aria-valuenow="progressPercent" aria-valuemin="0" aria-valuemax="100">
      <i :style="{ transform: `scaleX(${progressPercent / 100})` }"></i>
    </div>

    <p v-if="error" class="queue-message error" role="alert">{{ error }}</p>
    <p v-else-if="notice" class="queue-message" aria-live="polite">{{ notice }}</p>
    <div v-if="loading && !items.length" class="queue-empty">正在加载队列...</div>
    <div v-else-if="!items.length" class="queue-empty">当前没有等待执行的 FOFA 目标</div>

    <div v-else class="queue-list" :aria-busy="saving || deleting">
      <article v-for="(target, index) in items" :key="target.id" class="queue-row"
        :class="{ dragging: dragIndex === index }" :draggable="canWrite"
        @dragstart="startDrag(index, $event)" @dragover.prevent @drop.prevent="dropAt(index)" @dragend="endDrag">
        <span class="queue-position" :aria-label="`队列第 ${index + 1} 位`">#{{ index + 1 }}</span>
        <span class="queue-grip" aria-hidden="true">
          <svg viewBox="0 0 24 24"><circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/></svg>
        </span>
        <div class="queue-main">
          <b>{{ target.title || target.host || target.url }}</b>
          <code :title="target.url">{{ target.url }}</code>
          <small>{{ target.org || target.school || "FOFA" }}</small>
        </div>
        <div class="queue-score"><span>优先级</span><b>{{ Number(target.priority_score || 0).toFixed(1) }}</b></div>
        <time class="queue-time" :datetime="target.created_at">{{ target.created_at?.slice(0, 19).replace('T', ' ') }}</time>
        <div class="queue-actions">
          <button type="button" class="queue-icon-btn" :disabled="!canWrite || index === 0"
            :aria-label="`上移 ${target.host || target.url}`" title="上移" @click="move(index, -1)">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m18 15-6-6-6 6"/></svg>
          </button>
          <button type="button" class="queue-icon-btn" :disabled="!canWrite || index === items.length - 1"
            :aria-label="`下移 ${target.host || target.url}`" title="下移" @click="move(index, 1)">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <button type="button" class="queue-icon-btn danger" :disabled="!canWrite"
            :aria-label="`删除 ${target.host || target.url}`" title="删除" @click="deleteTarget = target">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5"/></svg>
          </button>
        </div>
      </article>
    </div>

    <Teleport to="body">
      <div v-if="deleteTarget" class="queue-modal-backdrop" @click.self="deleteTarget = null">
        <section class="queue-delete-modal" role="alertdialog" aria-modal="true" aria-labelledby="queue-delete-title">
          <h3 id="queue-delete-title">删除此队列目标？</h3>
          <code>{{ deleteTarget.url }}</code>
          <p>该目标将不再执行，也不会被 FOFA 重新加入此任务。</p>
          <footer>
            <button type="button" @click="deleteTarget = null">取消</button>
            <button type="button" class="danger-confirm" :disabled="deleting" @click="confirmDelete">
              {{ deleting ? "删除中..." : "确认删除" }}
            </button>
          </footer>
        </section>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.queued-targets-panel{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:16px}.queue-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.queue-head h3{margin:0;font-size:16px}.queue-progress-copy{display:flex;align-items:baseline;gap:9px;margin-top:6px;color:var(--muted);font-size:12px}.queue-progress-copy b{color:var(--ink);font-variant-numeric:tabular-nums}.queue-progress-copy strong{color:var(--accent);font-variant-numeric:tabular-nums}.queue-tools{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}.queue-tools select{min-height:38px}.queue-total{min-width:54px;color:var(--muted);font-size:12px;text-align:right;font-variant-numeric:tabular-nums}.queue-progress-track{height:4px;margin:14px 0 16px;overflow:hidden;background:var(--surface-2);border-radius:2px}.queue-progress-track i{display:block;width:100%;height:100%;transform-origin:left;background:var(--accent);transition:transform .25s ease}.queue-message{margin:0 0 12px;padding:9px 11px;border:1px solid color-mix(in srgb,var(--ok) 35%,var(--border));border-radius:6px;color:var(--ok);font-size:12px}.queue-message.error{border-color:color-mix(in srgb,var(--danger) 40%,var(--border));color:var(--danger)}.queue-empty{padding:34px;text-align:center;color:var(--muted)}.queue-list{display:grid;gap:8px}.queue-row{display:grid;grid-template-columns:48px 28px minmax(220px,1fr) 74px 142px 118px;gap:10px;align-items:center;min-height:74px;padding:10px 12px;border:1px solid var(--border);background:var(--surface-2);border-radius:7px;transition:border-color .15s ease,opacity .15s ease}.queue-row:hover{border-color:color-mix(in srgb,var(--accent) 42%,var(--border))}.queue-row.dragging{opacity:.48;border-color:var(--accent)}.queue-position{color:var(--accent);font-family:var(--mono);font-size:13px;font-weight:700;font-variant-numeric:tabular-nums}.queue-grip{display:grid;place-items:center;color:var(--muted);cursor:grab}.queue-grip svg{width:20px;height:24px;fill:currentColor}.queue-main{min-width:0}.queue-main b,.queue-main code,.queue-main small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.queue-main b{font-size:13px}.queue-main code{margin-top:4px;color:var(--muted);font-size:11px}.queue-main small{margin-top:3px;color:var(--muted);font-size:11px}.queue-score{display:grid;gap:3px;text-align:right}.queue-score span{color:var(--muted);font-size:10px}.queue-score b{font-family:var(--mono);font-size:13px;color:var(--warn)}.queue-time{color:var(--muted);font-family:var(--mono);font-size:10px;text-align:right}.queue-actions{display:flex;gap:6px;justify-content:flex-end}.queue-icon-btn{display:grid;place-items:center;width:38px;height:38px;padding:0;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--muted)}.queue-icon-btn:hover:not(:disabled),.queue-icon-btn:focus-visible{border-color:var(--accent);color:var(--accent)}.queue-icon-btn.danger:hover:not(:disabled),.queue-icon-btn.danger:focus-visible{border-color:var(--danger);color:var(--danger)}.queue-icon-btn svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}.queue-modal-backdrop{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;padding:16px;background:rgba(0,0,0,.64)}.queue-delete-modal{width:min(460px,100%);padding:20px;border:1px solid var(--border);border-radius:8px;background:var(--surface);box-shadow:0 20px 60px rgba(0,0,0,.35)}.queue-delete-modal h3{margin:0 0 12px;font-size:17px}.queue-delete-modal code{display:block;padding:10px;border-radius:6px;background:var(--surface-2);overflow-wrap:anywhere}.queue-delete-modal p{color:var(--muted);font-size:13px}.queue-delete-modal footer{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}.queue-delete-modal button{min-height:44px}.queue-delete-modal .danger-confirm{border-color:var(--danger);background:var(--danger);color:white}
@media(max-width:900px){.queue-row{grid-template-columns:46px 28px minmax(180px,1fr) 70px 118px}.queue-time{display:none}}
@media(max-width:680px){.queued-targets-panel{padding:12px}.queue-head{display:grid}.queue-tools{justify-content:flex-start}.queue-tools select{flex:1;min-width:150px}.queue-total{margin-left:auto}.queue-row{grid-template-columns:42px 26px minmax(0,1fr);min-height:112px}.queue-score,.queue-time{display:none}.queue-actions{grid-column:2/-1}.queue-icon-btn{width:44px;height:44px}.queue-main b,.queue-main code,.queue-main small{white-space:normal;overflow-wrap:anywhere}.queue-progress-copy{flex-wrap:wrap}}
@media(prefers-reduced-motion:reduce){.queue-progress-track i,.queue-row{transition:none}}
</style>

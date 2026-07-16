<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from "vue";
import { api } from "../api.js";
import {
  categoryLabel,
  cooldownLabel,
  endpointModeLabel,
  fofaHealthSnapshot,
  fofaKeyList,
  fofaKeyStatus,
  isFofaKeyUsable,
  isLegacyFofaKey,
  moveFofaKey,
  needsEffectiveFofaKeyReload,
} from "../fofaKeys.js";

const emit = defineEmits(["change", "mutated"]);

const keys = ref([]);
const loading = ref(true);
const loadError = ref("");
const actionError = ref("");
const deleteError = ref("");
const saving = ref(false);
const ordering = ref(false);
const mutationBusy = ref(false);
const busyNames = ref(new Set());
const testResults = reactive(new Map());
const editorOpen = ref(false);
const editingName = ref("");
const deleteTarget = ref(null);
const deleteCancelButton = ref(null);
const deleteErrorAlert = ref(null);
const addButton = ref(null);
const returnFocus = ref(null);
const nameInput = ref(null);
const baseUrlInput = ref(null);
const nowMs = ref(Date.now());
let clock = null;

const draft = reactive({
  name: "",
  key: "",
  key_set: false,
  base_url: "https://fofa.info",
  enabled: true,
});

const editing = computed(() => Boolean(editingName.value));
const keyRequired = computed(() => draft.enabled && !draft.key_set);
const usableCount = computed(() => keys.value.filter((item) => isFofaKeyUsable(item, nowMs.value)).length);

function applyKeys(response) {
  keys.value = fofaKeyList(response);
  emit("change", keys.value);
}

function errorMessage(error) {
  const raw = String(error?.message || error || "操作失败").replace(/^\d+\s*/, "").trim();
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed.detail === "string") return parsed.detail;
    if (Array.isArray(parsed.detail)) return parsed.detail.map((item) => item.msg || String(item)).join("；");
  } catch {
    // 非 JSON 错误直接显示服务端安全消息。
  }
  return raw || "操作失败";
}

function setBackgroundInert(value) {
  document.querySelector("#app")?.toggleAttribute("inert", value);
}

function restoreFocus() {
  const target = returnFocus.value;
  returnFocus.value = null;
  const destination = target?.isConnected ? target : addButton.value;
  if (destination?.isConnected && typeof destination.focus === "function") destination.focus();
}

function openDelete(item) {
  actionError.value = "";
  deleteError.value = "";
  returnFocus.value = document.activeElement;
  deleteTarget.value = item;
  setBackgroundInert(true);
  nextTick(() => deleteCancelButton.value?.focus());
}

function closeDelete(force = false) {
  if (mutationBusy.value && !force) return;
  deleteTarget.value = null;
  deleteError.value = "";
  setBackgroundInert(false);
  restoreFocus();
}

function trapModalFocus(event) {
  if (event.key !== "Tab" || (!editorOpen.value && !deleteTarget.value)) return;
  const modal = document.querySelector(deleteTarget.value ? ".provider-delete-modal" : ".provider-modal");
  const focusable = [...(modal?.querySelectorAll("button, input, select, textarea, [tabindex]") || [])]
    .filter((element) => !element.disabled && element.getAttribute("tabindex") !== "-1");
  if (!focusable.length) return;
  const current = document.activeElement;
  const index = focusable.indexOf(current);
  const next = event.shiftKey
    ? focusable[index <= 0 ? focusable.length - 1 : index - 1]
    : focusable[index === focusable.length - 1 ? 0 : index + 1];
  event.preventDefault();
  next.focus();
}

function markBusy(name, busy) {
  const next = new Set(busyNames.value);
  if (busy) next.add(name);
  else next.delete(name);
  busyNames.value = next;
}

async function loadKeys(showLoading = true) {
  if (showLoading) loading.value = true;
  loadError.value = "";
  try {
    applyKeys(await api.listFofaKeys());
  } catch (error) {
    loadError.value = errorMessage(error);
  } finally {
    if (showLoading) loading.value = false;
  }
}

function applyHealthCheck(response) {
  const snapshot = fofaHealthSnapshot(response);
  if (snapshot.keys.length) applyKeys(snapshot.keys);
  testResults.clear();
  for (const result of snapshot.results) {
    const legacy = snapshot.legacy && keys.value.find(isLegacyFofaKey);
    const name = legacy?.name || result.name;
    testResults.set(name, { ...result, name });
  }
}

defineExpose({ applyHealthCheck });

function resetDraft(item = null) {
  draft.name = item?.name || "";
  draft.key = "";
  draft.key_set = Boolean(item?.key_set);
  draft.base_url = item?.base_url || "https://fofa.info";
  draft.enabled = item?.enabled !== false;
}

async function openEditor(item = null) {
  actionError.value = "";
  returnFocus.value = document.activeElement;
  editingName.value = item?.name || "";
  resetDraft(item);
  editorOpen.value = true;
  setBackgroundInert(true);
  await nextTick();
  if (editing.value) baseUrlInput.value?.focus();
  else nameInput.value?.focus();
}

function closeEditor() {
  if (saving.value) return;
  editorOpen.value = false;
  editingName.value = "";
  draft.key = "";
  setBackgroundInert(false);
  restoreFocus();
}

async function saveKey() {
  actionError.value = "";
  if (keyRequired.value && !draft.key.trim()) {
    actionError.value = "启用的 FOFA Key 必须配置 Key";
    return;
  }
  const payload = {
    base_url: draft.base_url.trim(),
    enabled: Boolean(draft.enabled),
  };
  if (draft.key.trim()) payload.key = draft.key.trim();
  if (!editing.value) {
    payload.name = draft.name.trim();
    if (!("key" in payload)) payload.key = "";
  }

  saving.value = true;
  mutationBusy.value = true;
  try {
    const savedName = editingName.value;
    const response = editing.value
      ? await api.updateFofaKey(editingName.value, payload)
      : await api.createFofaKey(payload);
    applyKeys(response);
    if (savedName) testResults.delete(savedName);
    emit("mutated");
    editorOpen.value = false;
    editingName.value = "";
    draft.key = "";
    setBackgroundInert(false);
    restoreFocus();
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    saving.value = false;
    mutationBusy.value = false;
  }
}

async function toggleKey(item) {
  if (isLegacyFofaKey(item) || mutationBusy.value) return;
  actionError.value = "";
  markBusy(item.name, true);
  mutationBusy.value = true;
  try {
    applyKeys(await api.updateFofaKey(item.name, { enabled: !item.enabled }));
    testResults.delete(item.name);
    emit("mutated");
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    markBusy(item.name, false);
    mutationBusy.value = false;
  }
}

async function testKey(item) {
  if (mutationBusy.value) return;
  actionError.value = "";
  markBusy(item.name, true);
  mutationBusy.value = true;
  testResults.delete(item.name);
  try {
    const response = await api.testFofaKey(item.name);
    const result = response?.fofa_key || response;
    testResults.set(item.name, { ...result, name: item.name });
    await loadKeys(false);
    emit("mutated");
  } catch (error) {
    testResults.set(item.name, { name: item.name, ok: false, category: "transient", error: errorMessage(error) });
  } finally {
    markBusy(item.name, false);
    mutationBusy.value = false;
  }
}

async function reorder(index, delta) {
  if (mutationBusy.value) return;
  const names = keys.value.map((item) => item.name);
  const nextNames = moveFofaKey(names, index, delta);
  if (nextNames.every((name, position) => name === names[position])) return;

  actionError.value = "";
  ordering.value = true;
  mutationBusy.value = true;
  try {
    applyKeys(await api.orderFofaKeys(nextNames));
    emit("mutated");
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    ordering.value = false;
    mutationBusy.value = false;
  }
}

async function deleteKey() {
  const item = deleteTarget.value;
  if (!item || isLegacyFofaKey(item) || mutationBusy.value) return;
  deleteError.value = "";
  markBusy(item.name, true);
  mutationBusy.value = true;
  try {
    const response = await api.deleteFofaKey(item.name);
    testResults.delete(item.name);
    if (needsEffectiveFofaKeyReload(response)) await loadKeys();
    else applyKeys(response);
    closeDelete(true);
    emit("mutated");
  } catch (error) {
    deleteError.value = errorMessage(error);
    await nextTick();
    deleteErrorAlert.value?.focus();
  } finally {
    markBusy(item.name, false);
    mutationBusy.value = false;
  }
}

function handleEscape(event) {
  if (event.key !== "Escape") return;
  if (deleteTarget.value) closeDelete();
  else if (editorOpen.value) closeEditor();
}

onMounted(() => {
  loadKeys();
  clock = window.setInterval(() => (nowMs.value = Date.now()), 1000);
  window.addEventListener("keydown", handleEscape);
  window.addEventListener("keydown", trapModalFocus);
});
onUnmounted(() => {
  if (clock) window.clearInterval(clock);
  window.removeEventListener("keydown", handleEscape);
  window.removeEventListener("keydown", trapModalFocus);
  setBackgroundInert(false);
  draft.key = "";
});
</script>

<template>
  <section class="settings-block llm-provider-panel fofa-key-panel" aria-labelledby="fofa-key-title">
    <header class="provider-panel-head">
      <div>
        <h3 id="fofa-key-title">FOFA Key 池</h3>
        <p>多 Key 轮换、冷却恢复与自定义端点 · {{ usableCount }} 个可用</p>
      </div>
      <button ref="addButton" type="button" class="primary provider-add" :disabled="mutationBusy" @click="openEditor()">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
          stroke-width="2" stroke-linecap="round" aria-hidden="true">
          <path d="M12 5v14M5 12h14" />
        </svg>
        新增 FOFA Key
      </button>
    </header>

    <div v-if="loading" class="provider-state" aria-live="polite">正在加载 FOFA Key...</div>
    <div v-else-if="loadError" class="provider-state provider-state-error" role="alert">
      <span>{{ loadError }}</span>
      <button type="button" @click="loadKeys()">重试</button>
    </div>
    <template v-else>
      <div v-if="actionError" class="provider-action-error" role="alert">
        <span>{{ actionError }}</span>
        <button type="button" aria-label="关闭错误提示" title="关闭" @click="actionError = ''">×</button>
      </div>

      <div v-if="!keys.length" class="provider-state provider-empty">
        <b>尚未配置 FOFA Key</b>
        <span>新增一个 Key 后，Collector 会按状态自动选择和轮换。</span>
      </div>
      <div v-else class="provider-list">
        <article v-for="(item, index) in keys" :key="item.name"
          class="provider-row fofa-key-row"
          :class="{ disabled: !item.enabled, legacy: isLegacyFofaKey(item) }">
          <div class="provider-order" aria-label="FOFA Key 顺序">
            <button type="button" :disabled="mutationBusy || ordering || index === 0 || isLegacyFofaKey(item)"
              :aria-label="`上移 ${item.name}`" title="上移" @click="reorder(index, -1)">
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="m18 15-6-6-6 6" />
              </svg>
            </button>
            <button type="button" :disabled="mutationBusy || ordering || index === keys.length - 1 || isLegacyFofaKey(item)"
              :aria-label="`下移 ${item.name}`" title="下移" @click="reorder(index, 1)">
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="m6 9 6 6 6-6" />
              </svg>
            </button>
          </div>

          <div class="provider-main">
            <div class="provider-title">
              <b>{{ item.name }}</b>
              <span v-if="item.is_active" class="provider-badge active">当前使用</span>
              <span v-if="isLegacyFofaKey(item)" class="provider-badge legacy">兼容回退</span>
              <span class="provider-badge" :class="fofaKeyStatus(item).tone"
                :title="item.runtime_state || fofaKeyStatus(item).code">
                {{ fofaKeyStatus(item).label }}
              </span>
            </div>
            <code :title="item.base_url">{{ item.base_url }}</code>
            <div class="fofa-key-secret">
              <span>Key</span>
              <code :title="item.key">{{ item.key || "未配置" }}</code>
            </div>
            <dl class="provider-meta fofa-key-meta">
              <div><dt>状态码</dt><dd>{{ item.runtime_state || "ready" }}</dd></div>
              <div><dt>失败次数</dt><dd>{{ item.failure_count || 0 }}</dd></div>
              <div><dt>冷却</dt><dd>{{ cooldownLabel(item.cooldown_until, nowMs) || "—" }}</dd></div>
            </dl>
            <p v-if="testResults.get(item.name)" class="provider-test-result fofa-test-result"
              :class="{ ok: testResults.get(item.name).ok, stale: testResults.get(item.name).stale }"
              aria-live="polite">
              <span v-if="testResults.get(item.name).stale">结果已过期</span>
              <span v-else>{{ testResults.get(item.name).ok ? "检测成功" : "检测失败" }}</span>
              <template v-if="!testResults.get(item.name).stale">
                <span v-if="testResults.get(item.name).category"> · {{ categoryLabel(testResults.get(item.name).category) }}</span>
                <span v-if="testResults.get(item.name).latency_ms >= 0"> · {{ testResults.get(item.name).latency_ms }} ms</span>
                <span v-if="testResults.get(item.name).error"> · {{ testResults.get(item.name).error }}</span>
              </template>
            </p>
            <div v-if="testResults.get(item.name) && !testResults.get(item.name).stale"
              class="fofa-probe-details">
              <span v-if="testResults.get(item.name).http_status">HTTP {{ testResults.get(item.name).http_status }}</span>
              <span v-if="testResults.get(item.name).endpoint_mode">
                {{ endpointModeLabel(testResults.get(item.name).endpoint_mode) }}
              </span>
              <code v-if="testResults.get(item.name).resolved_url"
                :title="testResults.get(item.name).resolved_url">{{ testResults.get(item.name).resolved_url }}</code>
            </div>
          </div>

          <div class="provider-actions">
            <template v-if="!isLegacyFofaKey(item)">
              <button type="button" class="provider-switch" role="switch" :aria-checked="item.enabled"
                :disabled="mutationBusy || busyNames.has(item.name)" @click="toggleKey(item)">
                <span :class="{ on: item.enabled }"><i></i></span>
                {{ item.enabled ? "启用" : "停用" }}
              </button>
              <button type="button" :disabled="mutationBusy || busyNames.has(item.name)" @click="testKey(item)">
                {{ busyNames.has(item.name) ? "检测中..." : "检测" }}
              </button>
              <button type="button" class="provider-icon-action" :disabled="mutationBusy"
                :aria-label="`编辑 ${item.name}`" title="编辑" @click="openEditor(item)">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M12 20h9" /><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
                </svg>
              </button>
              <button type="button" class="provider-icon-action danger" :disabled="mutationBusy"
                :aria-label="`删除 ${item.name}`" title="删除" @click="openDelete(item)">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5" />
                </svg>
              </button>
            </template>
            <span v-else class="provider-readonly">只读 · 使用一键检测</span>
          </div>
        </article>
      </div>
    </template>

    <Teleport to="body">
      <div v-if="editorOpen" class="provider-modal-backdrop" @click.self="closeEditor">
        <form class="provider-modal" role="dialog" aria-modal="true" aria-labelledby="fofa-key-editor-title"
          @submit.prevent="saveKey">
          <header>
            <div>
              <h3 id="fofa-key-editor-title">{{ editing ? "编辑 FOFA Key" : "新增 FOFA Key" }}</h3>
              <p>{{ editing ? "名称不可修改，Key 留空会保留原值。" : "为一个可自动轮换的 FOFA 通道配置名称、地址和 Key。" }}</p>
            </div>
            <button type="button" class="icon-btn" aria-label="关闭" title="关闭" @click="closeEditor">×</button>
          </header>

          <div v-if="actionError" class="provider-action-error" role="alert">{{ actionError }}</div>
          <div class="provider-form-grid">
            <label>名称
              <input ref="nameInput" v-model="draft.name" required :disabled="editing"
                placeholder="Primary" autocomplete="off" />
            </label>
            <label>状态
              <select v-model="draft.enabled">
                <option :value="true">启用</option>
                <option :value="false">停用</option>
              </select>
            </label>
            <label class="full">FOFA URL
              <input ref="baseUrlInput" v-model="draft.base_url" required type="url"
                placeholder="https://fofa.info 或 http://fofapi.services/api.php" />
              <small class="fofa-url-hint">根地址会自动拼标准路径；填写 /api.php 或完整接口时按原地址调用。</small>
            </label>
            <label class="full">FOFA Key
              <input v-model="draft.key" type="password" :required="keyRequired" autocomplete="new-password"
                :placeholder="draft.key_set ? '已配置，留空保留原值' : (draft.enabled ? '启用前必须配置' : '可留空保存停用草稿')" />
            </label>
          </div>

          <footer>
            <button type="button" @click="closeEditor">取消</button>
            <button type="submit" class="primary" :disabled="saving">
              {{ saving ? "保存中..." : "保存 FOFA Key" }}
            </button>
          </footer>
        </form>
      </div>

      <div v-if="deleteTarget" class="provider-modal-backdrop" @click.self="closeDelete">
        <section class="provider-delete-modal" role="alertdialog" aria-modal="true"
          aria-labelledby="fofa-key-delete-title">
          <h3 id="fofa-key-delete-title">删除 {{ deleteTarget.name }}？</h3>
          <p>该 Key 会立即从轮换池移除，正在运行的任务会继续使用其余可用通道。</p>
          <div v-if="deleteError" ref="deleteErrorAlert" class="provider-action-error" role="alert" tabindex="-1">
            {{ deleteError }}
          </div>
          <div>
            <button ref="deleteCancelButton" type="button" @click="closeDelete">取消</button>
            <button type="button" class="provider-delete-confirm"
              :disabled="mutationBusy || busyNames.has(deleteTarget.name)" @click="deleteKey">
              {{ busyNames.has(deleteTarget.name) ? "删除中..." : "确认删除" }}
            </button>
          </div>
        </section>
      </div>
    </Teleport>
  </section>
</template>

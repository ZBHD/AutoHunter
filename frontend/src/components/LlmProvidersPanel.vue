<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { api } from "../api.js";
import {
  canReuseSavedProviderKey,
  isLegacyProvider,
  modelProbePayload,
  moveProvider,
  needsEffectiveProviderReload,
  providerHealthSnapshot,
  providerList,
  weightDistribution,
} from "../llmProviders.js";

const emit = defineEmits(["change", "mutated"]);

const providers = ref([]);
const loading = ref(true);
const loadError = ref("");
const actionError = ref("");
const saving = ref(false);
const ordering = ref(false);
const busyNames = ref(new Set());
const testResults = reactive(new Map());
const editorOpen = ref(false);
const editingName = ref("");
const deleteTarget = ref(null);
const nameInput = ref(null);
const baseUrlInput = ref(null);
const availableModels = ref([]);
const modelsLoading = ref(false);
const modelsError = ref("");
const savedBaseUrl = ref("");

const draft = reactive({
  name: "",
  base_url: "https://api.openai.com/v1",
  api_key: "",
  api_key_set: false,
  model: "",
  temperature: 0.3,
  weight: 5,
  protocol: "openai_chat",
  enabled: true,
});

const distribution = computed(() => weightDistribution(providers.value));
const enabledWeight = computed(() => distribution.value.reduce((sum, item) => sum + Number(item.weight || 0), 0));
const editing = computed(() => Boolean(editingName.value));
const keyRequired = computed(() => draft.enabled && !draft.api_key_set);
const canLoadModels = computed(() => (
  Boolean(draft.base_url.trim())
  && Boolean(
    draft.api_key.trim()
    || (
      editing.value
      && draft.api_key_set
      && canReuseSavedProviderKey(savedBaseUrl.value, draft.base_url)
    )
  )
));

const protocolLabels = {
  openai_chat: "OpenAI Chat",
  anthropic_messages: "Anthropic Messages",
  openai_responses: "OpenAI Responses",
};

function applyProviders(response) {
  providers.value = providerList(response);
  emit("change", providers.value);
}

function applyHealthCheck(response) {
  const snapshot = providerHealthSnapshot(response);
  testResults.clear();
  for (const result of snapshot.results) {
    testResults.set(result.name, result);
  }
  applyProviders(snapshot.providers);
}

defineExpose({ applyHealthCheck });

function errorMessage(error) {
  const raw = String(error?.message || error || "操作失败").replace(/^\d+\s*/, "").trim();
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed.detail === "string") return parsed.detail;
    if (Array.isArray(parsed.detail)) {
      return parsed.detail.map((item) => item.msg || String(item)).join("；");
    }
  } catch {
    // 非 JSON 错误直接显示服务端安全消息。
  }
  return raw || "操作失败";
}

function markBusy(name, busy) {
  const names = new Set(busyNames.value);
  if (busy) names.add(name);
  else names.delete(name);
  busyNames.value = names;
}

async function loadProviders() {
  loading.value = true;
  loadError.value = "";
  try {
    applyProviders(await api.listLlmProviders());
  } catch (error) {
    loadError.value = errorMessage(error);
  } finally {
    loading.value = false;
  }
}

function resetDraft(provider = null) {
  availableModels.value = [];
  modelsError.value = "";
  savedBaseUrl.value = provider?.base_url || "";
  draft.name = provider?.name || "";
  draft.base_url = provider?.base_url || "https://api.openai.com/v1";
  draft.api_key = "";
  draft.api_key_set = Boolean(provider?.api_key_set);
  draft.model = provider?.model || "";
  draft.temperature = Number(provider?.temperature ?? 0.3);
  draft.weight = Number(provider?.weight ?? 5);
  draft.protocol = provider?.protocol || "openai_chat";
  draft.enabled = provider?.enabled !== false;
}

async function loadModels() {
  if (!canLoadModels.value || modelsLoading.value) return;
  modelsLoading.value = true;
  modelsError.value = "";
  availableModels.value = [];
  const payload = modelProbePayload({
    baseUrl: draft.base_url,
    apiKey: draft.api_key,
    protocol: draft.protocol,
    providerName: editingName.value,
  });
  try {
    const response = await api.listModels(
      payload.base_url,
      payload.api_key || undefined,
      payload.protocol,
      payload.provider_name,
    );
    if (!response?.ok) {
      modelsError.value = response?.error || "未获取到可用模型";
      return;
    }
    availableModels.value = [...new Set(
      (response.models || []).map((model) => String(model || "").trim()).filter(Boolean),
    )];
    if (!availableModels.value.length) {
      modelsError.value = "该 Provider 未返回可用模型";
      return;
    }
    if (!draft.model.trim()) draft.model = availableModels.value[0];
  } catch (error) {
    modelsError.value = errorMessage(error);
  } finally {
    modelsLoading.value = false;
  }
}

async function openEditor(provider = null) {
  actionError.value = "";
  editingName.value = provider?.name || "";
  resetDraft(provider);
  editorOpen.value = true;
  await nextTick();
  if (editing.value) baseUrlInput.value?.focus();
  else nameInput.value?.focus();
}

function closeEditor() {
  if (saving.value) return;
  editorOpen.value = false;
  editingName.value = "";
}

async function saveProvider() {
  actionError.value = "";
  if (keyRequired.value && !draft.api_key.trim()) {
    actionError.value = "启用的 Provider 必须配置 API Key";
    return;
  }

  const payload = {
    base_url: draft.base_url.trim(),
    model: draft.model.trim(),
    temperature: Number(draft.temperature),
    weight: Number(draft.weight),
    protocol: draft.protocol,
    enabled: Boolean(draft.enabled),
  };
  if (draft.api_key.trim()) payload.api_key = draft.api_key.trim();
  if (!editing.value) {
    payload.name = draft.name.trim();
    if (!("api_key" in payload)) payload.api_key = "";
  }

  saving.value = true;
  try {
    const savedName = editingName.value;
    const response = editing.value
      ? await api.updateLlmProvider(editingName.value, payload)
      : await api.createLlmProvider(payload);
    applyProviders(response);
    if (savedName) testResults.delete(savedName);
    emit("mutated");
    editorOpen.value = false;
    editingName.value = "";
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    saving.value = false;
  }
}

async function toggleProvider(provider) {
  if (isLegacyProvider(provider)) return;
  actionError.value = "";
  markBusy(provider.name, true);
  try {
    applyProviders(await api.updateLlmProvider(provider.name, { enabled: !provider.enabled }));
    testResults.delete(provider.name);
    emit("mutated");
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    markBusy(provider.name, false);
  }
}

async function testProvider(provider) {
  actionError.value = "";
  markBusy(provider.name, true);
  testResults.delete(provider.name);
  try {
    testResults.set(provider.name, await api.testLlmProvider(provider.name));
  } catch (error) {
    testResults.set(provider.name, { ok: false, error: errorMessage(error) });
  } finally {
    markBusy(provider.name, false);
  }
}

async function reorder(index, delta) {
  const names = providers.value.map((provider) => provider.name);
  const nextNames = moveProvider(names, index, delta);
  if (nextNames.every((name, position) => name === names[position])) return;

  actionError.value = "";
  ordering.value = true;
  try {
    applyProviders(await api.orderLlmProviders(nextNames));
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    ordering.value = false;
  }
}

async function deleteProvider() {
  const provider = deleteTarget.value;
  if (!provider || isLegacyProvider(provider)) return;
  actionError.value = "";
  markBusy(provider.name, true);
  try {
    const response = await api.deleteLlmProvider(provider.name);
    testResults.delete(provider.name);
    deleteTarget.value = null;
    if (needsEffectiveProviderReload(response)) await loadProviders();
    else applyProviders(response);
    emit("mutated");
  } catch (error) {
    actionError.value = errorMessage(error);
  } finally {
    markBusy(provider.name, false);
  }
}

function handleEscape(event) {
  if (event.key !== "Escape") return;
  if (deleteTarget.value) deleteTarget.value = null;
  else if (editorOpen.value) closeEditor();
}

onMounted(() => {
  loadProviders();
  window.addEventListener("keydown", handleEscape);
});
onUnmounted(() => window.removeEventListener("keydown", handleEscape));

watch(
  () => [draft.base_url, draft.api_key, draft.protocol],
  () => {
    availableModels.value = [];
    modelsError.value = "";
  },
);
</script>

<template>
  <section class="settings-block llm-provider-panel" aria-labelledby="llm-provider-title">
    <header class="provider-panel-head">
      <div>
        <h3 id="llm-provider-title">LLM Provider 池</h3>
        <p>多协议模型通道与首选权重</p>
      </div>
      <button type="button" class="primary provider-add" @click="openEditor()">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
          stroke-width="2" stroke-linecap="round" aria-hidden="true">
          <path d="M12 5v14M5 12h14" />
        </svg>
        新增 Provider
      </button>
    </header>

    <div v-if="loading" class="provider-state" aria-live="polite">正在加载 Provider...</div>
    <div v-else-if="loadError" class="provider-state provider-state-error" role="alert">
      <span>{{ loadError }}</span>
      <button type="button" @click="loadProviders">重试</button>
    </div>
    <template v-else>
      <div v-if="distribution.length" class="provider-weight" aria-label="启用 Provider 权重分布">
        <div class="provider-weight-summary">
          <span>启用权重</span>
          <b>{{ enabledWeight }}</b>
        </div>
        <div class="provider-weight-bar" role="img"
          :aria-label="distribution.map((item) => `${item.name} ${item.percentage.toFixed(1)}%`).join('，')">
          <i v-for="item in distribution" :key="item.name"
            :style="{ width: `${item.percentage}%` }" :title="`${item.name} ${item.percentage.toFixed(1)}%`"></i>
        </div>
        <div class="provider-weight-legend">
          <span v-for="item in distribution" :key="item.name">
            <i></i><b>{{ item.name }}</b><em>{{ item.percentage.toFixed(1) }}%</em>
          </span>
        </div>
      </div>
      <div v-else-if="providers.length" class="provider-no-enabled" role="status">
        当前没有启用的 Provider
      </div>

      <div v-if="actionError" class="provider-action-error" role="alert">
        <span>{{ actionError }}</span>
        <button type="button" aria-label="关闭错误提示" title="关闭" @click="actionError = ''">×</button>
      </div>

      <div v-if="!providers.length" class="provider-state provider-empty">
        <b>尚未配置 Provider</b>
        <span>新增一个通道后，任务即可使用全局 Provider 池。</span>
      </div>
      <div v-else class="provider-list">
        <article v-for="(provider, index) in providers" :key="provider.name"
          class="provider-row" :class="{ disabled: !provider.enabled, legacy: isLegacyProvider(provider) }">
          <div class="provider-order" aria-label="Provider 顺序">
            <button type="button" :disabled="ordering || index === 0 || isLegacyProvider(provider)"
              :aria-label="`上移 ${provider.name}`" title="上移" @click="reorder(index, -1)">
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="m18 15-6-6-6 6" />
              </svg>
            </button>
            <button type="button" :disabled="ordering || index === providers.length - 1 || isLegacyProvider(provider)"
              :aria-label="`下移 ${provider.name}`" title="下移" @click="reorder(index, 1)">
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="m6 9 6 6 6-6" />
              </svg>
            </button>
          </div>

          <div class="provider-main">
            <div class="provider-title">
              <b>{{ provider.name }}</b>
              <span v-if="isLegacyProvider(provider)" class="provider-badge legacy">兼容回退</span>
              <span v-else-if="provider.enabled" class="provider-badge enabled">已启用</span>
              <span v-else class="provider-badge">已停用</span>
            </div>
            <code :title="provider.base_url">{{ provider.base_url }}</code>
            <dl class="provider-meta">
              <div><dt>协议</dt><dd>{{ protocolLabels[provider.protocol] || provider.protocol }}</dd></div>
              <div><dt>模型</dt><dd :title="provider.model">{{ provider.model }}</dd></div>
              <div><dt>权重</dt><dd>{{ provider.weight }}</dd></div>
              <div><dt>温度</dt><dd>{{ provider.temperature }}</dd></div>
            </dl>
            <p v-if="testResults.get(provider.name)" class="provider-test-result"
              :class="{ ok: testResults.get(provider.name).ok, stale: testResults.get(provider.name).stale }"
              aria-live="polite">
              <span v-if="testResults.get(provider.name).stale">结果已过期</span>
              <span v-else>{{ testResults.get(provider.name).ok ? "连接成功" : "连接失败" }}</span>
              <template v-if="testResults.get(provider.name).ok && !testResults.get(provider.name).stale">
                · {{ testResults.get(provider.name).latency_ms }} ms
              </template>
              <template v-else-if="!testResults.get(provider.name).stale">
                · {{ testResults.get(provider.name).error || "服务不可用" }}
                <strong v-if="testResults.get(provider.name).auto_disabled"> · 已自动停用</strong>
                <span v-if="testResults.get(provider.name).recommended_protocol">
                  · 建议协议 {{ protocolLabels[testResults.get(provider.name).recommended_protocol]
                    || testResults.get(provider.name).recommended_protocol }}
                </span>
                <span v-if="testResults.get(provider.name).diagnostic"
                  :title="testResults.get(provider.name).diagnostic">
                  · 诊断 {{ testResults.get(provider.name).diagnostic }}
                </span>
              </template>
            </p>
          </div>

          <div class="provider-actions">
            <template v-if="!isLegacyProvider(provider)">
              <button type="button" class="provider-switch" role="switch" :aria-checked="provider.enabled"
                :disabled="busyNames.has(provider.name)" @click="toggleProvider(provider)">
                <span :class="{ on: provider.enabled }"><i></i></span>
                {{ provider.enabled ? "启用" : "停用" }}
              </button>
            </template>
            <button type="button" :disabled="busyNames.has(provider.name)"
              @click="testProvider(provider)">
              {{ busyNames.has(provider.name) ? "处理中..." : "测试" }}
            </button>
            <template v-if="!isLegacyProvider(provider)">
              <button type="button" class="provider-icon-action" :aria-label="`编辑 ${provider.name}`"
                title="编辑" @click="openEditor(provider)">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M12 20h9" /><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
                </svg>
              </button>
              <button type="button" class="provider-icon-action danger" :aria-label="`删除 ${provider.name}`"
                title="删除" @click="deleteTarget = provider">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5" />
                </svg>
              </button>
            </template>
            <span v-else class="provider-readonly">只读</span>
          </div>
        </article>
      </div>
    </template>

    <Teleport to="body">
      <div v-if="editorOpen" class="provider-modal-backdrop" @click.self="closeEditor">
        <form class="provider-modal" role="dialog" aria-modal="true" aria-labelledby="provider-editor-title"
          @submit.prevent="saveProvider">
          <header>
            <div>
              <h3 id="provider-editor-title">{{ editing ? "编辑 Provider" : "新增 Provider" }}</h3>
              <p>{{ editing ? "名称不可修改，API Key 留空会保留原值。" : "配置可参与全局池调度的模型通道。" }}</p>
            </div>
            <button type="button" class="icon-btn" aria-label="关闭" title="关闭" @click="closeEditor">×</button>
          </header>

          <div v-if="actionError" class="provider-action-error" role="alert">{{ actionError }}</div>
          <div class="provider-form-grid">
            <label>名称
              <input ref="nameInput" v-model="draft.name" required :disabled="editing"
                placeholder="Primary" autocomplete="off" />
            </label>
            <label>协议
              <select v-model="draft.protocol">
                <option value="openai_chat">OpenAI Chat Completions</option>
                <option value="anthropic_messages">Anthropic Messages</option>
                <option value="openai_responses">OpenAI Responses</option>
              </select>
            </label>
            <label class="full">Base URL
              <input ref="baseUrlInput" v-model="draft.base_url" required type="url"
                placeholder="https://api.openai.com/v1" />
            </label>
            <label class="full">API Key
              <input v-model="draft.api_key" type="password" :required="keyRequired"
                autocomplete="new-password"
                :placeholder="draft.api_key_set ? '已配置，留空保留原值' : (draft.enabled ? '启用前必须配置' : '可留空保存停用草稿')" />
            </label>
            <label class="full">模型
              <div class="provider-model-picker">
                <select v-if="availableModels.length" v-model="draft.model" required>
                  <option v-if="draft.model && !availableModels.includes(draft.model)" :value="draft.model">
                    {{ draft.model }}（当前）
                  </option>
                  <option v-for="model in availableModels" :key="model" :value="model">{{ model }}</option>
                </select>
                <input v-else v-model="draft.model" required placeholder="gpt-4.1-mini" autocomplete="off" />
                <button type="button" class="provider-model-fetch" :disabled="!canLoadModels || modelsLoading"
                  @click="loadModels">
                  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                    stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M20 12a8 8 0 1 1-2.34-5.66" /><path d="M20 4v6h-6" />
                  </svg>
                  {{ modelsLoading ? "获取中..." : "获取模型" }}
                </button>
              </div>
              <small v-if="modelsError" class="provider-model-error" role="alert">{{ modelsError }}</small>
              <small v-else-if="availableModels.length" class="provider-model-status">
                已获取 {{ availableModels.length }} 个模型
              </small>
            </label>
            <label>Temperature
              <input v-model="draft.temperature" required type="number" min="0" max="2" step="0.1" />
            </label>
            <label>权重
              <input v-model="draft.weight" required type="number" min="1" max="100" step="1" />
            </label>
            <label class="provider-enabled-field full">
              <input v-model="draft.enabled" type="checkbox" />
              <span><b>启用 Provider</b><small>启用后参与首选权重分配和故障切换</small></span>
            </label>
          </div>

          <footer>
            <button type="button" @click="closeEditor">取消</button>
            <button type="submit" class="primary" :disabled="saving">
              {{ saving ? "保存中..." : "保存 Provider" }}
            </button>
          </footer>
        </form>
      </div>

      <div v-if="deleteTarget" class="provider-modal-backdrop" @click.self="deleteTarget = null">
        <section class="provider-delete-modal" role="alertdialog" aria-modal="true"
          aria-labelledby="provider-delete-title">
          <h3 id="provider-delete-title">删除 {{ deleteTarget.name }}？</h3>
          <p>该 Provider 会立即从全局池移除，现有任务的后续调用将不再使用它。</p>
          <div>
            <button type="button" @click="deleteTarget = null">取消</button>
            <button type="button" class="provider-delete-confirm"
              :disabled="busyNames.has(deleteTarget.name)" @click="deleteProvider">
              {{ busyNames.has(deleteTarget.name) ? "删除中..." : "确认删除" }}
            </button>
          </div>
        </section>
      </div>
    </Teleport>
  </section>
</template>

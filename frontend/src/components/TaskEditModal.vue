<script setup>
import { computed, reactive, ref, watch } from "vue";
import { api } from "../api.js";
import VulnerabilityTypeSelector from "./VulnerabilityTypeSelector.vue";
import { isAutoSource, isManualOnly, isSiteSource, isFofaPoolMode, fofaKeyPatch } from "../taskSourceModes.js";
import {
  buildLiteLlmTaskPayload,
  litellmFormFromTask,
  validateLiteLlmForm,
} from "../litellmTaskMode.js";

const props = defineProps({
  open: Boolean,
  task: Object,
});
const emit = defineEmits(["close", "saved"]);

const models = ref([]);            // 拉取到的可用模型列表
const modelsLoading = ref(false);
const modelsError = ref("");
const useCustomModel = ref(false); // 列表外手输模式
const formError = ref("");

async function loadModels() {
  if (form.use_global_pool) {
    models.value = [];
    modelsError.value = "";
    return;
  }
  modelsLoading.value = true;
  modelsError.value = "";
  try {
    const res = await api.listModels(
      form.base_url || undefined,
      form.api_key || undefined,
      form.protocol,
    );
    if (res?.ok && res.models?.length) {
      models.value = res.models;
      // 当前模型不在列表里 → 默认进入手输模式，避免选错
      useCustomModel.value = !!form.model && !models.value.includes(form.model);
    } else {
      models.value = [];
      modelsError.value = res?.error || "未获取到模型列表";
      useCustomModel.value = true;
    }
  } catch (e) {
    models.value = [];
    modelsError.value = "拉取失败，可手动输入模型名";
    useCustomModel.value = true;
  } finally {
    modelsLoading.value = false;
  }
}

const form = reactive({
  name: "",
  src_type: "edusrc",
  vuln_types: [],
  hunt_direction: "",
  target_source: "fofa",
  engine: "",
  fofa_query: "",
  intent_mode: "",
  manual_targets: "",
  src_rules: "",
  use_global_pool: true,
  base_url: "",
  api_key: "",
  api_key_set: false,
  model: "",
  protocol: "openai_chat",
  temperature: 0.3,
  prompt_version: "current",
  fofa_key: "",
  fofa_key_mode: "global",
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  concurrency: 3,
  site_recon_mode: "full",
  ...litellmFormFromTask({}),
});
const original = reactive({
  use_global_pool: true,
  intent_mode: "",
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  fofa_key_mode: "global",
  fofa_is_fofa: true,
});
const isSiteMode = computed(() => form.target_source === "site");
const isLiteLlmMode = computed(() => form.src_type === "litellm");
const isAutoMode = computed(() => isAutoSource(form.target_source));
const isManualOnlyMode = computed(() => isManualOnly(form.target_source));
const isFofaMode = computed(() => isFofaPoolMode(form.target_source, form.engine));
const showManualTargets = computed(() => isManualOnlyMode.value || isSiteSource(form.target_source) || form.target_source === "both");
const dedicatedKeyRequired = computed(() => (
  !form.use_global_pool && (original.use_global_pool || !form.api_key_set)
));

function handleTargetSourceChange() {
  if (isSiteMode.value) form.site_recon_mode = "full";
}

function handleTaskModeChange() {
  formError.value = "";
  if (isLiteLlmMode.value && form.target_source === "site") {
    form.target_source = "fofa";
  }
}

function handleEngineChange() {
  if (!isFofaMode.value) {
    form.fofa_key_mode = "global";
  }
}

function setFofaKeyMode(mode) {
  form.fofa_key_mode = mode;
}

function fill(task) {
  if (!task) return;
  const modelCfg = task.model_config_data || {};
  const fofaCfg = task.fofa_config || {};
  form.name = task.name || "";
  form.src_type = task.src_type || "edusrc";
  form.vuln_types = [...(task.vuln_types || [])];
  form.hunt_direction = task.hunt_direction || "";
  form.target_source = task.target_source || "fofa";
  form.site_recon_mode = fofaCfg.site_recon_mode || "full";
  form.engine = task.engine || "";
  form.fofa_query = task.fofa_query || "";
  form.intent_mode = fofaCfg.intent_mode || "";
  form.manual_targets = (task.manual_targets || []).join("\n");
  form.src_rules = task.src_rules || "";
  form.use_global_pool = modelCfg.use_global_pool !== false;
  form.base_url = modelCfg.base_url || "";
  form.api_key = "";
  form.api_key_set = Boolean(modelCfg.api_key_set);
  form.model = modelCfg.model || "";
  form.protocol = modelCfg.protocol || "openai_chat";
  form.temperature = Number(modelCfg.temperature ?? 0.3);
  form.prompt_version = modelCfg.prompt_version || "current";
  form.fofa_key = "";
  const initialIsFofa = isFofaPoolMode(form.target_source, form.engine);
  const initialHasTaskKey = fofaCfg.key_source === "task";
  form.fofa_key_mode = initialIsFofa && initialHasTaskKey ? "task" : "global";
  form.fofa_base_url = fofaCfg.base_url || "";
  form.max_pages = fofaCfg.max_pages ?? 20;
  form.page_size = fofaCfg.page_size ?? 100;
  form.concurrency = task.concurrency || 3;
  Object.assign(form, litellmFormFromTask(task));
  original.use_global_pool = form.use_global_pool;
  original.intent_mode = form.intent_mode;
  original.fofa_base_url = form.fofa_base_url;
  original.max_pages = Number(form.max_pages);
  original.page_size = Number(form.page_size);
  original.fofa_key_mode = initialHasTaskKey ? "task" : "global";
  original.fofa_is_fofa = initialIsFofa;
  // 重置模型列表状态（打开弹窗时 watch 会随即自动 loadModels 拉好列表）
  models.value = [];
  modelsError.value = "";
  useCustomModel.value = false;
  formError.value = "";
}

watch(() => props.task, fill, { immediate: true });
watch(() => props.open, (open) => {
  if (open) {
    fill(props.task);
    if (!form.use_global_pool) loadModels();
  }
});

async function save() {
  formError.value = "";
  const liteValidation = isLiteLlmMode.value ? validateLiteLlmForm(form) : null;
  if (liteValidation && !liteValidation.valid) {
    formError.value = liteValidation.errors[0];
    return;
  }
  const modelConfig = {
    use_global_pool: form.use_global_pool,
    prompt_version: form.prompt_version,
  };
  if (!form.use_global_pool) {
    modelConfig.base_url = form.base_url.trim();
    modelConfig.model = form.model.trim();
    modelConfig.protocol = form.protocol;
    modelConfig.temperature = Number(form.temperature);
    if (form.api_key.trim()) modelConfig.api_key = form.api_key.trim();
  }

  const maxPages = parseInt(form.max_pages) || 20;
  const pageSize = parseInt(form.page_size) || 100;
  const fofaConfig = {};
  const engineConfig = {};
  Object.assign(fofaConfig, fofaKeyPatch({
    initialMode: original.fofa_key_mode,
    finalMode: form.fofa_key_mode,
    initialIsFofa: original.fofa_is_fofa,
    finalIsFofa: isFofaMode.value,
    key: form.fofa_key,
  }));
  if (isFofaMode.value) {
    if (maxPages !== original.max_pages) fofaConfig.max_pages = maxPages;
    if (pageSize !== original.page_size) fofaConfig.page_size = pageSize;
    if (form.intent_mode !== original.intent_mode) fofaConfig.intent_mode = form.intent_mode;
    if (form.fofa_base_url !== original.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
  } else if (isAutoMode.value) {
    if (form.fofa_key.trim()) engineConfig.key = form.fofa_key.trim();
    if (form.fofa_base_url !== original.fofa_base_url) engineConfig.base_url = form.fofa_base_url;
  }
  if (isSiteMode.value) fofaConfig.site_recon_mode = form.site_recon_mode;

  const body = {
    name: form.name,
    src_type: form.src_type,
    vuln_types: [...form.vuln_types],
    hunt_direction: form.hunt_direction.trim(),
    target_source: form.target_source,
    engine: isAutoMode.value ? form.engine : "",
    fofa_query: isAutoMode.value || isSiteMode.value ? form.fofa_query : "",
    manual_targets: showManualTargets.value
      ? form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean)
      : [],
    src_rules: form.src_rules,
    concurrency: parseInt(form.concurrency) || 3,
    model_config_data: modelConfig,
    fofa_config: fofaConfig,
    engine_config: engineConfig,
  };
  if (isLiteLlmMode.value) {
    Object.assign(body, buildLiteLlmTaskPayload(form));
  }
  const updated = await api.updateTask(props.task.id, body);
  emit("saved", updated);
}
</script>

<template>
  <div v-if="open" class="task-edit-backdrop" @click.self="emit('close')">
    <form class="task-edit-modal" @submit.prevent="save">
      <header>
        <div>
          <h3>编辑任务参数</h3>
          <p>运行中的任务会在下一轮调度读取新参数；密钥留空则保留原值。</p>
        </div>
        <button type="button" class="icon-btn" @click="emit('close')">×</button>
      </header>

      <div class="settings-grid">
        <label>任务名称 <input v-model="form.name" required /></label>
        <label>worker 并发 <input v-model="form.concurrency" type="number" min="1" max="20" /></label>
        <label>任务模式
          <select v-model="form.src_type" @change="handleTaskModeChange">
            <option value="edusrc">EduSRC（教育行业）</option>
            <option value="enterprise">企业SRC</option>
            <option value="litellm">LiteLLM（专项网关巡检）</option>
          </select>
        </label>
        <label>目标来源
          <select v-model="form.target_source" @change="handleTargetSourceChange">
            <option value="fofa">FOFA 自动搜</option>
            <option value="manual">手动清单</option>
            <option value="both">两者</option>
            <option v-if="!isLiteLlmMode" value="site">单站协作</option>
          </select>
        </label>
        <div v-if="isSiteMode" class="site-recon-mode full">
          <div class="model-mode-switch" role="group" aria-label="入口盘点模式">
            <button type="button" :class="{ active: form.site_recon_mode === 'full' }"
              :aria-pressed="form.site_recon_mode === 'full'"
              @click="form.site_recon_mode = 'full'">
              完整入口盘点
            </button>
            <button type="button" :class="{ active: form.site_recon_mode === 'light' }"
              :aria-pressed="form.site_recon_mode === 'light'"
              @click="form.site_recon_mode = 'light'">
              轻量入口盘点（最多 18 轮）
            </button>
          </div>
          <p class="model-mode-copy">轻量模式保留全部路由，仅将 site_map 预算限制为最多 18 轮。</p>
        </div>
        <label v-if="isAutoMode">搜索引擎
          <select v-model="form.engine" @change="handleEngineChange">
            <option value="">默认引擎</option>
            <option value="fofa">FOFA</option>
            <option value="quake">360 Quake</option>
            <option value="hunter">Hunter (鹰图)</option>
            <option value="zoomeye">ZoomEye</option>
            <option value="shodan">Shodan</option>
            <option value="censys">Censys</option>
          </select>
        </label>
        <label v-if="isFofaMode && !isLiteLlmMode">搜集方式
          <select v-model="form.intent_mode">
            <option value="">自动判断</option>
            <option value="syntax">FOFA 语法</option>
            <option value="intent">自然语言意图</option>
          </select>
        </label>
      </div>

      <section v-if="isLiteLlmMode" class="litellm-mode-panel">
        <header>
          <h3>LiteLLM 专项检测</h3>
          <span>PROFILE v1</span>
        </header>
        <div class="model-mode-switch" role="group" aria-label="LiteLLM 巡检范围">
          <button type="button" :class="{ active: form.scopeMode === 'targeted' }"
            :aria-pressed="form.scopeMode === 'targeted'" @click="form.scopeMode = 'targeted'">
            定向巡检
          </button>
          <button type="button" :class="{ active: form.scopeMode === 'global' }"
            :aria-pressed="form.scopeMode === 'global'" @click="form.scopeMode = 'global'; form.target_source = 'fofa'">
            全网巡检
          </button>
        </div>
        <label v-if="form.scopeMode === 'targeted'">范围锚点（每行一个）
          <textarea v-model="form.scopeAnchors" rows="3" placeholder="example.com&#10;org:Example Corp&#10;cert:Example Gateway"></textarea>
        </label>
        <fieldset class="litellm-checks">
          <legend>检测项</legend>
          <label><input v-model="form.checks.key_leak" type="checkbox" /> Key 泄露</label>
          <label><input v-model="form.checks.env_leak" type="checkbox" /> 环境配置泄露</label>
          <label><input v-model="form.checks.management_exposure" type="checkbox" /> 管理接口暴露</label>
          <label><input v-model="form.checks.anonymous_models" type="checkbox" /> 匿名模型列表</label>
          <label><input v-model="form.checks.anonymous_inference" type="checkbox" /> 匿名最小推理</label>
        </fieldset>
        <div class="litellm-settings-grid">
          <label>验证级别
            <select v-model="form.validationLevel">
              <option value="basic">基础验证</option>
              <option value="full">完整验证</option>
            </select>
          </label>
          <label>单资产请求预算
            <input v-model="form.maxRequestsPerAssetEpoch" type="number" min="1" max="10000" />
          </label>
          <label>每轮凭据验证上限
            <input v-model="form.maxProviderValidationsPerCycle" type="number" min="0" max="10000" />
          </label>
          <label>最小推理 Token
            <input v-model="form.maxTokens" type="number" min="1" max="8" />
          </label>
          <label>已确认复查（小时）
            <input v-model="form.confirmedRecheckHours" type="number" min="0" max="720" />
          </label>
          <label>已保护复查（小时）
            <input v-model="form.protectedRecheckHours" type="number" min="0" max="720" />
          </label>
          <label>不可达复查（小时）
            <input v-model="form.unreachableRecheckHours" type="number" min="0" max="720" />
          </label>
        </div>
      </section>

      <VulnerabilityTypeSelector v-model="form.vuln_types" v-if="!isLiteLlmMode" />
      <label v-if="!isLiteLlmMode">指定挖掘方向（可选）
        <textarea v-model="form.hunt_direction" rows="3" maxlength="2000"
          placeholder="例：重点测试后台 API 的水平/垂直越权、批量导出和敏感写操作；优先关注 object_id、user_id 等对象参数。"></textarea>
      </label>
        <label v-if="isAutoMode && !isLiteLlmMode">FOFA 语法 / 搜集意图 <input v-model="form.fofa_query" /></label>
        <label v-else-if="isSiteMode">目标相关信息 / 协作重点 / 已有凭据
        <textarea v-model="form.fofa_query" rows="4" placeholder="可写重点方向、后台位置，以及【已有的登录凭据】。给了凭据 Agent 会先前台测、再登录进系统内部深挖。&#10;例：后台在 /admin；已有账号 test / Test@123；或 Cookie: JSESSIONID=xxxx"></textarea>
      </label>
        <label v-if="showManualTargets">{{ isSiteMode ? "主目标 URL（每行一个，会自动拆成多条协作路线）" : (isLiteLlmMode ? "LiteLLM 网关 URL（每行一个）" : "手动目标清单（每行一个）") }}
        <textarea v-model="form.manual_targets" rows="3"></textarea>
      </label>

      <details open>
        <summary>高级：模型{{ isFofaMode ? " / FOFA" : "" }}</summary>
        <div class="model-mode-switch" role="group" aria-label="任务模型来源">
          <button type="button" :class="{ active: form.use_global_pool }" :aria-pressed="form.use_global_pool"
            @click="form.use_global_pool = true">
            使用全局 Provider 池
          </button>
          <button type="button" :class="{ active: !form.use_global_pool }" :aria-pressed="!form.use_global_pool"
            @click="form.use_global_pool = false">
            任务专用模型
          </button>
        </div>
        <p class="model-mode-copy">
          {{ form.use_global_pool ? "后续调用使用全局权重与故障切换。" : "后续调用固定使用此任务的独立模型。" }}
        </p>
        <div class="settings-grid">
          <label v-if="!form.use_global_pool">协议
            <select v-model="form.protocol">
              <option value="openai_chat">OpenAI Chat Completions</option>
              <option value="anthropic_messages">Anthropic Messages</option>
              <option value="openai_responses">OpenAI Responses</option>
            </select>
          </label>
          <label v-if="!form.use_global_pool">Temperature
            <input v-model="form.temperature" type="number" min="0" max="2" step="0.1" required />
          </label>
          <label v-if="!form.use_global_pool" class="full">模型 base_url
            <input v-model="form.base_url" type="url" placeholder="https://api.openai.com/v1" required />
          </label>
          <label v-if="!form.use_global_pool" class="model-field full">
            模型名
            <div class="model-picker">
              <select v-if="models.length && !useCustomModel" v-model="form.model">
                <option v-for="m in models" :key="m" :value="m">{{ m }}</option>
              </select>
              <input v-else v-model="form.model" placeholder="deepseek-chat" />
              <button type="button" class="ghost-btn" :disabled="modelsLoading" @click="loadModels" title="改了 base_url/api_key 后可重新拉取">
                {{ modelsLoading ? "拉取中…" : "刷新" }}
              </button>
              <button
                v-if="models.length"
                type="button"
                class="ghost-btn"
                @click="useCustomModel = !useCustomModel"
              >
                {{ useCustomModel ? "选列表" : "手动输入" }}
              </button>
            </div>
            <small v-if="modelsError" class="model-hint">{{ modelsError }}</small>
            <small v-else-if="models.length" class="model-hint">已获取 {{ models.length }} 个可用模型</small>
          </label>
          <label class="full">Worker 提示词
            <select v-model="form.prompt_version">
              <option value="current">current（当前省 token 版）</option>
              <option value="legacy">legacy（旧版 23/25 风格）</option>
              <option value="modern">modern（当前完整版）</option>
            </select>
          </label>
          <label v-if="!form.use_global_pool" class="full">模型 api_key
            <input v-model="form.api_key" type="password" autocomplete="new-password"
              :required="dedicatedKeyRequired"
              :placeholder="dedicatedKeyRequired ? '切换到专用模型时必须填写' : '已配置，留空保留原值'" />
          </label>
          <template v-if="isFofaMode">
            <div class="model-mode-switch" role="group" aria-label="FOFA Key 来源">
              <button type="button" :class="{ active: form.fofa_key_mode === 'global' }"
                :aria-pressed="form.fofa_key_mode === 'global'" @click="setFofaKeyMode('global')">
                使用全局 FOFA Key 池
              </button>
              <button type="button" :class="{ active: form.fofa_key_mode === 'task' }"
                :aria-pressed="form.fofa_key_mode === 'task'" @click="setFofaKeyMode('task')">
                任务专用 FOFA Key
              </button>
            </div>
            <p class="model-mode-copy">任务专用 Key 不参与全局轮换。</p>
            <label v-if="form.fofa_key_mode === 'task'">FOFA Key <input v-model="form.fofa_key" type="password" placeholder="留空保留原值" /></label>
            <label>FOFA API 端点 <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
            <label>FOFA 最大页数 <input v-model="form.max_pages" type="number" min="1" max="200" /></label>
            <label>FOFA page_size <input v-model="form.page_size" type="number" min="1" max="1000" /></label>
          </template>
          <template v-else-if="isAutoMode">
            <label>{{ form.engine || "搜索引擎" }} Key <input v-model="form.fofa_key" type="password" placeholder="留空保留原值" /></label>
            <label>{{ form.engine || "搜索引擎" }} API 端点 <input v-model="form.fofa_base_url" placeholder="https://api.example.com" /></label>
          </template>
        </div>
      </details>

      <label v-if="!isLiteLlmMode">SRC 规则
        <textarea v-model="form.src_rules" rows="3"></textarea>
      </label>

      <p v-if="formError" class="form-error" role="alert">{{ formError }}</p>

      <footer>
        <button type="button" @click="emit('close')">取消</button>
        <button type="submit" class="primary">保存参数</button>
      </footer>
    </form>
  </div>
</template>

<style scoped>
.model-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.model-picker {
  display: flex;
  gap: 6px;
  align-items: center;
}
.model-picker select,
.model-picker input {
  flex: 1;
  min-width: 0;
}
.ghost-btn {
  flex: 0 0 auto;
  padding: 6px 10px;
  font-size: 12px;
  border: 1px solid var(--border, #d0d5dd);
  background: transparent;
  border-radius: 6px;
  cursor: pointer;
  white-space: nowrap;
}
.ghost-btn:disabled {
  opacity: 0.5;
  cursor: default;
}
.model-hint {
  color: var(--muted, #98a2b3);
  font-size: 11px;
}
</style>

<script setup>
import { computed, reactive, ref, onMounted } from "vue";
import { api } from "../api.js";
import LlmProvidersPanel from "../components/LlmProvidersPanel.vue";
import {
  isProviderUsable,
  markHealthCheckStale,
  summarizeHealthCheck,
} from "../llmProviders.js";

const loading = ref(true);
const saving = ref(false);
const toastMsg = ref("");
const meta = ref({ updated_at: null });
const providers = ref([]);
const providerPanel = ref(null);
const healthChecking = ref(false);
const healthResponse = ref(null);
const healthError = ref("");
const enabledProviders = computed(() => providers.value.filter(isProviderUsable));
const healthSummary = computed(() => summarizeHealthCheck(healthResponse.value || {}));

const form = reactive({
  fofa_key: "",
  fofa_key_set: false,
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  default_intent_mode: "",
  concurrency: 3,
  skip_score_threshold: -10,
  worker_prompt_version: "legacy",
});

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

function markHealthStale() {
  if (!healthResponse.value) return;
  healthResponse.value = markHealthCheckStale(healthResponse.value);
}

async function runHealthCheck() {
  if (healthChecking.value) return;
  healthChecking.value = true;
  healthError.value = "";
  try {
    const response = await api.healthCheck();
    healthResponse.value = response;
    providerPanel.value?.applyHealthCheck(response);
  } catch (error) {
    healthError.value = String(error?.message || error || "检测失败")
      .replace(/^\d+\s*/, "")
      .trim();
  } finally {
    healthChecking.value = false;
  }
}

async function load() {
  loading.value = true;
  try {
    const s = await api.getSettings();
    meta.value = { updated_at: s.updated_at };
    providers.value = s.llm_providers || [];
    form.fofa_key = "";
    form.fofa_key_set = s.fofa?.key_set;
    form.fofa_base_url = s.fofa?.base_url || "";
    form.max_pages = s.fofa?.max_pages ?? 20;
    form.page_size = s.fofa?.page_size ?? 100;
    form.default_intent_mode = s.fofa?.default_intent_mode || "";
    form.concurrency = s.defaults?.concurrency ?? 3;
    form.skip_score_threshold = s.defaults?.skip_score_threshold ?? -10;
    form.worker_prompt_version = s.defaults?.worker_prompt_version || "legacy";
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    const body = {
      fofa: {
        base_url: form.fofa_base_url,
        max_pages: Number(form.max_pages),
        page_size: Number(form.page_size),
        default_intent_mode: form.default_intent_mode,
      },
      defaults: {
        concurrency: Number(form.concurrency),
        skip_score_threshold: Number(form.skip_score_threshold),
        worker_prompt_version: form.worker_prompt_version,
      },
    };
    if (form.fofa_key.trim()) body.fofa.key = form.fofa_key.trim();
    const s = await api.updateSettings(body);
    meta.value = { updated_at: s.updated_at };
    form.fofa_key = "";
    form.fofa_key_set = s.fofa?.key_set;
    markHealthStale();
    toast("系统配置已保存");
  } catch (e) {
    toast(String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <section class="view settings-view">
    <header class="page-head">
      <h2>系统配置</h2>
      <p class="page-sub">
        管理全局 Provider 池、FOFA 与调度参数。任务可使用全局池，或显式切换到专用模型。
        <span v-if="meta.updated_at" class="settings-updated">上次保存 {{ meta.updated_at?.slice(0, 19).replace("T", " ") }}</span>
      </p>
    </header>

    <div v-if="loading" class="empty">加载中…</div>
    <div v-else class="settings-layout">
      <aside class="settings-summary" aria-label="当前系统配置摘要">
        <div class="settings-summary-head">
          <span>ACTIVE PROFILE</span>
          <b>全局默认</b>
        </div>
        <div class="settings-health">
          <div>
            <span>LLM</span>
            <b>{{ providers.length ? `${enabledProviders.length} 启用 · ${providers.length} 已加载` : "未配置 Provider" }}</b>
          </div>
          <i :class="{ on: enabledProviders.length }">{{ enabledProviders.length ? "pool ready" : "pool idle" }}</i>
        </div>
        <div class="settings-health">
          <div>
            <span>FOFA</span>
            <b>{{ form.max_pages }} 页 · {{ form.page_size }} / 页</b>
          </div>
          <i :class="{ on: form.fofa_key_set }">{{ form.fofa_key_set ? "key set" : "no key" }}</i>
        </div>
        <dl class="settings-facts">
          <div>
            <dt>任务默认并发</dt>
            <dd>{{ form.concurrency }}</dd>
          </div>
          <div>
            <dt>低分跳过阈值</dt>
            <dd>{{ form.skip_score_threshold }}</dd>
          </div>
          <div>
            <dt>Worker 提示词</dt>
            <dd>{{ form.worker_prompt_version }}</dd>
          </div>
        </dl>
        <p class="settings-note">
          权重决定每次调用的首选 Provider；单次失败后会按列表顺序切换到其余可用通道。
        </p>
        <section class="settings-health-check" :class="{ stale: healthSummary.stale }">
          <button type="button" class="primary settings-health-action"
            :disabled="healthChecking" @click="runHealthCheck">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
              stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 12a8 8 0 1 1-2.34-5.66" />
              <path d="M20 4v6h-6" />
            </svg>
            {{ healthChecking ? "检测中…" : "一键检测" }}
          </button>

          <div class="settings-health-live" aria-live="polite" aria-atomic="true">
            <p v-if="healthChecking" class="health-check-running">正在检测 LLM Provider 与 FOFA</p>
            <p v-else-if="healthError" class="health-check-error" role="alert">{{ healthError }}</p>
            <template v-else-if="healthSummary.total">
              <div class="health-check-head">
                <b>{{ healthSummary.stale ? "结果已过期" : `${healthSummary.passed}/${healthSummary.total} 可用` }}</b>
                <time v-if="healthSummary.checkedAt" :datetime="healthSummary.checkedAt">
                  {{ healthSummary.checkedAt.slice(0, 19).replace("T", " ") }}
                </time>
              </div>
              <div class="health-check-stats" aria-label="检测统计">
                <span><b>{{ healthSummary.passed }}</b>通过</span>
                <span><b>{{ healthSummary.failed }}</b>失败</span>
                <span><b>{{ healthSummary.autoDisabled }}</b>停用</span>
              </div>
              <ul class="health-check-results">
                <li v-for="result in healthSummary.results" :key="result.name"
                  :class="{
                    ok: result.ok,
                    failed: !result.ok,
                    stale: healthSummary.stale || result.stale,
                  }">
                  <i aria-hidden="true"></i>
                  <div>
                    <span class="health-check-result-title">
                      <b :title="result.name">{{ result.name }}</b>
                      <strong>{{ healthSummary.stale || result.stale ? "过期" : (result.ok ? "通过" : "失败") }}</strong>
                    </span>
                    <small v-if="healthSummary.stale || result.stale">配置已变更，请重新检测</small>
                    <small v-else-if="result.ok">
                      {{ result.latency_ms }} ms<span v-if="result.model"> · {{ result.model }}</span>
                    </small>
                    <small v-else>
                      {{ result.error || "连接失败" }}
                      <em v-if="result.auto_disabled">已自动停用</em>
                    </small>
                  </div>
                </li>
              </ul>
            </template>
          </div>
        </section>
      </aside>

      <div class="settings-main">
        <LlmProvidersPanel ref="providerPanel" @change="providers = $event" @mutated="markHealthStale" />

        <form class="form settings-form" @submit.prevent="save">
          <fieldset class="settings-block">
            <legend>
              <span>FOFA</span>
              <small>Collector 默认资产搜集参数</small>
            </legend>
            <div class="settings-grid">
              <label class="full">FOFA key
                <input v-model="form.fofa_key" type="password"
                  :placeholder="form.fofa_key_set ? '已配置，留空不修改' : 'FOFA API Key'" />
              </label>
              <label class="full">API 端点
                <input v-model="form.fofa_base_url" placeholder="https://fofa.info" />
              </label>
              <p class="field-hint full">自定义 FOFA 兼容端点（私有部署/镜像/代理网关），留空用官方地址。</p>
              <label>默认最大页数 <input v-model="form.max_pages" type="number" min="1" /></label>
              <label>每页条数 <input v-model="form.page_size" type="number" min="1" /></label>
              <label class="full">默认搜集方式
                <select v-model="form.default_intent_mode">
                  <option value="">自动判断</option>
                  <option value="syntax">FOFA 语法</option>
                  <option value="intent">自然语言意图</option>
                </select>
              </label>
            </div>
          </fieldset>

          <fieldset class="settings-block">
            <legend>
              <span>调度默认</span>
              <small>新任务创建时的保守默认值</small>
            </legend>
            <div class="settings-grid">
              <label>新建任务默认并发 <input v-model="form.concurrency" type="number" min="1" max="32" /></label>
              <label>低分跳过阈值
                <input v-model="form.skip_score_threshold" type="number" step="1" />
              </label>
              <label class="full">Worker 提示词版本
                <select v-model="form.worker_prompt_version">
                  <option value="legacy">legacy（旧版 23/25 风格）</option>
                  <option value="current">current（当前省 token 版）</option>
                  <option value="modern">modern（当前完整版）</option>
                </select>
              </label>
              <p class="field-hint full">Collector 评分低于此值的目标直接跳过，避免 worker 消耗在垃圾资产上。</p>
            </div>
          </fieldset>

          <div class="settings-actions">
            <button type="submit" class="primary" :disabled="saving">{{ saving ? "保存中…" : "保存配置" }}</button>
            <span>FOFA 密钥留空时不会覆盖已有值。</span>
          </div>
        </form>
      </div>
    </div>

    <div v-if="toastMsg" class="toast settings-toast">{{ toastMsg }}</div>
  </section>
</template>

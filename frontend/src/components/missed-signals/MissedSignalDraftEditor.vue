<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from "vue";
import { api } from "../../api.js";
import {
  createDraftFlushQueue,
  draftContentFromForm,
  draftFormFromContent,
} from "../../missedSignals.js";

const props = defineProps({
  signalId: { type: String, required: true },
  writable: { type: Boolean, default: false },
});
const emit = defineEmits(["confirmed", "toast"]);

const draft = ref(null);
const form = ref({});
const missingEvidenceText = ref("");
const loading = ref(false);
const generating = ref(false);
const saving = ref(false);
const confirming = ref(false);
const dirty = ref(false);
const error = ref("");
let hydrating = false;
let loadVersion = 0;
let editVersion = 0;
let savingSignalId = "";
let loadedSignalId = "";
let switchVersion = 0;
let unmounted = false;

function draftPayload(value) {
  return value?.draft || value || null;
}

function missingEvidence(value = missingEvidenceText.value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function evidenceJsonIsValid(value) {
  try {
    JSON.parse(String(value || "{}"));
    return true;
  } catch {
    return false;
  }
}

function currentDraftSnapshot() {
  if (!props.writable || !loadedSignalId || !draft.value || !dirty.value
      || draft.value.status === "confirmed") return null;
  return {
    signalId: loadedSignalId,
    revision: draft.value.revision,
    editVersion,
    form: { ...form.value },
    originalContent: draft.value.content || {},
    missingEvidenceText: missingEvidenceText.value,
  };
}

async function persistDraftSnapshot(snapshot) {
  const signalId = snapshot.signalId;
  if (!evidenceJsonIsValid(snapshot.form.evidence_json)) {
    if (!unmounted && loadedSignalId === signalId) {
      error.value = "证据 JSON 格式不正确，尚未保存";
    }
    return { revision: snapshot.revision, skipped: true };
  }

  savingSignalId = signalId;
  if (!unmounted && loadedSignalId === signalId) {
    saving.value = true;
    error.value = "";
  }
  try {
    const value = await api.updateMissedSignalDraft(signalId, {
      revision: snapshot.revision,
      content: draftContentFromForm(snapshot.form, snapshot.originalContent),
      missing_evidence: missingEvidence(snapshot.missingEvidenceText),
    });
    const updated = draftPayload(value);
    if (!unmounted && loadedSignalId === signalId) {
      draft.value = { ...draft.value, ...updated };
      dirty.value = snapshot.editVersion !== editVersion;
    }
    return updated;
  } catch (saveError) {
    if (!unmounted && loadedSignalId === signalId) {
      error.value = String(saveError?.message || saveError);
    }
    throw saveError;
  } finally {
    if (savingSignalId === signalId) savingSignalId = "";
    if (!unmounted && loadedSignalId === signalId) saving.value = false;
  }
}

const draftSaver = createDraftFlushQueue({
  delayMs: 600,
  persist: persistDraftSnapshot,
  onError: () => {},
});

function scheduleSave() {
  const snapshot = currentDraftSnapshot();
  if (snapshot) draftSaver.schedule(snapshot);
}

async function flushCurrentDraft() {
  const snapshot = currentDraftSnapshot();
  if (snapshot) draftSaver.schedule(snapshot);
  return draftSaver.flush(snapshot?.signalId || loadedSignalId);
}

async function applyDraft(value, signalId) {
  hydrating = true;
  loadedSignalId = signalId;
  draft.value = value;
  form.value = draftFormFromContent(value?.content || {});
  missingEvidenceText.value = (value?.missing_evidence || []).join("\n");
  dirty.value = false;
  editVersion = 0;
  await nextTick();
  hydrating = false;
}

async function loadDraft(requestedSignalId = props.signalId) {
  const signalId = String(requestedSignalId || props.signalId);
  const version = ++loadVersion;
  saving.value = savingSignalId === signalId;
  loading.value = true;
  error.value = "";
  try {
    const value = await api.missedSignalDraft(signalId);
    if (!unmounted && props.signalId === signalId && version === loadVersion) {
      await applyDraft(draftPayload(value), signalId);
    }
  } catch (loadError) {
    if (unmounted || props.signalId !== signalId || version !== loadVersion) return;
    const message = String(loadError?.message || loadError);
    if (!/^404\b/.test(message)) error.value = message;
    await applyDraft(null, signalId);
  } finally {
    if (!unmounted && props.signalId === signalId && version === loadVersion) loading.value = false;
  }
}

async function saveDraft() {
  try {
    return await flushCurrentDraft();
  } catch (saveError) {
    if (!unmounted && loadedSignalId === props.signalId) {
      error.value = String(saveError?.message || saveError);
    }
    return undefined;
  }
}

async function switchDraft(signalIdValue) {
  const signalId = String(signalIdValue || "");
  const version = ++switchVersion;
  const previousSignalId = loadedSignalId;
  if (previousSignalId && previousSignalId !== signalId) {
    try { await flushCurrentDraft(); }
    catch { /* The pending snapshot remains available for a later retry. */ }
  }
  if (unmounted || version !== switchVersion || props.signalId !== signalId) return;
  await loadDraft(signalId);
}

async function generateDraft() {
  if (!props.writable || generating.value) return;
  if (dirty.value) await saveDraft();
  if (dirty.value || error.value) return;
  const signalId = props.signalId;
  generating.value = true;
  error.value = "";
  try {
    const value = await api.generateMissedSignalDraft(signalId);
    if (props.signalId !== signalId) return;
    const generated = draftPayload(value);
    if (generated?.content || generated?.status) await applyDraft(generated, signalId);
    else await loadDraft(signalId);
    emit("toast", draft.value?.status === "failed" ? "草稿生成失败，可重试或手工编辑" : "报告草稿已生成");
  } catch (generateError) {
    if (props.signalId !== signalId) return;
    const message = String(generateError?.message || generateError);
    // Generation failures are persisted by the API so the user can retry or edit manually.
    await loadDraft(signalId);
    error.value = draft.value?.last_error || message;
  } finally {
    generating.value = false;
  }
}

async function confirmDraft() {
  if (!props.writable || !draft.value || confirming.value) return;
  if (dirty.value) await flushCurrentDraft().catch(() => undefined);
  if (dirty.value || error.value) return;
  const signalId = loadedSignalId;
  confirming.value = true;
  try {
    const result = await api.confirmMissedSignalDraft(signalId, { revision: draft.value.revision });
    if (props.signalId !== signalId) return;
    draft.value = { ...draft.value, status: "confirmed" };
    emit("toast", result?.already_confirmed ? "该草稿已经转入复审" : "已生成正式报告并进入复审队列");
    emit("confirmed", result);
  } catch (confirmError) {
    error.value = String(confirmError?.message || confirmError);
  } finally {
    confirming.value = false;
  }
}

watch(() => props.signalId, switchDraft, { immediate: true });
watch([form, missingEvidenceText], () => {
  if (hydrating || !props.writable || !draft.value || draft.value.status === "confirmed") return;
  editVersion += 1;
  dirty.value = true;
  scheduleSave();
}, { deep: true });

onBeforeUnmount(() => {
  const snapshot = currentDraftSnapshot();
  if (snapshot) draftSaver.schedule(snapshot);
  unmounted = true;
  switchVersion += 1;
  loadVersion += 1;
  void draftSaver.flushAll().catch(() => undefined);
});
</script>

<template>
  <section class="draft-editor operation-section">
    <header class="section-head">
      <div>
        <h4>报告草稿</h4>
        <p v-if="draft">修订 {{ draft.revision }} · {{ saving ? "保存中…" : dirty ? "等待保存" : "已保存" }}</p>
      </div>
      <span v-if="draft" class="status-chip" :class="draft.status">{{ draft.status }}</span>
    </header>

    <div v-if="loading" class="operations-empty compact">正在读取草稿…</div>
    <div v-else-if="!draft" class="draft-empty">
      <p>尚未生成报告草稿。生成过程只整理现有证据，不会向目标发包。</p>
      <button v-if="writable" type="button" class="primary" :disabled="generating" @click="generateDraft">
        {{ generating ? "生成中…" : "生成报告草稿" }}
      </button>
    </div>
    <template v-else>
      <p v-if="draft.last_error" class="operations-error">{{ draft.last_error }}</p>
      <div class="draft-toolbar" v-if="writable && draft.status !== 'confirmed'">
        <button type="button" :disabled="generating" @click="generateDraft">{{ generating ? "重新生成中…" : "重新生成" }}</button>
        <button type="button" :disabled="saving || !dirty" @click="saveDraft">立即保存</button>
      </div>
      <div class="draft-fields" :class="{ readonly: !writable || draft.status === 'confirmed' }">
        <label class="span-2">标题<input v-model="form.title" :disabled="!writable || draft.status === 'confirmed'" /></label>
        <label>漏洞类型<input v-model="form.vuln_type" :disabled="!writable || draft.status === 'confirmed'" /></label>
        <label>漏洞等级
          <select v-model="form.severity" :disabled="!writable || draft.status === 'confirmed'">
            <option value="严重">严重</option><option value="高危">高危</option>
            <option value="中危">中危</option><option value="低危">低危</option>
          </select>
        </label>
        <label class="span-2">归属单位及依据<input v-model="form.owner" :disabled="!writable || draft.status === 'confirmed'" /></label>
        <label class="span-2">目标 URL<input v-model="form.target_url" :disabled="!writable || draft.status === 'confirmed'" /></label>
        <label class="span-2">漏洞描述<textarea v-model="form.description" rows="4" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">影响范围<textarea v-model="form.affected_scope" rows="3" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">复现步骤（每行一步）<textarea v-model="form.steps" rows="5" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">PoC<textarea v-model="form.poc" rows="5" class="mono-input" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">原始请求<textarea v-model="form.raw_request" rows="7" class="mono-input" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">原始响应<textarea v-model="form.raw_response" rows="7" class="mono-input" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">证据 JSON<textarea v-model="form.evidence_json" rows="6" class="mono-input" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">攻击链路（每行“动作｜细节”）<textarea v-model="form.kill_chain" rows="5" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
        <label class="span-2">待补充证据（每行一项）<textarea v-model="missingEvidenceText" rows="3" :disabled="!writable || draft.status === 'confirmed'"></textarea></label>
      </div>
      <div v-if="writable && draft.status !== 'confirmed'" class="draft-confirm">
        <span>确认后创建正式 Finding，并进入人工复审队列。</span>
        <button type="button" class="primary" :disabled="confirming || saving" @click="confirmDraft">
          {{ confirming ? "确认中…" : "确认并转报告" }}
        </button>
      </div>
    </template>
    <p v-if="error" class="operations-error" role="alert">{{ error }}</p>
  </section>
</template>

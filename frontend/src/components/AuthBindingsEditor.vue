<script setup>
import { ref } from "vue";
import { emptyAuthBinding, parseAuthPaste } from "../authBindings.js";

const props = defineProps({ modelValue: { type: Array, default: () => [] } });
const emit = defineEmits(["update:modelValue"]);
const quickPaste = ref("");

function replaceRow(index, field, value) {
  const rows = props.modelValue.map((row, rowIndex) => (
    rowIndex === index ? { ...row, [field]: value } : row
  ));
  emit("update:modelValue", rows);
}

function addEmpty() {
  emit("update:modelValue", [...props.modelValue, emptyAuthBinding()]);
}

function addFromPaste() {
  if (!quickPaste.value.trim()) return;
  emit("update:modelValue", [
    ...props.modelValue,
    parseAuthPaste(quickPaste.value),
  ]);
  quickPaste.value = "";
}

function removeRow(index) {
  emit("update:modelValue", props.modelValue.filter((_row, rowIndex) => rowIndex !== index));
}
</script>

<template>
  <section class="auth-bindings-editor" aria-labelledby="auth-bindings-title">
    <header class="auth-bindings-head">
      <div>
        <h3 id="auth-bindings-title">登录凭据绑定</h3>
        <p>按目标绑定账号、Cookie 或 Authorization；匹配后由 Worker 启动时使用。</p>
      </div>
      <button type="button" class="ghost-btn" @click="addEmpty">添加绑定</button>
    </header>

    <div class="auth-quick-paste">
      <label>
        快速粘贴
        <textarea v-model="quickPaste" rows="3"
          placeholder="目标 URL、Cookie、Authorization 或 username / password"></textarea>
      </label>
      <button type="button" class="ghost-btn" :disabled="!quickPaste.trim()" @click="addFromPaste">
        解析并添加
      </button>
    </div>

    <div v-if="modelValue.length" class="auth-binding-list">
      <fieldset v-for="(binding, index) in modelValue" :key="index" class="auth-binding-row">
        <legend>绑定 {{ index + 1 }}</legend>
        <button type="button" class="auth-binding-remove" :aria-label="`删除绑定 ${index + 1}`"
          title="删除绑定" @click="removeRow(index)">×</button>
        <div class="auth-binding-grid">
          <label class="full">绑定目标
            <input :value="binding.target" placeholder="portal.example、完整 URL 或 *"
              @input="replaceRow(index, 'target', $event.target.value)" />
          </label>
          <label>账号
            <input :value="binding.username" autocomplete="off"
              @input="replaceRow(index, 'username', $event.target.value)" />
          </label>
          <label>密码
            <input :value="binding.password" type="password" autocomplete="new-password"
              @input="replaceRow(index, 'password', $event.target.value)" />
          </label>
          <label class="full">Cookie
            <input :value="binding.cookie" autocomplete="off" placeholder="sid=...; token=..."
              @input="replaceRow(index, 'cookie', $event.target.value)" />
          </label>
          <label class="full">Authorization
            <input :value="binding.authorization" autocomplete="off" placeholder="Bearer ..."
              @input="replaceRow(index, 'authorization', $event.target.value)" />
          </label>
          <label class="full">登录 URL（可选）
            <input :value="binding.login_url" type="url" placeholder="https://portal.example/sign-in"
              @input="replaceRow(index, 'login_url', $event.target.value)" />
          </label>
          <label class="full">备注
            <input :value="binding.note" placeholder="账号角色、适用范围"
              @input="replaceRow(index, 'note', $event.target.value)" />
          </label>
          <label v-if="binding.raw" class="full">未识别原文
            <textarea :value="binding.raw" rows="2"
              @input="replaceRow(index, 'raw', $event.target.value)"></textarea>
          </label>
        </div>
      </fieldset>
    </div>
  </section>
</template>

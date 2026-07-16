<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  api,
  applyAccessToken,
  authReadyRef,
  authRoleRef,
  cancelTokenModal,
  loadAuthRole,
  submitTokenModal,
} from "./api.js";
import { canAccessRoute, isNavigationActive, primaryNavigation } from "./navigation.js";
import {
  currentTheme,
  setThemePreference,
  TOKEN_DIALOG_EVENT,
} from "./preferences.js";

const route = useRoute();
const router = useRouter();
const showTokenModal = ref(false);
const tokenInput = ref("");
const tokenModalReason = ref("switch");
const toastMsg = ref("");
const operationCounts = ref({ reviewPending: 0, missedPending: 0, killsweepFailed: 0 });
const visibleNavigation = computed(() => primaryNavigation(authRoleRef.value, operationCounts.value));

function toast(message, ms = 2600) {
  toastMsg.value = message;
  setTimeout(() => {
    if (toastMsg.value === message) toastMsg.value = "";
  }, ms);
}

function openTokenDialog(reason = "switch") {
  tokenModalReason.value = reason;
  tokenInput.value = "";
  showTokenModal.value = true;
}

async function refreshOperationCounts() {
  if (!["full", "readonly"].includes(authRoleRef.value)) {
    operationCounts.value = { reviewPending: 0, missedPending: 0, killsweepFailed: 0 };
    return;
  }
  const [reviews, missed, killsweep] = await Promise.allSettled([
    api.globalReviewStats(),
    api.missedSignalStats(),
    api.killsweepStats(),
  ]);
  operationCounts.value = {
    reviewPending: reviews.status === "fulfilled"
      ? Number(reviews.value?.pending ?? 0)
      : operationCounts.value.reviewPending,
    missedPending: missed.status === "fulfilled"
      ? Number(missed.value?.pending ?? missed.value?.pending_count ?? 0)
      : operationCounts.value.missedPending,
    killsweepFailed: killsweep.status === "fulfilled"
      ? Number(killsweep.value?.failed ?? killsweep.value?.failed_count ?? 0)
      : operationCounts.value.killsweepFailed,
  };
}

async function confirmToken() {
  const raw = tokenInput.value.trim();
  if (!raw) {
    toast("请输入令牌");
    return;
  }
  showTokenModal.value = false;
  tokenInput.value = "";
  submitTokenModal(raw);
  const result = await applyAccessToken(raw);
  if (result.ok) {
    toast(result.role === "full" ? "已切换为全权限令牌"
      : result.role === "observer" ? "已切换为观摩令牌" : "已切换为只读令牌");
    window.dispatchEvent(new CustomEvent("autohunter-token-changed"));
    await refreshOperationCounts();
  } else {
    toast("令牌无效，请检查后重试");
  }
  if (!canAccessRoute(result.role, route.path)) await router.replace("/");
}

function closeTokenModal() {
  showTokenModal.value = false;
  tokenInput.value = "";
  cancelTokenModal();
}

function onOpenTokenModal(event) {
  openTokenDialog(event.detail?.reason || "auth");
}

function onOperationCounts(event) {
  operationCounts.value = {
    ...operationCounts.value,
    ...(event.detail || {}),
  };
}

onMounted(async () => {
  setThemePreference(currentTheme(), { notify: false });
  window.addEventListener(TOKEN_DIALOG_EVENT, onOpenTokenModal);
  window.addEventListener("autohunter-operation-counts", onOperationCounts);
  window.addEventListener("autohunter-refresh-operation-counts", refreshOperationCounts);
  await loadAuthRole();
  await refreshOperationCounts();
});

onUnmounted(() => {
  window.removeEventListener(TOKEN_DIALOG_EVENT, onOpenTokenModal);
  window.removeEventListener("autohunter-operation-counts", onOperationCounts);
  window.removeEventListener("autohunter-refresh-operation-counts", refreshOperationCounts);
});
</script>

<template>
  <header class="topbar">
    <div class="topbar-row">
      <div class="brand">
        <span class="logo"><i></i></span>
        <span class="brand-copy">
          <b>AutoHunter</b>
          <small class="brand-tag">SRC · 24×7</small>
        </span>
      </div>
      <div class="topbar-tools">
        <span v-if="authReadyRef && authRoleRef === 'none'" class="readonly-badge unauth-badge">未认证</span>
        <span v-else-if="authRoleRef === 'readonly'" class="readonly-badge">只读</span>
        <span v-else-if="authRoleRef === 'observer'" class="readonly-badge">观摩</span>
      </div>
    </div>

    <nav class="topbar-nav desktop-only-nav" aria-label="主导航">
      <router-link v-for="item in visibleNavigation" :key="item.id" :to="item.to"
        class="navbtn" :class="{ active: isNavigationActive(item, route.path) }">
        <span class="nav-icon" aria-hidden="true">
          <svg v-if="item.id === 'tasks'" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="11" width="18" height="4" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/></svg>
          <svg v-else-if="item.id === 'reviews'" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5h6"/><path d="M9 3h6a2 2 0 0 1 2 2v1h2v15H5V6h2V5a2 2 0 0 1 2-2Z"/><path d="m9 14 2 2 4-4"/></svg>
          <svg v-else-if="item.id === 'missed'" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/><path d="M11 8v3"/><path d="M11 14h.01"/></svg>
          <svg v-else-if="item.id === 'killsweeps'" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>
          <svg v-else viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09A1.65 1.65 0 0 0 20.91 10H21a2 2 0 0 1 0 4h-.09A1.65 1.65 0 0 0 19.4 15z"/></svg>
        </span>
        <span>{{ item.label }}</span>
        <span v-if="item.badge" class="nav-count" :aria-label="`${item.badge} 条待处理`">{{ item.badge }}</span>
      </router-link>
    </nav>
  </header>

  <main><router-view /></main>

  <footer class="app-credit" aria-label="署名">
    <span>Powered By <b>StanleyNull</b></span>
    <span class="app-credit-sep">·</span>
    <span>CC BY-NC 4.0</span>
  </footer>

  <nav class="bottom-nav mobile-only-nav" aria-label="主导航">
    <router-link v-for="item in visibleNavigation" :key="item.id" :to="item.to"
      class="bottom-nav-item" :class="{ active: isNavigationActive(item, route.path) }">
      <span class="bottom-nav-icon" aria-hidden="true">
        <svg v-if="item.id === 'tasks'" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="11" width="18" height="4" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/></svg>
        <svg v-else-if="item.id === 'reviews'" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5h6"/><path d="M9 3h6a2 2 0 0 1 2 2v1h2v15H5V6h2V5a2 2 0 0 1 2-2Z"/><path d="m9 14 2 2 4-4"/></svg>
        <svg v-else-if="item.id === 'missed'" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/><path d="M11 8v3"/><path d="M11 14h.01"/></svg>
        <svg v-else-if="item.id === 'killsweeps'" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>
        <svg v-else viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09A1.65 1.65 0 0 0 20.91 10H21a2 2 0 0 1 0 4h-.09A1.65 1.65 0 0 0 19.4 15z"/></svg>
      </span>
      <span class="bottom-nav-label">{{ item.label }}</span>
      <span v-if="item.badge" class="bottom-nav-count" :aria-label="`${item.badge} 条待处理`">{{ item.badge }}</span>
    </router-link>
  </nav>

  <div v-if="showTokenModal" class="token-modal-backdrop" @click.self="closeTokenModal">
    <div class="token-modal" role="dialog" aria-modal="true" aria-labelledby="token-modal-title">
      <h3 id="token-modal-title">{{ tokenModalReason === "auth" ? "输入访问令牌" : "更换访问令牌" }}</h3>
      <p class="token-modal-hint">可输入全权限、只读或观摩令牌；验证成功后立即切换访问范围。</p>
      <input v-model="tokenInput" class="token-modal-input" type="password" autocomplete="off"
        placeholder="粘贴令牌" @keyup.enter="confirmToken" />
      <div class="token-modal-actions">
        <button type="button" class="ghost" @click="closeTokenModal">取消</button>
        <button type="button" class="primary" @click="confirmToken">确认</button>
      </div>
    </div>
  </div>

  <div v-if="toastMsg" class="toast app-toast">{{ toastMsg }}</div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { RouterView } from "vue-router";
import AppSidebar from "@/components/layout/AppSidebar.vue";
import TopNav from "@/components/layout/TopNav.vue";
import { useAuthStore } from "@/stores/auth";
import { useUiStore } from "@/stores/ui";

const ui = useUiStore();
const auth = useAuthStore();

/** The pending-SSO banner asks the user to confirm or discard; both actions
 *  are one click, and a double click on either is harmless (the backend
 *  consumes the stash atomically). */
const pendingBusy = ref(false);

async function confirmPending() {
  if (pendingBusy.value) return;
  pendingBusy.value = true;
  try {
    await auth.confirmPendingSso();
  } catch {
    // The banner clears on failure too — the backend consumed or expired the
    // stash, and a stuck banner has no second meaning to offer.
    auth.pendingSso = null;
  } finally {
    pendingBusy.value = false;
  }
}

async function discardPending() {
  if (pendingBusy.value) return;
  pendingBusy.value = true;
  try {
    await auth.discardPendingSso();
  } finally {
    pendingBusy.value = false;
  }
}

function onKeydown(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "b") {
    e.preventDefault();
    ui.toggleSidebar();
  }
}

onMounted(() => {
  window.addEventListener("keydown", onKeydown);
  void auth.fetchMe();
});
onUnmounted(() => window.removeEventListener("keydown", onKeydown));
</script>

<template>
  <div class="flex min-h-screen w-full bg-background">
    <AppSidebar />
    <div class="flex min-w-0 flex-1 flex-col">
      <TopNav />
      <div
        v-if="auth.pendingSso"
        class="mx-4 mt-3 flex flex-wrap items-center gap-3 rounded-md border border-amber-300 bg-amber-50 px-4 py-3 text-sm dark:border-amber-700 dark:bg-amber-950"
        data-testid="pending-sso-banner"
      >
        <span class="flex-1">
          A sign-in with
          <strong>{{ auth.pendingSso.display_name || auth.pendingSso.provider }}</strong>
          (<code class="text-xs">{{ auth.pendingSso.provider }}</code>
          <template v-if="auth.pendingSso.email"> · {{ auth.pendingSso.email }}</template>)
          is waiting to be linked to this account. Link it only if you started that sign-in —
          otherwise discard it.
        </span>
        <div class="flex gap-2">
          <button
            class="rounded-md bg-primary px-3 py-1.5 font-medium text-primary-foreground disabled:opacity-50"
            :disabled="pendingBusy"
            data-testid="pending-sso-confirm"
            @click="confirmPending"
          >
            Link identity
          </button>
          <button
            class="rounded-md border px-3 py-1.5 disabled:opacity-50"
            :disabled="pendingBusy"
            data-testid="pending-sso-discard"
            @click="discardPending"
          >
            Discard
          </button>
        </div>
      </div>
      <main class="shell-inset flex-1 overflow-auto py-4">
        <div class="page-stack">
          <RouterView />
        </div>
      </main>
    </div>
  </div>
</template>

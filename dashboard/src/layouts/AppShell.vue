<script setup lang="ts">
import { onMounted, onUnmounted } from "vue";
import { RouterView } from "vue-router";
import AppSidebar from "@/components/layout/AppSidebar.vue";
import TopNav from "@/components/layout/TopNav.vue";
import { useAuthStore } from "@/stores/auth";
import { useUiStore } from "@/stores/ui";

const ui = useUiStore();
const auth = useAuthStore();

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
      <main class="shell-inset flex-1 overflow-auto py-4">
        <div class="page-stack">
          <RouterView />
        </div>
      </main>
    </div>
  </div>
</template>

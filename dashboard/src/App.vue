<script setup lang="ts">
import { onMounted } from "vue";
import { RouterView } from "vue-router";
import ConfirmHost from "@/components/ui/ConfirmHost.vue";
import { useBrandingStore } from "@/stores/branding";

const branding = useBrandingStore();

onMounted(() => {
  void branding.load();
});
</script>

<template>
  <RouterView />
  <ConfirmHost />
</template>

<script setup lang="ts">
import { Plus } from "@lucide/vue";
import UiButton from "@/components/ui/UiButton.vue";
import { buttonClass } from "@/components/ui/button";

defineProps<{
  selectedCount: number;
  batching: boolean;
  /** Export link, including the active group filter. */
  exportUrl: string;
}>();

defineEmits<{
  freeze: [];
  importJson: [];
  create: [];
}>();
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <UiButton
      v-if="selectedCount > 0"
      size="sm"
      variant="destructive"
      :disabled="batching"
      @click="$emit('freeze')"
    >
      {{ batching ? "Freezing…" : `Freeze selected (${selectedCount})` }}
    </UiButton>
    <UiButton size="sm" variant="secondary" @click="$emit('importJson')">
      Import JSON
    </UiButton>
    <a :href="exportUrl" :class="buttonClass('secondary', 'sm')">Export CSV</a>
    <UiButton size="sm" @click="$emit('create')">
      <Plus class="h-4 w-4" />
      New User
    </UiButton>
  </div>
</template>

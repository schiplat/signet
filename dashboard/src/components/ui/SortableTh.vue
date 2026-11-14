<script setup lang="ts">
defineProps<{
  label: string;
  column: string;
  indicator: "" | "asc" | "desc";
}>();

defineEmits<{ toggle: [column: string] }>();
</script>

<template>
  <th class="px-5 py-2.5 text-left">
    <button
      type="button"
      class="inline-flex items-center gap-1 text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80 transition-colors hover:text-foreground"
      @click="$emit('toggle', column)"
    >
      {{ label }}
      <span class="font-mono text-xs opacity-70">
        {{ indicator === "asc" ? "↑" : indicator === "desc" ? "↓" : "↕" }}
      </span>
    </button>
  </th>
</template>

<script setup lang="ts">
import { PAGE_SIZE_OPTIONS } from "@/composables/useClientPagination";

const page = defineModel<number>("page", { required: true });
const pageSize = defineModel<number>("pageSize", { required: true });

defineProps<{
  total: number;
  pageCount: number;
  rangeLabel: string;
}>();
</script>

<template>
  <div
    v-if="total > 0"
    class="flex flex-col gap-2.5 border-t border-border/40 px-5 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-3"
  >
    <p class="shrink-0 text-[11px] text-muted-foreground">{{ rangeLabel }}</p>
    <div
      class="flex w-full min-w-0 items-center justify-between gap-2 sm:w-auto sm:justify-end sm:gap-3"
    >
      <label class="flex shrink-0 items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
        <span class="hidden sm:inline">Per page</span>
        <span class="sm:hidden">Rows</span>
        <select
          v-model.number="pageSize"
          class="field-input h-8 w-auto min-w-[3.75rem] py-1 pl-2 pr-8 text-xs"
        >
          <option v-for="n in PAGE_SIZE_OPTIONS" :key="n" :value="n">{{ n }}</option>
        </select>
      </label>
      <div class="flex shrink-0 items-center gap-0.5 sm:gap-1">
        <button
          class="inline-flex items-center justify-center rounded-xl px-2 py-1 text-[11px] font-medium transition-colors sm:px-2.5"
          :class="
            page <= 1
              ? 'cursor-default text-muted-foreground/40'
              : 'text-muted-foreground hover:bg-muted/40 hover:text-foreground'
          "
          :disabled="page <= 1"
          @click="page = page - 1"
        >
          Prev
        </button>
        <span
          class="min-w-[3.25rem] px-1 text-center font-mono text-[11px] tabular-nums text-muted-foreground sm:min-w-[4.5rem]"
        >
          {{ page }} / {{ pageCount }}
        </span>
        <button
          class="inline-flex items-center justify-center rounded-xl px-2 py-1 text-[11px] font-medium transition-colors sm:px-2.5"
          :class="
            page >= pageCount
              ? 'cursor-default text-muted-foreground/40'
              : 'text-muted-foreground hover:bg-muted/40 hover:text-foreground'
          "
          :disabled="page >= pageCount"
          @click="page = page + 1"
        >
          Next
        </button>
      </div>
    </div>
  </div>
</template>

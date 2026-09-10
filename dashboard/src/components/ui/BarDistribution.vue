<script setup lang="ts">
import { computed } from "vue";
import type { NameCount } from "@/lib/api";

const props = defineProps<{
  items: NameCount[];
  /** Tailwind-friendly palette (hsl triplets) cycled per bar. */
  colors?: string[];
}>();

const PALETTE = [
  "hsl(219 90% 52%)",
  "hsl(152 72% 33%)",
  "hsl(25 92% 46%)",
  "hsl(262 83% 58%)",
  "hsl(335 85% 55%)",
  "hsl(190 85% 40%)",
  "hsl(45 95% 45%)",
  "hsl(120 55% 40%)",
  "hsl(285 70% 50%)",
  "hsl(8 80% 55%)",
];

const rows = computed(() => {
  const max = Math.max(...props.items.map((i) => i.count), 1);
  return props.items.map((item, idx) => ({
    ...item,
    pct: (item.count / max) * 100,
    color: (props.colors ?? PALETTE)[idx % (props.colors ?? PALETTE).length],
  }));
});

function display(name: string) {
  return name === "(direct)" ? "Signet (direct)" : name;
}
</script>

<template>
  <div v-if="!items.length" class="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
    No data in the last 30 days
  </div>
  <ul v-else class="space-y-2.5">
    <li v-for="row in rows" :key="row.name" class="group">
      <div class="mb-1 flex items-center justify-between gap-3 text-xs">
        <span class="min-w-0 truncate font-medium" :title="display(row.name)">
          {{ display(row.name) }}
        </span>
        <span class="shrink-0 tabular-nums text-muted-foreground">{{ row.count }}</span>
      </div>
      <div class="h-2 overflow-hidden rounded-full bg-muted/40">
        <div
          class="h-full rounded-full transition-[width] duration-300"
          :style="{ width: `${row.pct}%`, background: row.color }"
        />
      </div>
    </li>
  </ul>
</template>

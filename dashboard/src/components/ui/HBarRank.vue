<script setup lang="ts">
import { computed, ref } from "vue";
import type { ClientUsage } from "@/lib/api";

/**
 * Horizontal ranking bars for per-app logins (last 30 days, top N).
 * One bar encodes exactly one metric (logins); unique users live in their
 * own right-aligned column. Rank number pins the ordering; single hue keeps
 * bars comparable at a glance. No click-through — filtering lives in the
 * header dropdown.
 */
const props = defineProps<{
  items: ClientUsage[];
  max?: number;
}>();

const rows = computed(() => {
  const max = props.max ?? Math.max(...props.items.map((i) => i.logins_30d), 1);
  return props.items.map((item) => ({
    ...item,
    loginPct: (item.logins_30d / max) * 100,
    sharePct: (() => {
      const total = props.items.reduce((s, i) => s + i.logins_30d, 0) || 1;
      return Math.round((item.logins_30d / total) * 100);
    })(),
  }));
});

const hoverIdx = ref<number | null>(null);

function display(name: string) {
  return name === "(direct)" ? "Signet (direct)" : name;
}
</script>

<template>
  <div v-if="!items.length" class="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
    No app sign-ins in the last 30 days
  </div>
  <div v-else>
    <!-- Column header pins each number to its metric. -->
    <div class="mb-1.5 grid grid-cols-[1.5rem_9rem_1fr_2.5rem_3rem] items-end gap-3 border-b border-border/40 pb-1.5">
      <span class="type-eyebrow text-center">#</span>
      <span class="type-eyebrow">App</span>
      <span class="type-eyebrow">Logins · last 30 days</span>
      <span class="type-eyebrow text-right">Share</span>
      <span class="type-eyebrow text-right">Users</span>
    </div>

    <div class="space-y-0.5">
      <div
        v-for="(row, i) in rows"
        :key="row.client_id"
        class="group grid grid-cols-[1.5rem_9rem_1fr_2.5rem_3rem] items-center gap-3 rounded-lg px-1.5 py-1.5 transition-colors"
        :class="hoverIdx === i ? 'bg-muted/50' : ''"
        @mouseenter="hoverIdx = i"
        @mouseleave="hoverIdx = null"
      >
        <!-- Rank number: dimmed for places beyond the podium. -->
        <span
          class="text-center text-xs font-semibold tabular-nums"
          :class="i < 3 ? 'text-[hsl(217_90%_62%)]' : 'text-muted-foreground/60'"
        >
          {{ i + 1 }}
        </span>

        <span class="min-w-0 truncate text-xs font-medium" :title="display(row.client_id)">
          {{ display(row.client_id) }}
        </span>

        <!-- Bar: logins only. Top share shown inside when it fits. -->
        <div class="relative h-5 overflow-hidden rounded-md bg-muted">
          <div
            class="flex h-full items-center justify-end rounded-md pr-1.5 transition-[width] duration-300"
            :style="{ width: `${row.loginPct}%`, background: 'hsl(217 90% 70%)' }"
          >
            <span
              v-if="row.loginPct >= 22"
              class="text-[10px] font-semibold tabular-nums text-white"
            >
              {{ row.sharePct }}%
            </span>
          </div>
        </div>

        <!-- Share column mirrors the in-bar number for short bars. -->
        <span class="text-right text-xs tabular-nums text-muted-foreground">
          {{ row.sharePct }}%
        </span>

        <span class="text-right text-xs font-medium tabular-nums" :title="`${row.unique_users_30d} unique users`">
          {{ row.unique_users_30d }}
        </span>
      </div>
    </div>

    <p class="mt-2 flex flex-wrap items-center gap-x-4 border-t border-border/30 pt-2 text-[10px] text-muted-foreground">
      <span class="flex items-center gap-1.5">
        <span class="h-2 w-4 rounded-sm bg-[hsl(217_90%_70%)]" />
        bar = 30-day logins
      </span>
      <span>share = app's % of all app logins</span>
      <span>users = unique sign-in accounts</span>
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import type { Component } from "vue";
import type { NameCount } from "@/lib/api";

/**
 * Donut chart (hand-rolled SVG, no chart lib).
 * Layout: section title on top, ring on the left, legend list on the right
 * (name = count · share). Ring and legend rows highlight together on hover.
 */
const props = defineProps<{
  title: string;
  icon: Component;
  items: NameCount[];
  /** Fixed color per name (falls back to a rotating palette). */
  colors?: Record<string, string>;
  /** Optional icon component per name (brand glyphs). */
  icons?: Record<string, unknown>;
}>();

const FALLBACK = [
  "hsl(217 85% 68%)",
  "hsl(152 55% 60%)",
  "hsl(36 95% 66%)",
  "hsl(262 75% 72%)",
  "hsl(190 80% 62%)",
  "hsl(340 75% 70%)",
  "hsl(215 12% 72%)",
];

const SIZE = 92;
const STROKE = 14;
const R = (SIZE - STROKE) / 2;
const C = 2 * Math.PI * R;

const total = computed(() => props.items.reduce((s, i) => s + i.count, 0));

interface Slice {
  name: string;
  count: number;
  pct: number;
  dash: number;
  offset: number;
  color: string;
}

const slices = computed<Slice[]>(() => {
  const t = total.value || 1;
  let acc = 0;
  return props.items.map((item, idx) => {
    const frac = item.count / t;
    const slice: Slice = {
      name: item.name,
      count: item.count,
      pct: Math.round(frac * 100),
      dash: frac * C,
      offset: -acc * C,
      color: props.colors?.[item.name] ?? FALLBACK[idx % FALLBACK.length],
    };
    acc += frac;
    return slice;
  });
});

const hoverIdx = ref<number | null>(null);

function colorFor(name: string, idx: number): string {
  return props.colors?.[name] ?? FALLBACK[idx % FALLBACK.length];
}

function pctOf(item: NameCount): string {
  const t = total.value || 1;
  return `${Math.round((item.count / t) * 100)}%`;
}
</script>

<template>
  <div v-if="!items.length" class="flex h-[118px] items-center justify-center text-sm text-muted-foreground">
    No data in the last 30 days
  </div>
  <div v-else class="space-y-2.5">
    <div class="flex items-center gap-2">
      <span class="flex h-5 w-5 items-center justify-center rounded-md text-muted-foreground">
        <component :is="icon" class="h-3.5 w-3.5" />
      </span>
      <h3 class="text-[13px] font-semibold tracking-tight">{{ title }}</h3>
    </div>

    <div class="flex items-center gap-4">
      <div class="relative shrink-0">
        <svg
          :width="SIZE"
          :height="SIZE"
          :viewBox="`0 0 ${SIZE} ${SIZE}`"
          role="img"
          aria-label="Distribution donut chart"
        >
          <g :transform="`rotate(-90 ${SIZE / 2} ${SIZE / 2})`">
            <circle
              :cx="SIZE / 2"
              :cy="SIZE / 2"
              :r="R"
              fill="none"
              class="stroke-border/80"
              :stroke-width="STROKE"
            />
            <circle
              v-for="(s, i) in slices"
              :key="s.name"
              :cx="SIZE / 2"
              :cy="SIZE / 2"
              :r="R"
              fill="none"
              :stroke="s.color"
              :stroke-width="hoverIdx === i ? STROKE + 3 : STROKE"
              :stroke-dasharray="`${Math.max(s.dash - 2, 0.5)} ${C}`"
              :stroke-dashoffset="s.offset"
              stroke-linecap="butt"
              class="cursor-default transition-[stroke-width] duration-150"
              :class="hoverIdx != null && hoverIdx !== i ? 'opacity-45' : 'opacity-100'"
              @mouseenter="hoverIdx = i"
              @mouseleave="hoverIdx = null"
            />
          </g>
        </svg>
        <div class="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span class="text-sm font-semibold tabular-nums tracking-tight">
            {{ hoverIdx != null ? slices[hoverIdx].count : total }}
          </span>
          <span class="text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
            {{ hoverIdx != null ? slices[hoverIdx].pct + "%" : "logins" }}
          </span>
        </div>
      </div>

      <!-- Legend rows: color dot + glyph + name, count and share right-aligned. -->
      <ul class="min-w-0 flex-1 space-y-0.5">
        <li
          v-for="(item, i) in items"
          :key="item.name"
          class="flex cursor-default items-center gap-2 rounded-lg px-1.5 py-0.5 text-xs transition-colors"
          :class="hoverIdx === i ? 'bg-muted/60' : ''"
          @mouseenter="hoverIdx = i"
          @mouseleave="hoverIdx = null"
        >
          <span
            class="h-2.5 w-2.5 shrink-0 rounded-[3px]"
            :style="{ background: colorFor(item.name, i) }"
          />
          <span
            v-if="icons && icons[item.name]"
            class="shrink-0 text-muted-foreground"
            :title="item.name"
          >
            <component :is="icons[item.name]" class="h-3.5 w-3.5" />
          </span>
          <span class="min-w-0 flex-1 truncate" :title="item.name">{{ item.name }}</span>
          <span class="shrink-0 font-medium tabular-nums">{{ item.count }}</span>
          <span class="w-9 shrink-0 text-right tabular-nums text-muted-foreground/70">
            {{ pctOf(item) }}
          </span>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { LoginTrendHourPoint, LoginTrendPoint } from "@/lib/api";

/**
 * Login trend chart with a range switch: 24h (hourly, default), 7d and 30d
 * (daily). Each range renders exactly one series at its native grain, so the
 * x-axis always matches the data.
 *
 * Visual language follows the Falcon "Total Orders" line style: smooth
 * monotone curve (no overshoot), 3px line, gradient area fading to 0, no
 * default point markers — only the hovered point shows as a white dot with a
 * colored ring (symbolSize 8).
 */
const props = defineProps<{
  points: LoginTrendPoint[];
  hours: LoginTrendHourPoint[];
}>();

export type RangeKey = "24h" | "7d" | "30d";

/**
 * Per-range color system: `hue` drives the chart (line/area/hover, vivid);
 * `fill` is a darkened sibling for tag backgrounds so white text stays
 * readable; inactive tags use a 12% tint of the same hue.
 */
/**
 * One palette, three stops — 透亮红 / 黄 / 蓝 (high chroma, airy L):
 *   24h = lucid red
 *   7d  = lucid yellow
 *   30d = lucid blue
 * Saturated enough to read on the chart; light enough for soft tags.
 * `fill` is slightly deeper for active tag white text; inactive uses 18% tint.
 */
const RANGE_META: Record<RangeKey, { label: string; line: string; fill: string; tint: string }> = {
  "24h": { label: "Last 24 hours", line: "hsl(2 100% 68%)", fill: "2 95% 58%", tint: "hsl(2 100% 68% / 0.18)" },
  "7d": { label: "Last 7 days", line: "hsl(46 100% 58%)", fill: "44 98% 50%", tint: "hsl(46 100% 58% / 0.18)" },
  "30d": { label: "Last 30 days", line: "hsl(210 100% 66%)", fill: "210 95% 56%", tint: "hsl(210 100% 66% / 0.18)" },
};

/** Two-way bound so the KPI numbers above can switch the range too. */
const range = defineModel<RangeKey>({ default: "24h" });

const lineColor = computed(() => RANGE_META[range.value].line);
const tagStyle = (key: RangeKey) =>
  range.value === key
    ? { background: `hsl(${RANGE_META[key].fill})` }
    : {
        color: `hsl(${RANGE_META[key].fill})`,
        background: RANGE_META[key].tint,
      };

watch(
  () => [props.hours.length, props.points.length] as const,
  ([h, d]) => {
    // Fall back to a range that has data (e.g. fresh deployments).
    if (range.value === "24h" && h === 0 && d > 0) range.value = "30d";
  },
);

const color = computed(() => lineColor.value);

const W = 720;
const H = 240;
const PAD = { top: 16, right: 12, bottom: 26, left: 36 };

const hoverIdx = ref<number | null>(null);

/** Uniform point shape for both grains. */
const data = computed<{ label: string; value: number }[]>(() => {
  if (range.value === "24h") {
    return props.hours.map((p) => {
      const d = new Date(`${p.hour}Z`);
      return { label: `${String(d.getHours()).padStart(2, "0")}:00`, value: p.logins };
    });
  }
  const days = range.value === "7d" ? 7 : 30;
  return props.points.slice(-days).map((p) => ({
    label: formatDay(p.day),
    value: p.logins_1d,
  }));
});

const total = computed(() => data.value.reduce((s, p) => s + p.value, 0));
// Exposed so the parent card can show the range total next to the title.
defineExpose({ total });

const maxY = computed(() => Math.max(...data.value.map((p) => p.value), 1));

const yTicks = computed(() => {
  const max = maxY.value;
  const step = niceStep(max);
  const ticks: number[] = [];
  for (let v = 0; v <= max; v += step) ticks.push(v);
  if (ticks[ticks.length - 1] < max) ticks.push(ticks[ticks.length - 1] + step);
  return ticks;
});

const chartMax = computed(() => yTicks.value[yTicks.value.length - 1] || 1);

const plotW = W - PAD.left - PAD.right;
const plotH = H - PAD.top - PAD.bottom;

function xAt(i: number) {
  const n = Math.max(data.value.length - 1, 1);
  return PAD.left + (i / n) * plotW;
}

function yAt(v: number) {
  return PAD.top + plotH - (v / chartMax.value) * plotH;
}

/**
 * Fritsch–Carlson monotone cubic interpolation (what ECharts' `smooth` +
 * `smoothMonotone: 'x'` produce): gentle curves that never overshoot the
 * data — dips stay dips, peaks stay peaks.
 */
function monotonePath(pts: { x: number; y: number }[]): string {
  const n = pts.length;
  if (n === 0) return "";
  if (n === 1) return `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;

  const dx: number[] = [];
  const slope: number[] = [];
  for (let i = 0; i < n - 1; i++) {
    dx.push(pts[i + 1].x - pts[i].x);
    slope.push((pts[i + 1].y - pts[i].y) / (pts[i + 1].x - pts[i].x));
  }

  // Tangents at each point; flatten where neighbours disagree in sign.
  const tan: number[] = [slope[0]];
  for (let i = 1; i < n - 1; i++) {
    if (slope[i - 1] * slope[i] <= 0) {
      tan.push(0);
    } else {
      const w1 = 2 * dx[i] + dx[i - 1];
      const w2 = dx[i] + 2 * dx[i - 1];
      tan.push((w1 + w2) / (w1 / slope[i - 1] + w2 / slope[i]));
    }
  }
  tan.push(slope[n - 2]);

  let d = `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;
  for (let i = 0; i < n - 1; i++) {
    const x1 = pts[i].x + dx[i] / 3;
    const y1 = pts[i].y + (tan[i] * dx[i]) / 3;
    const x2 = pts[i + 1].x - dx[i] / 3;
    const y2 = pts[i + 1].y - (tan[i + 1] * dx[i]) / 3;
    d += ` C ${x1.toFixed(2)} ${y1.toFixed(2)}, ${x2.toFixed(2)} ${y2.toFixed(2)}, ${pts[i + 1].x.toFixed(2)} ${pts[i + 1].y.toFixed(2)}`;
  }
  return d;
}

const pts = computed(() => data.value.map((p, i) => ({ x: xAt(i), y: yAt(p.value) })));

const linePath = computed(() => monotonePath(pts.value));

/** Area fill under the curve: same monotone path + baseline. */
const areaPath = computed(() => {
  const p = pts.value;
  if (!p.length) return "";
  const base = (PAD.top + plotH).toFixed(2);
  return `${monotonePath(p)} L ${p[p.length - 1].x.toFixed(2)} ${base} L ${p[0].x.toFixed(2)} ${base} Z`;
});

function formatDay(day: string) {
  const d = new Date(`${day}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return day;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

function niceStep(max: number) {
  if (max <= 4) return 1;
  const raw = max / 4;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const n = raw / pow;
  const nice = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return nice * pow;
}

function onMove(e: MouseEvent) {
  const svg = e.currentTarget as SVGSVGElement;
  const rect = svg.getBoundingClientRect();
  const x = ((e.clientX - rect.left) / rect.width) * W;
  if (x < PAD.left || x > W - PAD.right || !data.value.length) {
    hoverIdx.value = null;
    return;
  }
  const n = Math.max(data.value.length - 1, 1);
  const i = Math.round(((x - PAD.left) / plotW) * n);
  hoverIdx.value = Math.min(Math.max(i, 0), data.value.length - 1);
}

function onLeave() {
  hoverIdx.value = null;
}

const hover = computed(() => (hoverIdx.value == null ? null : data.value[hoverIdx.value] ?? null));

const xLabels = computed(() => {
  const pts = data.value;
  if (pts.length === 0) return [];
  const idxs = new Set<number>([0, pts.length - 1]);
  if (pts.length > 2) idxs.add(Math.floor((pts.length - 1) / 2));
  if (pts.length > 8) {
    idxs.add(Math.floor((pts.length - 1) / 4));
    idxs.add(Math.floor(((pts.length - 1) * 3) / 4));
  }
  return [...idxs].sort((a, b) => a - b).map((i) => ({ i, label: pts[i].label }));
});
</script>

<template>
  <div class="space-y-3">
    <!-- Card header: title + description on the left, range tags on the right. -->
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 class="text-sm font-semibold tracking-tight">User logins</h2>
        <p class="type-meta mt-1">Successful Signet sign-ins (auth.login)</p>
      </div>
      <!-- Range tags: dark tint fill + white text when active; 12% tint + colored text otherwise. -->
      <div class="flex items-center gap-1.5">
        <button
          v-for="key in (Object.keys(RANGE_META) as RangeKey[])"
          :key="key"
          type="button"
          class="rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors"
          :class="range === key ? 'text-white' : ''"
          :style="tagStyle(key)"
          :aria-pressed="range === key"
          @click="range = key; hoverIdx = null"
        >
          {{ key }}
        </button>
      </div>
    </div>

    <div class="relative">
      <svg
        class="h-[240px] w-full select-none"
        :viewBox="`0 0 ${W} ${H}`"
        role="img"
        aria-label="Login trend for the selected range"
        @mousemove="onMove"
        @mouseleave="onLeave"
      >
        <defs>
          <linearGradient id="trendArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" :stop-color="color" stop-opacity="0.32" />
            <stop offset="100%" :stop-color="color" stop-opacity="0" />
          </linearGradient>
        </defs>

        <!-- Faint horizontal guides only; no axis lines, no plot box. -->
        <g v-for="tick in yTicks" :key="tick">
          <line
            :x1="PAD.left"
            :x2="W - PAD.right"
            :y1="yAt(tick)"
            :y2="yAt(tick)"
            class="stroke-border/60"
            stroke-width="1"
            stroke-dasharray="2 4"
          />
          <text
            :x="PAD.left - 8"
            :y="yAt(tick) + 3"
            text-anchor="end"
            class="fill-muted-foreground"
            font-size="10"
          >
            {{ tick }}
          </text>
        </g>

        <!-- Gradient area, fading to fully transparent at the baseline. -->
        <path :d="areaPath" fill="url(#trendArea)" />

        <!-- Smooth monotone line, 3px, rounded caps. -->
        <path
          :d="linePath"
          fill="none"
          :stroke="color"
          stroke-width="2.5"
          stroke-linecap="round"
          stroke-linejoin="round"
        />

        <!-- Hover dot only (showSymbol:false): white core + colored ring. -->
        <circle
          v-if="hoverIdx != null && hover"
          :cx="pts[hoverIdx].x"
          :cy="pts[hoverIdx].y"
          r="3.5"
          class="fill-card"
          :stroke="color"
          stroke-width="2"
        />

        <!-- Hover guide line. -->
        <line
          v-if="hoverIdx != null && hover"
          :x1="pts[hoverIdx].x"
          :x2="pts[hoverIdx].x"
          :y1="PAD.top"
          :y2="PAD.top + plotH"
          class="stroke-foreground/20"
          stroke-width="1"
          stroke-dasharray="3 3"
        />

        <text
          v-for="lab in xLabels"
          :key="lab.i"
          :x="pts[lab.i].x"
          :y="H - 8"
          text-anchor="middle"
          class="fill-muted-foreground"
          font-size="10"
        >
          {{ lab.label }}
        </text>
      </svg>

      <div
        v-if="hover && hoverIdx != null"
        class="pointer-events-none absolute top-2 z-10 min-w-[8rem] rounded-lg border border-border/50 bg-card px-3 py-2 shadow-sm"
        :style="{
          left: `clamp(0.5rem, ${(pts[hoverIdx].x / W) * 100}% , calc(100% - 9rem))`,
        }"
      >
        <p class="text-[11px] font-semibold tracking-tight">{{ hover.label }}</p>
        <p class="mt-1 flex items-center justify-between gap-4 text-[11px]">
          <span class="flex items-center gap-1.5 text-muted-foreground">
            <span class="h-1.5 w-1.5 rounded-full" :style="{ background: color }" />
            logins
          </span>
          <span class="font-medium tabular-nums">{{ hover.value }}</span>
        </p>
      </div>
    </div>
  </div>
</template>

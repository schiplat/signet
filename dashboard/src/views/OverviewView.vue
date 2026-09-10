<script setup lang="ts">
import {
  AppWindow,
  ArrowUpRight,
  Boxes,
  Compass,
  DoorOpen,
  Flame,
  Globe,
  Laptop,
  Monitor,
  MonitorSmartphone,
  ShieldCheck,
  Smartphone,
  Terminal,
  UserRoundCog,
  Users,
} from "@lucide/vue";
import type { Component } from "vue";
import { computed, onMounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import DonutChart from "@/components/ui/DonutChart.vue";
import HBarRank from "@/components/ui/HBarRank.vue";
import LoginTrendChart from "@/components/ui/LoginTrendChart.vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import { fetchAdminStats, listClients, type AdminStats, type AdminClient, type NameCount } from "@/lib/api";

const loading = ref(true);
const error = ref("");
const stats = ref<AdminStats | null>(null);

/** Chart range for the User logins trend (24h default, switched by KPI taps). */
const loginRange = ref<"24h" | "7d" | "30d">("24h");

// --- app (client) scope filter ---
const clients = ref<AdminClient[]>([]);
const clientFilter = ref(""); // "" = all apps; "(direct)" = unattributed sign-ins

const clientOptions = computed(() => [
  { value: "", label: "All apps" },
  { value: "(direct)", label: "Signet (direct)" },
  ...clients.value.map((c) => ({
    value: c.client_id,
    label: c.client_id + (c.enabled ? "" : " (disabled)"),
  })),
]);

async function load() {
  loading.value = true;
  error.value = "";
  try {
    stats.value = await fetchAdminStats(clientFilter.value || undefined);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load overview";
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  void load();
  try {
    clients.value = await listClients();
  } catch {
    // Non-fatal: the filter dropdown just stays with the default options.
  }
});

watch(clientFilter, () => {
  void load();
});

// --- stat card definitions (semantic hue + glyph per identity) ---
interface StatCard {
  key: string;
  eyebrow: string;
  value: string;
  meta: string;
  icon: Component;
  /** Semantic accent in the pastel band: indigo=people, violet=authority, amber=ops, green=apps. */
  hue: string;
  to?: string;
}

const statCards = computed<StatCard[]>(() => [
  {
    key: "users",
    eyebrow: "Users",
    value: fmt(stats.value?.users_total),
    meta: loading.value
      ? "Total accounts"
      : `${stats.value?.users_active ?? 0} active · ${stats.value?.users_disabled ?? 0} disabled`,
    icon: Users,
    hue: "219 85% 62%",
    to: "/users",
  },
  {
    key: "admins",
    eyebrow: "Admins",
    value: fmt(stats.value?.users_admin),
    meta: "Active administrators",
    icon: ShieldCheck,
    hue: "262 80% 68%",
  },
  {
    key: "managers",
    eyebrow: "Managers",
    value: fmt(stats.value?.users_manager),
    meta: "Active managers",
    icon: UserRoundCog,
    hue: "35 95% 60%",
  },
  {
    key: "clients",
    eyebrow: "Clients",
    value: fmt(stats.value?.clients_enabled),
    meta: loading.value ? "OIDC apps" : `of ${stats.value?.clients_total ?? 0} registered apps`,
    icon: Boxes,
    hue: "152 65% 48%",
    to: "/clients",
  },
]);

function fmt(v: number | undefined): string {
  if (loading.value) return "—";
  return String(v ?? 0);
}

// --- device portrait: browser / OS glyphs ---
// Unified pastel palette: every family sits in the same lightness band
// (L 62-70) with soft saturation (S 55-70), so the whole page reads as one
// airy tone regardless of hue.
const BROWSER_COLORS: Record<string, string> = {
  Chrome: "hsl(8 85% 66%)",
  Safari: "hsl(211 90% 68%)",
  Firefox: "hsl(27 95% 66%)",
  Edge: "hsl(189 80% 58%)",
  Opera: "hsl(340 80% 68%)",
  Unknown: "hsl(215 12% 72%)",
};

const OS_ICONS: Record<string, unknown> = {
  macOS: Laptop,
  Windows: Monitor,
  iOS: Smartphone,
  Android: Smartphone,
  Linux: Terminal,
  ChromeOS: Monitor,
};

function osIcons(items: NameCount[] | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const it of items ?? []) {
    out[it.name] = OS_ICONS[baseName(it.name)] ?? FALLBACK_ICON;
  }
  return out;
}
// Same pastel band as browsers (L 62-70, soft S) for tonal consistency.
const OS_COLORS: Record<string, string> = {
  macOS: "hsl(25 80% 68%)",
  Windows: "hsl(206 85% 66%)",
  iOS: "hsl(233 85% 72%)",
  Android: "hsl(142 60% 58%)",
  Linux: "hsl(262 75% 70%)",
  ChromeOS: "hsl(190 80% 60%)",
};

const FALLBACK_ICON = MonitorSmartphone;

const BROWSER_ICONS: Record<string, unknown> = {
  Chrome: Monitor,
  Firefox: Flame,
  Safari: Compass,
  Edge: Globe,
  Opera: Globe,
};

/** Strip a trailing version ("Chrome 128" -> "Chrome") for family lookup. */
const baseName = (name: string) => name.replace(/\s+\d+(\.\d+)*$/, "");

/** Deterministic hue for families outside the fixed tables (rare long tail). */
function tailColor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  return `hsl(${h} 65% 66%)`;
}

function browserIcons(items: NameCount[] | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const it of items ?? []) {
    out[it.name] = BROWSER_ICONS[baseName(it.name)] ?? FALLBACK_ICON;
  }
  return out;
}

function browserColors(items: NameCount[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const it of items ?? []) {
    const family = baseName(it.name);
    out[it.name] = BROWSER_COLORS[family] ?? (family === "Unknown" ? BROWSER_COLORS.Unknown : tailColor(family));
  }
  return out;
}

function osColors(items: NameCount[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const it of items ?? []) {
    const family = baseName(it.name);
    out[it.name] = OS_COLORS[family] ?? (family === "Unknown" ? BROWSER_COLORS.Unknown : tailColor(family));
  }
  return out;
}

function clientLabel(id: string | null): string {
  if (!id) return "";
  return id === "(direct)" ? "Signet (direct)" : id;
}

function formatShortTime(iso: string) {
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch {
    return iso;
  }
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Overview"
      description="Global snapshot of Signet identity and connected applications."
    >
      <template #actions>
        <label class="flex items-center gap-2 text-xs text-muted-foreground">
          <Boxes class="h-3.5 w-3.5" />
          <span class="sr-only">Filter by app</span>
          <select
            v-model="clientFilter"
            class="h-8 rounded-lg border border-border/60 bg-background px-2 text-xs outline-none"
          >
            <option v-for="opt in clientOptions" :key="opt.value || 'all'" :value="opt.value">
              {{ opt.label }}
            </option>
          </select>
        </label>
      </template>
    </PageHeader>

    <p v-if="error" class="field-error">{{ error }}</p>

    <!-- Identity cards: semantic hue + glyph, arrow marks navigable cards. -->
    <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <component
        :is="card.to ? RouterLink : 'div'"
        v-for="card in statCards"
        :key="card.key"
        :to="card.to"
        class="surface-card group relative block py-6 px-5 transition-shadow hover:shadow-sm"
      >
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <p class="type-eyebrow">{{ card.eyebrow }}</p>
            <p class="mt-2 text-2xl font-semibold tracking-tight tabular-nums">{{ card.value }}</p>
            <p class="type-meta mt-1.5 truncate">{{ card.meta }}</p>
          </div>
          <span
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition-colors"
            :style="{ background: `hsl(${card.hue} / 0.12)`, color: `hsl(${card.hue})` }"
          >
            <component :is="card.icon" class="h-5 w-5" />
          </span>
        </div>
        <ArrowUpRight
          v-if="card.to"
          class="absolute right-3 top-3 h-3.5 w-3.5 text-muted-foreground/0 transition-colors group-hover:text-muted-foreground"
        />
      </component>
    </div>

    <!-- Login trend + device portrait: headers live inside each card so the
         two cards top-align and nothing floats above the right card. -->
    <section class="grid gap-4 lg:grid-cols-5">
      <div class="surface-card flex flex-col px-5 py-6 lg:col-span-3">
        <LoginTrendChart v-if="!loading && stats?.login_trend?.length" v-model="loginRange" :points="stats.login_trend" :hours="stats.login_trend_24h ?? []" />
        <div v-else-if="loading" class="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
          Loading…
        </div>
        <div v-else class="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
          No login trend data
        </div>
      </div>

        <div class="surface-card px-5 py-6 lg:col-span-2">
          <div class="mb-4 flex items-center justify-between gap-3">
            <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
              <MonitorSmartphone class="h-4 w-4 text-muted-foreground" />
              Device portrait
            </h2>
            <span class="type-meta">Last 30 days</span>
          </div>
          <div v-if="loading" class="flex h-[210px] items-center justify-center text-sm text-muted-foreground">
            Loading…
          </div>
          <div v-else class="space-y-5">
            <DonutChart
              title="Browsers"
              :icon="Compass"
              :items="stats?.browsers ?? []"
              :icons="browserIcons(stats?.browsers)"
              :colors="browserColors(stats?.browsers)"
            />
            <DonutChart
              title="Operating systems"
              :icon="Laptop"
              :items="stats?.oses ?? []"
              :icons="osIcons(stats?.oses)"
              :colors="osColors(stats?.oses)"
            />
          </div>
        </div>
    </section>

    <!-- Per-app ranking + recent logins -->
    <section class="grid gap-4 lg:grid-cols-5">
      <div class="surface-card px-5 py-6 lg:col-span-3">
        <div class="mb-4">
          <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
            <Boxes class="h-4 w-4 text-muted-foreground" />
            Logins by app
          </h2>
          <p class="type-meta mt-1">
            Sign-ins per app over the last 30 days (top 10) — bar = logins, Users = unique
            accounts.
          </p>
        </div>
        <div v-if="loading" class="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
          Loading…
        </div>
        <HBarRank v-else :items="stats?.by_client ?? []" />
      </div>

      <div class="surface-card flex flex-col overflow-hidden lg:col-span-2">
        <div class="flex shrink-0 items-center justify-between border-b border-border/30 px-5 py-4">
          <p class="text-xs font-semibold uppercase tracking-[0.06em] text-muted-foreground">
            Recent logins
          </p>
          <RouterLink
            to="/audit-logs"
            class="text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            View all →
          </RouterLink>
        </div>
        <div v-if="loading" class="py-10 text-center text-sm text-muted-foreground">Loading…</div>
        <div
          v-else-if="!stats?.recent_logins?.length"
          class="flex flex-1 items-center justify-center py-10 text-center text-sm text-muted-foreground"
        >
          No login events in the last 7 days
        </div>
        <ul v-else class="max-h-[300px] divide-y divide-border/20 overflow-y-auto">
          <li v-for="(row, idx) in stats.recent_logins" :key="idx" class="px-5 py-3">
            <div class="flex items-center justify-between gap-3">
              <p class="flex min-w-0 items-center gap-2">
                <span class="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                  <AppWindow v-if="row.client_id && row.client_id !== '(direct)'" class="h-3 w-3" />
                  <DoorOpen v-else class="h-3 w-3" />
                </span>
                <span class="min-w-0 truncate text-xs font-medium">{{ row.actor_email || "—" }}</span>
              </p>
              <p class="whitespace-nowrap text-[11px] text-muted-foreground">
                {{ formatShortTime(row.created_at) }}
              </p>
            </div>
            <p class="mt-1 flex flex-wrap items-center gap-x-2 pl-8 font-mono text-[11px] text-muted-foreground">
              <span>{{ [row.ip, row.browser, row.os].filter(Boolean).join(" · ") || "—" }}</span>
              <span
                v-if="clientLabel(row.client_id)"
                class="rounded-full border border-[hsl(219_85%_62%/0.35)] bg-[hsl(219_85%_62%/0.12)] px-2 py-px font-sans text-[10px] font-medium not-italic text-[hsl(219_60%_45%)]"
              >
                {{ clientLabel(row.client_id) }}
              </span>
            </p>
          </li>
        </ul>
        <div class="shrink-0 border-t border-border/30 px-5 py-3.5 text-center">
          <RouterLink
            to="/audit-logs"
            class="text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            Open audit logs
          </RouterLink>
        </div>
      </div>
    </section>
  </div>
</template>

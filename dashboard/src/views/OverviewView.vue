<script setup lang="ts">
import {
  AlertTriangle,
  AppWindow,
  ArrowRight,
  ArrowUpRight,
  Check,
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
  X,
} from "@lucide/vue";
import type { Component } from "vue";
import { computed, onMounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import DonutChart from "@/components/ui/DonutChart.vue";
import HBarRank from "@/components/ui/HBarRank.vue";
import LoginTrendChart from "@/components/ui/LoginTrendChart.vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  fetchAdminStats,
  fetchServerSettings,
  fetchSmtpSettings,
  listClients,
  type AdminStats,
  type AdminClient,
  type NameCount,
  type ServerSettings,
  type SmtpSettings,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

const loading = ref(true);
const error = ref("");
const stats = ref<AdminStats | null>(null);

// --- first-run setup guide ------------------------------------------------
//
// Shown to administrators until they dismiss it. Every step is derived from
// data that already exists (issuer source, SMTP configuration, registered
// clients), so the guide never asks for the same value twice and cannot drift
// from the real state. Dismissal is per user and per browser: a guide is a
// convenience, not a deployment setting.
const auth = useAuthStore();
const serverSettings = ref<ServerSettings | null>(null);
const smtp = ref<SmtpSettings | null>(null);
const guideLoaded = ref(false);
const guideDismissed = ref(false);

const guideStorageKey = computed(
  () => `signet.getStarted.dismissed.${auth.user?.id ?? "anonymous"}`,
);

type GuideStatus = "done" | "warning" | "todo";

interface GuideStep {
  key: string;
  title: string;
  detail: string;
  status: GuideStatus;
  /// Required for a usable deployment. The guide cannot be dismissed while one
  /// of these is not `done`; email delivery is deliberately optional (a local
  /// trial has no relay and still works).
  required: boolean;
  to?: string;
  cta?: string;
}

const checkedAt = ref<Date | null>(null);

/// `localhost` plain http is a legitimate local trial; anything else on http is
/// a credential-in-the-clear warning rather than a hard error.
function isLocalHost(host: string) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

/// Validates the *saved* issuer rather than merely its presence: a value that
/// parses, matches the origin the admin is actually using, and uses https off
/// localhost. The API already rejects a malformed origin; this catches the
/// operational mismatch (dashboard on one URL, clients sent to another).
function checkIssuer(): { status: GuideStatus; detail: string } {
  const saved = serverSettings.value;
  if (!saved) {
    return {
      status: "warning",
      detail: "Could not read the issuer settings — open Settings to check them.",
    };
  }
  let parsed: URL;
  try {
    parsed = new URL(saved.issuer);
  } catch {
    return { status: "warning", detail: "The saved issuer is not a valid URL." };
  }
  const origin = window.location.origin;
  const trimmed = saved.issuer.replace(/\/$/, "");
  // localhost is a working value for a local trial and a broken one for every
  // client that is not on this machine — say so instead of calling it done.
  if (isLocalHost(parsed.hostname)) {
    return {
      status: "warning",
      detail: `${saved.issuer} is only reachable from this machine. Replace it with the address clients will use (for example https://sso.example.com) before connecting real applications.`,
    };
  }
  if (saved.source === "default") {
    return trimmed === origin
      ? {
          status: "done",
          detail: `Using the built-in default ${saved.issuer}, which matches this dashboard.`,
        }
      : {
          status: "todo",
          detail: `Still on the built-in default ${saved.issuer}, but this dashboard is opened as ${origin}. Set the public URL clients will use.`,
        };
  }
  if (parsed.protocol === "http:" && !isLocalHost(parsed.hostname)) {
    return {
      status: "warning",
      detail: `${saved.issuer} is plain http — sign-in traffic and cookies would travel unencrypted. Use https outside local development.`,
    };
  }
  if (trimmed !== origin) {
    return {
      status: "warning",
      detail: `Saved as ${saved.issuer}, but this dashboard is opened as ${origin}. Clients are sent to the saved issuer — confirm DNS and the reverse proxy point both at this instance.`,
    };
  }
  return {
    status: "done",
    detail: `Clients discover this server at ${saved.issuer}.`,
  };
}

/// Checks the parts a password-reset actually needs: a relay plus a From
/// address. `configured` alone can be true while a field is still empty.
function checkSmtp(): { status: GuideStatus; detail: string } {
  const saved = smtp.value;
  if (!saved) {
    return {
      status: "warning",
      detail: "Could not read the SMTP settings — open Settings to check them.",
    };
  }
  if (!saved.configured) {
    return {
      status: "todo",
      detail:
        "No relay configured: password reset and email verification cannot be delivered. Optional for a local trial.",
    };
  }
  if (!saved.host || !saved.from) {
    return {
      status: "warning",
      detail: "Mail is marked configured, but the relay host or From address is missing — reset mail will fail.",
    };
  }
  return {
    status: "done",
    detail: `Mail is sent through ${saved.host} as ${saved.from}.`,
  };
}

/// `n > 0` is not enough: a disabled client refuses sign-in, and a redirect URI
/// that is not http(s) can never complete a flow.
function checkClients(): { status: GuideStatus; detail: string } {
  if (clients.value.length === 0) {
    return {
      status: "todo",
      detail: "Sign-in only becomes useful once a client is registered with a redirect URI.",
    };
  }
  const enabled = clients.value.filter((c) => c.enabled);
  if (enabled.length === 0) {
    return {
      status: "warning",
      detail: `${clients.value.length} application(s) registered, but all are disabled — sign-in will be refused.`,
    };
  }
  const broken = enabled.find(
    (c) =>
      c.redirect_uris.length === 0 ||
      c.redirect_uris.some((u) => !/^https?:\/\//i.test(u) || u.includes("#")),
  );
  if (broken) {
    return {
      status: "warning",
      detail: `"${broken.client_name || broken.client_id}" has a redirect URI that is missing, not http(s), or carries a fragment.`,
    };
  }
  return {
    status: "done",
    detail: `${enabled.length} enabled application${enabled.length === 1 ? "" : "s"} with valid redirect URIs.`,
  };
}

const guideSteps = computed<GuideStep[]>(() => {
  const issuer = checkIssuer();
  const mail = checkSmtp();
  const client = checkClients();
  return [
    {
      key: "admin",
      title: "Administrator account",
      detail: `Signed in as ${auth.user?.email ?? "an administrator"}.`,
      status: "done",
      required: true,
    },
    {
      key: "issuer",
      title: "Public issuer",
      detail: issuer.detail,
      status: issuer.status,
      required: true,
      to: "/settings",
      cta: "Review issuer",
    },
    {
      key: "email",
      title: "Email delivery",
      detail: mail.detail,
      status: mail.status,
      required: false,
      to: "/settings",
      cta: "Configure SMTP",
    },
    {
      key: "client",
      title: "First application",
      detail: client.detail,
      status: client.status,
      required: true,
      to: "/clients",
      cta: "Register a client",
    },
  ];
});

const guideDone = computed(() => guideSteps.value.filter((s) => s.status === "done").length);
const guideRequiredPending = computed(
  () => guideSteps.value.filter((s) => s.required && s.status !== "done").length,
);
const guideCanDismiss = computed(() => guideRequiredPending.value === 0);
const guideWarnings = computed(
  () => guideSteps.value.filter((s) => s.status === "warning").length,
);
const guideAllDone = computed(() => guideDone.value === guideSteps.value.length);
const showGuide = computed(
  () => auth.isAdmin && guideLoaded.value && !guideDismissed.value,
);
const checkedLabel = computed(() =>
  checkedAt.value
    ? `Checked ${checkedAt.value.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : "",
);

function statusColor(status: GuideStatus) {
  return status === "done"
    ? "hsl(152 42% 42%)"
    : status === "warning"
      ? "hsl(38 92% 45%)"
      : "hsl(215 14% 82%)";
}

/// A tint of [`statusColor`] for the icon chip; `color-mix` is avoided to keep
/// the value legible in older browser engines.
function statusTint(status: GuideStatus) {
  return status === "done"
    ? "hsl(152 42% 42% / 0.12)"
    : status === "warning"
      ? "hsl(38 92% 45% / 0.14)"
      : "transparent";
}

function statusLabel(status: GuideStatus) {
  return status === "done" ? "Done" : status === "warning" ? "Needs attention" : "To do";
}


function readGuideDismissed() {
  try {
    guideDismissed.value = localStorage.getItem(guideStorageKey.value) === "1";
  } catch {
    guideDismissed.value = false;
  }
}

function dismissGuide() {
  // Required work first: a guide that can be dismissed while sign-in is still
  // broken is a guide that will never be finished.
  if (!guideCanDismiss.value) return;
  guideDismissed.value = true;
  try {
    localStorage.setItem(guideStorageKey.value, "1");
  } catch {
    /* storage disabled: the guide simply returns next visit */
  }
}

function reopenGuide() {
  guideDismissed.value = false;
  try {
    localStorage.removeItem(guideStorageKey.value);
  } catch {
    /* ignore */
  }
}

async function loadGuide() {
  const [issuerRes, smtpRes] = await Promise.allSettled([
    fetchServerSettings(),
    fetchSmtpSettings(),
  ]);
  if (issuerRes.status === "fulfilled") serverSettings.value = issuerRes.value;
  if (smtpRes.status === "fulfilled") smtp.value = smtpRes.value;
  guideLoaded.value = true;
  checkedAt.value = new Date();
}

/// Re-reads everything the checks depend on, so "looks correct" is measured
/// against the server now rather than at page load.
async function recheckGuide() {
  guideLoaded.value = false;
  try {
    clients.value = await listClients();
  } catch {
    /* keep the previous list; the check reports what it has */
  }
  await loadGuide();
}

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
  if (auth.isAdmin) {
    readGuideDismissed();
    void loadGuide();
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
        <UiButton
          v-if="auth.isAdmin && guideLoaded && !showGuide && !guideAllDone"
          variant="ghost"
          size="sm"
          @click="reopenGuide"
        >
          Setup guide · {{ guideDone }}/{{ guideSteps.length }}
        </UiButton>
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

    <section v-if="showGuide" class="surface-card overflow-hidden">
      <div class="flex items-start justify-between gap-4 px-5 pb-5 pt-6">
        <div class="min-w-0">
          <p class="text-[10px] font-semibold uppercase tracking-[0.14em] text-primary/70">
            First-run setup
          </p>
          <h2 class="mt-1.5 text-lg font-semibold tracking-tight">
            {{ guideAllDone ? "You're all set" : "Finish setting up Signet" }}
          </h2>
          <p class="mt-1.5 max-w-2xl text-[12px] leading-relaxed text-muted-foreground">
            {{
              guideAllDone
                ? "Every required check passes. Dismiss this guide — the same checks stay available from the header."
                : "Required steps are verified against the live configuration. The guide can be dismissed once they pass."
            }}
          </p>
        </div>

        <div class="flex shrink-0 items-start gap-1">
          <div class="pr-1 text-right">
            <p
              class="text-2xl font-semibold leading-none tabular-nums"
              :class="guideAllDone ? 'text-emerald-600' : 'text-foreground'"
            >
              {{ guideDone }}<span class="text-sm font-normal text-muted-foreground/60">/{{ guideSteps.length }}</span>
            </p>
            <p class="mt-1 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
              complete
            </p>
          </div>
          <button
            type="button"
            class="-mr-1 rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
            :disabled="!guideCanDismiss"
            :title="
              guideCanDismiss
                ? 'Hide the setup guide'
                : 'Finish the required steps before dismissing'
            "
            @click="dismissGuide"
          >
            <X class="h-4 w-4" />
          </button>
        </div>
      </div>

      <div class="px-5">
        <div class="flex h-1 w-full gap-1">
          <span
            v-for="step in guideSteps"
            :key="step.key"
            class="h-1 flex-1 rounded-full transition-colors duration-300"
            :style="{ background: statusColor(step.status) }"
          />
        </div>
        <div
          class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground"
        >
          <span
            v-if="guideWarnings"
            class="inline-flex items-center gap-1 font-medium text-amber-600"
          >
            <AlertTriangle class="h-3 w-3" />
            {{ guideWarnings }} needs attention
          </span>
          <span v-if="checkedLabel" class="tabular-nums">{{ checkedLabel }}</span>
          <button
            type="button"
            class="font-medium text-muted-foreground transition-colors hover:text-foreground disabled:opacity-50"
            :disabled="!guideLoaded"
            @click="recheckGuide"
          >
            Re-check
          </button>
        </div>
      </div>

      <ul class="mt-4 space-y-1 px-2 pb-1">
        <li
          v-for="(step, i) in guideSteps"
          :key="step.key"
          class="flex items-start gap-3 rounded-xl px-3 py-2.5 transition-colors"
          :class="step.status === 'warning' ? 'bg-amber-500/[0.07]' : 'hover:bg-card/70'"
        >
          <span
            class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold"
            :class="step.status === 'todo' ? 'bg-muted text-muted-foreground' : ''"
            :style="
              step.status === 'todo'
                ? undefined
                : { background: statusTint(step.status), color: statusColor(step.status) }
            "
          >
            <Check v-if="step.status === 'done'" class="h-3.5 w-3.5" />
            <AlertTriangle v-else-if="step.status === 'warning'" class="h-3.5 w-3.5" />
            <template v-else>{{ i + 1 }}</template>
          </span>

          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
              <p class="text-[13px] font-medium">{{ step.title }}</p>
              <span
                class="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em]"
                :class="
                  step.status === 'done'
                    ? 'text-emerald-700/80'
                    : step.status === 'warning'
                      ? 'bg-amber-500/12 text-amber-700'
                      : 'bg-muted text-muted-foreground'
                "
              >
                {{ statusLabel(step.status) }}
              </span>
              <span
                v-if="!step.required"
                class="text-[10px] uppercase tracking-[0.06em] text-muted-foreground/60"
              >
                optional
              </span>
            </div>
            <p class="mt-0.5 text-[12px] leading-relaxed text-muted-foreground">
              {{ step.detail }}
            </p>
          </div>

          <RouterLink
            v-if="step.status !== 'done' && step.to"
            :to="step.to"
            class="group mt-0.5 inline-flex shrink-0 items-center gap-1 text-[12px] font-medium text-foreground hover:underline"
          >
            {{ step.cta }}
            <ArrowRight class="h-3 w-3 transition-transform group-hover:translate-x-0.5" />
          </RouterLink>
        </li>
      </ul>

      <div class="flex flex-wrap items-center justify-between gap-2 px-5 pb-5 pt-2">
        <p class="text-[11px] text-muted-foreground">
          <template v-if="guideCanDismiss">
            Read-only checks. You can dismiss this guide.
          </template>
          <template v-else>
            Required steps must pass before this guide can be dismissed.
          </template>
        </p>
        <UiButton
          size="sm"
          variant="secondary"
          :disabled="!guideCanDismiss"
          :title="guideCanDismiss ? 'Hide the setup guide' : 'Finish the required steps first'"
          @click="dismissGuide"
        >
          Dismiss guide
        </UiButton>
      </div>
    </section>

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

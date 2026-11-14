<script setup lang="ts">
import { AppWindow, KeyRound, Laptop, LogIn, LogOut, ShieldCheck, ShieldAlert, Smartphone, UserRound } from "@lucide/vue";
import { computed, onMounted, ref, watch } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import TablePagination from "@/components/ui/TablePagination.vue";
import { fetchMyActivity, type ActivityItem } from "@/lib/api";

type Summary = {
  last_login: { ip: string | null; browser: string | null; os: string | null; at: string } | null;
  active_sessions: number;
  totp_enabled: boolean;
  passkey_count: number;
  consent_count: number;
};

const loading = ref(true);
const error = ref("");
const items = ref<ActivityItem[]>([]);
const summary = ref<Summary | null>(null);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);

const ACTION_META: Record<string, { label: string; icon: typeof LogIn; tone: "ok" | "warn" | "danger" | "muted" }> = {
  "auth.login": { label: "Signed in", icon: LogIn, tone: "ok" },
  "auth.login_failed": { label: "Failed sign-in", icon: ShieldAlert, tone: "danger" },
  "auth.new_device": { label: "Signed in from a new device", icon: Smartphone, tone: "warn" },
  "auth.password_change": { label: "Changed password", icon: KeyRound, tone: "muted" },
  "me.profile_update": { label: "Updated profile", icon: UserRound, tone: "muted" },
  "mfa.enroll": { label: "Enabled two-factor auth", icon: ShieldAlert, tone: "ok" },
  "mfa.verify": { label: "Completed MFA verification", icon: ShieldAlert, tone: "muted" },
  "mfa.recovery_use": { label: "Used a recovery code", icon: KeyRound, tone: "warn" },
  "mfa.recovery_regen": { label: "Regenerated recovery codes", icon: KeyRound, tone: "muted" },
  "mfa.rebind": { label: "Rebound authenticator", icon: Smartphone, tone: "muted" },
  "mfa.passkey_enroll": { label: "Added a passkey", icon: KeyRound, tone: "ok" },
  "mfa.passkey_remove": { label: "Removed a passkey", icon: KeyRound, tone: "muted" },
  "oauth.consent_revoke": { label: "Revoked app access", icon: LogOut, tone: "muted" },
};

const TONE_CLASS: Record<string, string> = {
  ok: "bg-emerald-500/10 text-emerald-600",
  warn: "bg-amber-500/10 text-amber-700",
  danger: "bg-destructive/10 text-destructive",
  muted: "bg-muted text-muted-foreground",
};

function metaFor(action: string) {
  return ACTION_META[action] ?? { label: action, icon: LogIn, tone: "muted" as const };
}

function formatRelative(iso: string) {
  try {
    const d = new Date(iso);
    const diff = Date.now() - d.getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch {
    return iso;
  }
}

const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)));
const rangeLabel = computed(() => {
  if (total.value === 0) return "0 results";
  const start = (page.value - 1) * pageSize.value + 1;
  const end = Math.min(page.value * pageSize.value, total.value);
  return `${start}–${end} of ${total.value}`;
});

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const res = await fetchMyActivity({ page: page.value, page_size: pageSize.value });
    items.value = res.items;
    summary.value = res.summary;
    total.value = res.total;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load activity";
  } finally {
    loading.value = false;
  }
}

watch([page, pageSize], load);

onMounted(load);
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="My security"
      description="A personal view of your account security and recent activity."
    />

    <p v-if="error" class="field-error">{{ error }}</p>

    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <div class="surface-card p-5">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <p class="type-eyebrow">Last sign-in</p>
            <p class="mt-2 truncate text-lg font-semibold tracking-tight">
              <template v-if="loading">—</template>
              <template v-else-if="summary?.last_login">{{ formatRelative(summary.last_login.at) }}</template>
              <template v-else>Never</template>
            </p>
            <p class="type-meta mt-1.5 truncate">
              <template v-if="!loading && summary?.last_login">
                {{ [summary.last_login.browser, summary.last_login.os].filter(Boolean).join(" · ") || "—" }}
              </template>
              <template v-else-if="!loading">No sign-ins yet</template>
            </p>
          </div>
          <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-muted text-muted-foreground">
            <LogIn class="h-4 w-4" />
          </span>
        </div>
      </div>

      <div class="surface-card p-5">
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="type-eyebrow">Active sessions</p>
            <p class="mt-2 text-lg font-semibold tracking-tight">
              <template v-if="loading">—</template>
              <template v-else>{{ summary?.active_sessions ?? 0 }}</template>
            </p>
            <p class="type-meta mt-1.5">Devices currently signed in</p>
          </div>
          <span class="flex h-9 w-9 items-center justify-center rounded-xl bg-muted text-muted-foreground">
            <Laptop class="h-4 w-4" />
          </span>
        </div>
      </div>

      <div class="surface-card p-5">
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="type-eyebrow">Two-factor auth</p>
            <p class="mt-2 text-lg font-semibold tracking-tight">
              <template v-if="loading">—</template>
              <template v-else-if="summary?.totp_enabled">Enabled</template>
              <template v-else>Not set up</template>
            </p>
            <p class="type-meta mt-1.5">{{ summary?.passkey_count ?? 0 }} passkey(s) enrolled</p>
          </div>
          <span
            class="flex h-9 w-9 items-center justify-center rounded-xl"
            :class="summary?.totp_enabled ? 'bg-emerald-500/10 text-emerald-600' : 'bg-muted text-muted-foreground'"
          >
            <ShieldCheck class="h-4 w-4" />
          </span>
        </div>
      </div>

      <div class="surface-card p-5">
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="type-eyebrow">Connected apps</p>
            <p class="mt-2 text-lg font-semibold tracking-tight">
              <template v-if="loading">—</template>
              <template v-else>{{ summary?.consent_count ?? 0 }}</template>
            </p>
            <p class="type-meta mt-1.5">OAuth authorizations granted</p>
          </div>
          <span class="flex h-9 w-9 items-center justify-center rounded-xl bg-muted text-muted-foreground">
            <AppWindow class="h-4 w-4" />
          </span>
        </div>
      </div>
    </div>

    <section class="space-y-3">
      <div>
        <h2 class="text-sm font-semibold tracking-tight">Recent activity</h2>
        <p class="type-meta mt-1">Your sign-ins and account/security actions.</p>
      </div>

      <div
        v-if="loading"
        class="surface-card overflow-hidden py-12 text-center text-sm text-muted-foreground"
      >
        Loading…
      </div>

      <section v-else class="surface-card overflow-hidden">
        <ul v-if="items.length" class="divide-y divide-border/50">
          <li
            v-for="it in items"
            :key="it.id"
            class="flex items-start justify-between gap-4 px-5 py-3.5"
          >
            <div class="flex min-w-0 items-start gap-3">
              <span
                class="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
                :class="TONE_CLASS[metaFor(it.action).tone]"
              >
                <component :is="metaFor(it.action).icon" class="h-4 w-4" />
              </span>
              <div class="min-w-0">
                <p class="text-sm font-medium">{{ metaFor(it.action).label }}</p>
                <p class="type-meta mt-0.5 text-xs">
                  <template v-if="it.browser || it.os">
                    {{ [it.browser, it.os].filter(Boolean).join(" · ") }}
                    <template v-if="it.ip"> · {{ it.ip }}</template>
                  </template>
                  <template v-else-if="it.ip">{{ it.ip }}</template>
                  <template v-else>—</template>
                </p>
              </div>
            </div>
            <time class="shrink-0 type-meta text-xs" :title="it.created_at">
              {{ new Date(it.created_at).toLocaleString() }}
            </time>
          </li>
        </ul>

        <div v-else class="py-12 text-center text-sm text-muted-foreground">
          No activity yet.
        </div>

        <TablePagination
          v-if="total > 0"
          v-model:page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-count="pageCount"
          :range-label="rangeLabel"
        />
      </section>
    </section>
  </div>
</template>

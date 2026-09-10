<script setup lang="ts">
import { AppWindow, ChevronDown, Download, Fingerprint, KeyRound, Laptop, Link2, LogOut, PanelLeft, Shield, User } from "@lucide/vue";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import UiButton from "@/components/ui/UiButton.vue";
import { useQrDataUrl } from "@/composables/useQrDataUrl";
import {
  changePassword,
  checkPhone,
  fetchMeMfa,
  fetchMyIdentities,
  fetchEnabledSsoProviders,
  fetchMySessions,
  listPasskeys,
  listMyConsents,
  meMfaEnrollConfirm,
  meMfaEnrollStart,
  meMfaDisable,
  meMfaRebindConfirm,
  meMfaRebindStart,
  meMfaRegenerateRecovery,
  removePasskey,
  revokeMyConsent,
  revokeMySession,
  revokeOtherSessions,
  unlinkIdentity,
  updateMe,
  type Consent,
  type LinkedIdentity,
  type Passkey,
  type SessionInfo,
  type SsoProviderType,
} from "@/lib/api";
import { enrollPasskey } from "@/composables/usePasskeys";
import { useAuthStore } from "@/stores/auth";
import { useUiStore } from "@/stores/ui";

const ui = useUiStore();
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const pageTitle = computed(() => {
  const matched = route.matched[route.matched.length - 1];
  return (matched?.meta?.title as string) || "Signet";
});

const pageSubtitle = "Unified identity for internal systems";
const displayInitial = computed(() => (auth.displayName || "?").slice(0, 1));

const menuOpen = ref(false);
const menuRoot = ref<HTMLElement | null>(null);

const showProfile = ref(false);
const showPassword = ref(false);
const showMfa = ref(false);
const showSessions = ref(false);
const showPasskeys = ref(false);
const showConsents = ref(false);
const showIdentities = ref(false);
const identities = ref<LinkedIdentity[]>([]);
const identitiesLoading = ref(false);
const identitiesErr = ref("");
const identitiesBusy = ref(false);
const enabledSsoProviders = ref<{ code: string; type: SsoProviderType; display_name: string }[]>([]);

const linkedProviderCodes = computed(() => new Set(identities.value.map((i) => i.provider_code)));
const linkableProviders = computed(() =>
  enabledSsoProviders.value.filter((p) => !linkedProviderCodes.value.has(p.code)),
);
const displayName = ref("");
const profilePhone = ref("");
const profileErr = ref("");
const profileSaving = ref(false);

const sessions = ref<SessionInfo[]>([]);
const currentSessionId = ref<string | null>(null);
const sessionsLoading = ref(false);
const sessionsErr = ref("");
const sessionsBusy = ref(false);

const passkeys = ref<Passkey[]>([]);
const passkeyName = ref("");
const passkeyLoading = ref(false);
const passkeyBusy = ref(false);
const passkeyErr = ref("");

const consents = ref<Consent[]>([]);
const consentsLoading = ref(false);
const consentsBusy = ref(false);
const consentsErr = ref("");

const currentPassword = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const passwordErr = ref("");
const passwordSaving = ref(false);

type MfaPanel = "status" | "enroll" | "regen" | "rebind_auth" | "rebind" | "codes" | "disable";
const mfaPanel = ref<MfaPanel>("status");
const mfaLoading = ref(false);
const mfaErr = ref("");
const totpEnabled = ref(false);
const recoveryRemaining = ref(0);
const policyRequired = ref(false);
const mfaCode = ref("");
const enrollSecret = ref("");
const enrollUri = ref("");
const { dataUrl: qrUrl } = useQrDataUrl(enrollUri);
const recoveryCodes = ref<string[]>([]);

async function handleLogout() {
  menuOpen.value = false;
  await auth.logout();
  await router.push({ name: "login" });
}

function openProfile() {
  menuOpen.value = false;
  displayName.value = auth.user?.display_name ?? "";
  profilePhone.value = auth.user?.phone ?? "";
  profilePhoneCheckState.value = "idle";
  profileErr.value = "";
  showProfile.value = true;
}

function openPassword() {
  menuOpen.value = false;
  currentPassword.value = "";
  newPassword.value = "";
  confirmPassword.value = "";
  passwordErr.value = "";
  showPassword.value = true;
}

async function openMfa() {
  menuOpen.value = false;
  mfaErr.value = "";
  mfaPanel.value = "status";
  mfaCode.value = "";
  recoveryCodes.value = [];
  showMfa.value = true;
  mfaLoading.value = true;
  try {
    const s = await fetchMeMfa();
    totpEnabled.value = s.totp_enabled;
    recoveryRemaining.value = s.recovery_codes_remaining;
    policyRequired.value = s.policy_required;
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Failed to load MFA status";
  } finally {
    mfaLoading.value = false;
  }
}

async function openSessions() {
  menuOpen.value = false;
  sessionsErr.value = "";
  showSessions.value = true;
  await loadSessions();
}

async function openPasskeys() {
  menuOpen.value = false;
  passkeyErr.value = "";
  passkeyName.value = "";
  showPasskeys.value = true;
  await loadPasskeys();
}

const CONSENT_SCOPE_LABELS: Record<string, string> = {
  openid: "Sign you in",
  profile: "Profile (name)",
  email: "Email address",
  phone: "Phone number",
  groups: "Group memberships",
};

function scopeLabel(s: string) {
  return CONSENT_SCOPE_LABELS[s] ?? s;
}

const SSO_TYPE_TAG_CLASS: Record<SsoProviderType, string> = {
  github: "bg-[hsl(217_30%_20%)] text-white",
  google: "bg-[hsl(0_70%_55%)] text-white",
  feishu: "bg-[hsl(211_100%_50%)] text-white",
  wechat: "bg-[hsl(142_70%_40%)] text-white",
  oidc: "bg-primary/10 text-primary",
};

function ssoTypeTagClass(type: string) {
  return SSO_TYPE_TAG_CLASS[type as SsoProviderType] ?? SSO_TYPE_TAG_CLASS.oidc;
}

async function openConsents() {
  menuOpen.value = false;
  consentsErr.value = "";
  showConsents.value = true;
  await loadConsents();
}

async function openIdentities() {
  menuOpen.value = false;
  identitiesErr.value = "";
  showIdentities.value = true;
  await loadIdentities();
}

async function loadIdentities() {
  identitiesLoading.value = true;
  try {
    const [res, providers] = await Promise.all([
      fetchMyIdentities(),
      fetchEnabledSsoProviders().catch(() => ({ providers: [] as typeof enabledSsoProviders.value })),
    ]);
    identities.value = res.identities;
    enabledSsoProviders.value = providers.providers;
  } catch (e) {
    identitiesErr.value = e instanceof Error ? e.message : "Failed to linked accounts";
  } finally {
    identitiesLoading.value = false;
  }
}

function linkIdentityUrl(providerCode: string): string {
  // Full navigation so the session cookie rides along; SSO callback binds to
  // the already-authenticated user when no prior link exists.
  return `/api/v1/auth/sso/${encodeURIComponent(providerCode)}/start`;
}

async function onUnlinkIdentity(providerCode: string) {
  identitiesErr.value = "";
  identitiesBusy.value = true;
  try {
    await unlinkIdentity(providerCode);
    await loadIdentities();
  } catch (e) {
    identitiesErr.value = e instanceof Error ? e.message : "Unlink failed";
  } finally {
    identitiesBusy.value = false;
  }
}

async function loadConsents() {
  consentsLoading.value = true;
  try {
    const res = await listMyConsents();
    consents.value = res.consents;
  } catch (e) {
    consentsErr.value = e instanceof Error ? e.message : "Failed to load connected apps";
  } finally {
    consentsLoading.value = false;
  }
}

async function revokeConsent(clientId: string) {
  consentsErr.value = "";
  consentsBusy.value = true;
  try {
    await revokeMyConsent(clientId);
    await loadConsents();
  } catch (e) {
    consentsErr.value = e instanceof Error ? e.message : "Revoke failed";
  } finally {
    consentsBusy.value = false;
  }
}

async function loadPasskeys() {
  passkeyLoading.value = true;
  try {
    passkeys.value = await listPasskeys();
  } catch (e) {
    passkeyErr.value = e instanceof Error ? e.message : "Failed to load passkeys";
  } finally {
    passkeyLoading.value = false;
  }
}

async function registerPasskey() {
  passkeyErr.value = "";
  passkeyBusy.value = true;
  try {
    await enrollPasskey(passkeyName.value.trim());
    passkeyName.value = "";
    await loadPasskeys();
  } catch (e) {
    passkeyErr.value = e instanceof Error ? e.message : "Registration failed";
  } finally {
    passkeyBusy.value = false;
  }
}

async function deletePasskey(id: string) {
  passkeyErr.value = "";
  passkeyBusy.value = true;
  try {
    await removePasskey(id);
    await loadPasskeys();
  } catch (e) {
    passkeyErr.value = e instanceof Error ? e.message : "Remove failed";
  } finally {
    passkeyBusy.value = false;
  }
}

async function loadSessions() {
  sessionsLoading.value = true;
  try {
    const res = await fetchMySessions();
    sessions.value = res.sessions;
    currentSessionId.value = res.current_session_id;
  } catch (e) {
    sessionsErr.value = e instanceof Error ? e.message : "Failed to load sessions";
  } finally {
    sessionsLoading.value = false;
  }
}

async function revokeSession(id: string) {
  sessionsBusy.value = true;
  sessionsErr.value = "";
  try {
    await revokeMySession(id);
    await loadSessions();
  } catch (e) {
    sessionsErr.value = e instanceof Error ? e.message : "Failed to revoke session";
  } finally {
    sessionsBusy.value = false;
  }
}

async function revokeOthers() {
  sessionsBusy.value = true;
  sessionsErr.value = "";
  try {
    await revokeOtherSessions();
    await loadSessions();
  } catch (e) {
    sessionsErr.value = e instanceof Error ? e.message : "Failed to revoke sessions";
  } finally {
    sessionsBusy.value = false;
  }
}

async function submitProfile() {
  profileErr.value = "";
  if (profilePhoneCheckState.value === "exists") {
    profileErr.value = "This phone is already registered.";
    return;
  }
  profileSaving.value = true;
  try {
    const res = await updateMe({
      display_name: displayName.value.trim(),
      phone: profilePhone.value.trim(),
    });
    auth.setUser(res.user);
    showProfile.value = false;
  } catch (e) {
    profileErr.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    profileSaving.value = false;
  }
}

const profilePhoneCheckState = ref<"idle" | "checking" | "exists" | "ok">("idle");
let profilePhoneTimer: ReturnType<typeof setTimeout> | undefined;

watch(profilePhone, (val) => {
  if (profilePhoneTimer) clearTimeout(profilePhoneTimer);
  const phone = val.trim();
  const original = auth.user?.phone ?? "";
  if (!phone || phone === original) {
    profilePhoneCheckState.value = "idle";
    return;
  }
  profilePhoneCheckState.value = "checking";
  profilePhoneTimer = setTimeout(async () => {
    try {
      const { exists } = await checkPhone(phone, auth.user?.id);
      profilePhoneCheckState.value = exists ? "exists" : "ok";
    } catch {
      profilePhoneCheckState.value = "idle";
    }
  }, 350);
});

async function submitPassword() {
  passwordErr.value = "";
  const pw = newPassword.value;
  if (pw.length < 10 || !/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) {
    passwordErr.value =
      "Password must be at least 10 characters and include upper, lower case and a digit";
    return;
  }
  if (newPassword.value !== confirmPassword.value) {
    passwordErr.value = "Passwords do not match";
    return;
  }
  passwordSaving.value = true;
  try {
    await changePassword({
      current_password: currentPassword.value,
      new_password: newPassword.value,
    });
    showPassword.value = false;
  } catch (e) {
    passwordErr.value = e instanceof Error ? e.message : "Change failed";
  } finally {
    passwordSaving.value = false;
  }
}

async function startEnroll() {
  mfaErr.value = "";
  mfaLoading.value = true;
  try {
    const res = await meMfaEnrollStart();
    enrollSecret.value = res.secret;
    enrollUri.value = res.otpauth_uri;
    mfaCode.value = "";
    mfaPanel.value = "enroll";
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Start failed";
  } finally {
    mfaLoading.value = false;
  }
}

async function confirmEnroll() {
  mfaErr.value = "";
  mfaLoading.value = true;
  try {
    const res = await meMfaEnrollConfirm(mfaCode.value.trim());
    auth.setUser(res.user);
    recoveryCodes.value = res.recovery_codes;
    totpEnabled.value = true;
    recoveryRemaining.value = res.recovery_codes.length;
    mfaPanel.value = "codes";
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Confirm failed";
  } finally {
    mfaLoading.value = false;
  }
}

async function regenRecovery() {
  mfaErr.value = "";
  mfaLoading.value = true;
  try {
    const res = await meMfaRegenerateRecovery(mfaCode.value.trim());
    recoveryCodes.value = res.recovery_codes;
    recoveryRemaining.value = res.recovery_codes.length;
    mfaPanel.value = "codes";
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Regenerate failed";
  } finally {
    mfaLoading.value = false;
  }
}

async function disableMfa() {
  mfaErr.value = "";
  mfaLoading.value = true;
  try {
    const res = await meMfaDisable(mfaCode.value.trim());
    auth.setUser(res.user);
    totpEnabled.value = false;
    recoveryRemaining.value = 0;
    mfaPanel.value = "status";
    mfaCode.value = "";
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Disable failed";
  } finally {
    mfaLoading.value = false;
  }
}

async function startRebind() {
  mfaErr.value = "";
  mfaLoading.value = true;
  try {
    const res = await meMfaRebindStart(mfaCode.value.trim());
    enrollSecret.value = res.secret;
    enrollUri.value = res.otpauth_uri;
    mfaCode.value = "";
    mfaPanel.value = "rebind";
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Rebind start failed";
  } finally {
    mfaLoading.value = false;
  }
}

async function confirmRebind() {
  mfaErr.value = "";
  mfaLoading.value = true;
  try {
    const res = await meMfaRebindConfirm(mfaCode.value.trim());
    auth.setUser(res.user);
    recoveryCodes.value = res.recovery_codes;
    recoveryRemaining.value = res.recovery_codes.length;
    mfaPanel.value = "codes";
  } catch (e) {
    mfaErr.value = e instanceof Error ? e.message : "Rebind failed";
  } finally {
    mfaLoading.value = false;
  }
}

async function copyRecovery() {
  try {
    await navigator.clipboard.writeText(recoveryCodes.value.join("\n"));
  } catch {
    /* ignore */
  }
}

function downloadRecovery() {
  const content = recoveryCodes.value.join("\n");
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "signet-recovery-codes.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function onDocClick(e: MouseEvent) {
  if (!menuOpen.value) return;
  const el = menuRoot.value;
  if (el && !el.contains(e.target as Node)) {
    menuOpen.value = false;
  }
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === "Escape") {
    menuOpen.value = false;
    if (!profileSaving.value) showProfile.value = false;
    if (!passwordSaving.value) showPassword.value = false;
    if (!mfaLoading.value) showMfa.value = false;
    if (!sessionsBusy.value) showSessions.value = false;
    if (!passkeyBusy.value) showPasskeys.value = false;
    if (!consentsBusy.value) showConsents.value = false;
    if (!identitiesBusy.value) showIdentities.value = false;
  }
}

onMounted(() => {
  document.addEventListener("click", onDocClick);
  document.addEventListener("keydown", onKeydown);
});
onUnmounted(() => {
  document.removeEventListener("click", onDocClick);
  document.removeEventListener("keydown", onKeydown);
});
</script>

<template>
  <header
    class="shell-inset sticky top-0 z-10 flex h-14 items-center justify-between gap-4 border-b border-border bg-background"
  >
    <div class="flex min-w-0 items-center gap-3">
      <UiButton
        v-if="ui.isCollapsed"
        variant="ghost"
        size="icon"
        title="Expand sidebar (⌘B)"
        @click="ui.toggleSidebar()"
      >
        <PanelLeft class="h-4 w-4" />
      </UiButton>
      <div class="min-w-0">
        <p class="truncate text-sm font-medium tracking-tight">{{ pageTitle }}</p>
        <p class="type-meta truncate">{{ pageSubtitle }}</p>
      </div>
    </div>

    <div v-if="auth.isAuthenticated" class="flex items-center gap-2.5">
      <div ref="menuRoot" class="relative">
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full py-1 pl-1.5 pr-2.5 text-sm transition-colors hover:bg-muted"
          :aria-expanded="menuOpen"
          aria-haspopup="menu"
          @click.stop="menuOpen = !menuOpen"
        >
          <span
            class="flex h-7 w-7 items-center justify-center rounded-full bg-secondary text-xs font-semibold uppercase text-secondary-foreground"
          >
            {{ displayInitial }}
          </span>
          <span class="max-w-[140px] truncate text-sm text-muted-foreground">
            {{ auth.user?.email }}
          </span>
          <ChevronDown
            class="h-3.5 w-3.5 text-muted-foreground transition-transform"
            :class="menuOpen && 'rotate-180'"
          />
        </button>

        <div
          v-if="menuOpen"
          role="menu"
          class="absolute right-0 top-full z-50 mt-1.5 w-52 overflow-hidden rounded-xl border border-border bg-background py-1 shadow-lg"
        >
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openProfile"
          >
            <User class="h-3.5 w-3.5 text-muted-foreground" />
            Edit profile
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openPassword"
          >
            <KeyRound class="h-3.5 w-3.5 text-muted-foreground" />
            Change password
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openMfa"
          >
            <Shield class="h-3.5 w-3.5 text-muted-foreground" />
            Two-factor auth
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openSessions"
          >
            <Laptop class="h-3.5 w-3.5 text-muted-foreground" />
            Active sessions
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openPasskeys"
          >
            <Fingerprint class="h-3.5 w-3.5 text-muted-foreground" />
            Passkeys
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openConsents"
          >
            <AppWindow class="h-3.5 w-3.5 text-muted-foreground" />
            Connected apps
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="openIdentities"
          >
            <Link2 class="h-3.5 w-3.5 text-muted-foreground" />
            Linked accounts
          </button>
          <button
            type="button"
            role="menuitem"
            class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
            @click="handleLogout"
          >
            <LogOut class="h-3.5 w-3.5 text-muted-foreground" />
            Log out
          </button>
        </div>
      </div>
    </div>
  </header>

  <Teleport to="body">
    <div v-if="showProfile" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!profileSaving && (showProfile = false)" />
      <div class="relative z-10 mx-4 w-full max-w-sm rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Edit profile</h2>
        <form class="space-y-3.5" @submit.prevent="submitProfile">
          <div>
            <label class="type-label mb-1.5 block">Email</label>
            <input class="field-input opacity-70" :value="auth.user?.email" disabled />
          </div>
          <div>
            <label class="type-label mb-1.5 block">Display name</label>
            <input v-model="displayName" class="field-input" required />
          </div>
          <div>
            <label class="type-label mb-1.5 block">Phone</label>
            <input v-model="profilePhone" class="field-input" placeholder="e.g. +86 138 0000 0000" />
            <p v-if="profilePhoneCheckState === 'exists'" class="field-error mt-1">
              This phone is already registered.
            </p>
            <p v-else-if="profilePhoneCheckState === 'checking'" class="type-meta mt-1 text-[11px]">
              Checking…
            </p>
          </div>
          <p v-if="profileErr" class="field-error">{{ profileErr }}</p>
          <div class="flex justify-end gap-2 pt-1">
            <UiButton type="button" variant="ghost" size="sm" :disabled="profileSaving" @click="showProfile = false">
              Cancel
            </UiButton>
            <UiButton type="submit" size="sm" :disabled="profileSaving">
              {{ profileSaving ? "Saving…" : "Save" }}
            </UiButton>
          </div>
        </form>
      </div>
    </div>
  </Teleport>

  <Teleport to="body">
    <div v-if="showPassword" class="fixed inset-0 z-50 flex items-center justify-center">
      <div
        class="absolute inset-0 bg-black/30 backdrop-blur-sm"
        @click="!passwordSaving && (showPassword = false)"
      />
      <div class="relative z-10 mx-4 w-full max-w-sm rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Change password</h2>
        <form class="space-y-3.5" @submit.prevent="submitPassword">
          <div>
            <label class="type-label mb-1.5 block">Current password</label>
            <input v-model="currentPassword" type="password" required class="field-input" />
          </div>
          <div>
            <label class="type-label mb-1.5 block">New password</label>
            <input
              v-model="newPassword"
              type="password"
              required
              minlength="10"
              class="field-input"
            />
            <p class="type-meta mt-1 text-[11px]">
              10+ characters with upper, lower case and a digit.
            </p>
          </div>
          <div>
            <label class="type-label mb-1.5 block">Confirm new password</label>
            <input v-model="confirmPassword" type="password" required minlength="10" class="field-input" />
          </div>
          <p v-if="passwordErr" class="field-error">{{ passwordErr }}</p>
          <div class="flex justify-end gap-2 pt-1">
            <UiButton
              type="button"
              variant="ghost"
              size="sm"
              :disabled="passwordSaving"
              @click="showPassword = false"
            >
              Cancel
            </UiButton>
            <UiButton type="submit" size="sm" :disabled="passwordSaving">
              {{ passwordSaving ? "Updating…" : "Update" }}
            </UiButton>
          </div>
        </form>
      </div>
    </div>
  </Teleport>

  <Teleport to="body">
    <div v-if="showMfa" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!mfaLoading && (showMfa = false)" />
      <div class="relative z-10 mx-4 max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Two-factor authentication</h2>

        <div v-if="mfaLoading && mfaPanel === 'status'" class="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </div>

        <div v-else-if="mfaPanel === 'status'" class="space-y-4">
          <p class="text-sm">
            Authenticator:
            <span class="font-medium">{{ totpEnabled ? "Enabled" : "Not enabled" }}</span>
          </p>
          <p v-if="totpEnabled" class="text-xs text-muted-foreground">
            Recovery codes remaining: {{ recoveryRemaining }}
          </p>
          <p v-if="policyRequired && totpEnabled" class="text-xs text-amber-800/90">
            MFA is required by policy and cannot be disabled.
          </p>
          <p v-else-if="policyRequired && !totpEnabled" class="text-xs text-amber-800/90">
            Policy requires MFA for your account.
          </p>
          <p v-if="mfaErr" class="field-error">{{ mfaErr }}</p>
          <div class="flex flex-wrap justify-end gap-2">
            <UiButton type="button" variant="ghost" size="sm" @click="showMfa = false">Close</UiButton>
            <UiButton v-if="!totpEnabled" type="button" size="sm" :disabled="mfaLoading" @click="startEnroll">
              Enable MFA
            </UiButton>
            <template v-else>
              <UiButton
                type="button"
                variant="ghost"
                size="sm"
                @click="
                  mfaPanel = 'regen';
                  mfaCode = '';
                  mfaErr = '';
                "
              >
                New recovery codes
              </UiButton>
              <UiButton
                type="button"
                size="sm"
                @click="
                  mfaPanel = 'rebind_auth';
                  mfaCode = '';
                  enrollSecret = '';
                  enrollUri = '';
                  mfaErr = '';
                "
              >
                Rebind
              </UiButton>
              <UiButton
                v-if="!policyRequired"
                type="button"
                variant="ghost"
                size="sm"
                @click="
                  mfaPanel = 'disable';
                  mfaCode = '';
                  mfaErr = '';
                "
              >
                Disable MFA
              </UiButton>
            </template>
          </div>
        </div>

        <form
          v-else-if="mfaPanel === 'enroll' || mfaPanel === 'rebind'"
          class="space-y-3.5"
          @submit.prevent="mfaPanel === 'enroll' ? confirmEnroll() : confirmRebind()"
        >
          <p class="text-xs text-muted-foreground">
            {{ mfaPanel === "enroll" ? "Scan with your authenticator app." : "Enter current code first was verified; scan the new QR." }}
          </p>
          <div v-if="qrUrl" class="flex justify-center">
            <img :src="qrUrl" alt="TOTP QR" class="rounded-lg border border-border/50" />
          </div>
          <p class="break-all rounded-lg bg-muted px-3 py-2 font-mono text-[11px]">{{ enrollSecret }}</p>
          <div>
            <label class="type-label mb-1.5 block">Authentication code</label>
            <input v-model="mfaCode" class="field-input font-mono" required autocomplete="one-time-code" />
          </div>
          <p v-if="mfaErr" class="field-error">{{ mfaErr }}</p>
          <div class="flex justify-end gap-2">
            <UiButton type="button" variant="ghost" size="sm" :disabled="mfaLoading" @click="mfaPanel = 'status'">
              Back
            </UiButton>
            <UiButton type="submit" size="sm" :disabled="mfaLoading">
              {{ mfaLoading ? "Saving…" : "Confirm" }}
            </UiButton>
          </div>
        </form>

        <form
          v-else-if="mfaPanel === 'regen' || mfaPanel === 'rebind_auth'"
          class="space-y-3.5"
          @submit.prevent="mfaPanel === 'regen' ? regenRecovery() : startRebind()"
        >
          <p class="text-xs text-muted-foreground">Enter a current authenticator code to continue.</p>
          <div>
            <label class="type-label mb-1.5 block">Authentication code</label>
            <input v-model="mfaCode" class="field-input font-mono" required autocomplete="one-time-code" />
          </div>
          <p v-if="mfaErr" class="field-error">{{ mfaErr }}</p>
          <div class="flex justify-end gap-2">
            <UiButton type="button" variant="ghost" size="sm" @click="mfaPanel = 'status'">Back</UiButton>
            <UiButton type="submit" size="sm" :disabled="mfaLoading">
              {{ mfaLoading ? "…" : "Continue" }}
            </UiButton>
          </div>
        </form>

        <form
          v-else-if="mfaPanel === 'disable'"
          class="space-y-3.5"
          @submit.prevent="disableMfa"
        >
          <p class="text-xs text-muted-foreground">
            Enter a current authenticator code to disable MFA. You can enable it again later.
          </p>
          <div>
            <label class="type-label mb-1.5 block">Authentication code</label>
            <input v-model="mfaCode" class="field-input font-mono" required autocomplete="one-time-code" />
          </div>
          <p v-if="mfaErr" class="field-error">{{ mfaErr }}</p>
          <div class="flex justify-end gap-2">
            <UiButton type="button" variant="ghost" size="sm" :disabled="mfaLoading" @click="mfaPanel = 'status'">
              Back
            </UiButton>
            <UiButton type="submit" size="sm" :disabled="mfaLoading">
              {{ mfaLoading ? "Disabling…" : "Disable MFA" }}
            </UiButton>
          </div>
        </form>

        <div v-else-if="mfaPanel === 'codes'" class="space-y-3.5">
          <p class="text-xs text-muted-foreground">
            Save these recovery codes now. They will not be shown again.
          </p>
          <pre
            class="max-h-40 overflow-auto rounded-lg border border-border/50 bg-muted/40 p-3 font-mono text-xs leading-6"
            >{{ recoveryCodes.join("\n") }}</pre
          >
          <div class="flex justify-end gap-2">
            <UiButton type="button" variant="ghost" size="sm" @click="downloadRecovery">
              <Download class="h-3.5 w-3.5" />
              Download
            </UiButton>
            <UiButton type="button" variant="ghost" size="sm" @click="copyRecovery">Copy</UiButton>
            <UiButton type="button" size="sm" @click="showMfa = false">Done</UiButton>
          </div>
        </div>
      </div>
    </div>
  </Teleport>

  <Teleport to="body">
    <div v-if="showSessions" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!sessionsBusy && (showSessions = false)" />
      <div class="relative z-10 mx-4 max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Active sessions</h2>

        <div v-if="sessionsLoading" class="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </div>

        <div v-else class="space-y-3">
          <p v-if="sessionsErr" class="field-error">{{ sessionsErr }}</p>

          <div
            v-for="s in sessions"
            :key="s.id"
            class="flex items-center justify-between gap-3 rounded-xl border border-border/50 px-4 py-3"
            :class="s.id === currentSessionId && 'border-primary/40 bg-primary/[0.04]'"
          >
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="truncate font-mono text-xs">{{ s.ip || "Unknown IP" }}</span>
                <span
                  v-if="s.id === currentSessionId"
                  class="shrink-0 rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
                >
                  Current
                </span>
              </div>
              <p class="type-meta mt-1 truncate text-xs">{{ s.user_agent || "Unknown device" }}</p>
              <p class="type-meta mt-0.5 text-[11px]">
                Last seen {{ new Date(s.last_seen_at).toLocaleString() }}
              </p>
            </div>
            <UiButton
              v-if="s.id !== currentSessionId"
              type="button"
              variant="ghost"
              size="sm"
              :disabled="sessionsBusy"
              @click="revokeSession(s.id)"
            >
              Revoke
            </UiButton>
          </div>

          <div v-if="sessions.length === 0" class="py-6 text-center text-sm text-muted-foreground">
            No active sessions
          </div>

          <div class="flex flex-wrap items-center justify-between gap-3 border-t border-border/30 pt-4">
            <UiButton
              type="button"
              variant="ghost"
              size="sm"
              :disabled="sessionsBusy || sessions.length <= 1"
              @click="revokeOthers"
            >
              Revoke all other sessions
            </UiButton>
            <UiButton type="button" size="sm" @click="showSessions = false">Close</UiButton>
          </div>
        </div>
      </div>
    </div>
  </Teleport>

  <Teleport to="body">
    <div v-if="showPasskeys" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!passkeyBusy && (showPasskeys = false)" />
      <div class="relative z-10 mx-4 max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Passkeys</h2>

        <div v-if="passkeyLoading" class="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </div>

        <div v-else class="space-y-4">
          <p v-if="passkeyErr" class="field-error">{{ passkeyErr }}</p>

          <div
            v-for="p in passkeys"
            :key="p.id"
            class="flex items-center justify-between gap-3 rounded-xl border border-border/50 px-4 py-3"
          >
            <div class="min-w-0">
              <p class="truncate text-sm font-medium">{{ p.name }}</p>
              <p class="type-meta mt-0.5 text-[11px]">
                Added {{ new Date(p.created_at).toLocaleDateString() }}
                <template v-if="p.last_used_at">
                  · last used {{ new Date(p.last_used_at).toLocaleDateString() }}
                </template>
              </p>
            </div>
            <UiButton
              type="button"
              variant="ghost"
              size="sm"
              :disabled="passkeyBusy"
              @click="deletePasskey(p.id)"
            >
              Remove
            </UiButton>
          </div>

          <div v-if="passkeys.length === 0" class="py-4 text-center text-sm text-muted-foreground">
            No passkeys registered yet.
          </div>

          <form class="space-y-3 border-t border-border/30 pt-4" @submit.prevent="registerPasskey">
            <label class="type-label block">Add a passkey</label>
            <div class="flex gap-2">
              <input
                v-model="passkeyName"
                class="field-input"
                placeholder="Name (e.g. MacBook)"
              />
              <UiButton type="submit" size="sm" :disabled="passkeyBusy">
                {{ passkeyBusy ? "…" : "Register" }}
              </UiButton>
            </div>
            <p class="type-meta text-[11px]">
              Uses your device's biometrics or security key. Supported in modern browsers.
            </p>
          </form>

          <div class="flex justify-end">
            <UiButton type="button" size="sm" @click="showPasskeys = false">Close</UiButton>
          </div>
        </div>
      </div>
    </div>
  </Teleport>

  <Teleport to="body">
    <div v-if="showConsents" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!consentsBusy && (showConsents = false)" />
      <div class="relative z-10 mx-4 max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Connected apps</h2>

        <div v-if="consentsLoading" class="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </div>

        <div v-else class="space-y-3">
          <p v-if="consentsErr" class="field-error">{{ consentsErr }}</p>
          <p class="text-xs text-muted-foreground">
            Applications you have authorized to access your account. Revoking access will require
            you to consent again on the next sign-in and invalidates the app's refresh tokens.
          </p>

          <div
            v-for="c in consents"
            :key="c.client_id"
            class="flex items-start justify-between gap-3 rounded-xl border border-border/50 px-4 py-3"
          >
            <div class="min-w-0">
              <p class="truncate text-sm font-medium">{{ c.client_id }}</p>
              <p class="mt-0.5 text-[11px] text-muted-foreground">
                {{ c.scopes.map(scopeLabel).join(" · ") }}
              </p>
              <p class="type-meta mt-0.5 text-[11px]">
                Authorized {{ new Date(c.granted_at).toLocaleDateString() }}
              </p>
            </div>
            <UiButton
              type="button"
              variant="ghost"
              size="sm"
              :disabled="consentsBusy"
              @click="revokeConsent(c.client_id)"
            >
              Revoke
            </UiButton>
          </div>

          <div v-if="consents.length === 0" class="py-6 text-center text-sm text-muted-foreground">
            No connected apps
          </div>

          <div class="flex justify-end">
            <UiButton type="button" size="sm" @click="showConsents = false">Close</UiButton>
          </div>
        </div>
      </div>
    </div>
  </Teleport>

  <!-- Linked accounts (third-party identities) -->
  <Teleport to="body">
    <div v-if="showIdentities" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!identitiesBusy && (showIdentities = false)" />
      <div class="relative z-10 mx-4 max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
        <h2 class="mb-4 text-base font-semibold">Linked accounts</h2>

        <div v-if="identitiesLoading" class="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </div>

        <div v-else class="space-y-3">
          <p v-if="identitiesErr" class="field-error">{{ identitiesErr }}</p>
          <p class="text-xs text-muted-foreground">
            Link any enabled third-party provider (GitHub, Google, Feishu, WeChat, OIDC) to this
            account. Unlinking requires keeping at least one sign-in method (password or another
            provider).
          </p>

          <div
            v-for="i in identities"
            :key="i.provider_code"
            class="flex items-start justify-between gap-3 rounded-xl border border-border/50 px-4 py-3"
          >
            <div class="min-w-0">
              <div class="flex min-w-0 items-center gap-2">
                <span
                  class="inline-flex max-w-full truncate items-center rounded-md px-1.5 py-0.5 text-[11px] font-semibold tracking-wide"
                  :class="ssoTypeTagClass(i.provider_type)"
                  :title="i.provider_code"
                >
                  {{ i.provider_display_name }}
                </span>
              </div>
              <p class="mt-0.5 text-[11px] text-muted-foreground">{{ i.email ?? i.provider_code }}</p>
              <p class="type-meta mt-0.5 text-[11px]">
                Linked {{ new Date(i.linked_at).toLocaleDateString() }}
                <template v-if="i.last_login_at">
                  · Last used {{ new Date(i.last_login_at).toLocaleDateString() }}
                </template>
              </p>
            </div>
            <UiButton
              type="button"
              variant="ghost"
              size="sm"
              :disabled="identitiesBusy"
              @click="onUnlinkIdentity(i.provider_code)"
            >
              Unlink
            </UiButton>
          </div>

          <div v-if="identities.length === 0" class="py-2 text-center text-sm text-muted-foreground">
            No linked accounts yet
          </div>

          <div v-if="linkableProviders.length" class="space-y-2 border-t border-border/50 pt-3">
            <p class="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Link a provider
            </p>
            <p class="text-[11px] text-muted-foreground">
              Feishu / Google / GitHub / OIDC must return an email on first link. If the
              provider has no email permission, linking will fail with a reminder on the
              login page.
            </p>
            <a
              v-for="p in linkableProviders"
              :key="p.code"
              :href="linkIdentityUrl(p.code)"
              class="flex items-center justify-between gap-3 rounded-xl border border-dashed border-border px-4 py-3 text-sm transition-colors hover:bg-muted/50"
            >
              <span class="min-w-0">
                <span
                  class="inline-flex max-w-full truncate items-center rounded-md px-1.5 py-0.5 text-[11px] font-semibold tracking-wide"
                  :class="ssoTypeTagClass(p.type)"
                  :title="p.code"
                >
                  {{ p.display_name }}
                </span>
              </span>
              <span class="shrink-0 text-xs text-primary">Link →</span>
            </a>
          </div>

          <div class="flex justify-end pt-1">
            <UiButton type="button" size="sm" @click="showIdentities = false">Close</UiButton>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

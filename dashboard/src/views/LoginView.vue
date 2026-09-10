<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import UiButton from "@/components/ui/UiButton.vue";
import SsoProviderIcon from "@/components/ui/SsoProviderIcon.vue";
import { useQrDataUrl } from "@/composables/useQrDataUrl";
import {
  fetchEnabledSsoProviders,
  loginChangePassword,
  mfaEnrollConfirm,
  mfaEnrollStart,
  verifyMfa,
  type LoginResult,
  type PublicUser,
  type SsoProviderType,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";
import { loginWithPasskey } from "@/composables/usePasskeys";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

type Step = "password" | "mfa" | "enroll" | "password_change" | "recovery_codes";

const step = ref<Step>("password");
const email = ref("");
const password = ref("");
const showPassword = ref(false);
const newPassword = ref("");
const confirmPassword = ref("");
const showNewPassword = ref(false);
const error = ref("");
const loading = ref(false);

const mfaCode = ref("");
const mfaMethod = ref<"totp" | "recovery">("totp");

const enrollSecret = ref("");
const enrollUri = ref("");
const enrollCode = ref("");
const { dataUrl: qrUrl } = useQrDataUrl(enrollUri);

const recoveryCodes = ref<string[]>([]);
const recoveryAck = ref(false);

// Only allow return_to to bounce back to the OIDC endpoints; reject absolute
// (https://) and protocol-relative (//) URLs. Final redirect targets are still
// validated server-side against each client's allow-list.
function safeOAuthReturn(returnTo: string): string {
  if (!returnTo || returnTo.includes("://") || returnTo.startsWith("//")) return "";
  if (!returnTo.startsWith("/oauth/authorize") && !returnTo.startsWith("/oauth/end_session")) return "";
  return returnTo;
}

/// Sanitized return_to used for OAuth app attribution of login audit events.
function oauthReturnTo(): string | undefined {
  const raw = typeof route.query.return_to === "string" ? route.query.return_to : "";
  return safeOAuthReturn(raw) || undefined;
}

async function finishWithUser(user: PublicUser) {
  auth.completeLogin(user);
  const raw = typeof route.query.return_to === "string" ? route.query.return_to : "";
  const oauthReturn = safeOAuthReturn(raw);
  if (oauthReturn) {
    window.location.href = oauthReturn;
    return;
  }
  const fallback =
    user.role === "admin" || user.role === "manager" ? "/overview" : "/activity";
  await router.replace(raw && !raw.startsWith("/login") ? raw : fallback);
}

async function handleLoginResult(res: LoginResult) {
  if (res.status === "ok") {
    await finishWithUser(res.user);
    return;
  }
  if (res.status === "mfa_required") {
    step.value = "mfa";
    mfaCode.value = "";
    mfaMethod.value = "totp";
    return;
  }
  if (res.status === "enroll_required") {
    const started = await mfaEnrollStart();
    enrollSecret.value = started.secret;
    enrollUri.value = started.otpauth_uri;
    enrollCode.value = "";
    step.value = "enroll";
    return;
  }
  if (res.status === "password_change_required") {
    newPassword.value = "";
    confirmPassword.value = "";
    showNewPassword.value = false;
    step.value = "password_change";
  }
}

async function handleLogin() {
  error.value = "";
  loading.value = true;
  try {
    const res = await auth.login(email.value.trim(), password.value, oauthReturnTo());
    await handleLoginResult(res);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Login failed";
  } finally {
    loading.value = false;
  }
}

async function handlePasswordChange() {
  error.value = "";
  if (newPassword.value !== confirmPassword.value) {
    error.value = "Passwords do not match";
    return;
  }
  loading.value = true;
  try {
    const res = await loginChangePassword(newPassword.value);
    await handleLoginResult(res);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Password change failed";
  } finally {
    loading.value = false;
  }
}

async function handlePasskeyLogin() {
  error.value = "";
  loading.value = true;
  try {
    const user = await loginWithPasskey(email.value.trim(), oauthReturnTo());
    await finishWithUser(user);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Passkey sign-in failed";
  } finally {
    loading.value = false;
  }
}

async function handleVerify() {
  error.value = "";
  loading.value = true;
  try {
    const res = await verifyMfa({
      code: mfaCode.value.trim(),
      method: mfaMethod.value,
      return_to: oauthReturnTo(),
    });
    await finishWithUser(res.user);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Verification failed";
  } finally {
    loading.value = false;
  }
}

async function handleEnrollConfirm() {
  error.value = "";
  loading.value = true;
  try {
    const res = await mfaEnrollConfirm(enrollCode.value.trim(), oauthReturnTo());
    recoveryCodes.value = res.recovery_codes;
    recoveryAck.value = false;
    auth.completeLogin(res.user);
    step.value = "recovery_codes";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Enrollment failed";
  } finally {
    loading.value = false;
  }
}

async function continueAfterRecovery() {
  if (!recoveryAck.value || !auth.user) return;
  await finishWithUser(auth.user);
}

const recoveryText = computed(() => recoveryCodes.value.join("\n"));

async function copyRecovery() {
  try {
    await navigator.clipboard.writeText(recoveryText.value);
  } catch {
    /* ignore */
  }
}

function backToPassword() {
  step.value = "password";
  error.value = "";
}

// --- Third-party sign-in ---

type EnabledProvider = { code: string; type: SsoProviderType; display_name: string };
const ssoProviders = ref<EnabledProvider[]>([]);

const SSO_ERROR_MESSAGES: Record<string, string> = {
  unknown_provider: "This sign-in provider is not configured.",
  provider_disabled: "This sign-in provider is currently disabled.",
  state_mismatch: "Sign-in session expired. Please try again.",
  upstream_error: "The sign-in provider returned an error. Please try again.",
  missing_code: "Sign-in was cancelled or incomplete. Please try again.",
  no_matching_account:
    "Could not sign you in with this third-party account. The provider must return a verified email (for first-time auto-create), or sign in with your existing password within 15 minutes to link it.",
};

onMounted(async () => {
  try {
    const res = await fetchEnabledSsoProviders();
    ssoProviders.value = res.providers;
  } catch {
    /* provider buttons are optional; ignore load failures */
  }
  const err = typeof route.query.sso_error === "string" ? route.query.sso_error : "";
  if (err) {
    error.value = SSO_ERROR_MESSAGES[err] ?? "Third-party sign-in failed.";
  }
});

function ssoStartUrl(code: string): string {
  const params = new URLSearchParams();
  const returnTo = oauthReturnTo();
  if (returnTo) params.set("client_id", returnTo);
  const query = params.toString();
  return `/api/v1/auth/sso/${encodeURIComponent(code)}/start${query ? `?${query}` : ""}`;
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background px-4">
    <div class="w-full max-w-sm space-y-6">
      <div class="space-y-1 text-center">
        <div class="mb-3 flex justify-center">
          <span
            class="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-sm font-semibold tracking-wide text-primary-foreground"
          >
            Sg
          </span>
        </div>
        <h1 class="text-lg font-semibold tracking-tight">Signet</h1>
        <p class="type-meta">
          <template v-if="step === 'password'">Sign in to your identity provider</template>
          <template v-else-if="step === 'mfa'">Two-factor authentication</template>
          <template v-else-if="step === 'enroll'">Set up authenticator</template>
          <template v-else-if="step === 'password_change'">Set a new password</template>
          <template v-else>Save your recovery codes</template>
        </p>
      </div>

      <form v-if="step === 'password'" class="space-y-4" @submit.prevent="handleLogin">
        <div class="space-y-1.5">
          <label class="type-label">Email or username</label>
          <input
            v-model="email"
            type="text"
            autocomplete="username"
            placeholder="you@example.com or username"
            class="field-input"
            required
          />
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Password</label>
          <div class="relative">
            <input
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="current-password"
              placeholder="Enter password"
              class="field-input pr-14"
              required
            />
            <button
              type="button"
              class="absolute right-2 top-1/2 -translate-y-1/2 cursor-pointer text-[11px] text-muted-foreground transition-colors hover:text-foreground"
              @click="showPassword = !showPassword"
            >
              {{ showPassword ? "Hide" : "Show" }}
            </button>
          </div>
        </div>
        <div v-if="error" class="field-error">{{ error }}</div>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Signing in…" : "Sign in" }}
        </UiButton>
        <UiButton
          type="button"
          variant="ghost"
          class="w-full"
          :disabled="loading || !email.trim()"
          @click="handlePasskeyLogin"
        >
          Sign in with a passkey
        </UiButton>
        <div class="text-center">
          <RouterLink to="/reset-password" class="text-xs text-muted-foreground hover:text-foreground">
            Forgot password?
          </RouterLink>
        </div>

        <div v-if="ssoProviders.length" class="space-y-3 pt-1">
          <div class="flex items-center gap-3">
            <span class="h-px flex-1 bg-border" />
            <span class="text-[11px] uppercase tracking-wider text-muted-foreground">
              or continue with
            </span>
            <span class="h-px flex-1 bg-border" />
          </div>
          <div class="flex flex-wrap justify-center gap-4">
            <a
              v-for="p in ssoProviders"
              :key="p.code"
              :href="ssoStartUrl(p.code)"
              class="inline-flex items-center justify-center rounded-lg p-1.5 transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              :aria-label="`Continue with ${p.display_name}`"
              :title="p.display_name"
            >
              <SsoProviderIcon :type="p.type" class="h-10 w-10" />
            </a>
          </div>
        </div>
      </form>

      <form v-else-if="step === 'mfa'" class="space-y-4" @submit.prevent="handleVerify">
        <div class="flex gap-2 text-xs">
          <button
            type="button"
            class="rounded-md px-2 py-1"
            :class="mfaMethod === 'totp' ? 'bg-muted font-medium' : 'text-muted-foreground'"
            @click="mfaMethod = 'totp'"
          >
            Authenticator
          </button>
          <button
            type="button"
            class="rounded-md px-2 py-1"
            :class="mfaMethod === 'recovery' ? 'bg-muted font-medium' : 'text-muted-foreground'"
            @click="mfaMethod = 'recovery'"
          >
            Recovery code
          </button>
        </div>
        <div class="space-y-1.5">
          <label class="type-label">
            {{ mfaMethod === "totp" ? "Authentication code" : "Recovery code" }}
          </label>
          <input
            v-model="mfaCode"
            class="field-input font-mono tracking-wider"
            :placeholder="mfaMethod === 'totp' ? '123456' : 'ABCD-EFGH'"
            autocomplete="one-time-code"
            required
          />
        </div>
        <div v-if="error" class="field-error">{{ error }}</div>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Verifying…" : "Verify" }}
        </UiButton>
        <button type="button" class="w-full text-center text-xs text-muted-foreground" @click="backToPassword">
          Back
        </button>
      </form>

      <form v-else-if="step === 'enroll'" class="space-y-4" @submit.prevent="handleEnrollConfirm">
        <p class="text-xs leading-relaxed text-muted-foreground">
          MFA is required for this account. Scan the QR code with your authenticator app, then enter
          the 6-digit code.
        </p>
        <div v-if="qrUrl" class="flex justify-center">
          <img :src="qrUrl" alt="TOTP QR code" class="rounded-lg border border-border/50" />
        </div>
        <div class="space-y-1">
          <p class="type-label">Manual secret</p>
          <p class="break-all rounded-lg bg-muted px-3 py-2 font-mono text-[11px]">{{ enrollSecret }}</p>
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Authentication code</label>
          <input
            v-model="enrollCode"
            class="field-input font-mono tracking-wider"
            placeholder="123456"
            autocomplete="one-time-code"
            required
          />
        </div>
        <div v-if="error" class="field-error">{{ error }}</div>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Confirming…" : "Enable MFA" }}
        </UiButton>
      </form>

      <form v-else-if="step === 'password_change'" class="space-y-4" @submit.prevent="handlePasswordChange">
        <p class="text-xs leading-relaxed text-muted-foreground">
          You must set a new password before continuing. Your current password is temporary.
        </p>
        <div class="space-y-1.5">
          <label class="type-label">New password</label>
          <div class="relative">
            <input
              v-model="newPassword"
              :type="showNewPassword ? 'text' : 'password'"
              autocomplete="new-password"
              placeholder="New password"
              minlength="10"
              title="10+ characters with upper, lower case and a digit"
              class="field-input pr-14"
              required
            />
            <button
              type="button"
              class="absolute right-2 top-1/2 -translate-y-1/2 cursor-pointer text-[11px] text-muted-foreground transition-colors hover:text-foreground"
              @click="showNewPassword = !showNewPassword"
            >
              {{ showNewPassword ? "Hide" : "Show" }}
            </button>
          </div>
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Confirm password</label>
          <input
            v-model="confirmPassword"
            type="password"
            autocomplete="new-password"
            placeholder="Re-enter password"
            minlength="10"
            class="field-input"
            required
          />
        </div>
        <div v-if="error" class="field-error">{{ error }}</div>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Saving…" : "Set new password" }}
        </UiButton>
      </form>

      <div v-else class="space-y-4">
        <p class="text-xs leading-relaxed text-muted-foreground">
          Store these recovery codes in a safe place. Each code can be used once if you lose your
          authenticator.
        </p>
        <pre
          class="max-h-48 overflow-auto rounded-lg border border-border/50 bg-muted/40 p-3 font-mono text-xs leading-6"
          >{{ recoveryText }}</pre
        >
        <UiButton type="button" variant="ghost" size="sm" class="w-full" @click="copyRecovery">
          Copy codes
        </UiButton>
        <label class="flex items-start gap-2 text-xs">
          <input v-model="recoveryAck" type="checkbox" class="mt-0.5 rounded" />
          I have saved these recovery codes
        </label>
        <UiButton
          type="button"
          class="w-full"
          :disabled="!recoveryAck"
          @click="continueAfterRecovery"
        >
          Continue
        </UiButton>
      </div>
    </div>
  </div>
</template>

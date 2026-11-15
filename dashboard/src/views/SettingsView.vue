<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import BrandLogo from "@/components/ui/BrandLogo.vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  createApiToken,
  fetchApiTokens,
  fetchBrandingSettings,
  fetchCaptchaSettings,
  fetchMfaSettings,
  fetchRuntimeSettings,
  fetchServerSettings,
  fetchSignInSettings,
  fetchSignupSettings,
  fetchSmtpSettings,
  fetchSsoSettings,
  me,
  resetBrandingSettings,
  removeBrandingLogo,
  resetCaptchaSettings,
  resetServerSettings,
  resetSmtpSettings,
  revokeApiToken,
  testSmtp,
  updateBrandingSettings,
  updateCaptchaSettings,
  updateMfaSettings,
  updateRuntimeSettings,
  updateServerSettings,
  updateSignInSettings,
  updateSignupSettings,
  uploadBrandingLogo,
  updateSmtpSettings,
  updateSsoSettings,
  type ApiToken,
  type RuntimeSettings,
  type ServerSettings,
  type SignupSettings,
} from "@/lib/api";
import { confirm } from "@/lib/confirm";
import { useBrandingStore } from "@/stores/branding";
import { joinList, splitList } from "@/lib/directoryMapping";

const loading = ref(true);
const error = ref("");

const mfaSaving = ref(false);
const mfaSaved = ref(false);
const requiredGlobally = ref(false);

const ssoSaving = ref(false);
const ssoSaved = ref(false);
const jitProvision = ref(false);

const signup = ref<SignupSettings | null>(null);
const signupEnabled = ref(false);
const signupSaving = ref(false);
const signupSaved = ref(false);
const signupChecking = ref(false);
const signupChecked = ref(false);
let signupCheckedTimer: ReturnType<typeof setTimeout> | null = null;
/** Enabling is refused while any blocking prerequisite is missing (server-side too). */
const signupPrereqMissing = computed(
  () => signupEnabled.value && signup.value !== null && !signup.value.ready,
);

/**
 * Operational policy. Values here take effect on the next request — no
 * redeploy — and the environment only applies to fields nobody has saved here.
 */
const runtime = ref<RuntimeSettings | null>(null);
const runtimeOverridden = ref<(keyof RuntimeSettings)[]>([]);
const runtimeSaving = ref(false);
const runtimeSaved = ref(false);
const runtimeRows: {
  key: keyof RuntimeSettings;
  label: string;
  hint: string;
  min: number;
  max: number;
}[] = [
  { key: "session_ttl_hours", label: "Session lifetime", hint: "hours a dashboard session stays valid", min: 1, max: 720 },
  { key: "auth_code_ttl_secs", label: "Authorization code lifetime", hint: "seconds an OIDC code can be exchanged", min: 30, max: 3600 },
  { key: "access_token_ttl_secs", label: "Access token lifetime", hint: "seconds an access token is accepted", min: 60, max: 86400 },
  { key: "id_token_ttl_secs", label: "ID token lifetime", hint: "seconds an ID token is accepted", min: 60, max: 86400 },
  { key: "refresh_token_ttl_days", label: "Refresh token lifetime", hint: "days a refresh token lives before re-auth", min: 1, max: 365 },
  { key: "max_login_attempts", label: "Login attempts before lockout", hint: "failed passwords charged to the account", min: 1, max: 100 },
  { key: "lockout_minutes", label: "Lockout duration", hint: "minutes the account stays locked", min: 1, max: 1440 },
  { key: "password_min_length", label: "Minimum password length", hint: "characters required for a new password", min: 8, max: 128 },
  { key: "password_history_size", label: "Password history", hint: "previous passwords that cannot be reused (0 = off)", min: 0, max: 24 },
  { key: "audit_retention_days", label: "Audit retention", hint: "days audit rows are kept before the hourly sweep", min: 1, max: 3650 },
  { key: "rate_limit_per_minute", label: "Rate limit", hint: "requests per minute per client IP", min: 1, max: 100000 },
];

const allowlistSaving = ref(false);
const allowlistSaved = ref(false);
/** The list as one editable string; parsed on save, like the source scope rows. */
const allowlistInput = ref("");
const allowlistOrigin = ref<"setting" | "environment" | "unrestricted">("unrestricted");
/** The acting admin's own address, for the warning below the field. */
const ownEmail = ref("");

/** The domain of an address, lowercased, or "" when there is none to read. */
function domainOf(email: string): string {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return "";
  return email.slice(at + 1).trim().toLowerCase();
}

/** The domains as typed, without the save-time validation the server owns. */
const allowlistDomains = computed(() => splitList(allowlistInput.value));

/**
 * Whether saving this list would lock the acting admin out.
 *
 * The server refuses this too, and is the authority; saying it here is what
 * turns a 400 after the fact into something the admin sees while typing. Empty
 * means unrestricted, so it can never lock anyone out.
 */
const allowlistLocksMeOut = computed(() => {
  const domains = allowlistDomains.value;
  if (domains.length === 0 || !ownEmail.value) return false;
  const mine = domainOf(ownEmail.value);
  return !domains.some((allowed) => mine === allowed || mine.endsWith(`.${allowed}`));
});

// --- Server identity: the issuer -----------------------------------------
//
// The database wins over the environment: SIGNET_ISSUER only seeds the value
// until a dashboard save, so this field stays editable even when the variable
// is set. The first save locks the value — changing it invalidates outstanding
// tokens and every client config — and Reset clears the override.
const server = ref<ServerSettings | null>(null);
const serverIssuer = ref("");
const serverSaving = ref(false);
const serverSaved = ref(false);
let serverSavedTimer: ReturnType<typeof setTimeout> | null = null;
const normalizedServerIssuer = computed(() => serverIssuer.value.trim().replace(/\/+$/, ""));
const serverDirty = computed(
  () =>
    server.value !== null &&
    normalizedServerIssuer.value !== "" &&
    normalizedServerIssuer.value !== server.value.issuer,
);

async function refreshServer() {
  const res = await fetchServerSettings();
  server.value = res;
  serverIssuer.value = res.issuer;
}

function markServerSaved() {
  serverSaved.value = true;
  if (serverSavedTimer) clearTimeout(serverSavedTimer);
  serverSavedTimer = setTimeout(() => {
    serverSaved.value = false;
  }, 2000);
}

async function onSaveServerIssuer() {
  if (!server.value) return;
  const next = normalizedServerIssuer.value;
  if (!next || next === server.value.issuer) return;
  if (
    !(await confirm({
      title: "Change the issuer?",
      message:
        `Every token minted so far stops validating (they carry the old iss), and every ` +
        `client plus third-party SSO callback must be reconfigured to ${next}. ` +
        `The saved value overrides SIGNET_ISSUER; Reset override restores it. ` +
        `Sessions stay valid and you will not be signed out. Continue?`,
      confirmText: "Change issuer",
      danger: true,
    }))
  ) {
    serverIssuer.value = server.value.issuer;
    return;
  }
  error.value = "";
  serverSaving.value = true;
  try {
    const res = await updateServerSettings({ issuer: next });
    server.value = res;
    serverIssuer.value = res.issuer;
    markServerSaved();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Issuer save failed";
    serverIssuer.value = server.value.issuer;
  } finally {
    serverSaving.value = false;
  }
}

async function onResetServer() {
  if (!server.value) return;
  if (
    !(await confirm({
      title: "Reset the issuer override?",
      message:
        `The saved issuer is cleared and the value falls back to ` +
        `${server.value.env_fallback ? "SIGNET_ISSUER" : "the built-in default"}. ` +
        `Tokens carrying the current iss stop validating. Continue?`,
      confirmText: "Reset",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  serverSaving.value = true;
  try {
    const res = await resetServerSettings();
    server.value = res;
    serverIssuer.value = res.issuer;
    markServerSaved();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Reset failed";
  } finally {
    serverSaving.value = false;
  }
}

async function onToggleRepeat(allow: boolean) {
  if (allow) {
    if (
      !(await confirm({
        title: "Allow repeated issuer changes?",
        message:
          "The issuer can be edited again from this page. Each change invalidates outstanding " +
          "tokens and requires every client to be reconfigured. Re-lock it when you are done.",
        confirmText: "Allow",
        danger: true,
      }))
    ) {
      return;
    }
  }
  error.value = "";
  serverSaving.value = true;
  try {
    const res = await updateServerSettings({ allow_repeat_changes: allow });
    server.value = res;
    serverIssuer.value = res.issuer;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    serverSaving.value = false;
  }
}

onMounted(async () => {
  try {
    const [mfa, sso, signIn, signupRes, who, runtimeRes] = await Promise.all([
      fetchMfaSettings(),
      fetchSsoSettings(),
      fetchSignInSettings(),
      fetchSignupSettings(),
      me(),
      fetchRuntimeSettings(),
    ]);
    requiredGlobally.value = mfa.required_globally;
    jitProvision.value = sso.jit_provision;
    signup.value = signupRes;
    signupEnabled.value = signupRes.enabled;
    allowlistInput.value = joinList(signIn.allowed_email_domains);
    allowlistOrigin.value = signIn.origin;
    ownEmail.value = who.user.email;
    runtime.value = runtimeRes.settings;
    runtimeOverridden.value = runtimeRes.overridden;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load settings";
  } finally {
    loading.value = false;
  }
  // Non-fatal: a token list that fails to load still leaves the settings page
  // usable, with the section showing its own error on save attempts.
  try {
    await refreshApiTokens();
  } catch {
    /* surfaced when the operator interacts with the section */
  }
  try {
    await refreshSmtp();
  } catch {
    /* surfaced when the operator interacts with the section */
  }
  try {
    await refreshCaptcha();
  } catch {
    /* surfaced when the operator interacts with the section */
  }
  try {
    await refreshBranding();
  } catch {
    /* surfaced when the operator interacts with the section */
  }
  try {
    await refreshServer();
  } catch {
    /* surfaced when the operator interacts with the section */
  }
});

async function onSaveAllowlist() {
  error.value = "";
  allowlistSaved.value = false;
  allowlistSaving.value = true;
  try {
    const domains = allowlistDomains.value;
    // An empty box clears the row rather than storing `[]`, so the environment
    // gets a say again — the two are only the same when nothing is in the
    // environment, and that is not knowable from here.
    const res = await updateSignInSettings(domains.length === 0 ? null : domains);
    allowlistInput.value = joinList(res.allowed_email_domains);
    allowlistOrigin.value = res.origin;
    allowlistSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    allowlistSaving.value = false;
  }
}

async function onSaveMfa() {
  error.value = "";
  mfaSaved.value = false;
  mfaSaving.value = true;
  try {
    const res = await updateMfaSettings({ required_globally: requiredGlobally.value });
    requiredGlobally.value = res.required_globally;
    mfaSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    mfaSaving.value = false;
  }
}

async function onSaveRuntime() {
  if (!runtime.value) return;
  error.value = "";
  runtimeSaved.value = false;
  runtimeSaving.value = true;
  try {
    const res = await updateRuntimeSettings({ ...runtime.value });
    runtime.value = res.settings;
    runtimeOverridden.value = res.overridden;
    runtimeSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    runtimeSaving.value = false;
  }
}

async function onSaveSso() {
  error.value = "";
  ssoSaved.value = false;
  ssoSaving.value = true;
  try {
    const res = await updateSsoSettings({ jit_provision: jitProvision.value });
    jitProvision.value = res.jit_provision;
    ssoSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    ssoSaving.value = false;
  }
}

async function onSaveSignup() {
  error.value = "";
  signupSaved.value = false;
  signupSaving.value = true;
  try {
    const res = await updateSignupSettings(signupEnabled.value);
    signup.value = res;
    signupEnabled.value = res.enabled;
    signupSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
    // The checkbox shows the last state the server accepted; refresh the
    // checklist too, in case the configuration changed since this page loaded.
    try {
      signup.value = await fetchSignupSettings();
    } catch {
      /* the error above already says what happened */
    }
    signupEnabled.value = signup.value?.enabled ?? false;
  } finally {
    signupSaving.value = false;
  }
}

/// Re-reads the server's preflight result without changing the unsaved toggle.
async function recheckSignup() {
  signupChecking.value = true;
  signupChecked.value = false;
  try {
    signup.value = await fetchSignupSettings();
    if (signupCheckedTimer) clearTimeout(signupCheckedTimer);
    signupChecked.value = true;
    signupCheckedTimer = setTimeout(() => {
      signupChecked.value = false;
    }, 2000);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Prerequisite check failed";
  } finally {
    signupChecking.value = false;
  }
}

// --- API tokens (machine credentials) ---
//
// The plaintext is returned by the server exactly once, so it is held in
// `freshToken` and cleared the moment it is copied or dismissed — not kept in
// component state longer than the operator needs it.

const apiTokens = ref<ApiToken[]>([]);
const newTokenName = ref("");
const newTokenExpiryDays = ref<string>("");
const freshToken = ref("");
const tokenWorking = ref(false);

function formatWhen(iso: string): string {
  return new Date(iso).toLocaleString();
}

function copyFreshToken() {
  navigator.clipboard.writeText(freshToken.value).then(
    () => {
      freshToken.value = "";
    },
    () => {
      /* selection copy still works; keep the token visible */
    },
  );
}

async function refreshApiTokens() {
  const res = await fetchApiTokens();
  apiTokens.value = res.tokens;
}

async function onCreateToken() {
  error.value = "";
  const name = newTokenName.value.trim();
  if (!name) return;
  const days = newTokenExpiryDays.value ? Number(newTokenExpiryDays.value) : null;
  if (days !== null && (!Number.isInteger(days) || days < 1 || days > 3650)) {
    error.value = "Expiry must be a whole number of days (1-3650), or empty";
    return;
  }
  tokenWorking.value = true;
  try {
    const res = await createApiToken(name, days);
    freshToken.value = res.token;
    newTokenName.value = "";
    newTokenExpiryDays.value = "";
    await refreshApiTokens();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Token creation failed";
  } finally {
    tokenWorking.value = false;
  }
}

async function onRevokeToken(t: ApiToken) {
  error.value = "";
  tokenWorking.value = true;
  try {
    await revokeApiToken(t.id);
    await refreshApiTokens();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Revoke failed";
  } finally {
    tokenWorking.value = false;
  }
}

// --- SMTP relay ---
//
// The password is write-only: the server never sends it back, and the input
// here stays empty unless the operator is setting a new one. Leaving a field
// alone means omitting it from the PATCH, not sending null — null means
// "clear the override and let the environment answer".

const smtp = ref<{
  host: string;
  port: number | null;
  username: string;
  from: string;
  password_set: boolean;
  configured: boolean;
  overridden: string[];
} | null>(null);
const smtpPassword = ref("");
const smtpTo = ref("");
const smtpSaving = ref(false);
const smtpSaved = ref(false);
const smtpTesting = ref(false);
const smtpTestResult = ref<{ ok: boolean; error?: string } | null>(null);

async function refreshSmtp() {
  const res = await fetchSmtpSettings();
  smtp.value = {
    host: res.host ?? "",
    port: res.port,
    username: res.username ?? "",
    from: res.from ?? "",
    password_set: res.password_set,
    configured: res.configured,
    overridden: res.overridden,
  };
}

async function onSaveSmtp() {
  error.value = "";
  smtpSaved.value = false;
  smtpSaving.value = true;
  try {
    if (!smtp.value) return;
    const patch: Record<string, string | number | null> = {};
    // Only send fields with an editable value; `from`/`host` empty means
    // "clear this override" only via the explicit reset button.
    patch.host = smtp.value.host || null;
    patch.from = smtp.value.from || null;
    patch.username = smtp.value.username || null;
    if (smtp.value.port !== null) patch.port = smtp.value.port;
    if (smtpPassword.value) patch.password = smtpPassword.value;
    const res = await updateSmtpSettings(patch);
    await refreshSmtp();
    smtpPassword.value = "";
    smtpSaved.value = true;
    smtp.value.overridden = res.overridden;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "SMTP save failed";
  } finally {
    smtpSaving.value = false;
  }
}

async function onTestSmtp() {
  error.value = "";
  smtpTestResult.value = null;
  const to = smtpTo.value.trim();
  if (!to) return;
  smtpTesting.value = true;
  try {
    smtpTestResult.value = await testSmtp(to);
  } catch (e) {
    smtpTestResult.value = {
      ok: false,
      error: e instanceof Error ? e.message : "Test failed",
    };
  } finally {
    smtpTesting.value = false;
  }
}

async function onResetSmtp() {
  error.value = "";
  smtpSaving.value = true;
  try {
    await resetSmtpSettings();
    await refreshSmtp();
    smtpPassword.value = "";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "SMTP reset failed";
  } finally {
    smtpSaving.value = false;
  }
}

// --- CAPTCHA gate ---
//
// Same three-state semantics as the relay settings. The secret is write-only;
// the site key ships to every browser, so it is shown in plain text.

const captcha = ref<{
  enabled: boolean;
  provider: string | null;
  site_key: string;
  secret_set: boolean;
  overridden: string[];
} | null>(null);
const captchaSecret = ref("");
const captchaSaving = ref(false);
const captchaSaved = ref(false);

async function refreshCaptcha() {
  const res = await fetchCaptchaSettings();
  captcha.value = {
    enabled: res.enabled,
    provider: res.provider,
    site_key: res.site_key ?? "",
    secret_set: res.secret_set,
    overridden: res.overridden,
  };
}

async function onSaveCaptcha() {
  error.value = "";
  captchaSaved.value = false;
  captchaSaving.value = true;
  try {
    if (!captcha.value) return;
    const patch: Record<string, string | null> = {};
    // provider "off" is the explicit disable; empty selection clears.
    patch.provider = captcha.value.provider || null;
    patch.site_key = captcha.value.site_key || null;
    if (captchaSecret.value) patch.secret_key = captchaSecret.value;
    const res = await updateCaptchaSettings(patch);
    await refreshCaptcha();
    captchaSecret.value = "";
    captchaSaved.value = true;
    captcha.value.overridden = res.overridden;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "CAPTCHA save failed";
  } finally {
    captchaSaving.value = false;
  }
}

async function onResetCaptcha() {
  error.value = "";
  captchaSaving.value = true;
  try {
    await resetCaptchaSettings();
    await refreshCaptcha();
    captchaSecret.value = "";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "CAPTCHA reset failed";
  } finally {
    captchaSaving.value = false;
  }
}

// --- Branding ---
//
// One string, shown everywhere the product names itself. Rendered as plain
// text by every surface (never HTML), so the only validation that matters is
// length and control characters — both enforced server-side.

const branding = useBrandingStore();
const brandingName = ref("");
const brandingSaving = ref(false);
const brandingSaved = ref(false);

// Logo: the browser reads the file and posts a data URL; the server validates
// the MIME, the magic bytes and a 256 KiB cap (SVG is rejected there — it can
// execute script when navigated to from this origin).
const LOGO_MAX_BYTES = 256 * 1024;
const logoInput = ref<HTMLInputElement | null>(null);
const logoSet = ref(false);
const logoBusy = ref(false);

async function refreshBranding() {
  const res = await fetchBrandingSettings();
  brandingName.value = res.name;
  logoSet.value = res.logo_set;
  branding.logoUrl = res.logo_url;
}

async function onPickLogo(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  error.value = "";
  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    error.value = "Logo must be a PNG, JPEG or WebP image";
    input.value = "";
    return;
  }
  if (file.size > LOGO_MAX_BYTES) {
    error.value = "Logo must be at most 256 KB";
    input.value = "";
    return;
  }
  logoBusy.value = true;
  try {
    const dataUrl = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(new Error("Could not read the file"));
      reader.readAsDataURL(file);
    });
    const res = await uploadBrandingLogo(dataUrl);
    branding.logoUrl = res.logo_url;
    logoSet.value = res.logo_set;
    brandingSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Logo upload failed";
  } finally {
    logoBusy.value = false;
    input.value = "";
  }
}

async function onRemoveLogo() {
  if (
    !(await confirm({
      title: "Remove the logo?",
      message: "Every brand surface falls back to the product name's initial.",
      confirmText: "Remove",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  logoBusy.value = true;
  try {
    const res = await removeBrandingLogo();
    branding.logoUrl = res.logo_url;
    logoSet.value = res.logo_set;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Could not remove the logo";
  } finally {
    logoBusy.value = false;
  }
}

async function onSaveBranding() {
  error.value = "";
  brandingSaved.value = false;
  const name = brandingName.value.trim();
  if (!name) return;
  brandingSaving.value = true;
  try {
    const res = await updateBrandingSettings(name);
    brandingName.value = res.name;
    branding.name = res.name; // live in this session too
    document.title = `Settings · ${res.name}`;
    brandingSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Branding save failed";
  } finally {
    brandingSaving.value = false;
  }
}

async function onResetBranding() {
  error.value = "";
  brandingSaving.value = true;
  try {
    const res = await resetBrandingSettings();
    brandingName.value = res.name;
    branding.name = res.name;
    document.title = `Settings · ${res.name}`;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Branding reset failed";
  } finally {
    brandingSaving.value = false;
  }
}
// --- Section navigation ----------------------------------------------------
//
// Ten settings sections do not fit one scroll column; the left sub-nav keeps
// one section visible at a time and groups them by intent. State only — the
// route stays /settings.

type SettingsSection =
  | "server"
  | "branding"
  | "security"
  | "domains"
  | "signup"
  | "sso"
  | "captcha"
  | "policies"
  | "smtp"
  | "tokens";

type NavItem = { key: SettingsSection; label: string; badge: string | null };
type NavGroup = { group: string; items: NavItem[] };

/// The active section lives in `?section=` so a reload (or a shared link)
/// lands on the same panel; an unknown value falls back to the first one.
const SECTION_KEYS = [
  "server",
  "branding",
  "security",
  "domains",
  "signup",
  "sso",
  "captcha",
  "policies",
  "smtp",
  "tokens",
] as const;

const route = useRoute();
const router = useRouter();

function sectionFromQuery(): SettingsSection {
  const value = route.query.section;
  return typeof value === "string" && (SECTION_KEYS as readonly string[]).includes(value)
    ? (value as SettingsSection)
    : "server";
}

const section = ref<SettingsSection>(sectionFromQuery());

// Back/forward (and any other query change) keep the pane in sync.
watch(
  () => route.query.section,
  () => {
    const next = sectionFromQuery();
    if (next !== section.value) section.value = next;
  },
);

const settingsNav = computed<NavGroup[]>(() => [
  {
    group: "General",
    items: [
      {
        key: "server",
        label: "Server identity",
        badge:
          server.value?.source === "database"
            ? "saved"
            : server.value?.source === "environment"
              ? "env"
              : null,
      },
      { key: "branding", label: "Branding", badge: null },
    ],
  },
  {
    group: "Access",
    items: [
      {
        key: "security",
        label: "Security",
        badge: requiredGlobally.value ? "on" : null,
      },
      {
        key: "domains",
        label: "Email domains",
        badge: allowlistDomains.value.length
          ? String(allowlistDomains.value.length)
          : null,
      },
      {
        key: "signup",
        label: "Public sign-up",
        badge: signup.value?.enabled
          ? signup.value.smtp_configured && signup.value.captcha_configured
            ? "on"
            : "blocked"
          : null,
      },
      {
        key: "sso",
        label: "SSO / federation",
        badge: jitProvision.value ? "JIT" : null,
      },
      {
        key: "captcha",
        label: "CAPTCHA",
        badge: captcha.value?.enabled ? "on" : null,
      },
    ],
  },
  {
    group: "Operations",
    items: [
      { key: "policies", label: "Runtime policies", badge: null },
      {
        key: "smtp",
        label: "Email relay",
        badge: smtp.value?.configured ? "ready" : "not set",
      },
    ],
  },
  {
    group: "Developer",
    items: [
      {
        key: "tokens",
        label: "API tokens",
        badge: apiTokens.value.length ? String(apiTokens.value.length) : null,
      },
    ],
  },
]);

function selectSection(key: SettingsSection) {
  section.value = key;
  const query = { ...route.query };
  if (key === "server") delete query.section;
  else query.section = key;
  // replace, not push: switching panes should not grow the history stack.
  void router.replace({ query });
  document.querySelector("main")?.scrollTo({ top: 0, behavior: "smooth" });
}

/// One row per check. Blocking and advisory findings share this shape, so the
/// pane has a single list instead of a status table plus two message blocks.
type SignupCheckStatus = "ready" | "blocked" | "advisory";
type SignupCheck = {
  key: string;
  label: string;
  status: SignupCheckStatus;
  detail: string;
  link: { label: string; section: SettingsSection } | null;
};

const SMTP_PREFIX = "Email relay: ";
const CAPTCHA_PREFIX = "CAPTCHA: ";

function problemDetail(prefix: string): string | null {
  const text = signup.value?.problems.find((problem) => problem.startsWith(prefix));
  return text ? text.slice(prefix.length).trim() : null;
}

const signupChecks = computed<SignupCheck[]>(() => {
  const s = signup.value;
  if (!s) return [];
  const checks: SignupCheck[] = [
    {
      key: "smtp",
      label: "Email relay",
      status: s.smtp_configured ? "ready" : "blocked",
      detail: s.smtp_configured ? "" : (problemDetail(SMTP_PREFIX) ?? "Not configured."),
      link: s.smtp_configured ? null : { label: "Configure", section: "smtp" },
    },
    {
      key: "captcha",
      label: "CAPTCHA",
      status: s.captcha_configured ? "ready" : "blocked",
      detail: s.captcha_configured ? "" : (problemDetail(CAPTCHA_PREFIX) ?? "Not configured."),
      link: s.captcha_configured ? null : { label: "Configure", section: "captcha" },
    },
  ];

  for (const warning of s.warnings) {
    if (warning.startsWith("No email-domain allowlist")) {
      checks.push({
        key: "domains",
        label: "Email domains",
        status: "advisory",
        detail: warning,
        link: { label: "Review", section: "domains" },
      });
    } else if (warning.startsWith("Verification links")) {
      checks.push({
        key: "links",
        label: "Public links",
        status: "advisory",
        detail: warning,
        link: { label: "Configure", section: "server" },
      });
    } else {
      checks.push({
        key: `warning-${checks.length}`,
        label: "Advisory",
        status: "advisory",
        detail: warning,
        link: null,
      });
    }
  }

  // A future blocking check outside the two known prefixes is still shown,
  // rather than leaving "N issues" with no matching row.
  for (const problem of s.problems) {
    if (problem.startsWith(SMTP_PREFIX) || problem.startsWith(CAPTCHA_PREFIX)) continue;
    checks.push({
      key: `problem-${checks.length}`,
      label: "Other",
      status: "blocked",
      detail: problem,
      link: null,
    });
  }
  return checks;
});

const signupBlockingCount = computed(() => signup.value?.problems.length ?? 0);

const signupSummary = computed(() => {
  const count = signupBlockingCount.value;
  if (count === 0) return "Required checks pass";
  return `${count} blocking issue${count === 1 ? "" : "s"}`;
});

function checkDotClass(status: SignupCheckStatus): string {
  if (status === "ready") return "bg-emerald-500";
  if (status === "blocked") return "bg-amber-500";
  return "bg-muted-foreground/40";
}

function checkStatusClass(status: SignupCheckStatus): string {
  if (status === "ready") return "text-emerald-700 dark:text-emerald-400";
  if (status === "blocked") return "text-amber-700 dark:text-amber-400";
  return "text-muted-foreground";
}

function checkStatusLabel(status: SignupCheckStatus): string {
  if (status === "ready") return "Ready";
  if (status === "blocked") return "Action needed";
  return "Advisory";
}

/// Follows the in-page links without leaving the reader halfway down the
/// target pane; the link itself still supports opening in a new tab.
function scrollSettingsTop() {
  document.querySelector("main")?.scrollTo({ top: 0, behavior: "smooth" });
}

</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Settings"
      description="Global Signet configuration. Admin only."
    />

    <p v-if="error" class="field-error">{{ error }}</p>
    <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>

    <template v-else>
      <div class="flex flex-col gap-6 lg:flex-row lg:items-start">
        <nav
          class="flex gap-1 overflow-x-auto pb-1 lg:sticky lg:top-4 lg:w-52 lg:shrink-0 lg:flex-col lg:overflow-visible lg:pb-0"
        >
          <template v-for="g in settingsNav" :key="g.group">
            <p class="type-eyebrow hidden px-2.5 pb-1.5 pt-7 first:pt-0 lg:block">
              {{ g.group }}
            </p>
            <button
              v-for="item in g.items"
              :key="item.key"
              type="button"
              class="flex shrink-0 items-center gap-2 whitespace-nowrap rounded-xl px-3 py-2 text-left text-[13px] transition-colors lg:w-full"
              :class="
                section === item.key
                  ? 'bg-sidebar-accent font-medium text-foreground'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              "
              @click="selectSection(item.key)"
            >
              {{ item.label }}
              <span
                v-if="item.badge"
                class="ml-auto hidden text-[10px] font-medium text-muted-foreground/70 lg:inline"
              >
                {{ item.badge }}
              </span>
            </button>
          </template>
        </nav>

        <div class="min-w-0 flex-1 lg:max-w-2xl">
          <section v-if="section === 'server' && server" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Server identity</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            The issuer is the origin every token carries as <code>iss</code> and every client
            discovers. Changing it invalidates outstanding tokens and requires each client (and
            third-party SSO callback) to be reconfigured. Dashboard sessions are unaffected.
          </p>
        </div>

        <div>
          <label class="type-label mb-1.5 block" for="issuer">Issuer</label>
          <input
            id="issuer"
            v-model="serverIssuer"
            class="field-input font-mono text-[12px]"
            :disabled="server.locked"
            placeholder="https://sso.example.com"
          />
          <p class="type-meta mt-1.5 text-[11px] leading-relaxed">
            <span class="mr-2 inline-flex rounded-md bg-muted px-1.5 py-0.5 font-medium">
              {{
                server.source === "environment"
                  ? "from environment"
                  : server.source === "database"
                    ? "saved here"
                    : "default"
              }}
            </span>
            <template v-if="server.source === 'database'">
              <template v-if="server.locked">
                Locked after the first change. Unlock below to edit again.
              </template>
              <template v-else>
                Applies immediately; peer replicas converge within 30 seconds.
              </template>
            </template>
            <template v-else-if="server.env_fallback">
              Seeded from <code>SIGNET_ISSUER</code>; saving here overrides it, and Reset restores
              it.
            </template>
            <template v-else>
              Built-in default; saving a value here overrides it.
            </template>
          </p>
          <p v-if="server.public_base_url" class="type-meta mt-1 text-[11px]">
            Absolute links keep using <code>SIGNET_PUBLIC_BASE_URL</code> =
            {{ server.public_base_url }}.
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <UiButton
            size="sm"
            :disabled="serverSaving || server.locked || !serverDirty"
            @click="onSaveServerIssuer"
          >
            {{ serverSaving ? "Saving…" : "Save" }}
          </UiButton>
          <UiButton
            v-if="server.locked"
            size="sm"
            variant="secondary"
            :disabled="serverSaving"
            @click="onToggleRepeat(true)"
          >
            Unlock to change
          </UiButton>
          <UiButton
            v-if="server.allow_repeat_changes"
            size="sm"
            variant="ghost"
            :disabled="serverSaving"
            @click="onToggleRepeat(false)"
          >
            Re-lock
          </UiButton>
          <UiButton
            v-if="server.source === 'database'"
            size="sm"
            variant="secondary"
            :disabled="serverSaving"
            @click="onResetServer"
          >
            Reset override
          </UiButton>
          <span v-if="serverSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>

        <p class="rounded-lg bg-destructive/5 px-3 py-2 text-[11px] leading-relaxed text-destructive/90">
          Impact: outstanding access / ID / refresh tokens stop validating; clients configured
          with a different issuer lose discovery and sign-in; third-party SSO callback URLs
          registered against this issuer must be updated.
        </p>
      </section>

      <section v-if="section === 'security'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Security</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Controls whether users without TOTP must enroll before signing in. Users who already
            enabled MFA always verify on login.
          </p>
        </div>

        <label class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3">
          <input v-model="requiredGlobally" type="checkbox" class="mt-0.5 rounded" />
          <span>
            <span class="block text-sm font-medium">Require MFA for all users</span>
            <span class="mt-0.5 block text-xs text-muted-foreground">
              When on, every account without an authenticator must enroll at next login. Per-user
              Require MFA still applies when this is off.
            </span>
          </span>
        </label>

        <div class="flex items-center gap-3">
          <UiButton size="sm" :disabled="mfaSaving" @click="onSaveMfa">
            {{ mfaSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="mfaSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section v-if="section === 'domains'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Email domain allowlist</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Only these domains may sign in or be provisioned. Subdomains are included; there are
            no wildcards. Empty allows every domain. Accounts that fall outside keep their data
            and are <em>not</em> disabled — they simply cannot sign in until the list is widened.
          </p>
        </div>

        <div>
          <label class="type-label mb-1.5 block" for="allowlist">
            Allowed domains
          </label>
          <textarea
            id="allowlist"
            v-model="allowlistInput"
            rows="3"
            class="field-input font-mono text-[12px]"
            placeholder="corp.example, partner.example"
          />
          <p class="type-meta mt-1 text-[11px]">
            Comma or newline separated.
            <template v-if="allowlistOrigin === 'environment'">
              Currently in force from <code class="text-[11px]">SIGNET_ALLOWED_EMAIL_DOMAINS</code>;
              saving here overrides it.
            </template>
            <template v-else-if="allowlistOrigin === 'unrestricted'">
              Nothing is restricted right now.
            </template>
          </p>
          <!-- The server refuses this save; warning here is the difference
               between seeing it while typing and a 400 after pressing Save.
               The whitelist never applies to /setup, so an operator cannot
               brick an instance before an admin exists. -->
          <p
            v-if="allowlistLocksMeOut"
            class="type-meta mt-2 text-amber-700 dark:text-amber-400"
          >
            Your own address ({{ ownEmail }}) is not covered, so saving this would refuse your
            next sign-in.
          </p>
        </div>

        <div class="flex items-center gap-3">
          <UiButton
            size="sm"
            :disabled="allowlistSaving || allowlistLocksMeOut"
            @click="onSaveAllowlist"
          >
            {{ allowlistSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="allowlistSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section v-if="section === 'policies'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Runtime policies</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Token lifetimes, lockout and password policy, audit retention and the global rate
            limit. Changes apply immediately; a field shows <em>env</em> when nothing has been
            saved here and the environment value is in force.
          </p>
        </div>

        <div v-if="runtime" class="space-y-3">
          <label
            v-for="row in runtimeRows"
            :key="row.key"
            class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3"
          >
            <span class="flex-1">
              <span class="block text-sm font-medium">{{ row.label }}</span>
              <span class="mt-0.5 block text-xs text-muted-foreground">
                {{ row.hint }} · {{ runtime[row.key] }}
                <template v-if="!runtimeOverridden.includes(row.key)">
                  (from <code class="text-[11px]">env</code>)
                </template>
              </span>
            </span>
            <input
              v-model.number="runtime[row.key]"
              type="number"
              :min="row.min"
              :max="row.max"
              class="field-input w-28 text-right font-mono text-[12px]"
            />
          </label>
        </div>

        <div class="flex items-center gap-3">
          <UiButton size="sm" :disabled="runtimeSaving || !runtime" @click="onSaveRuntime">
            {{ runtimeSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="runtimeSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section v-if="section === 'signup' && signup" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Public sign-up</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Let people create their own account. Nothing is created until the email link is
            confirmed (30 minutes, single use); new accounts are
            <code class="text-[11px]">member</code> accounts with no groups. Off by default.
          </p>
        </div>

        <!-- One place for every check, blocking and advisory, each with a single
             link to the section that fixes it. -->
        <div
          class="overflow-hidden rounded-lg border"
          :class="signupBlockingCount ? 'border-amber-600/20' : 'border-border/40'"
        >
          <div
            class="flex items-center justify-between gap-3 border-b border-border/40 bg-muted/20 px-4 py-2.5"
          >
            <span class="type-label">Preflight</span>
            <span
              class="text-[11px] font-medium"
              :class="
                signupBlockingCount
                  ? 'text-amber-700 dark:text-amber-400'
                  : 'text-emerald-700 dark:text-emerald-400'
              "
            >
              {{ signupSummary }}
            </span>
          </div>
          <ul class="divide-y divide-border/40">
            <li v-for="check in signupChecks" :key="check.key" class="flex gap-3 px-4 py-3">
              <span
                class="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
                :class="checkDotClass(check.status)"
              />
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                  <div class="flex items-center gap-2">
                    <span class="text-[13px] font-medium">{{ check.label }}</span>
                    <span
                      class="text-[10px] uppercase tracking-wide"
                      :class="checkStatusClass(check.status)"
                    >
                      {{ checkStatusLabel(check.status) }}
                    </span>
                  </div>
                  <RouterLink
                    v-if="check.link"
                    :to="{ name: 'settings', query: { section: check.link.section } }"
                    class="text-[11px] font-medium underline underline-offset-2 hover:no-underline"
                    @click="scrollSettingsTop"
                  >
                    {{ check.link.label }} →
                  </RouterLink>
                </div>
                <p
                  v-if="check.detail"
                  class="mt-0.5 text-[11px] leading-relaxed text-muted-foreground"
                >
                  {{ check.detail }}
                </p>
              </div>
            </li>
          </ul>
        </div>

        <label class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3">
          <input v-model="signupEnabled" type="checkbox" class="mt-0.5 rounded" />
          <span>
            <span class="block text-sm font-medium">Allow public sign-up</span>
            <span class="mt-0.5 block text-xs text-muted-foreground">
              Shows “Create account” on the sign-in page. Turning it off stops new requests;
              links already sent stay valid for their remaining 30 minutes.
            </span>
          </span>
        </label>

        <div class="flex flex-wrap items-center gap-3">
          <UiButton
            size="sm"
            :disabled="signupSaving || signupChecking || signupPrereqMissing"
            @click="onSaveSignup"
          >
            {{ signupSaving ? "Saving…" : "Save" }}
          </UiButton>
          <UiButton
            size="sm"
            variant="secondary"
            :disabled="signupSaving || signupChecking"
            @click="recheckSignup"
          >
            {{ signupChecking ? "Checking…" : "Re-check" }}
          </UiButton>
          <span v-if="signupSaved" class="text-xs text-muted-foreground">Saved</span>
          <span v-else-if="signupChecked" class="text-xs text-muted-foreground">
            Checklist updated
          </span>
        </div>
      </section>

      <section v-if="section === 'sso'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">SSO / federation</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            First-login behavior when a third-party identity has a verified email that does not
            match an existing local user.
          </p>
        </div>

        <label class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3">
          <input v-model="jitProvision" type="checkbox" class="mt-0.5 rounded" />
          <span>
            <span class="block text-sm font-medium">JIT provision on SSO</span>
            <span class="mt-0.5 block text-xs text-muted-foreground">
              When on, create a local <code class="text-[11px]">member</code> account and link it
              automatically. When off, users must already exist (or bind via password within 15
              minutes). Providers without a verified email never JIT.
            </span>
          </span>
        </label>

        <div class="flex items-center gap-3">
          <UiButton size="sm" :disabled="ssoSaving" @click="onSaveSso">
            {{ ssoSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="ssoSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section v-if="section === 'tokens'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">API tokens</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Bearer credentials for automation (<code class="text-[11px]">Authorization: Bearer
            …</code> on <code class="text-[11px]">/api/v1/admin/*</code>). A token acts as the
            account that created it: demoting or disabling that account, or revoking the token,
            cuts access on the next call.
          </p>
        </div>

        <!-- Shown once, then gone: the server stores only the digest. -->
        <div v-if="freshToken" class="space-y-2 rounded-lg border border-border/40 px-4 py-3">
          <p class="text-xs text-muted-foreground">
            Copy this token now — it is never shown again.
          </p>
          <code class="block break-all font-mono text-[12px]">{{ freshToken }}</code>
          <div class="flex gap-2">
            <UiButton size="sm" variant="secondary" @click="copyFreshToken">
              Copy
            </UiButton>
            <UiButton size="sm" variant="secondary" @click="freshToken = ''">
              Done
            </UiButton>
          </div>
        </div>

        <div class="space-y-2">
          <label class="type-label block" for="token-name">Token name</label>
          <div class="flex gap-2">
            <input
              id="token-name"
              v-model="newTokenName"
              type="text"
              class="field-input flex-1"
              placeholder="ci-pipeline"
              maxlength="100"
            />
            <input
              v-model="newTokenExpiryDays"
              type="number"
              min="1"
              max="3650"
              class="field-input w-36 text-right font-mono text-[12px]"
              placeholder="days (empty = never)"
            />
            <UiButton size="sm" :disabled="tokenWorking || !newTokenName.trim()" @click="onCreateToken">
              {{ tokenWorking ? "Working…" : "Create" }}
            </UiButton>
          </div>
        </div>

        <div v-if="apiTokens.length" class="space-y-2">
          <div
            v-for="t in apiTokens"
            :key="t.id"
            class="flex items-center gap-3 rounded-lg border border-border/40 px-4 py-3"
          >
            <span class="flex-1">
              <span class="block text-sm font-medium">
                {{ t.name }}
                <span
                  v-if="t.revoked_at"
                  class="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                >revoked</span>
                <span
                  v-else-if="t.expires_at && new Date(t.expires_at) < new Date()"
                  class="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                >expired</span>
              </span>
              <span class="mt-0.5 block text-xs text-muted-foreground">
                {{ t.user_email }} ·
                last used {{ t.last_used_at ? formatWhen(t.last_used_at) : "never" }} ·
                {{ t.expires_at ? `expires ${formatWhen(t.expires_at)}` : "no expiry" }}
              </span>
            </span>
            <UiButton
              v-if="!t.revoked_at"
              size="sm"
              variant="destructive"
              :disabled="tokenWorking"
              @click="onRevokeToken(t)"
            >
              Revoke
            </UiButton>
          </div>
        </div>
        <p v-else class="text-xs text-muted-foreground">No tokens yet.</p>
      </section>

      <section v-if="section === 'smtp'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Email relay (SMTP)</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Where password-reset and email-change messages are delivered. Saved here it wins over
            <code class="text-[11px]">SIGNET_SMTP_*</code> and applies to the next message — no
            redeploy. The password is stored encrypted and never shown again; leave it blank to
            keep the current one.
          </p>
        </div>

        <div v-if="smtp" class="space-y-3">
          <label class="block">
            <span class="type-label mb-1.5 block">SMTP host</span>
            <input
              v-model="smtp.host"
              type="text"
              class="field-input font-mono text-[12px]"
              placeholder="smtp.example.com"
            />
            <span v-if="smtp.overridden.includes('host')" class="type-meta mt-1 block text-[11px]">
              saved here — clearing the field and saving falls back to the environment
            </span>
          </label>

          <div class="flex gap-3">
            <label class="block w-28">
              <span class="type-label mb-1.5 block">Port</span>
              <input
                v-model.number="smtp.port"
                type="number"
                min="1"
                max="65535"
                class="field-input text-right font-mono text-[12px]"
              />
            </label>
            <label class="block flex-1">
              <span class="type-label mb-1.5 block">Username</span>
              <input
                v-model="smtp.username"
                type="text"
                class="field-input font-mono text-[12px]"
                autocomplete="off"
              />
            </label>
          </div>

          <label class="block">
            <span class="type-label mb-1.5 block">
              Password
              <span v-if="smtp.password_set" class="ml-1 text-[10px] font-normal uppercase tracking-wide text-muted-foreground">
                set
              </span>
            </span>
            <input
              v-model="smtpPassword"
              type="password"
              class="field-input font-mono text-[12px]"
              :placeholder="smtp.password_set ? 'leave blank to keep' : 'not set'"
              autocomplete="new-password"
            />
          </label>

          <label class="block">
            <span class="type-label mb-1.5 block">From</span>
            <input
              v-model="smtp.from"
              type="text"
              class="field-input font-mono text-[12px]"
              placeholder="Signet &lt;no-reply@example.com&gt;"
            />
          </label>

          <p class="type-meta text-[11px]">
            465 uses implicit TLS; other ports negotiate STARTTLS. Certificates must be trusted —
            there is no skip-verification switch.
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <UiButton size="sm" :disabled="smtpSaving || !smtp" @click="onSaveSmtp">
            {{ smtpSaving ? "Saving…" : "Save" }}
          </UiButton>
          <UiButton
            size="sm"
            variant="secondary"
            :disabled="smtpSaving || !smtp"
            @click="onResetSmtp"
          >
            Reset to env
          </UiButton>
          <span v-if="smtpSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>

        <div class="space-y-2 border-t border-border/40 pt-4">
          <span class="type-label block">Send a test message</span>
          <div class="flex gap-2">
            <input
              v-model="smtpTo"
              type="email"
              class="field-input flex-1"
              :placeholder="ownEmail"
            />
            <UiButton size="sm" variant="secondary" :disabled="smtpTesting || !smtpTo.trim()" @click="onTestSmtp">
              {{ smtpTesting ? "Sending…" : "Send test" }}
            </UiButton>
          </div>
          <p v-if="smtpTestResult" :class="smtpTestResult.ok ? 'type-meta text-[11px]' : 'field-error text-[12px]'">
            {{ smtpTestResult.ok ? "Sent — check the inbox." : `Failed: ${smtpTestResult.error}` }}
          </p>
        </div>
      </section>

      <section v-if="section === 'captcha'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">CAPTCHA</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            A challenge on the sign-in and password-reset forms, against brute-force sprays.
            Cloudflare Turnstile or hCaptcha — pick the provider and paste its site key and secret.
            The gate is on only when provider, site key and secret are all present. The site key is
            public (every browser renders it); the secret is stored encrypted and never shown.
          </p>
        </div>

        <div v-if="captcha" class="space-y-3">
          <label class="block">
            <span class="type-label mb-1.5 block">Provider</span>
            <select v-model="captcha.provider" class="field-input">
              <option :value="null">Off (no challenge)</option>
              <option value="turnstile">Cloudflare Turnstile</option>
              <option value="hcaptcha">hCaptcha</option>
            </select>
          </label>

          <label class="block">
            <span class="type-label mb-1.5 block">Site key</span>
            <input
              v-model="captcha.site_key"
              type="text"
              class="field-input font-mono text-[12px]"
              autocomplete="off"
            />
          </label>

          <label class="block">
            <span class="type-label mb-1.5 block">
              Secret key
              <span v-if="captcha.secret_set" class="ml-1 text-[10px] font-normal uppercase tracking-wide text-muted-foreground">
                set
              </span>
            </span>
            <input
              v-model="captchaSecret"
              type="password"
              class="field-input font-mono text-[12px]"
              :placeholder="captcha.secret_set ? 'leave blank to keep' : 'not set'"
              autocomplete="new-password"
            />
          </label>

          <p class="type-meta text-[11px]">
            The gate applies to the next sign-in attempt — no redeploy. Test with a real sign-in
            after saving; a wrong site key shows itself as an invisible/failed widget.
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <UiButton size="sm" :disabled="captchaSaving || !captcha" @click="onSaveCaptcha">
            {{ captchaSaving ? "Saving…" : "Save" }}
          </UiButton>
          <UiButton
            size="sm"
            variant="secondary"
            :disabled="captchaSaving || !captcha"
            @click="onResetCaptcha"
          >
            Reset to env
          </UiButton>
          <span v-if="captchaSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section v-if="section === 'branding'" class="surface-card space-y-5 p-6">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Branding</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            The logo and product name shown on the sign-in page, setup wizard, sidebar and
            browser tab. Saved here they apply immediately — no redeploy. The name is stored as
            plain text and wins over <code class="text-[11px]">SIGNET_BRAND_NAME</code>.
          </p>
        </div>

        <div class="flex items-start gap-4">
          <BrandLogo size-class="h-12 w-12" />
          <div class="min-w-0">
            <input
              ref="logoInput"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              class="hidden"
              @change="onPickLogo"
            />
            <div class="flex flex-wrap items-center gap-2">
              <UiButton
                size="sm"
                variant="secondary"
                :disabled="logoBusy"
                @click="logoInput?.click()"
              >
                {{ logoBusy ? "Uploading…" : logoSet ? "Replace logo" : "Upload logo" }}
              </UiButton>
              <UiButton
                v-if="logoSet"
                size="sm"
                variant="ghost"
                :disabled="logoBusy"
                @click="onRemoveLogo"
              >
                Remove
              </UiButton>
            </div>
            <p class="type-meta mt-1.5 text-[11px]">
              PNG, JPEG or WebP, up to 256 KB. Square images look best (shown at 32–40 px).
            </p>
          </div>
        </div>

        <label class="block">
          <span class="type-label mb-1.5 block">Product name</span>
          <input
            v-model="brandingName"
            type="text"
            class="field-input"
            maxlength="64"
            placeholder="Signet"
          />
        </label>

        <div class="flex flex-wrap items-center gap-3">
          <UiButton size="sm" :disabled="brandingSaving || !brandingName.trim()" @click="onSaveBranding">
            {{ brandingSaving ? "Saving…" : "Save" }}
          </UiButton>
          <UiButton size="sm" variant="secondary" :disabled="brandingSaving" @click="onResetBranding">
            Reset to env
          </UiButton>
          <span v-if="brandingSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>
        </div>
      </div>
    </template>
  </div>
</template>

export type UserRole = "admin" | "manager" | "member";

export type PublicUser = {
  id: string;
  sub: string;
  email: string;
  username: string | null;
  display_name: string;
  status: string;
  role: UserRole;
  is_admin: boolean;
  mfa_required: boolean;
  must_change_password: boolean;
  totp_enabled: boolean;
  groups: string[];
  phone: string | null;
  created_at: string;
};

export type LoginResult =
  | { status: "ok"; user: PublicUser }
  | { status: "mfa_required" }
  | { status: "enroll_required" }
  | { status: "password_change_required" };

async function parseJson<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = (data as { error?: string }).error ?? res.statusText;
    throw new Error(message);
  }
  return data as T;
}

export async function login(email: string, password: string, returnTo?: string) {
  const res = await fetch("/api/v1/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email, password, return_to: returnTo || undefined }),
  });
  return parseJson<LoginResult>(res);
}

export async function loginChangePassword(newPassword: string) {
  const res = await fetch("/api/v1/login/password-change", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ new_password: newPassword }),
  });
  return parseJson<LoginResult>(res);
}

export async function verifyMfa(body: {
  code: string;
  method: "totp" | "recovery";
  return_to?: string;
}) {
  const res = await fetch("/api/v1/mfa/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ status: "ok"; user: PublicUser }>(res);
}

export async function mfaEnrollStart() {
  const res = await fetch("/api/v1/mfa/enroll/start", {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ secret: string; otpauth_uri: string }>(res);
}

export async function mfaEnrollConfirm(code: string, returnTo?: string) {
  const res = await fetch("/api/v1/mfa/enroll/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code, return_to: returnTo || undefined }),
  });
  return parseJson<{ status: "ok"; user: PublicUser; recovery_codes: string[] }>(res);
}

export async function fetchMeMfa() {
  const res = await fetch("/api/v1/me/mfa", { credentials: "include" });
  return parseJson<{
    totp_enabled: boolean;
    mfa_required: boolean;
    policy_required: boolean;
    required_globally: boolean;
    recovery_codes_remaining: number;
  }>(res);
}

export async function meMfaEnrollStart() {
  const res = await fetch("/api/v1/me/mfa/enroll/start", {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ secret: string; otpauth_uri: string }>(res);
}

export async function meMfaEnrollConfirm(code: string) {
  const res = await fetch("/api/v1/me/mfa/enroll/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code }),
  });
  return parseJson<{ ok: boolean; user: PublicUser; recovery_codes: string[] }>(res);
}

export async function meMfaRegenerateRecovery(code: string) {
  const res = await fetch("/api/v1/me/mfa/recovery/regenerate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code }),
  });
  return parseJson<{ recovery_codes: string[] }>(res);
}

export async function meMfaDisable(code: string) {
  const res = await fetch("/api/v1/me/mfa/disable", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code }),
  });
  return parseJson<{ ok: boolean; user: PublicUser }>(res);
}

export async function meMfaRebindStart(code: string) {
  const res = await fetch("/api/v1/me/mfa/rebind/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code }),
  });
  return parseJson<{ secret: string; otpauth_uri: string }>(res);
}

export async function meMfaRebindConfirm(code: string) {
  const res = await fetch("/api/v1/me/mfa/rebind/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code }),
  });
  return parseJson<{ ok: boolean; user: PublicUser; recovery_codes: string[] }>(res);
}

export async function fetchMfaSettings() {
  const res = await fetch("/api/v1/admin/settings/mfa", { credentials: "include" });
  return parseJson<{ required_globally: boolean }>(res);
}

export async function updateMfaSettings(body: { required_globally: boolean }) {
  const res = await fetch("/api/v1/admin/settings/mfa", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ required_globally: boolean }>(res);
}

export async function resetUserMfa(id: string) {
  const res = await fetch(`/api/v1/admin/users/${id}/mfa/reset`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function logout() {
  const res = await fetch("/api/v1/logout", {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function me() {
  const res = await fetch("/api/v1/me", { credentials: "include" });
  return parseJson<{ user: PublicUser }>(res);
}

export async function fetchSetupStatus() {
  const res = await fetch("/api/v1/setup/status");
  return parseJson<{ needs_setup: boolean }>(res);
}

export async function setupAdmin(body: {
  email: string;
  password: string;
  display_name?: string;
}) {
  const res = await fetch("/api/v1/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ status: "ok"; user: PublicUser }>(res);
}

export async function updateMe(body: { display_name: string; phone?: string }) {
  const res = await fetch("/api/v1/me", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ user: PublicUser }>(res);
}

export async function changePassword(body: {
  current_password: string;
  new_password: string;
}) {
  const res = await fetch("/api/v1/me/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function listUsers() {
  const res = await fetch("/api/v1/admin/users", { credentials: "include" });
  return parseJson<PublicUser[]>(res);
}

export async function checkEmail(email: string) {
  const qs = new URLSearchParams({ email });
  const res = await fetch(`/api/v1/admin/users/email-check?${qs}`, {
    credentials: "include",
  });
  return parseJson<{ exists: boolean }>(res);
}

export async function checkUsername(username: string) {
  const qs = new URLSearchParams({ username });
  const res = await fetch(`/api/v1/admin/users/username-check?${qs}`, {
    credentials: "include",
  });
  return parseJson<{ exists: boolean }>(res);
}

export async function checkPhone(phone: string, excludeId?: string) {
  const qs = new URLSearchParams({ phone });
  if (excludeId) qs.set("exclude_id", excludeId);
  const res = await fetch(`/api/v1/admin/users/phone-check?${qs}`, {
    credentials: "include",
  });
  return parseJson<{ exists: boolean }>(res);
}

export async function createUser(body: {
  email: string;
  password: string;
  username?: string;
  display_name?: string;
  role?: UserRole;
  groups?: string[];
  phone?: string;
  must_change_password?: boolean;
}) {
  const res = await fetch("/api/v1/admin/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<PublicUser>(res);
}

export async function updateUser(
  id: string,
  body: {
    email?: string;
    username?: string;
    display_name?: string;
    role?: UserRole;
    password?: string;
    status?: string;
    mfa_required?: boolean;
    must_change_password?: boolean;
    groups?: string[];
    phone?: string;
  },
) {
  const res = await fetch(`/api/v1/admin/users/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<PublicUser>(res);
}

export async function deleteUser(id: string) {
  const res = await fetch(`/api/v1/admin/users/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function disableUser(id: string) {
  const res = await fetch(`/api/v1/admin/users/${id}/disable`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<PublicUser>(res);
}

export async function enableUser(id: string) {
  const res = await fetch(`/api/v1/admin/users/${id}/enable`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<PublicUser>(res);
}

export async function batchDisableUsers(ids: string[]) {
  const res = await fetch("/api/v1/admin/users/batch-disable", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ ids }),
  });
  return parseJson<{ disabled: number }>(res);
}

export type RecentLogin = {
  actor_email: string | null;
  ip: string | null;
  browser: string | null;
  os: string | null;
  client_id: string | null;
  created_at: string;
};

export type LoginTrendPoint = {
  day: string;
  logins_1d: number;
  logins_7d: number;
  logins_30d: number;
};

/** One hourly bucket of the last 24 hours (UTC hour start). */
export type LoginTrendHourPoint = {
  hour: string;
  logins: number;
};

export type ClientUsage = {
  /// OAuth client identifier; "(direct)" = sign-ins without app context.
  client_id: string;
  logins_24h: number;
  logins_7d: number;
  logins_30d: number;
  unique_users_30d: number;
};

export type NameCount = {
  name: string;
  count: number;
};

export type AdminStats = {
  users_total: number;
  users_active: number;
  users_disabled: number;
  users_admin: number;
  users_manager: number;
  clients_total: number;
  clients_enabled: number;
  logins_24h: number;
  logins_7d: number;
  logins_30d: number;
  unique_users_24h: number;
  unique_users_7d: number;
  unique_users_30d: number;
  login_trend: LoginTrendPoint[];
  login_trend_24h: LoginTrendHourPoint[];
  recent_logins: RecentLogin[];
  by_client: ClientUsage[];
  browsers: NameCount[];
  oses: NameCount[];
  scope: { client_id: string | null };
};

export async function fetchAdminStats(clientId?: string) {
  const qs = new URLSearchParams();
  if (clientId) qs.set("client_id", clientId);
  const suffix = qs.toString() ? `?${qs}` : "";
  const res = await fetch(`/api/v1/admin/stats${suffix}`, { credentials: "include" });
  return parseJson<AdminStats>(res);
}

export type AdminClient = {
  id: string;
  client_id: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: string[];
  pkce_required: boolean;
  scopes: string[];
  enabled: boolean;
  ip_allowlist_enabled: boolean;
  allowed_cidrs: string[];
  created_at: string;
  updated_at: string;
};

export type ClientCreated = {
  client: AdminClient;
  client_secret: string;
};

export async function listClients() {
  const res = await fetch("/api/v1/admin/clients", { credentials: "include" });
  return parseJson<AdminClient[]>(res);
}

export async function createClient(body: {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  pkce_required?: boolean;
  scopes?: string[];
  ip_allowlist_enabled?: boolean;
  allowed_cidrs?: string[];
}) {
  const res = await fetch("/api/v1/admin/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<ClientCreated>(res);
}

export async function updateClient(
  id: string,
  body: {
    redirect_uris?: string[];
    post_logout_redirect_uris?: string[];
    pkce_required?: boolean;
    scopes?: string[];
    ip_allowlist_enabled?: boolean;
    allowed_cidrs?: string[];
  },
) {
  const res = await fetch(`/api/v1/admin/clients/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<AdminClient>(res);
}

export async function deleteClient(id: string) {
  const res = await fetch(`/api/v1/admin/clients/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function disableClient(id: string) {
  const res = await fetch(`/api/v1/admin/clients/${id}/disable`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<AdminClient>(res);
}

export async function enableClient(id: string) {
  const res = await fetch(`/api/v1/admin/clients/${id}/enable`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<AdminClient>(res);
}

export async function rotateClientSecret(id: string) {
  const res = await fetch(`/api/v1/admin/clients/${id}/rotate-secret`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<ClientCreated>(res);
}

export type AuditLogItem = {
  id: string;
  actor_user_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  detail: Record<string, unknown>;
  ip: string | null;
  user_agent: string | null;
  browser: string | null;
  os: string | null;
  client_id: string | null;
  created_at: string;
};

export async function fetchAuditLogs(params: {
  q?: string;
  action?: string;
  client_id?: string;
  browser?: string;
  os?: string;
  page?: number;
  page_size?: number;
  sort?: string;
  dir?: "asc" | "desc";
}) {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.action) qs.set("action", params.action);
  if (params.client_id) qs.set("client_id", params.client_id);
  if (params.browser) qs.set("browser", params.browser);
  if (params.os) qs.set("os", params.os);
  if (params.page) qs.set("page", String(params.page));
  if (params.page_size) qs.set("page_size", String(params.page_size));
  if (params.sort) qs.set("sort", params.sort);
  if (params.dir) qs.set("dir", params.dir);
  const res = await fetch(`/api/v1/admin/audit-logs?${qs}`, { credentials: "include" });
  return parseJson<{
    items: AuditLogItem[];
    total: number;
    page: number;
    page_size: number;
  }>(res);
}

export function auditLogsExportUrl(
  params: { q?: string; action?: string; client_id?: string; browser?: string; os?: string } = {},
) {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.action) qs.set("action", params.action);
  if (params.client_id) qs.set("client_id", params.client_id);
  if (params.browser) qs.set("browser", params.browser);
  if (params.os) qs.set("os", params.os);
  return `/api/v1/admin/audit-logs/export?${qs}`;
}

export type AuditLogFacets = {
  browsers: string[];
  oses: string[];
  clients: { client_id: string; enabled: boolean }[];
};

export async function fetchAuditLogFacets() {
  const res = await fetch("/api/v1/admin/audit-logs/facets", { credentials: "include" });
  return parseJson<AuditLogFacets>(res);
}

export type SessionInfo = {
  id: string;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
};

export async function fetchMySessions() {
  const res = await fetch("/api/v1/me/sessions", { credentials: "include" });
  return parseJson<{ sessions: SessionInfo[]; current_session_id: string | null }>(res);
}

export async function revokeMySession(id: string) {
  const res = await fetch(`/api/v1/me/sessions/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function revokeOtherSessions() {
  const res = await fetch("/api/v1/me/sessions", {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

// --- OAuth consents ---

export type Consent = {
  client_id: string;
  scopes: string[];
  granted_at: string;
};

export async function listMyConsents() {
  const res = await fetch("/api/v1/me/consents", { credentials: "include" });
  return parseJson<{ consents: Consent[] }>(res);
}

export async function revokeMyConsent(clientId: string) {
  const res = await fetch(`/api/v1/me/consents/${encodeURIComponent(clientId)}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

// --- My activity ---

export type ActivityItem = {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  detail: Record<string, unknown>;
  ip: string | null;
  browser: string | null;
  os: string | null;
  created_at: string;
};

export async function fetchMyActivity(params: { page?: number; page_size?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.page) qs.set("page", String(params.page));
  if (params.page_size) qs.set("page_size", String(params.page_size));
  const res = await fetch(`/api/v1/me/activity?${qs}`, { credentials: "include" });
  return parseJson<{
    summary: {
      last_login: { ip: string | null; browser: string | null; os: string | null; at: string } | null;
      active_sessions: number;
      totp_enabled: boolean;
      passkey_count: number;
      consent_count: number;
    };
    items: ActivityItem[];
    total: number;
    page: number;
    page_size: number;
  }>(res);
}

export async function revokeUserSessions(id: string) {
  const res = await fetch(`/api/v1/admin/users/${id}/sessions/revoke`, {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ revoked: number }>(res);
}

// --- Password reset ---

export async function requestPasswordReset(email: string) {
  const res = await fetch("/api/v1/password-reset/request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function confirmPasswordReset(token: string, new_password: string) {
  const res = await fetch("/api/v1/password-reset/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password }),
  });
  return parseJson<{ ok: boolean }>(res);
}

// --- Passkeys (WebAuthn) ---

export type Passkey = {
  id: string;
  name: string;
  credential_id: string;
  created_at: string;
  last_used_at: string | null;
};

export async function listPasskeys() {
  const res = await fetch("/api/v1/me/passkeys", { credentials: "include" });
  return parseJson<Passkey[]>(res);
}

export async function passkeyRegisterStart() {
  const res = await fetch("/api/v1/me/passkeys/start", {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ token: string; challenge: Record<string, unknown> }>(res);
}

export async function passkeyRegisterFinish(body: {
  token: string;
  name: string;
  credential: unknown;
}) {
  const res = await fetch("/api/v1/me/passkeys/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ ok: boolean; id: string }>(res);
}

export async function removePasskey(id: string) {
  const res = await fetch(`/api/v1/me/passkeys/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function passkeyLoginStart(email: string) {
  const res = await fetch("/api/v1/passkeys/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  return parseJson<{ token: string; challenge: Record<string, unknown> }>(res);
}

export async function passkeyLoginFinish(body: {
  token: string;
  credential: unknown;
  return_to?: string;
}) {
  const res = await fetch("/api/v1/passkeys/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ status: "ok"; user: PublicUser }>(res);
}

// --- Webhooks ---

export type WebhookKind = "generic" | "feishu";

export type Webhook = {
  id: string;
  url: string;
  kind: WebhookKind;
  enabled: boolean;
  secret_set: boolean;
};

export type WebhookDelivery = {
  id: string;
  event_id: string;
  status_code: number | null;
  success: boolean;
  error: string | null;
  created_at: string;
};

export async function listWebhooks() {
  const res = await fetch("/api/v1/admin/webhooks", { credentials: "include" });
  return parseJson<Webhook[]>(res);
}

export async function createWebhook(body: {
  url: string;
  secret?: string;
  kind?: WebhookKind;
}) {
  const res = await fetch("/api/v1/admin/webhooks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<Webhook>(res);
}

export async function deleteWebhook(id: string) {
  const res = await fetch(`/api/v1/admin/webhooks/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function listWebhookDeliveries(id: string) {
  const res = await fetch(`/api/v1/admin/webhooks/${id}/deliveries`, {
    credentials: "include",
  });
  return parseJson<WebhookDelivery[]>(res);
}

// --- Integrations ---

export type Integrations = {
  scim: {
    enabled: boolean;
    base_url: string;
    token_configured: boolean;
  };
  webauthn: {
    rp_id: string;
    rp_origin: string;
  };
};

export async function fetchIntegrations() {
  const res = await fetch("/api/v1/admin/integrations", { credentials: "include" });
  return parseJson<Integrations>(res);
}

export async function generateScimToken() {
  const res = await fetch("/api/v1/admin/scim/token", {
    method: "POST",
    credentials: "include",
  });
  return parseJson<{ token: string }>(res);
}

export async function revokeScimToken() {
  const res = await fetch("/api/v1/admin/scim/token", {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

// --- Federated identity (third-party sign-in) ---

export type SsoProviderType = "github" | "google" | "feishu" | "wechat" | "oidc";

export type SsoProvider = {
  code: string;
  provider_type: SsoProviderType;
  display_name: string;
  client_id: string;
  issuer_url: string | null;
  scopes: string | null;
  enabled: boolean;
  bindings: number;
  /** Concrete redirect URI to register with this provider (server-computed). */
  callback_url: string;
  created_at: string;
  updated_at: string;
};

export type SsoProviderBody = {
  code: string;
  provider_type: SsoProviderType;
  display_name: string;
  client_id: string;
  client_secret?: string;
  issuer_url?: string;
  scopes?: string;
  enabled?: boolean;
};

export async function fetchSsoProviders() {
  const res = await fetch("/api/v1/admin/sso/providers", { credentials: "include" });
  return parseJson<{ providers: SsoProvider[] }>(res);
}

export async function createSsoProvider(body: SsoProviderBody) {
  const res = await fetch("/api/v1/admin/sso/providers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ ok: boolean; code: string }>(res);
}

export async function updateSsoProvider(code: string, body: SsoProviderBody) {
  const res = await fetch(`/api/v1/admin/sso/providers/${encodeURIComponent(code)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function deleteSsoProvider(code: string) {
  const res = await fetch(`/api/v1/admin/sso/providers/${encodeURIComponent(code)}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function setSsoProviderEnabled(code: string, enabled: boolean) {
  const res = await fetch(`/api/v1/admin/sso/providers/${encodeURIComponent(code)}/enabled`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ enabled }),
  });
  return parseJson<{ ok: boolean }>(res);
}

export async function fetchSsoCallbackUrl() {
  const res = await fetch("/api/v1/auth/sso/callback-url", { credentials: "include" });
  return parseJson<{ callback_url: string }>(res);
}

/** Public (pre-auth): enabled providers for the login page buttons. */
export async function fetchEnabledSsoProviders() {
  const res = await fetch("/api/v1/auth/sso/providers");
  return parseJson<{ providers: { code: string; type: SsoProviderType; display_name: string }[] }>(res);
}

export type LinkedIdentity = {
  provider_code: string;
  provider_display_name: string;
  email: string | null;
  linked_at: string;
  last_login_at: string | null;
};

export async function fetchMyIdentities() {
  const res = await fetch("/api/v1/auth/sso/identities", { credentials: "include" });
  return parseJson<{ identities: LinkedIdentity[] }>(res);
}

export async function unlinkIdentity(providerCode: string) {
  const res = await fetch(`/api/v1/auth/sso/identities/${encodeURIComponent(providerCode)}`, {
    method: "DELETE",
    credentials: "include",
  });
  return parseJson<{ ok: boolean }>(res);
}

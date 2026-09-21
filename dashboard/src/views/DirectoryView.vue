<script setup lang="ts">
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  Clock,
  History,
  Plus,
  RefreshCw,
  ServerCog,
  Trash2,
  X,
  XCircle,
} from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import MappingPanel from "@/components/directory/MappingPanel.vue";
import { joinList, mappingKeys, splitList, withListValues } from "@/lib/directoryMapping";
import {
  createDirectorySource,
  deleteDirectorySource,
  listDirectoryRuns,
  listDirectorySources,
  setDirectorySourceEnabled,
  triggerDirectorySync,
  updateDirectorySource,
  type DirectoryRun,
  type DirectorySource,
  type DirectorySourceBody,
  type DirectorySourceKind,
  type HttpJsonSourceConfig,
  type HttpJsonAuth,
  type HttpJsonPagination,
  type LdapSourceConfig,
} from "@/lib/api";
import { confirm } from "@/lib/confirm";

const loading = ref(true);
const error = ref("");
const sources = ref<DirectorySource[]>([]);
/** Per-source in-flight action, so one row's button spinner doesn't disable others. */
const busyCode = ref<string | null>(null);

// --- Run history panel ---
const historyFor = ref<DirectorySource | null>(null);
const runs = ref<DirectoryRun[]>([]);
const runsLoading = ref(false);

// --- Create/edit modal ---
const showModal = ref(false);
const saving = ref(false);
const formErr = ref("");
const editing = ref<string | null>(null); // source code being edited; null = create

/**
 * The form's config keeps the optional attributes as plain strings (a blank
 * input is `""`, not absent) and `buildBody` strips them before sending: the
 * server's `LdapConfig` uses `deny_unknown_fields` and rejects an empty
 * `group_base_dn`, so an omitted-but-sent empty string is a hard error rather
 * than a default.
 */
type ConfigForm = Omit<
  LdapSourceConfig,
  | "display_name_attribute"
  | "group_base_dn"
  | "email_domains"
  | "department_attribute"
  | "department_values"
> & {
  display_name_attribute: string;
  group_base_dn: string;
  /**
   * The §7 scope. The two lists are held as one string each — a blank input is
   * `""`, not `[]` — and `buildBody` splits them into the arrays the server
   * expects. Keeping the shape uniform is what lets the mapping table read and
   * write every key the same way.
   */
  email_domains: string;
  department_attribute: string;
  department_values: string;
};

const LDAP_DEFAULTS: ConfigForm = {
  url: "",
  bind_dn: "",
  base_dn: "",
  user_filter: "(&(objectClass=person)(mail=*))",
  email_domains: "",
  department_attribute: "",
  department_values: "",
  username_attribute: "uid",
  email_attribute: "mail",
  display_name_attribute: "displayName",
  external_id_attribute: "entryUUID",
  group_base_dn: "",
  group_filter: "(objectClass=groupOfNames)",
  group_member_attribute: "member",
  group_name_attribute: "cn",
  page_size: 500,
};

/**
 * The HTTP JSON form, all-strings for the same reason as `ConfigForm`: a blank
 * input is `""` and `buildBody` decides whether that means "omit" or "keep".
 */
type HttpForm = {
  url: string;
  auth: "none" | "bearer" | "basic";
  basic_username: string;
  users_path: string;
  external_id_path: string;
  email_path: string;
  email_domains: string;
  department_path: string;
  department_values: string;
  username_path: string;
  display_name_path: string;
  groups_path: string;
  pagination: "none" | "page" | "cursor";
  page_param: string;
  page_size_param: string;
  page_size: number;
  cursor_param: string;
  cursor_next_path: string;
  max_pages: number;
};

const HTTP_DEFAULTS: HttpForm = {
  url: "",
  auth: "bearer",
  basic_username: "",
  users_path: "data.users",
  external_id_path: "id",
  email_path: "email",
  email_domains: "",
  department_path: "",
  department_values: "",
  username_path: "",
  display_name_path: "",
  groups_path: "",
  pagination: "none",
  page_param: "page",
  page_size_param: "page_size",
  page_size: 200,
  cursor_param: "cursor",
  cursor_next_path: "next",
  max_pages: 10,
};

const form = ref<{
  kind: DirectorySourceKind;
  code: string;
  name: string;
  enabled: boolean;
  priority: number;
  sync_groups: boolean;
  interval_minutes: string;
  credential: string;
  ca_cert_pem: string;
  config: ConfigForm;
  http: HttpForm;
}>({
  kind: "ldap",
  code: "",
  name: "",
  enabled: false,
  priority: 100,
  sync_groups: true,
  /** Empty string = manual only, which is what a first cautious rollout wants. */
  interval_minutes: "",
  credential: "",
  ca_cert_pem: "",
  config: { ...LDAP_DEFAULTS },
  http: { ...HTTP_DEFAULTS },
});

/** One-line summary of a config, for the list row. */
function endpointLabel(s: DirectorySource): string {
  return s.config?.url ?? "—";
}

function scheduleLabel(s: DirectorySource): string {
  return s.interval_minutes ? `every ${s.interval_minutes}m` : "manual only";
}

function openCreate() {
  editing.value = null;
  form.value = {
    kind: "ldap",
    code: "",
    name: "",
    enabled: false,
    priority: 100,
    sync_groups: true,
    interval_minutes: "",
    credential: "",
    ca_cert_pem: "",
    config: { ...LDAP_DEFAULTS },
    http: { ...HTTP_DEFAULTS },
  };
  formErr.value = "";
  showModal.value = true;
}

function openEdit(s: DirectorySource) {
  editing.value = s.code;
  const base = {
    code: s.code,
    name: s.name,
    enabled: s.enabled,
    priority: s.priority,
    sync_groups: s.sync_groups,
    interval_minutes: s.interval_minutes === null ? "" : String(s.interval_minutes),
    // Left blank on purpose: the server never returns the stored secret, so
    // prefilling it is impossible and echoing an empty string would clear it
    // (the API treats "" as "delete"). Blank = keep.
    credential: "",
    ca_cert_pem: "",
  };
  if (s.kind === "http_json") {
    const c = (s.config ?? {}) as HttpJsonSourceConfig;
    const auth = c.auth ?? "none";
    form.value = {
      ...base,
      kind: "http_json",
      config: { ...LDAP_DEFAULTS },
      http: {
        ...HTTP_DEFAULTS,
        url: c.url ?? "",
        // The stored auth is a tagged union; flattening it into the three form
        // fields (mode + username) is what keeps the template simple.
        auth: typeof auth === "string" ? (auth as "none" | "bearer") : "basic",
        basic_username: typeof auth === "object" ? (auth.basic?.username ?? "") : "",
        users_path: c.users_path ?? "",
        external_id_path: c.external_id_path ?? "",
        email_path: c.email_path ?? "",
        // The scope's lists are arrays in the config and one string each in the
        // form.
        email_domains: joinList(c.email_domains),
        department_path: c.department_path ?? "",
        department_values: joinList(c.department_values),
        username_path: c.username_path ?? "",
        display_name_path: c.display_name_path ?? "",
        groups_path: c.groups_path ?? "",
        ...paginationToForm(c.pagination),
      },
    };
    formErr.value = "";
    showModal.value = true;
    return;
  }
  form.value = {
    ...base,
    kind: "ldap",
    http: { ...HTTP_DEFAULTS },
    config: {
      ...LDAP_DEFAULTS,
      ...(s.config as LdapSourceConfig),
      // An absent optional attribute becomes a blank input, not `undefined`, so
      // the form's type stays simple and `buildBody` decides what to omit.
      display_name_attribute: (s.config as LdapSourceConfig).display_name_attribute ?? "",
      group_base_dn: (s.config as LdapSourceConfig).group_base_dn ?? "",
      email_domains: joinList((s.config as LdapSourceConfig).email_domains),
      department_attribute: (s.config as LdapSourceConfig).department_attribute ?? "",
      department_values: joinList((s.config as LdapSourceConfig).department_values),
    },
  };
  formErr.value = "";
  showModal.value = true;
}

/** Flattens the stored pagination union into the form's select + fields. */
function paginationToForm(p: HttpJsonPagination | undefined): Partial<HttpForm> {
  if (!p) return { pagination: "none" };
  if (p.mode === "page") {
    return {
      pagination: "page",
      page_param: p.param,
      page_size_param: p.size_param ?? "page_size",
      page_size: p.size ?? 200,
      max_pages: p.max_pages,
    };
  }
  if (p.mode === "cursor") {
    return {
      pagination: "cursor",
      cursor_param: p.param,
      cursor_next_path: p.next_path,
      max_pages: p.max_pages,
    };
  }
  return { pagination: "none" };
}

/** The reverse of `paginationToForm`, omitting the fields of other modes. */
function paginationBody(h: HttpForm): HttpJsonPagination {
  if (h.pagination === "page") {
    return {
      mode: "page",
      param: h.page_param.trim(),
      size_param: h.page_size_param.trim() || "page_size",
      size: Number(h.page_size),
      max_pages: Number(h.max_pages),
    };
  }
  if (h.pagination === "cursor") {
    return {
      mode: "cursor",
      param: h.cursor_param.trim(),
      next_path: h.cursor_next_path.trim(),
      max_pages: Number(h.max_pages),
    };
  }
  return { mode: "none" };
}

/** Builds the `auth` union from the form's mode + username. */
function authBody(h: HttpForm): HttpJsonAuth {
  if (h.auth === "bearer") return "bearer";
  if (h.auth === "basic") return { basic: { username: h.basic_username.trim() } };
  return "none";
}

/**
 * The mapping table's view of the form.
 *
 * The panel edits a flat bag of mapping keys, while the form keeps the config
 * split by kind (`config` for LDAP, `http` for HTTP JSON). Bridging here rather
 * than in the panel means the panel never has to know which kind stores what.
 *
 * Reads come straight from the live form, so the rows and the preview both track
 * what is on screen as it is typed. This used to be routed through `buildBody`
 * because the preview endpoint parsed the config strictly and rejected a blank
 * optional path — which meant the preview only worked once the *connection*
 * settings above were complete. The endpoint now reads just the mapping keys and
 * treats a blank one as "not set yet", so the indirection no longer buys
 * anything, and going through the save builder would only make the preview lag
 * the form.
 *
 * Writes merge back into the form, so a key holding `""` stays a key rather than
 * being dropped.
 */
const mappingValue = computed<Record<string, unknown>>(() => {
  const source = (form.value.kind === "http_json" ? form.value.http : form.value.config) as
    | unknown as Record<string, unknown>
    | undefined;
  const out: Record<string, unknown> = {};
  for (const key of mappingKeys(form.value.kind)) out[key] = source?.[key] ?? "";
  return out;
});

/**
 * The config the preview is run against: the live form values for the current
 * kind, as the modal currently holds them.
 *
 * Not `buildBody()`: that is the *save* payload, and routing the preview through
 * it would make the preview lag the form — it trims values and decides which
 * optional keys to omit. The endpoint reads only the mapping keys and treats a
 * blank one as "not set yet", so it does not need the trimming.
 *
 * The connection keys (`url`, `bind_dn`, `page_size`, …) ride along so the
 * payload has the shape a save would carry; the endpoint ignores them, since it
 * never opens a connection. Secrets are not exposed by this: the service-account
 * password and the bearer token live in `form.credential`, outside the config
 * object read here.
 */
const previewInput = computed<Record<string, unknown>>(() => {
  const source = (form.value.kind === "http_json" ? form.value.http : form.value.config) as
    | unknown as Record<string, unknown>
    | undefined;
  // The list inputs are strings in the form (so every key reads and writes the
  // same way), but the server's scope fields are arrays — sending a string where
  // a `Vec<String>` is expected is a hard 400, not a defaulted value.
  return withListValues(form.value.kind, { ...source });
});

function applyMapping(value: Record<string, unknown>) {
  if (form.value.kind === "http_json") {
    form.value.http = { ...form.value.http, ...value };
    return;
  }
  form.value.config = { ...form.value.config, ...value };
}

function buildBody(): DirectorySourceBody {
  const f = form.value;
  const interval = f.interval_minutes.trim();

  if (f.kind === "http_json") {
    const h = f.http;
    const config: HttpJsonSourceConfig = {
      url: h.url.trim(),
      method: "GET",
      auth: authBody(h),
      users_path: h.users_path.trim(),
      external_id_path: h.external_id_path.trim(),
      email_path: h.email_path.trim(),
    };
    // Optional paths must be absent, not blank: the server's config uses
    // `deny_unknown_fields` and rejects an empty optional path, so sending `""`
    // where the field should be omitted is a hard 400.
    if (h.username_path.trim()) config.username_path = h.username_path.trim();
    if (h.display_name_path.trim()) config.display_name_path = h.display_name_path.trim();
    if (h.groups_path.trim()) config.groups_path = h.groups_path.trim();
    // §7 scope. An empty list is meaningful (it means "no scoping") and is sent
    // as `[]`; a blank department path is not, and is omitted.
    config.email_domains = splitList(h.email_domains);
    config.department_values = splitList(h.department_values);
    if (h.department_path.trim()) config.department_path = h.department_path.trim();
    config.pagination = paginationBody(h);
    return {
      code: f.code.trim(),
      name: f.name.trim(),
      kind: "http_json",
      enabled: f.enabled,
      priority: Number(f.priority),
      config,
      // `auth: none` genuinely has no secret, so clearing it is the honest
      // thing to send; every other scheme requires one.
      credential: f.credential.trim()
        ? f.credential.trim()
        : editing.value && !needsCredential()
          ? ""
          : editing.value
            ? undefined
            : "",
      ca_cert_pem: undefined,
      sync_groups: f.sync_groups,
      interval_minutes: interval ? Number(interval) : null,
    };
  }

  // Trim before deciding what to omit: the inputs are the only place an operator
  // can introduce whitespace, and the server compares a blank optional attribute
  // against absent rather than against itself.
  const config: LdapSourceConfig = {
    ...f.config,
    url: f.config.url.trim(),
    bind_dn: f.config.bind_dn.trim(),
    base_dn: f.config.base_dn.trim(),
    user_filter: f.config.user_filter.trim(),
    username_attribute: f.config.username_attribute.trim(),
    email_attribute: f.config.email_attribute.trim(),
    external_id_attribute: f.config.external_id_attribute.trim(),
    display_name_attribute: f.config.display_name_attribute.trim(),
    group_base_dn: f.config.group_base_dn.trim(),
    group_filter: f.config.group_filter.trim(),
    group_member_attribute: f.config.group_member_attribute.trim(),
    group_name_attribute: f.config.group_name_attribute.trim(),
    // §7 scope: the two lists are strings in the form and arrays in the config.
    email_domains: splitList(f.config.email_domains),
    department_values: splitList(f.config.department_values),
    department_attribute: f.config.department_attribute.trim(),
  };
  // Optional empty strings must be absent, not empty: `LdapConfig` uses
  // `deny_unknown_fields` and rejects an empty `group_base_dn` outright, so
  // sending `""` where the field should be omitted is a hard 400.
  if (!config.display_name_attribute) delete config.display_name_attribute;
  if (!config.group_base_dn) delete config.group_base_dn;
  if (!config.department_attribute) delete config.department_attribute;

  return {
    code: f.code.trim(),
    name: f.name.trim(),
    kind: "ldap",
    enabled: f.enabled,
    priority: Number(f.priority),
    config,
    credential: f.credential.trim() ? f.credential.trim() : editing.value ? undefined : "",
    ca_cert_pem: f.ca_cert_pem.trim() ? f.ca_cert_pem : undefined,
    sync_groups: f.sync_groups,
    interval_minutes: interval ? Number(interval) : null,
  };
}

/** Whether the selected kind + auth scheme needs a stored secret. */
function needsCredential(): boolean {
  if (form.value.kind === "ldap") return true;
  return form.value.http.auth !== "none";
}

function validate(): string {
  const f = form.value;
  if (!/^[a-zA-Z0-9_-]+$/.test(f.code.trim())) {
    return "Code may only contain letters, digits, - and _";
  }
  if (!f.name.trim()) return "Name is required";

  if (f.kind === "http_json") {
    const h = f.http;
    const url = h.url.trim().toLowerCase();
    if (!url.startsWith("https://") && !url.startsWith("http://")) {
      return "The URL must start with http(s)://";
    }
    if (!h.users_path.trim()) return "Users path is required";
    if (!h.external_id_path.trim()) return "External ID path is required";
    if (!h.email_path.trim()) return "Email path is required";
    if (h.auth === "basic" && !h.basic_username.trim()) {
      return "A username is required for basic auth";
    }
    if (!editing.value && needsCredential() && !f.credential.trim()) {
      return "A credential is required for this auth scheme";
    }
    if (h.pagination === "page") {
      if (!h.page_param.trim()) return "The page parameter name is required";
      if (Number(h.page_size) < 1) return "The page size must be at least 1";
    }
    if (h.pagination === "cursor" && !h.cursor_next_path.trim()) {
      return "The cursor path is required (where the next cursor appears in the response)";
    }
    if (h.pagination !== "none" && Number(h.max_pages) < 1) {
      return "Max pages must be at least 1";
    }
    if (f.interval_minutes.trim() && Number(f.interval_minutes) < 1) {
      return "The interval must be at least 1 minute (leave it blank for manual only)";
    }
    return "";
  }

  if (!f.config.url.trim().toLowerCase().startsWith("ldaps://")) {
    return "The URL must start with ldaps:// — plaintext LDAP is refused (certificate verification is mandatory)";
  }
  if (!f.config.bind_dn.trim()) return "Bind DN is required";
  if (!f.config.base_dn.trim()) return "Base DN is required";
  if (!f.config.username_attribute.trim()) return "Username attribute is required";
  if (!f.config.external_id_attribute.trim()) return "External ID attribute is required";
  if (!editing.value && !f.credential.trim()) {
    return "A credential is required: the sync binds as a service account";
  }
  if (f.interval_minutes.trim() && Number(f.interval_minutes) < 1) {
    return "The interval must be at least 1 minute (leave it blank for manual only)";
  }
  return "";
}

async function onSave() {
  formErr.value = validate();
  if (formErr.value) return;
  saving.value = true;
  try {
    const body = buildBody();
    if (editing.value) {
      await updateDirectorySource(editing.value, body);
    } else {
      await createDirectorySource(body);
    }
    showModal.value = false;
    await refresh();
  } catch (e) {
    formErr.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    saving.value = false;
  }
}

async function refresh() {
  sources.value = await listDirectorySources();
}

onMounted(async () => {
  try {
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load directory sources";
  } finally {
    loading.value = false;
  }
});

async function onToggle(s: DirectorySource) {
  busyCode.value = s.code;
  error.value = "";
  try {
    await setDirectorySourceEnabled(s.code, !s.enabled);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    busyCode.value = null;
  }
}

async function onSyncNow(s: DirectorySource) {
  busyCode.value = s.code;
  error.value = "";
  try {
    await triggerDirectorySync(s.code);
    // The run is asynchronous: open the history panel so the operator sees the
    // result arrive, rather than a toast that says nothing.
    await viewRuns(s);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Could not start the sync";
  } finally {
    busyCode.value = null;
  }
}

async function onDelete(s: DirectorySource) {
  if (
    !(await confirm({
      title: "Delete source?",
      message: `"${s.name}" can only be deleted once it manages no users. To stop syncing but keep the accounts, disable it instead.`,
      confirmText: "Delete",
      danger: true,
    }))
  ) {
    return;
  }
  busyCode.value = s.code;
  error.value = "";
  try {
    await deleteDirectorySource(s.code);
    if (historyFor.value?.code === s.code) historyFor.value = null;
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  } finally {
    busyCode.value = null;
  }
}

async function viewRuns(s: DirectorySource) {
  historyFor.value = s;
  runs.value = [];
  runsLoading.value = true;
  try {
    runs.value = await listDirectoryRuns(s.code);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load the run history";
  } finally {
    runsLoading.value = false;
  }
}

async function reloadRuns() {
  if (historyFor.value) await viewRuns(historyFor.value);
}

const STATUS_CLASS: Record<string, string> = {
  succeeded: "bg-emerald-500/10 text-emerald-600",
  partial: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  failed: "bg-destructive/10 text-destructive",
  running: "bg-blue-500/10 text-blue-600",
};

function duration(r: DirectoryRun): string {
  if (!r.finished_at) return "—";
  const ms = new Date(r.finished_at).getTime() - new Date(r.started_at).getTime();
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Directory sync"
      description="Pull users from an external LDAP directory. Synced attributes are read-only here, and those users sign in with their directory password."
    >
      <template #actions>
        <UiButton size="sm" @click="openCreate">
          <Plus class="h-3.5 w-3.5" />
          New source
        </UiButton>
      </template>
    </PageHeader>

    <p v-if="error" class="field-error">{{ error }}</p>
    <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>

    <section v-else class="rounded-xl bg-card p-6 shadow-sm">
      <div class="mb-4">
        <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
          <ServerCog class="h-4 w-4 text-muted-foreground" />
          Sources
        </h2>
        <p class="mt-1 text-xs text-muted-foreground">
          Lowest priority wins when two directories list the same person. Turning a source off
          stops its users signing in through it and hands their accounts back to local
          administration.
        </p>
      </div>

      <div
        v-if="sources.length === 0"
        class="py-8 text-center text-sm text-muted-foreground"
      >
        No directory sources yet.
      </div>

      <ul v-else class="divide-y divide-border/50">
        <li
          v-for="s in sources"
          :key="s.id"
          class="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-sm font-medium">{{ s.name }}</span>
              <span class="type-meta font-mono text-[10px]">{{ s.code }}</span>
              <span
                class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                :class="s.enabled ? 'bg-emerald-500/10 text-emerald-600' : 'bg-muted text-muted-foreground'"
              >
                {{ s.enabled ? "Enabled" : "Disabled" }}
              </span>
              <span
                v-if="!s.credential_set"
                class="rounded-full bg-destructive/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-destructive"
              >
                No credential
              </span>
            </div>
            <p class="type-meta mt-1 truncate font-mono text-[11px]">{{ endpointLabel(s) }}</p>
            <p class="type-meta mt-0.5 text-[11px]">
              priority {{ s.priority }} · {{ scheduleLabel(s) }} ·
              {{ s.sync_groups ? "groups synced" : "groups ignored" }} ·
              {{ s.ca_cert_set ? "custom CA" : "system CAs" }}
            </p>
          </div>
          <div class="flex shrink-0 items-center gap-2">
            <UiButton
              variant="ghost"
              size="sm"
              :disabled="busyCode === s.code || !s.enabled"
              :title="s.enabled ? 'Start a sync now' : 'Enable the source first'"
              @click="onSyncNow(s)"
            >
              <RefreshCw class="h-3.5 w-3.5" />
              Sync now
            </UiButton>
            <UiButton variant="ghost" size="sm" @click="viewRuns(s)">
              <History class="h-3.5 w-3.5" />
              History
            </UiButton>
            <UiButton variant="ghost" size="sm" :disabled="busyCode === s.code" @click="onToggle(s)">
              {{ s.enabled ? "Disable" : "Enable" }}
            </UiButton>
            <UiButton variant="ghost" size="sm" @click="openEdit(s)">Edit</UiButton>
            <UiButton
              variant="ghost"
              size="icon"
              :disabled="busyCode === s.code"
              @click="onDelete(s)"
            >
              <Trash2 class="h-4 w-4 text-destructive" />
            </UiButton>
          </div>
        </li>
      </ul>

      <!-- Run history -->
      <div
        v-if="historyFor"
        class="mt-4 rounded-xl border border-border/50 bg-muted/30 p-4"
      >
        <div class="mb-3 flex items-center justify-between gap-2">
          <p class="text-xs font-medium">Run history · {{ historyFor.name }}</p>
          <div class="flex items-center gap-1">
            <UiButton variant="ghost" size="sm" :disabled="runsLoading" @click="reloadRuns">
              <RefreshCw class="h-3.5 w-3.5" />
              Refresh
            </UiButton>
            <UiButton variant="ghost" size="sm" @click="historyFor = null">Close</UiButton>
          </div>
        </div>

        <div v-if="runsLoading" class="py-4 text-center text-xs text-muted-foreground">
          Loading…
        </div>
        <div v-else-if="runs.length === 0" class="py-4 text-center text-xs text-muted-foreground">
          No runs yet.
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="text-muted-foreground">
              <tr>
                <th class="py-1.5 pr-3 font-medium">Status</th>
                <th class="py-1.5 pr-3 font-medium">Started</th>
                <th class="py-1.5 pr-3 font-medium">Trigger</th>
                <th class="py-1.5 pr-3 font-medium">Took</th>
                <th class="py-1.5 pr-3 font-medium">Scanned</th>
                <th class="py-1.5 pr-3 font-medium">Created</th>
                <th class="py-1.5 pr-3 font-medium">Updated</th>
                <th class="py-1.5 pr-3 font-medium">Disabled</th>
                <th class="py-1.5 pr-3 font-medium">Skipped</th>
                <th class="py-1.5 pr-3 font-medium">Conflicts</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in runs" :key="r.id" class="border-t border-border/40">
                <td class="py-1.5 pr-3">
                  <span
                    class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold"
                    :class="STATUS_CLASS[r.status] ?? 'bg-muted text-muted-foreground'"
                  >
                    <CheckCircle2 v-if="r.status === 'succeeded'" class="h-3 w-3" />
                    <AlertTriangle v-else-if="r.status === 'partial'" class="h-3 w-3" />
                    <XCircle v-else-if="r.status === 'failed'" class="h-3 w-3" />
                    <Clock v-else class="h-3 w-3" />
                    {{ r.status }}
                  </span>
                </td>
                <td class="py-1.5 pr-3 whitespace-nowrap">
                  {{ new Date(r.started_at).toLocaleString() }}
                </td>
                <td class="py-1.5 pr-3">{{ r.trigger }}</td>
                <td class="py-1.5 pr-3 whitespace-nowrap">{{ duration(r) }}</td>
                <td class="py-1.5 pr-3">{{ r.scanned }}</td>
                <td class="py-1.5 pr-3">{{ r.created_count }}</td>
                <td class="py-1.5 pr-3">{{ r.updated_count }}</td>
                <td class="py-1.5 pr-3">{{ r.disabled_count }}</td>
                <td class="py-1.5 pr-3">{{ r.skipped_count }}</td>
                <td
                  class="py-1.5 pr-3"
                  :class="r.conflict_count > 0 ? 'font-semibold text-amber-700 dark:text-amber-400' : ''"
                >
                  {{ r.conflict_count }}
                </td>
              </tr>
            </tbody>
          </table>
          <p
            v-for="r in runs.filter((x) => x.error)"
            :key="`${r.id}-err`"
            class="mt-1.5 flex items-start gap-1.5 text-[11px] text-destructive"
          >
            <AlertTriangle class="mt-0.5 h-3 w-3 shrink-0" />
            <span class="font-mono">{{ r.error }}</span>
          </p>
        </div>
        <p
          v-if="runs.some((r) => r.conflict_count > 0)"
          class="type-meta mt-3 text-[11px]"
        >
          A conflict means an entry matched a local account that no directory manages. Nothing was
          taken over — resolve it by hand, or link the account before the next run.
        </p>
      </div>
    </section>

    <!-- Create/edit modal -->
    <Teleport to="body">
      <div v-if="showModal" class="fixed inset-0 z-50 flex items-center justify-center">
        <div
          class="absolute inset-0 bg-black/30 backdrop-blur-sm"
          @click="!saving && (showModal = false)"
        />
        <div
          class="relative z-10 mx-4 max-h-[90vh] w-full max-w-6xl overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <div class="mb-4 flex items-center justify-between">
            <h2 class="flex items-center gap-2 text-base font-semibold">
              <ArrowRightLeft class="h-4 w-4 text-muted-foreground" />
              {{ editing ? "Edit directory source" : "New directory source" }}
            </h2>
            <button
              class="text-muted-foreground hover:text-foreground"
              type="button"
              @click="showModal = false"
            >
              <X class="h-4 w-4" />
            </button>
          </div>

          <form class="space-y-4" @submit.prevent="onSave">
            <div class="grid gap-3 sm:grid-cols-3">
              <div>
                <label class="type-label mb-1.5 block">Code</label>
                <input
                  v-model="form.code"
                  class="field-input"
                  placeholder="corp-ldap"
                  pattern="[a-zA-Z0-9_-]+"
                  :disabled="!!editing"
                  required
                />
              </div>
              <div>
                <label class="type-label mb-1.5 block">Display name</label>
                <input v-model="form.name" class="field-input" placeholder="Corporate LDAP" required />
              </div>
              <div>
                <label class="type-label mb-1.5 block">Priority</label>
                <input v-model.number="form.priority" type="number" min="1" class="field-input" />
                <p class="type-meta mt-1 text-[11px]">Lower wins</p>
              </div>
            </div>

            <div v-if="!editing" class="grid gap-3 sm:grid-cols-3">
              <div class="sm:col-span-1">
                <label class="type-label mb-1.5 block">Source kind</label>
                <select v-model="form.kind" class="field-input">
                  <option value="ldap">LDAP (LDAPS)</option>
                  <option value="http_json">HTTP JSON API</option>
                </select>
                <p class="type-meta mt-1 text-[11px]">Cannot be changed later.</p>
              </div>
            </div>

            <template v-if="form.kind === 'ldap'">
              <div class="grid gap-3 sm:grid-cols-2">
                <div>
                  <label class="type-label mb-1.5 block">LDAPS URL</label>
                  <input
                    v-model="form.config.url"
                    class="field-input"
                    placeholder="ldaps://ldap.corp.example.com:636"
                    required
                  />
                  <p class="type-meta mt-1 text-[11px]">
                    Must be ldaps:// — certificate verification cannot be turned off.
                  </p>
                </div>
                <div>
                  <label class="type-label mb-1.5 block">
                    Service-account password
                    {{ editing ? "(leave blank to keep the stored one)" : "" }}
                  </label>
                  <input
                    v-model="form.credential"
                    type="password"
                    class="field-input"
                    :placeholder="editing ? '••••••••' : 'Password for the bind DN'"
                    autocomplete="new-password"
                    :required="!editing"
                  />
                </div>
              </div>

              <div class="grid gap-3 sm:grid-cols-2">
                <div>
                  <label class="type-label mb-1.5 block">Bind DN</label>
                  <input
                    v-model="form.config.bind_dn"
                    class="field-input"
                    placeholder="cn=svc-signet,ou=service,dc=corp,dc=example,dc=com"
                    required
                  />
                </div>
                <div>
                  <label class="type-label mb-1.5 block">Page size</label>
                  <input
                    v-model.number="form.config.page_size"
                    type="number"
                    min="1"
                    max="1000"
                    class="field-input"
                  />
                  <p class="type-meta mt-1 text-[11px]">AD caps paged searches at 1000</p>
                </div>
              </div>

              <div>
                <label class="type-label mb-1.5 block">CA certificate (optional)</label>
                <textarea
                  v-model="form.ca_cert_pem"
                  rows="3"
                  class="field-input font-mono text-[11px]"
                  :placeholder="
                    editing && !form.ca_cert_pem
                      ? 'A certificate is stored — leave blank to keep it for a self-signed directory'
                      : 'PEM for a self-signed / internal CA. Leave blank to use the system trust store.'
                  "
                />
              </div>
            </template>

            <template v-else>
              <div class="grid gap-3 sm:grid-cols-2">
                <div>
                  <label class="type-label mb-1.5 block">Endpoint URL</label>
                  <input
                    v-model="form.http.url"
                    class="field-input"
                    placeholder="https://directory.corp.example.com/api/users"
                    required
                  />
                  <p class="type-meta mt-1 text-[11px]">
                    Must be http(s):// and publicly routable, unless the deployment opted into
                    private networks. Redirects are not followed.
                  </p>
                </div>
                <div>
                  <label class="type-label mb-1.5 block">Auth</label>
                  <select v-model="form.http.auth" class="field-input">
                    <option value="bearer">Bearer token</option>
                    <option value="basic">Basic (username + password)</option>
                    <option value="none">None</option>
                  </select>
                </div>
              </div>

              <div class="grid gap-3 sm:grid-cols-2">
                <div v-if="form.http.auth === 'basic'">
                  <label class="type-label mb-1.5 block">Username</label>
                  <input
                    v-model="form.http.basic_username"
                    class="field-input"
                    placeholder="svc-signet"
                    :required="form.http.auth === 'basic'"
                  />
                </div>
                <div v-if="form.http.auth !== 'none'">
                  <label class="type-label mb-1.5 block">
                    {{ form.http.auth === "bearer" ? "Token" : "Password" }}
                    {{ editing ? "(leave blank to keep the stored one)" : "" }}
                  </label>
                  <input
                    v-model="form.credential"
                    type="password"
                    class="field-input"
                    :placeholder="editing ? '••••••••' : 'Secret sent with every request'"
                    autocomplete="new-password"
                    :required="!editing"
                  />
                </div>
              </div>

              <div class="grid gap-3 sm:grid-cols-4">
                <div>
                  <label class="type-label mb-1.5 block">Pagination</label>
                  <select v-model="form.http.pagination" class="field-input">
                    <option value="none">None (single response)</option>
                    <option value="page">Page number</option>
                    <option value="cursor">Cursor</option>
                  </select>
                </div>
                <template v-if="form.http.pagination === 'page'">
                  <div>
                    <label class="type-label mb-1.5 block">Page param</label>
                    <input v-model="form.http.page_param" class="field-input font-mono text-xs" />
                  </div>
                  <div>
                    <label class="type-label mb-1.5 block">Size param</label>
                    <input v-model="form.http.page_size_param" class="field-input font-mono text-xs" />
                  </div>
                  <div>
                    <label class="type-label mb-1.5 block">Page size / max pages</label>
                    <div class="flex gap-2">
                      <input
                        v-model.number="form.http.page_size"
                        type="number"
                        min="1"
                        max="1000"
                        class="field-input"
                      />
                      <input
                        v-model.number="form.http.max_pages"
                        type="number"
                        min="1"
                        class="field-input"
                      />
                    </div>
                  </div>
                </template>
                <template v-else-if="form.http.pagination === 'cursor'">
                  <div>
                    <label class="type-label mb-1.5 block">Cursor param</label>
                    <input v-model="form.http.cursor_param" class="field-input font-mono text-xs" />
                  </div>
                  <div>
                    <label class="type-label mb-1.5 block">Next-cursor path</label>
                    <input
                      v-model="form.http.cursor_next_path"
                      class="field-input font-mono text-xs"
                      placeholder="paging.next"
                    />
                  </div>
                  <div>
                    <label class="type-label mb-1.5 block">Max pages</label>
                    <input
                      v-model.number="form.http.max_pages"
                      type="number"
                      min="1"
                      class="field-input"
                    />
                  </div>
                </template>
              </div>
            </template>

            <div class="border-t border-border/60 pt-4">
              <div class="mb-3 flex items-baseline gap-2">
                <h3 class="text-sm font-semibold">Field mapping</h3>
                <p class="type-meta text-[11px]">
                  Paste a sample on the left, then pick each field's source from the list. Nothing
                  is written until you save.
                </p>
              </div>
              <MappingPanel
                :kind="form.kind"
                :model-value="mappingValue"
                :config="previewInput"
                :sync-groups="form.sync_groups"
                @update:model-value="applyMapping"
              />
            </div>

            <div class="grid gap-3 sm:grid-cols-2">
              <div>
                <label class="type-label mb-1.5 block">Sync interval (minutes)</label>
                <input
                  v-model="form.interval_minutes"
                  type="number"
                  min="1"
                  class="field-input"
                  placeholder="Blank = manual only"
                />
                <p class="type-meta mt-1 text-[11px]">
                  The background scheduler runs the source this often.
                </p>
              </div>
              <div class="space-y-2 pt-6">
                <label class="flex items-center gap-2 text-sm">
                  <input v-model="form.enabled" type="checkbox" class="rounded" />
                  Enabled (scheduled and able to authenticate users)
                </label>
                <label class="flex items-center gap-2 text-sm">
                  <input v-model="form.sync_groups" type="checkbox" class="rounded" />
                  Sync group membership
                </label>
              </div>
            </div>

            <p v-if="formErr" class="field-error">{{ formErr }}</p>

            <div class="flex justify-end gap-2 pt-1">
              <UiButton type="button" variant="ghost" size="sm" :disabled="saving" @click="showModal = false">
                Cancel
              </UiButton>
              <UiButton type="submit" size="sm" :disabled="saving">
                {{ saving ? "Saving…" : editing ? "Save changes" : "Create source" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>
  </div>
</template>

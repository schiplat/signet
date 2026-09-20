import type { DirectorySourceKind, MappingRow } from "./api";

/**
 * Where a value can come from.
 *
 * `leaf` values are picked from inside one entry (a JSON leaf, or an LDAP
 * attribute name), `array` must be an array (the users list), and `none` is typed
 * by hand because the sample has nothing to offer — `base_dn` is a DN, not a
 * field of an entry.
 */
export type PickSource = "leaf" | "array" | "none";

/**
 * One input inside a mapping row.
 *
 * Some rows are a single value ("email attribute") while others are a small set
 * (LDAP works out groups from a base DN, a member attribute and a name
 * attribute). Modelling the row as a list of fields rather than one key per kind
 * is what lets both shapes sit in the same table.
 */
export type MappingField = {
  /** The `config` key this input writes. */
  key: string;
  /** Shown before the input; omitted for single-field rows. */
  label?: string;
  /** Checked client-side for emptiness only — the server owns the real rules. */
  required: boolean;
  pick: PickSource;
  /**
   * `list` is a set of values the admin types rather than picks: a domain or a
   * department has no counterpart in a sample of entries, so there is nothing to
   * offer. Kept in the form as one comma- or newline-separated string and split
   * into the array the server expects on the way out.
   */
  shape?: "list";
};

/**
 * One row of the mapping table.
 *
 * The six questions a directory source has to answer are the same regardless of
 * how it answers them, so the rows live here once and each kind supplies the
 * fields. Adding a pull connector should mean adding entries to this table, not
 * writing another form.
 */
export type MappingDefinition = {
  row: MappingRow;
  label: string;
  hint: string;
  /** `scope` selects the entries; every other row reads one entry. */
  group: "scope" | "entry";
  /** `undefined` means the kind does not offer this row at all. */
  fields: Partial<Record<DirectorySourceKind, MappingField[]>>;
};

export const MAPPING_DEFINITIONS: MappingDefinition[] = [
  {
    row: "scope",
    label: "Which entries are users",
    hint:
      "What this source owns. An entry outside the scope is not synced — and a user who " +
      "leaves the scope is disabled, exactly as if the directory had deleted them.",
    group: "scope",
    fields: {
      ldap: [
        { key: "base_dn", label: "Base DN", required: true, pick: "none" },
        { key: "user_filter", label: "Filter", required: true, pick: "none" },
        {
          key: "email_domains",
          label: "Email domains",
          required: false,
          pick: "none",
          shape: "list",
        },
        { key: "department_attribute", label: "Department attribute", required: false, pick: "leaf" },
        {
          key: "department_values",
          label: "Departments",
          required: false,
          pick: "none",
          shape: "list",
        },
      ],
      http_json: [
        { key: "users_path", label: "Users path", required: true, pick: "array" },
        {
          key: "email_domains",
          label: "Email domains",
          required: false,
          pick: "none",
          shape: "list",
        },
        { key: "department_path", label: "Department path", required: false, pick: "leaf" },
        {
          key: "department_values",
          label: "Departments",
          required: false,
          pick: "none",
          shape: "list",
        },
      ],
    },
  },
  {
    row: "external_id",
    label: "External ID",
    hint: "Stable per-entry identifier. Changing it makes every user look new.",
    group: "entry",
    fields: {
      ldap: [{ key: "external_id_attribute", required: true, pick: "leaf" }],
      http_json: [{ key: "external_id_path", required: true, pick: "leaf" }],
    },
  },
  {
    row: "email",
    label: "Email",
    hint: "Required: an entry without one is skipped by the sync.",
    group: "entry",
    fields: {
      ldap: [{ key: "email_attribute", required: true, pick: "leaf" }],
      http_json: [{ key: "email_path", required: true, pick: "leaf" }],
    },
  },
  {
    row: "username",
    label: "Username",
    hint: "Login name. Falls back to the email when unset.",
    group: "entry",
    fields: {
      ldap: [{ key: "username_attribute", required: true, pick: "leaf" }],
      http_json: [{ key: "username_path", required: false, pick: "leaf" }],
    },
  },
  {
    row: "display_name",
    label: "Display name",
    hint: "Falls back to the email local part when empty.",
    group: "entry",
    fields: {
      ldap: [{ key: "display_name_attribute", required: false, pick: "leaf" }],
      http_json: [{ key: "display_name_path", required: false, pick: "leaf" }],
    },
  },
  {
    row: "groups",
    label: "Groups",
    hint: "Only written when Sync group membership is on for this source.",
    group: "entry",
    fields: {
      ldap: [
        { key: "group_base_dn", label: "Group base DN", required: false, pick: "none" },
        { key: "group_filter", label: "Filter", required: false, pick: "none" },
        { key: "group_member_attribute", label: "Member attribute", required: false, pick: "leaf" },
        { key: "group_name_attribute", label: "Name attribute", required: false, pick: "leaf" },
      ],
      http_json: [{ key: "groups_path", required: false, pick: "leaf" }],
    },
  },
];

/** The rows offered for a kind, scope first. */
export function mappingRows(kind: DirectorySourceKind): MappingDefinition[] {
  return MAPPING_DEFINITIONS.filter((d) => d.fields[kind] !== undefined);
}

/** Every `config` key the mapping table owns for a kind. */
export function mappingKeys(kind: DirectorySourceKind): string[] {
  return mappingRows(kind).flatMap((d) => (d.fields[kind] ?? []).map((f) => f.key));
}

/** The mapping keys that hold a set of values rather than one. */
export function listKeys(kind: DirectorySourceKind): string[] {
  return mappingRows(kind).flatMap((d) =>
    (d.fields[kind] ?? []).filter((f) => f.shape === "list").map((f) => f.key),
  );
}

/**
 * Splits what an admin typed into the array the server expects.
 *
 * Commas and newlines both separate, and blanks are dropped: a trailing comma or
 * an empty line is a typo, not an empty domain. Dropping it matters — an empty
 * entry would be a scope value that can never match, and the server refuses those
 * outright.
 */
export function splitList(value: unknown): string[] {
  return String(value ?? "")
    .split(/[\n,]/)
    .map((part) => part.trim())
    .filter((part) => part !== "");
}

/**
 * Renders a stored list back into the single string the form holds.
 *
 * The inverse of `splitList`, so opening a source and saving it again without
 * touching the scope cannot change it.
 */
export function joinList(value: unknown): string {
  if (Array.isArray(value)) return value.map((part) => String(part)).join(", ");
  return typeof value === "string" ? value : "";
}

/**
 * The form values as config values, with the list inputs split.
 *
 * Used for both the preview payload and the save payload, so the check an admin
 * runs and the config that gets stored cannot disagree about what the list means.
 */
export function withListValues(
  kind: DirectorySourceKind,
  values: Record<string, unknown>,
): Record<string, unknown> {
  const out = { ...values };
  for (const key of listKeys(kind)) out[key] = splitList(values[key]);
  return out;
}

/**
 * Which row a `config` key belongs to.
 *
 * Used to hang the server's per-row verdict next to the input that caused it,
 * which is the whole reason the preview reports row ids rather than messages.
 */
export function rowForKey(kind: DirectorySourceKind, key: string): MappingRow | null {
  for (const def of mappingRows(kind)) {
    if ((def.fields[kind] ?? []).some((f) => f.key === key)) return def.row;
  }
  return null;
}

/** Placeholder text for one input, so an empty box still shows the shape. */
export function placeholderFor(kind: DirectorySourceKind, key: string): string {
  const byKind: Record<string, Record<string, string>> = {
    ldap: {
      base_dn: "ou=people,dc=corp,dc=example",
      user_filter: "(&(objectClass=person)(mail=*))",
      external_id_attribute: "entryUUID",
      email_attribute: "mail",
      username_attribute: "uid",
      display_name_attribute: "displayName",
      group_base_dn: "ou=groups,dc=corp,dc=example",
      group_filter: "(objectClass=groupOfNames)",
      group_member_attribute: "member",
      group_name_attribute: "cn",
      email_domains: "corp.example, partner.example",
      department_attribute: "department",
      department_values: "Engineering, Platform",
    },
    http_json: {
      users_path: "data.users",
      external_id_path: "id",
      email_path: "email",
      username_path: "login",
      display_name_path: "profile.name",
      groups_path: "groups",
      email_domains: "corp.example, partner.example",
      department_path: "dept",
      department_values: "Engineering, Platform",
    },
  };
  return byKind[kind]?.[key] ?? "";
}

/** Reads one mapping value as the trimmed string a form field holds. */
function read(values: Record<string, unknown>, key: string): string {
  const value = values[key];
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Whether a row has been answered.
 *
 * Counted from its `required` fields only. A row whose fields are all optional
 * (display name, groups) is answered as soon as any of them is set — reporting
 * it as unfinished while it is deliberately empty would nag about a decision the
 * admin has already made.
 */
export function isRowMapped(
  kind: DirectorySourceKind,
  row: MappingRow,
  values: Record<string, unknown>,
): boolean {
  const def = mappingRows(kind).find((d) => d.row === row);
  const fields = (def?.fields[kind] ?? []) as MappingField[];
  const required = fields.filter((f) => f.required);
  if (required.length) return required.every((f) => read(values, f.key) !== "");
  return fields.some((f) => read(values, f.key) !== "");
}

/**
 * How many rows are answered, for the progress line.
 *
 * Exists so the count and the per-row rendering cannot disagree: both call
 * `isRowMapped`.
 */
export function mappedProgress(
  kind: DirectorySourceKind,
  values: Record<string, unknown>,
): { mapped: number; total: number } {
  const rows = mappingRows(kind);
  return {
    mapped: rows.filter((def) => isRowMapped(kind, def.row, values)).length,
    total: rows.length,
  };
}

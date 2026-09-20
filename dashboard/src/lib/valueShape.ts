/**
 * Reading what a source field *is*.
 *
 * The picker shows a target field ("Email") on one side and a list of source
 * fields ("mail", "profile.name", "id") on the other. A path and one example
 * value are not enough to choose between them from a user's point of view —
 * `profile.name` and `login` are just names until something says "this one is a
 * person's name" and "this one is a login". That is what a shape is.
 *
 * Two sources of evidence, in order of trust:
 *
 * 1. **The name** (`mail`, `entryUUID`, `displayName`). Directories are named by
 *    convention, and the conventions are strong enough to be worth encoding.
 *    This matters most for LDAP, where `uid` and `sn` give the value itself
 *    almost nothing to go on.
 * 2. **The value** (an `@`, a UUID, a DN, a date). Used when the name says
 *    nothing, so an unconventionally named field still reads as *something*
 *    rather than as a blank "Text".
 *
 * A shape is a *hint for ranking and labelling*, never a verdict: nothing here
 * is used to accept or reject a mapping. That stays with the server preview,
 * which is the only thing that knows what a run would actually write.
 */
export type ValueShape =
  | "email"
  | "username"
  | "id"
  | "dn"
  | "name"
  | "url"
  | "date"
  | "list"
  | "flag"
  | "number"
  | "text";

export const SHAPE_LABEL: Record<ValueShape, string> = {
  email: "Email",
  username: "Username",
  id: "ID",
  dn: "DN",
  name: "Name",
  url: "URL",
  date: "Date",
  list: "List",
  flag: "Flag",
  number: "Number",
  text: "Text",
};

/**
 * Field names that conventionally mean a given shape.
 *
 * Deliberately a closed list: an open-ended heuristic ("contains `id`") would
 * label `identity_provider` as an ID and `valid_from` as a flag, which is worse
 * than labelling them `Text`. Names are normalized before lookup, so
 * `display_name`, `displayName` and `display-name` are one entry.
 *
 * `text` is absent by design — a name that matches nothing gets `Text` from the
 * value heuristic, and `Text` is never ranked as likely for any target.
 */
const NAMES: Record<Exclude<ValueShape, "text">, string[]> = {
  email: ["mail", "email", "emailaddress", "mailaddress", "primaryemail"],
  username: [
    "uid",
    "username",
    "login",
    "loginname",
    "accountname",
    "samaccountname",
    "userprincipalname",
    "upn",
    "account",
  ],
  id: [
    "id",
    "uuid",
    "guid",
    "objectguid",
    "objectid",
    "entryuuid",
    "entryid",
    "externalid",
    "employeeid",
    "employeeNumber",
    "staffid",
    "userid",
    "accountid",
    "identifier",
    "oid",
  ],
  dn: ["dn", "distinguishedname", "entrydn", "member", "uniquemember", "manager", "owner"],
  name: [
    "name",
    "displayname",
    "fullname",
    "commonname",
    "cn",
    "givenname",
    "sn",
    "surname",
    "firstname",
    "lastname",
    "nickname",
    "preferredname",
    "title",
  ],
  list: ["groups", "group", "roles", "role", "memberof", "members", "teams", "entitlements"],
  url: ["url", "uri", "link", "href", "avatar", "picture", "photo", "image"],
  date: [
    "createdat",
    "updatedat",
    "created",
    "modified",
    "whencreated",
    "whenchanged",
    "lastlogin",
    "hiredate",
  ],
  flag: ["active", "enabled", "disabled", "locked", "suspended", "verified", "deleted"],
  number: ["count", "size", "age", "order", "level", "priority", "quota"],
};

/** The lookup key for a field name: case- and separator-insensitive. */
const normalize = (name: string) => name.toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * The last segment of a path, so a JSON field is judged by its own name rather
 * than by its parent's: `profile.name` is a name, `data.users` is a list of
 * users.
 */
function lastSegment(path: string): string {
  const withoutIndex = path.replace(/\[\d+\]$/, "");
  const segment = withoutIndex.split(".").pop() ?? withoutIndex;
  return segment.replace(/^\[["']?/, "").replace(/["']?\]$/, "");
}

/** The shape a field name conventionally implies, or `null` if it says nothing. */
export function shapeFromName(name: string): ValueShape | null {
  const key = normalize(lastSegment(name));
  if (!key) return null;
  for (const [shape, names] of Object.entries(NAMES)) {
    if (names.some((candidate) => normalize(candidate) === key)) {
      return shape as ValueShape;
    }
  }
  return null;
}

const EMAIL = /^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** AD stores `objectGUID` as raw bytes; rendered as hex it can be 16/20/32 bytes. */
const HEX_ID = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
const DN = /^[A-Za-z][\w-]*=[^,]*(?:,[A-Za-z][\w-]*=)/;
const DATE = /^\d{4}-\d{2}-\d{2}([T ]|$)/;

/** The shape a value implies on its own. */
function shapeFromValue(value: string): ValueShape {
  const trimmed = value.trim();
  if (!trimmed) return "text";
  if (EMAIL.test(trimmed)) return "email";
  if (/^https?:\/\//i.test(trimmed)) return "url";
  if (UUID.test(trimmed) || HEX_ID.test(trimmed)) return "id";
  if (DATE.test(trimmed)) return "date";
  if (DN.test(trimmed)) return "dn";
  return "text";
}

/**
 * The shape of one source field, from its value and (when available) its name.
 *
 * Arrays, booleans and numbers are decided by the value alone — a JSON `members`
 * array is a list however it is named, and an LDAP attribute is always a string
 * so it never lands here.
 */
export function shapeOf(value: unknown, name?: string): ValueShape {
  if (Array.isArray(value)) return "list";
  if (typeof value === "boolean") return "flag";
  if (typeof value === "number") return "number";
  if (typeof value !== "string" || !value.trim()) {
    // No value to read: fall back to the name, which is all there is.
    return (name && shapeFromName(name)) || "text";
  }
  const byName = name ? shapeFromName(name) : null;
  // A name can say "list" while the value is a single string (`groups:
  // "engineering"`). The value wins there: showing `List` next to a scalar would
  // be a lie about the data, and `users_path` is the one target where being wrong
  // about it disables users.
  if (byName && byName !== "list") return byName;
  return shapeFromValue(value);
}

/**
 * The shapes a target field is expected to be filled from, used to rank
 * candidates so the likely answer is first and visibly marked.
 *
 * Kept narrow on purpose. Listing `text` for `username` would make almost every
 * candidate "likely" and the ranking worthless, so a target only claims the
 * shapes that really do mean it: a login-shaped name or an email for a username,
 * never a generic string.
 */
export const EXPECTED_SHAPES: Record<string, ValueShape[]> = {
  // http_json
  users_path: ["list"],
  external_id_path: ["id", "dn"],
  email_path: ["email"],
  username_path: ["username", "email"],
  display_name_path: ["name"],
  groups_path: ["list"],
  // ldap
  external_id_attribute: ["id", "dn"],
  email_attribute: ["email"],
  username_attribute: ["username", "email"],
  display_name_attribute: ["name"],
  group_member_attribute: ["dn"],
  group_name_attribute: ["name"],
};

/** Whether a candidate is a likely answer for this config key. */
export function isLikely(key: string, shape: ValueShape): boolean {
  return EXPECTED_SHAPES[key]?.includes(shape) ?? false;
}

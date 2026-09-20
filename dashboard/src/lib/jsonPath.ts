/**
 * Client-side helpers for reading a pasted JSON sample.
 *
 * These stay deliberately thin: they enumerate paths and render values. They
 * never *interpret* a mapping — resolving a path to a value, normalizing an email
 * and deciding whether an entry is usable are the server's job
 * (`directory::mapping`). A second implementation of those rules would
 * eventually disagree with the sync, and be believed.
 *
 * The job here is narrower and purely presentational: turn the sample into
 * labelled *choices*, so mapping a field is picking a value you can see rather
 * than typing a path from memory.
 */

export type JsonKind = "object" | "array" | "string" | "number" | "boolean" | "null";

import { shapeOf, type ValueShape } from "./valueShape";

export function kindOf(value: unknown): JsonKind {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return "array";
  switch (typeof value) {
    case "object":
      return "object";
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    default:
      return "string";
  }
}

/** Appends a segment to a path, quoting keys that are not plain identifiers. */
export function joinPath(base: string, key: string): string {
  const plain = /^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
  const segment = plain ? key : `["${key.replace(/"/g, '\\"')}"]`;
  if (!base) return segment;
  // A bracketed segment follows the previous one directly: `data["a.b"]`, not
  // `data.["a.b"]`.
  return segment.startsWith("[") ? `${base}${segment}` : `${base}.${segment}`;
}

/**
 * Resolves a dotted path against a document.
 *
 * A display-side mirror of the server's `http_json::lookup`, used only to render
 * the sample. It never decides whether a mapping is *correct* — that verdict
 * comes from the preview endpoint — so a syntax the client cannot handle shows up
 * as "cannot display", not as a mapping error.
 */
export function resolvePath(document: unknown, path: string): unknown {
  let current: unknown = document;
  for (const segment of splitPath(path)) {
    if (segment.index !== null) {
      if (!Array.isArray(current)) return undefined;
      current = current[segment.index];
      continue;
    }
    if (kindOf(current) !== "object") return undefined;
    current = (current as Record<string, unknown>)[segment.key];
  }
  return current;
}

type Segment = { key: string; index: number | null };

function splitPath(path: string): Segment[] {
  const segments: Segment[] = [];
  let buffer = "";
  let index = 0;
  let inBracket = false;
  let quote: string | null = null;

  const pushKey = () => {
    if (buffer) segments.push({ key: buffer, index: null });
    buffer = "";
  };

  while (index < path.length) {
    const char = path[index];
    if (quote) {
      if (char === "\\" && index + 1 < path.length) {
        buffer += path[index + 1];
        index += 2;
        continue;
      }
      if (char === quote) {
        quote = null;
        index += 1;
        continue;
      }
      buffer += char;
      index += 1;
      continue;
    }
    if (char === "." && !inBracket) {
      pushKey();
      index += 1;
      continue;
    }
    if (char === "[") {
      pushKey();
      inBracket = true;
      index += 1;
      continue;
    }
    if (char === "]") {
      inBracket = false;
      const asIndex = /^\d+$/.test(buffer) ? Number(buffer) : null;
      if (asIndex === null && buffer) segments.push({ key: buffer, index: null });
      else if (asIndex !== null) segments.push({ key: "", index: asIndex });
      buffer = "";
      index += 1;
      continue;
    }
    if ((char === '"' || char === "'") && inBracket) {
      quote = char;
      index += 1;
      continue;
    }
    buffer += char;
    index += 1;
  }
  pushKey();
  return segments;
}

/**
 * One selectable value: the config string, plus what the sample shows for it.
 *
 * `detail` is what makes the choice obvious — the whole point of reading the
 * sample is to pick by recognition, so every option carries a real value from it
 * rather than being a bare path.
 */
export type MappingOption = {
  value: string;
  /** The sample value (or a structural summary), shown next to the path. */
  detail?: string;
  /** Extra qualification, e.g. "2/3 entries". */
  note?: string;
  /** The option exists but is worth a second look (present in few entries). */
  partial?: boolean;
  /** What the field appears to hold, used to rank it against the target. */
  shape?: ValueShape;
};

/**
 * Every array in the document, with its length.
 *
 * The users path has to be an array, so offering only arrays makes the one
 * destructive misconfiguration — pointing it at an object, which reads as "the
 * directory is empty" and disables every user the source manages — impossible to
 * express rather than merely warned about.
 */
export function arrayPaths(document: unknown, limit = 40): MappingOption[] {
  const out: MappingOption[] = [];
  const walk = (value: unknown, path: string) => {
    if (out.length >= limit) return;
    const kind = kindOf(value);
    if (kind === "array") {
      out.push({
        value: path,
        detail: `${(value as unknown[]).length} item${(value as unknown[]).length === 1 ? "" : "s"}`,
        shape: "list",
      });
      // Nested arrays inside array elements are not useful as a users path.
      return;
    }
    if (kind === "object") {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        walk(child, joinPath(path, key));
      }
    }
  };
  walk(document, "");
  return out;
}

/**
 * How many of the sampled entries carry each entry-relative path.
 *
 * The signal that distinguishes a field every entry has from one a quarter of
 * them has — invisible when only the first entry is shown, and exactly how
 * someone ends up mapping a display name that resolves for nobody else.
 */
export function entryCounts(entries: unknown[], limit = 50): { counts: Record<string, number>; total: number } {
  const sample = entries.slice(0, limit).filter((entry) => kindOf(entry) === "object");
  const counts: Record<string, number> = {};
  for (const entry of sample) {
    const seen = new Set<string>();
    const walk = (value: unknown, path: string) => {
      if (path) seen.add(path);
      const kind = kindOf(value);
      if (kind === "object") {
        for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
          walk(child, joinPath(path, key));
        }
      }
    };
    walk(entry, "");
    for (const path of seen) counts[path] = (counts[path] ?? 0) + 1;
  }
  return { counts, total: sample.length };
}

/**
 * Selectable paths *inside* one entry, with the sample value each holds.
 *
 * Paths are relative to the entry by construction (`id`, `profile.name`), never
 * absolute (`data.users[0].id`): the absolute form is right only for the first
 * user of the first page, so offering it would produce a mapping that breaks on
 * the next page.
 */
export function entryOptions(entry: unknown, counts: Record<string, number>, total: number): MappingOption[] {
  const out: MappingOption[] = [];
  const walk = (value: unknown, path: string) => {
    const kind = kindOf(value);
    if (kind === "object") {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        walk(child, joinPath(path, key));
      }
      return;
    }
    if (!path) return;
    const seen = counts[path];
    const partial = seen !== undefined && total > 0 && seen < total;
    out.push({
      value: path,
      detail: kind === "array" ? `${(value as unknown[]).length} items` : preview(value),
      note: partial ? `${seen}/${total} entries` : undefined,
      partial,
      shape: shapeOf(value, path),
    });
  };
  walk(entry, "");
  return out;
}

/** Renders a scalar for display, truncating long values. */
export function preview(value: unknown, max = 48): string {
  if (value === null || value === undefined) return "null";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** Parses a pasted document, returning a message on failure rather than throwing. */
export function parseSample(
  text: string,
): { value: unknown; error: null } | { value: null; error: string } {
  const trimmed = text.trim();
  if (!trimmed) return { value: null, error: "Nothing pasted yet." };
  try {
    return { value: JSON.parse(trimmed), error: null };
  } catch (e) {
    return { value: null, error: e instanceof Error ? e.message : "Not valid JSON." };
  }
}

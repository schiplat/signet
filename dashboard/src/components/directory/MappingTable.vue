<script setup lang="ts">
// The mapping form: one row per Signet field, each expanding in place to a
// candidate list.
//
// A row has three parts, and the first two are always on screen — including
// while a picker is open, which is the point:
//
//   target + verdict   what this row fills, and whether the last check passed
//   purpose            what it is for, in one line
//   control            the choice, or the button that opens the picker
//
// Rows with several inputs (LDAP groups needs a base DN, a member attribute, a
// name attribute) render them as indented sub-rows, so the six Signet fields
// stay countable at a glance.
import { computed, ref, useId } from "vue";
import type { DirectorySourceKind, MappingPreviewField, MappingRow } from "../../lib/api";
import type { MappingField } from "../../lib/directoryMapping";
import { mappingRows, placeholderFor } from "../../lib/directoryMapping";
import type { MappingOption } from "../../lib/jsonPath";
import FieldPicker from "./FieldPicker.vue";

const props = defineProps<{
  kind: DirectorySourceKind;
  /** The mapping keys being edited; `v-model`. */
  modelValue: Record<string, unknown>;
  /** Per-row verdicts from the last preview, keyed by row id. */
  verdicts: Map<MappingRow, MappingPreviewField>;
  /** Selectable values per input key, built from the sample. */
  options: Record<string, MappingOption[]>;
  /** True while the preview is in flight. */
  busy?: boolean;
}>();
const emit = defineEmits<{
  "update:modelValue": [value: Record<string, unknown>];
  changed: [];
}>();

interface Row {
  row: MappingRow;
  label: string;
  hint: string;
  fields: MappingField[];
}

const rows = computed<Row[]>(() =>
  mappingRows(props.kind).map((def) => ({
    row: def.row,
    label: def.label,
    hint: def.hint,
    fields: (def.fields[props.kind] ?? []) as MappingField[],
  })),
);

/** The input whose picker is open. One at a time, so context is never ambiguous. */
const openField = ref<string | null>(null);
/** The row that just changed, for the confirmation flash. */
const justAssigned = ref<string | null>(null);

const uid = useId();
const labelId = (row: MappingRow) => `row-${uid}-${row}-label`;

function valueOf(key: string): string {
  const value = props.modelValue[key];
  return typeof value === "string" ? value : "";
}

function setValue(key: string, value: string) {
  emit("update:modelValue", { ...props.modelValue, [key]: value });
  emit("changed");
}

function open(key: string) {
  openField.value = key;
}

function close() {
  openField.value = null;
}

/**
 * Applies a choice, then closes the picker.
 *
 * The row's own state changes here, synchronously, before any request: it flips
 * to mapped and shows the value the choice resolved to. That immediate change is
 * the acknowledgement — waiting for the preview means waiting on a debounce plus
 * a round trip, during which the click appears to have done nothing.
 */
function assign(key: string, value: string) {
  setValue(key, value);
  close();
  justAssigned.value = key;
  window.setTimeout(() => {
    if (justAssigned.value === key) justAssigned.value = null;
  }, 1000);
}

const verdictOf = (row: MappingRow): MappingPreviewField | null => props.verdicts.get(row) ?? null;

/** What the sample holds for a value, so a choice can be checked by reading. */
function proof(key: string): MappingOption | undefined {
  const current = valueOf(key);
  if (!current) return undefined;
  return props.options[key]?.find((o) => o.value === current);
}

/**
 * Values already assigned elsewhere, so the same source field is not silently
 * wired to two targets.
 *
 * Flagged, not blocked: one source field legitimately can fill two targets — an
 * email address is commonly both the email and the username.
 */
function usedBy(key: string): Record<string, string> {
  const current = valueOf(key);
  const out: Record<string, string> = {};
  for (const row of rows.value) {
    for (const field of row.fields) {
      if (field.key === key) continue;
      const value = valueOf(field.key);
      if (value && value !== current) out[value] = row.label;
    }
  }
  return out;
}

function verdictLabel(field: MappingPreviewField | null): string | null {
  if (!field) return null;
  if (!field.ok) return "needs attention";
  if (field.total) return `${field.resolved}/${field.total} entries`;
  return "checked";
}

const noun = computed(() => (props.kind === "ldap" ? "attributes" : "fields"));
</script>

<template>
  <div class="divide-y divide-border/60 rounded-xl border border-border">
    <div
      v-for="row in rows"
      :key="row.row"
      class="px-3 py-2.5 motion-safe:transition-colors motion-safe:duration-500"
      :class="justAssigned && row.fields.some((f) => f.key === justAssigned)
        ? 'bg-emerald-500/5 ring-1 ring-emerald-500/30'
        : ''"
    >
      <header class="flex items-baseline gap-2">
        <span :id="labelId(row.row)" class="text-xs font-medium text-foreground">
          {{ row.label }}
        </span>
        <span class="flex-1" />
        <span
          v-if="verdictOf(row.row)"
          class="shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-semibold"
          :class="
            verdictOf(row.row)!.ok
              ? 'bg-emerald-500/10 text-emerald-600'
              : 'bg-destructive/10 text-destructive'
          "
        >
          {{ verdictLabel(verdictOf(row.row)) }}
        </span>
      </header>

      <!-- Always visible, including while a picker is open: it is the answer to
           "what is this field for?". It used to be replaced by the proof line as
           soon as a value was chosen, which lost the explanation exactly when the
           user was deciding. -->
      <p class="mt-0.5 text-[11px] text-muted-foreground/80">{{ row.hint }}</p>

      <div class="mt-2 space-y-1.5">
        <div v-for="field in row.fields" :key="field.key">
          <label v-if="field.label" class="type-label mb-1 block text-[10px]">
            {{ field.label }}
          </label>

          <!-- A set, typed by hand: a domain or a department has no counterpart
               in a sample of entries, so a picker would offer nothing. Commas or
               newlines separate, and the split happens on the way out. -->
          <textarea
            v-if="field.shape === 'list'"
            :value="valueOf(field.key)"
            :disabled="busy"
            :placeholder="placeholderFor(kind, field.key)"
            rows="2"
            spellcheck="false"
            autocomplete="off"
            class="field-input resize-y px-2.5 py-1.5 font-mono text-xs"
            @input="setValue(field.key, ($event.target as HTMLTextAreaElement).value)"
          />

          <!-- Typed by hand. A base DN and a filter are not fields of an entry, so
               a picker would offer nothing and only add a step. -->
          <input
            v-else-if="field.pick === 'none'"
            :value="valueOf(field.key)"
            :disabled="busy"
            :placeholder="placeholderFor(kind, field.key)"
            spellcheck="false"
            autocomplete="off"
            class="field-input h-9 px-2.5 font-mono text-xs"
            @input="setValue(field.key, ($event.target as HTMLInputElement).value)"
          />

          <template v-else>
            <!-- Mapped: the choice reads back as a value, with a way to change it. -->
            <div v-if="valueOf(field.key)" class="flex items-center gap-2">
              <div
                class="flex h-9 min-w-0 flex-1 items-center rounded-lg border border-border bg-card px-2.5"
              >
                <span class="min-w-0 truncate font-mono text-xs text-foreground">
                  {{ valueOf(field.key) }}
                </span>
              </div>
              <button
                type="button"
                class="shrink-0 rounded-lg border border-border px-2 py-1 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground"
                :disabled="busy"
                @click="open(field.key)"
              >
                Change
              </button>
              <button
                type="button"
                class="shrink-0 px-1 text-muted-foreground hover:text-destructive"
                aria-label="Clear"
                :disabled="busy"
                @click="setValue(field.key, '')"
              >
                ×
              </button>
            </div>

            <!-- Unmapped: a button, not an empty input. An empty input looks like it
                 wants typing, which is the wrong action here. -->
            <button
              v-else
              type="button"
              class="flex h-9 w-full items-center rounded-lg border border-dashed border-border bg-card/50 px-2.5 text-left text-xs text-muted-foreground hover:border-foreground/30 hover:bg-card"
              :disabled="busy"
              :aria-expanded="openField === field.key"
              @click="open(field.key)"
            >
              Choose the field…
            </button>

            <FieldPicker
              v-if="openField === field.key"
              :target="field.label ?? row.label"
              :config-key="field.key"
              :options="options[field.key] ?? []"
              :model-value="valueOf(field.key)"
              :used-by="usedBy(field.key)"
              :noun="noun"
              :labelled-by="labelId(row.row)"
              :empty-hint="`Paste a sample on the left to see the source's ${noun}.`"
              @pick="assign(field.key, $event)"
              @close="close"
            />

            <!-- The proof line: one real value from the sample for the choice. -->
            <p
              v-else-if="proof(field.key)"
              class="mt-1 truncate text-[11px] text-muted-foreground"
            >
              <span class="font-mono">{{ proof(field.key)!.detail }}</span>
              <span v-if="proof(field.key)!.note" class="text-amber-700">
                · {{ proof(field.key)!.note }}
              </span>
            </p>
          </template>
        </div>
      </div>

      <p v-if="verdictOf(row.row)?.error" class="field-error mt-1.5 text-[11px]">
        {{ verdictOf(row.row)!.error }}
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
// The mapping workspace: the sample on the left, the fields it fills in and the
// result on the right.
//
// The sample is *reference material*, so it is pinned: while the right column
// scrolls through six rows the paste stays put. The previous single-column stack
// put the paste above the rows and both above the result, so filling row five
// meant scrolling away from the thing being read.
//
// The sample is read-only in the UI: every value is picked from a dropdown, so
// there is one way to fill a field and no hidden "what am I assigning to?" state.
import { computed, ref, watch } from "vue";
import { ChevronDown } from "@lucide/vue";
import type { DirectorySourceKind, MappingPreview, MappingPreviewField, MappingRow } from "../../lib/api";
import { previewDirectoryMapping } from "../../lib/api";
import { arrayPaths, entryCounts, entryOptions, parseSample, resolvePath, preview } from "../../lib/jsonPath";
import type { MappingOption } from "../../lib/jsonPath";
import { mappedProgress, mappingRows } from "../../lib/directoryMapping";
import { SHAPE_LABEL, shapeOf, type ValueShape } from "../../lib/valueShape";
import MappingTable from "./MappingTable.vue";

const props = defineProps<{
  kind: DirectorySourceKind;
  /** The mapping keys being edited; `v-model`. */
  modelValue: Record<string, unknown>;
  /**
   * The live config the preview runs against, including the connection keys, so
   * the payload has the shape a save would carry. The endpoint reads only the
   * mapping keys — the connection keys ride along unused, because the preview
   * never opens a connection to the source.
   */
  config: Record<string, unknown>;
  syncGroups: boolean;
}>();
const emit = defineEmits<{ "update:modelValue": [value: Record<string, unknown>] }>();

const sample = ref("");
const busy = ref(false);
const failure = ref("");
const result = ref<MappingPreview | null>(null);

/** The pasted document, parsed locally purely to render the reference list. */
const parsed = computed(() => {
  if (props.kind !== "http_json" || !sample.value.trim()) return null;
  return parseSample(sample.value);
});
const document = computed(() => (parsed.value?.error === null ? parsed.value?.value : null));

const usersPath = computed(() => {
  const value = props.modelValue["users_path"];
  return typeof value === "string" ? value.trim() : "";
});

const entries = computed<unknown[]>(() => {
  if (!document.value || !usersPath.value) return [];
  const found = resolvePath(document.value, usersPath.value);
  return Array.isArray(found) ? found : [];
});

const counts = computed(() => entryCounts(entries.value));

/**
 * The choices offered per input key.
 *
 * JSON options come from the document the admin just pasted: the users path gets
 * every array in it, every other field gets the leaves of the first entry.
 * LDAP options come from the server, which parses the LDIF with the same code a
 * sync uses, so the attribute list cannot disagree with what a run would read.
 *
 * Inputs declared `pick: "none"` get no list at all: a base DN is not a field of
 * an entry, and offering entry fields for it would be noise.
 */
const options = computed<Record<string, MappingOption[]>>(() => {
  const out: Record<string, MappingOption[]> = {};
  const pickable = mappingRows(props.kind).flatMap((def) =>
    (def.fields[props.kind] ?? []).filter((field) => field.pick !== "none"),
  );
  if (props.kind === "ldap") {
    for (const field of pickable) out[field.key] = ldapOptions.value;
    return out;
  }
  if (!document.value) return out;
  const arrays = arrayPaths(document.value);
  const entry = entries.value[0];
  const leaves =
    entry === undefined ? [] : entryOptions(entry, counts.value.counts, counts.value.total);
  for (const field of pickable) {
    out[field.key] = field.pick === "array" ? arrays : leaves;
  }
  return out;
});

const ldapOptions = computed<MappingOption[]>(() => {
  const total = result.value?.entry_count ?? 0;
  return (result.value?.targets ?? []).map((target) => {
    // Attributes carried by every user entry and ones carried by two thirds of
    // them look identical in a bare list, so the count is what makes the choice
    // informed.
    const userScoped = target.source !== "group";
    const partial = userScoped && total > 0 && target.user_entries < total;
    const note = partial
      ? `${target.user_entries}/${total} entries`
      : target.source === "group"
        ? "groups"
        : target.multi
          ? `${target.count} values`
          : undefined;
    return {
      value: target.key,
      detail: target.sample_value ? `"${preview(target.sample_value)}"` : undefined,
      note,
      partial,
      // The attribute's own name is the main evidence here, which is why a
      // vocabulary of directory conventions matters more for LDAP than for JSON.
      shape: shapeOf(target.sample_value, target.key),
    };
  });
});

const verdicts = computed(() => {
  const map = new Map<MappingRow, MappingPreviewField>();
  for (const field of result.value?.fields ?? []) map.set(field.row, field);
  return map;
});

/**
 * The reference list beside the paste: what the sample actually contains.
 *
 * For LDAP this is the server's parsed attribute list, which appears as soon as
 * the paste parses — no other setting required, which is the point, since the
 * list is what tells an admin what to type in the rows.
 */
interface ReferenceItem {
  key: string;
  detail?: string;
  note?: string;
  partial?: boolean;
  shape?: ValueShape;
}

const reference = computed<ReferenceItem[]>(() => {
  if (props.kind === "ldap") {
    const total = result.value?.entry_count ?? 0;
    return (result.value?.targets ?? []).map((target) => ({
      key: target.key,
      detail: target.sample_value ? `"${preview(target.sample_value)}"` : undefined,
      note:
        target.source === "group"
          ? "groups"
          : target.user_entries < total
            ? `${target.user_entries}/${total}`
            : undefined,
      partial: target.source !== "group" && total > 0 && target.user_entries < total,
      shape: shapeOf(target.sample_value, target.key),
    }));
  }
  const entry = entries.value[0];
  if (entry === undefined) return [];
  return entryOptions(entry, counts.value.counts, counts.value.total).map((option) => ({
    key: option.value,
    detail: option.detail,
    note: option.note,
    partial: option.partial,
    shape: option.shape,
  }));
});

const hasSample = computed(() => sample.value.trim().length > 0);

/** How many rows are answered, and which ones the last check flagged. */
const progress = computed(() => mappedProgress(props.kind, props.modelValue));
const attention = computed(() =>
  (result.value?.fields ?? []).filter((field) => !field.ok).map((field) => field.row),
);

/** The reference list is evidence, not the working surface; it can be folded. */
const referenceOpen = ref(true);

/**
 * Which page of the normalized row table to show, counted in source entries.
 *
 * Sent to the endpoint rather than sliced here: a paste can hold tens of
 * thousands of entries, and the whole point is not to move them all across the
 * wire just to render 25. Reset whenever the result is recomputed for a reason
 * other than paging (`schedule`), so a page number can never outlive the sample
 * it referred to.
 */
const rowOffset = ref(0);
const samplePlaceholder = computed(() =>
  props.kind === "ldap"
    ? "Paste `ldapsearch -LLL …` output; include group entries to check the Groups row."
    : 'Paste the endpoint\'s response, e.g. {"data":{"users":[ … ]}}',
);

let timer: number | undefined;
function schedule() {
  // Debounced: this also fires while a value is still being typed.
  if (timer !== undefined) window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    // A recomputed result replaces the row set, so page 3 of the old sample means
    // nothing for the new one. Reset here rather than in each watcher: every
    // non-paging reason to re-run funnels through this function.
    rowOffset.value = 0;
    void run();
  }, 400);
}

/**
 * Moves the row table to another page.
 *
 * Only re-runs the endpoint, and deliberately does *not* go through `schedule`:
 * paging changes which rows are returned, never which ones are checked, so the
 * verdicts stay valid and the debounce would only add latency to a button press.
 */
function goToPage(offset: number) {
  rowOffset.value = Math.max(0, offset);
  void run();
}

/**
 * Which slice of the directory the table is showing, e.g. `1–25` of `120`.
 *
 * Measured in *entries*, not rows, and the end is the window edge rather than
 * `rows.length`. A page spans its full width even when fewer rows come back (an
 * entry with no external id yields none), so numbering by row count would label
 * the second page `26–34` while it actually covers entries 26–50 — and would
 * contradict the `page_size` the paging buttons step by.
 */
const rowRange = computed(() => {
  const total = result.value?.entry_count ?? 0;
  const from = (result.value?.offset ?? 0) + 1;
  return { from, to: Math.min(from + pageSize.value - 1, total), total };
});

/**
 * How far to step when paging.
 *
 * Taken from the response rather than from `rows.length`: a page can hold fewer
 * rows than it spans (an entry with no external id produces none), so stepping by
 * the row count would overlap the previous window.
 */
const pageSize = computed(() => result.value?.page_size ?? 0);
const canPageBack = computed(() => (result.value?.offset ?? 0) > 0);
const canPageForward = computed(() => result.value?.truncated ?? false);

async function run() {
  // A sample the client can already see is malformed needs no round trip: the
  // parse error is rendered under the paste box, and the endpoint would answer
  // 400 with the same sentence. Skipping it keeps a half-pasted sample from
  // turning into a server-side warning per debounce tick — 20 of them from one
  // paste, in the log this was found in.
  //
  // Clearing `result` is the point of doing this rather than firing and ignoring
  // the failure: verdicts and resolved counts were computed against the previous
  // sample, and leaving them on screen next to a broken paste claims a check that
  // no longer describes anything.
  //
  // LDAP has no client-side parser, so there the server's message is the only one
  // there is and the request has to go out.
  if (parsed.value?.error) {
    result.value = null;
    failure.value = "";
    return;
  }
  busy.value = true;
  failure.value = "";
  try {
    result.value = await previewDirectoryMapping({
      kind: props.kind,
      // The live values as they stand. A blank key comes back as "not set yet" on
      // its own row rather than failing the whole check, which is what lets this
      // run against a half-filled form.
      config: { ...props.config },
      sample: hasSample.value ? sample.value : undefined,
      sync_groups: props.syncGroups,
      // Which page of the row table to return. The verdicts above it are computed
      // across the whole sample regardless of this.
      offset: rowOffset.value,
    });
  } catch (e) {
    // Not shown as a banner over the whole panel: a preview failure almost always
    // concerns one input, and naming it next to that input is what makes it
    // fixable.
    failure.value = e instanceof Error ? e.message : "The mapping could not be checked.";
    result.value = null;
  } finally {
    busy.value = false;
  }
}

// Re-run on everything that can change the result: the mapping keys and the
// groups toggle. `config` is deliberately not watched on its own — the only keys
// it adds over `modelValue` are connection settings the endpoint ignores, so a
// re-run triggered by them would send an identical response.
watch(() => props.modelValue, schedule, { deep: true });
watch(() => props.syncGroups, schedule);
watch(
  () => props.kind,
  () => {
    result.value = null;
    failure.value = "";
    sample.value = "";
    rowOffset.value = 0;
  },
);
</script>

<template>
  <div class="grid items-start gap-4 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
    <!-- Reference: the source's own data. -->
    <div class="space-y-2 lg:sticky lg:top-0">
      <div class="flex items-baseline justify-between gap-2">
        <label class="type-label text-[10px]">Sample from the source</label>
        <span class="text-[10px] text-muted-foreground">read in memory, never saved</span>
      </div>
      <textarea
        v-model="sample"
        rows="10"
        spellcheck="false"
        :placeholder="samplePlaceholder"
        class="field-input min-h-40 resize-y font-mono text-[11px] leading-4"
        @input="schedule"
      />

      <p v-if="parsed?.error" class="field-error text-[11px]">{{ parsed.error }}</p>
      <p
        v-else-if="kind === 'http_json' && hasSample && usersPath && !entries.length"
        class="field-error text-[11px]"
      >
        `{{ usersPath }}` is not an array in this sample, so there are no entries to preview.
      </p>
      <p v-else-if="!hasSample" class="type-meta text-[11px]">
        Without a sample the fields are only syntax-checked, not checked against real data.
      </p>

      <div v-if="reference.length" class="rounded-xl border border-border">
        <button
          type="button"
          class="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-[10px] text-muted-foreground hover:bg-muted/50"
          :aria-expanded="referenceOpen"
          @click="referenceOpen = !referenceOpen"
        >
          <ChevronDown
            class="h-3 w-3 shrink-0 transition-transform motion-safe:duration-200"
            :class="referenceOpen ? '' : '-rotate-90'"
          />
          <template v-if="kind === 'ldap'">
            {{ reference.length }} attributes in this paste
          </template>
          <template v-else>Fields on the first entry</template>
        </button>
        <template v-if="referenceOpen">
          <ul class="divide-y divide-border/50 border-t border-border/60">
            <li
              v-for="item in reference"
              :key="item.key"
              class="flex items-baseline gap-2 px-2.5 py-1.5 text-[11px]"
            >
              <span class="shrink-0 font-mono text-foreground">{{ item.key }}</span>
              <span
                v-if="item.shape"
                class="shrink-0 rounded px-1 text-[10px] text-muted-foreground/80"
              >
                {{ SHAPE_LABEL[item.shape] }}
              </span>
              <span class="min-w-0 flex-1 truncate font-mono text-muted-foreground">
                {{ item.detail }}
              </span>
              <span
                v-if="item.note"
                class="shrink-0 rounded px-1 text-[10px]"
                :class="
                  item.partial ? 'bg-amber-500/10 text-amber-700' : 'text-muted-foreground/70'
                "
              >
                {{ item.note }}
              </span>
            </li>
          </ul>
          <p
            v-if="kind === 'http_json' && counts.total > 1"
            class="border-t border-border/60 px-2.5 py-1.5 text-[10px] text-muted-foreground"
          >
            Counts are taken across all {{ counts.total }} entries; this list shows the first.
          </p>
        </template>
      </div>
    </div>

    <!-- The form, and what it would produce. -->
    <div class="space-y-3">
      <!-- Progress: answers "what have I done, what is left?" without counting
           rows by eye. -->
      <div class="flex items-baseline gap-2">
        <p class="text-[11px] text-muted-foreground">
          <span class="font-medium text-foreground">{{ progress.mapped }}</span>
          of {{ progress.total }} fields mapped
        </p>
        <span class="flex-1" />
        <p v-if="attention.length" class="text-[11px] text-destructive">
          {{ attention.length }} needs attention
        </p>
      </div>

      <MappingTable
        :kind="kind"
        :model-value="modelValue"
        :verdicts="verdicts"
        :options="options"
        :busy="busy"
        @update:model-value="emit('update:modelValue', $event)"
        @changed="schedule"
      />

      <p v-if="failure" class="field-error text-[11px]">{{ failure }}</p>

      <template v-else-if="result">
        <ul v-if="result.warnings.length" class="space-y-1">
          <li
            v-for="warning in result.warnings"
            :key="warning"
            class="rounded-xl bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-700"
          >
            {{ warning }}
          </li>
        </ul>

        <div v-if="result.rows.length">
          <div class="mb-1.5 flex items-center gap-2">
            <p class="text-[11px] text-muted-foreground">
              <span class="font-medium text-foreground">What would be written</span>
              · {{ result.entry_count }} entr{{ result.entry_count === 1 ? "y" : "ies" }},
              showing {{ rowRange.from }}–{{ rowRange.to }}
            </p>
            <!-- Paging the rows only. The verdicts above already cover every
                 entry, so these buttons move a window over the same conclusion
                 rather than changing it. -->
            <span class="flex-1" />
            <div v-if="canPageBack || canPageForward" class="flex items-center gap-1">
              <button
                type="button"
                class="rounded-md border border-border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
                :disabled="!canPageBack || busy"
                @click="goToPage(result.offset - pageSize)"
              >
                Prev
              </button>
              <button
                type="button"
                class="rounded-md border border-border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
                :disabled="!canPageForward || busy"
                @click="goToPage(result.offset + pageSize)"
              >
                Next
              </button>
            </div>
          </div>
          <div class="max-h-56 overflow-auto rounded-xl border border-border">
            <table class="w-full text-[11px]">
              <thead class="sticky top-0 bg-muted text-left text-muted-foreground">
                <tr>
                  <th class="px-2.5 py-1.5 font-medium">Email</th>
                  <th class="px-2.5 py-1.5 font-medium">Username</th>
                  <th class="px-2.5 py-1.5 font-medium">Display name</th>
                  <th class="px-2.5 py-1.5 font-medium">Groups</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="row in result.rows"
                  :key="row.external_id"
                  class="border-t border-border/50"
                >
                  <td class="px-2.5 py-1.5 text-foreground">{{ row.email || "—" }}</td>
                  <td class="px-2.5 py-1.5 text-foreground">{{ row.username || "—" }}</td>
                  <td class="px-2.5 py-1.5 text-foreground">{{ row.display_name || "—" }}</td>
                  <td class="px-2.5 py-1.5 text-muted-foreground">
                    {{ row.groups.length ? row.groups.join(", ") : "—" }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <!-- Normalization is not inferable from the form: emails are lowercased,
               display names fall back to the email local part, groups are deduped
               and sorted. -->
          <p class="mt-1 text-[10px] text-muted-foreground/80">
            Values are shown as they would be stored — an email local part under Display name
            means the source had no display name for that entry.
          </p>
        </div>
      </template>
    </div>
  </div>
</template>

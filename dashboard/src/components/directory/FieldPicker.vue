<script setup lang="ts">
// The candidate picker, rendered *in place* inside the row it belongs to.
//
// It replaces a floating `absolute` dropdown, which had three problems that no
// amount of styling fixes:
//
//   1. It was clipped. The modal is `max-h-[90vh] overflow-y-auto`, and `overflow`
//      clips absolutely-positioned descendants, so on the lower rows the list was
//      cut off at the modal's edge and scrolled with the content.
//   2. It covered what it was for. Opening a list about "Email" hid the rows
//      below, and the target's name and purpose sat above the input and were not
//      carried into the list.
//   3. It gave no reading of the candidates. `profile.name` and `login` are just
//      names until something says which is a person's name and which is a login.
//
// Expanding in flow answers all three: the target line and its purpose stay
// directly above the list, the rows below are pushed rather than covered, and
// each candidate carries a shape label, an example value and its coverage.
import { computed, nextTick, onMounted, ref, useId } from "vue";
import { Search } from "@lucide/vue";
import { SHAPE_LABEL, isLikely } from "@/lib/valueShape";
import type { MappingOption } from "@/lib/jsonPath";

const props = withDefaults(
  defineProps<{
    /** The target being filled, e.g. "Email". Used as the panel's heading. */
    target: string;
    /** The config key, which decides what counts as a likely candidate. */
    configKey: string;
    options: MappingOption[];
    /** Current value, so the list can mark what is already chosen. */
    modelValue: string;
    /** Values already used by other rows, mapped to the target that uses them. */
    usedBy: Record<string, string>;
    /** "fields" for JSON documents, "attributes" for LDAP. */
    noun?: string;
    /** Shown when the sample produced nothing to offer at all. */
    emptyHint?: string;
    /** Id of the element naming this list, for screen readers. */
    labelledBy?: string;
  }>(),
  { noun: "fields", options: () => [] },
);
const emit = defineEmits<{
  pick: [value: string];
  close: [];
}>();

const query = ref("");
const active = ref(0);
const root = ref<HTMLElement | null>(null);
const filter = ref<HTMLInputElement | null>(null);
/** Set once "Use a custom value…" is chosen, which swaps the list for an input. */
const custom = ref<string | null>(null);

interface Candidate {
  option: MappingOption;
  likely: boolean;
  /** Position in the flat list, so keyboard motion crosses buckets naturally. */
  index: number;
}

/**
 * Candidates, likely ones first.
 *
 * Ranked, never filtered: the right answer is occasionally the one the heuristic
 * did not expect, and hiding it would be worse than putting it second. The
 * `Likely` heading makes the ordering explainable rather than mysterious.
 */
const buckets = computed<{ label: string; candidates: Candidate[] }[]>(() => {
  const needle = query.value.trim().toLowerCase();
  const matches = props.options.filter(
    (option) =>
      !needle ||
      option.value.toLowerCase().includes(needle) ||
      (option.detail ?? "").toLowerCase().includes(needle) ||
      (option.shape ? SHAPE_LABEL[option.shape].toLowerCase().includes(needle) : false),
  );

  const likely: Candidate[] = [];
  const other: Candidate[] = [];
  for (const option of matches) {
    const candidate = {
      option,
      likely: isLikely(props.configKey, option.shape ?? "text"),
      index: 0,
    };
    (candidate.likely ? likely : other).push(candidate);
  }

  const flat = [...likely, ...other];
  flat.forEach((candidate, index) => {
    candidate.index = index;
  });

  const out: { label: string; candidates: Candidate[] }[] = [];
  if (likely.length) out.push({ label: "Likely", candidates: likely });
  if (other.length) out.push({ label: `Other ${props.noun} on this entry`, candidates: other });
  return out;
});

const total = computed(() => buckets.value.reduce((sum, b) => sum + b.candidates.length, 0));

/** Every candidate in flat order, for `Enter` on the active one. */
const flat = computed(() => buckets.value.flatMap((bucket) => bucket.candidates));

const uid = useId();
const listId = `picker-${uid}`;
const optionId = (index: number) => `${listId}-${index}`;

onMounted(() => {
  filter.value?.focus();
  // Start on the current choice when there is one, so re-opening a filled field
  // does not point at an arbitrary alternative.
  const index = flat.value.findIndex((c) => c.option.value === props.modelValue);
  active.value = index >= 0 ? index : 0;
});

function move(step: number) {
  if (!total.value) return;
  active.value = (active.value + step + total.value) % total.value;
  void nextTick(() =>
    document.getElementById(optionId(active.value))?.scrollIntoView({ block: "nearest" }),
  );
}

function submitCustom() {
  const value = (custom.value ?? "").trim();
  if (value) emit("pick", value);
  else emit("close");
}

function onEnter() {
  if (custom.value !== null) {
    submitCustom();
    return;
  }
  const candidate = flat.value[active.value];
  if (candidate) emit("pick", candidate.option.value);
}

/** Closes when focus leaves the picker entirely, so clicking away dismisses it. */
function onFocusOut(event: FocusEvent) {
  const next = event.relatedTarget as Node | null;
  if (next && root.value?.contains(next)) return;
  emit("close");
}
</script>

<template>
  <div
    ref="root"
    class="mt-1.5 rounded-xl border border-border bg-muted/40 p-2"
    @focusout="onFocusOut"
    @keydown.esc.stop.prevent="emit('close')"
  >
    <p class="mb-1.5 px-1 text-[11px] text-muted-foreground">
      Choose the {{ noun }} that holds
      <span class="font-medium text-foreground">{{ target }}</span>
    </p>

    <!-- Filter on top: past a dozen fields, scanning is slower than typing. -->
    <div class="mb-1.5 flex items-center gap-1.5 rounded-lg border border-border bg-card px-2">
      <Search class="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      <input
        ref="filter"
        v-model="query"
        type="text"
        spellcheck="false"
        autocomplete="off"
        role="combobox"
        aria-autocomplete="list"
        :aria-expanded="true"
        :aria-controls="listId"
        :aria-labelledby="labelledBy"
        :aria-activedescendant="total ? optionId(active) : undefined"
        :placeholder="`Filter ${noun}…`"
        class="h-7 min-w-0 flex-1 bg-transparent font-mono text-xs outline-none placeholder:font-sans"
        @input="active = 0"
        @keydown.down.prevent="move(1)"
        @keydown.up.prevent="move(-1)"
        @keydown.enter.prevent="onEnter"
      />
    </div>

    <!-- The escape hatch: a field only some entries carry, or one from a page the
         sample did not include, still has to be expressible. -->
    <div v-if="custom !== null" class="flex items-center gap-1.5">
      <input
        v-model="custom"
        type="text"
        spellcheck="false"
        autocomplete="off"
        placeholder="Type a value…"
        class="h-7 min-w-0 flex-1 rounded-lg border border-border bg-card px-2 font-mono text-xs outline-none"
        @keydown.enter.prevent="submitCustom"
      />
      <button
        type="button"
        class="rounded-lg border border-border bg-card px-2 py-1 text-[11px] hover:bg-muted"
        @click="submitCustom"
      >
        Use
      </button>
    </div>

    <template v-else>
      <div :id="listId" role="listbox" class="max-h-56 space-y-0.5 overflow-auto">
        <p v-if="!total" class="px-1 py-2 text-[11px] text-muted-foreground">
          {{ options.length ? "Nothing matches that filter." : emptyHint }}
        </p>

        <template v-for="bucket in buckets" :key="bucket.label">
          <p
            class="px-1 pt-1 pb-0.5 text-[10px] font-semibold tracking-[0.06em] text-muted-foreground/70 uppercase"
          >
            {{ bucket.label }}
          </p>
          <button
            v-for="candidate in bucket.candidates"
            :id="optionId(candidate.index)"
            :key="candidate.option.value"
            type="button"
            role="option"
            :aria-selected="candidate.option.value === modelValue"
            class="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left"
            :class="
              candidate.index === active
                ? 'bg-card ring-1 ring-border'
                : 'hover:bg-card/70'
            "
            @mousemove="active = candidate.index"
            @click="emit('pick', candidate.option.value)"
          >
            <span class="shrink-0 font-mono text-xs text-foreground">
              {{ candidate.option.value }}
            </span>
            <span
              v-if="candidate.option.shape"
              class="shrink-0 rounded px-1 text-[10px]"
              :class="
                candidate.likely
                  ? 'bg-emerald-500/10 text-emerald-600'
                  : 'bg-muted text-muted-foreground'
              "
            >
              {{ SHAPE_LABEL[candidate.option.shape] }}
            </span>
            <span class="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground">
              {{ candidate.option.detail }}
            </span>
            <span
              v-if="usedBy[candidate.option.value]"
              class="shrink-0 text-[10px] text-muted-foreground/80"
            >
              used for {{ usedBy[candidate.option.value] }}
            </span>
            <span
              v-if="candidate.option.note"
              class="shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-semibold"
              :class="
                candidate.option.partial
                  ? 'bg-amber-500/10 text-amber-700'
                  : 'bg-muted text-muted-foreground'
              "
            >
              {{ candidate.option.note }}
            </span>
          </button>
        </template>
      </div>

      <button
        type="button"
        class="mt-1 w-full rounded-lg px-2 py-1 text-left text-[11px] text-muted-foreground hover:bg-card"
        @click="custom = ''"
      >
        Use a custom value…
      </button>
    </template>
  </div>
</template>

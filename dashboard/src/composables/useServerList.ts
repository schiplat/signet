import { computed, ref, watch, type Ref } from "vue";
import type { SortDir } from "./useClientSort";

/** What one page request needs to know. */
type PageQuery = {
  q: string;
  sort: string;
  dir: SortDir;
  limit: number;
  offset: number;
};

/** One page of rows, as the server answers. */
export type PageResult<T> = { items: T[]; total: number };

/**
 * Search, sort and page a list that lives on the server.
 *
 * The counterpart of [`useClientPagination`] + [`useClientSort`] for lists too
 * large to send in one response. It keeps the same shape — `page`, `pageSize`,
 * `pageCount`, `total`, `pageItems`, `rangeLabel`, `toggleSort`,
 * `sortIndicator` — so a view can switch without its template changing, but the
 * sorting and slicing happen in SQL rather than over an array that no longer
 * exists client-side.
 *
 * Three things it has to get right that the client-side pair did not:
 *
 * * **Out-of-order responses.** Typing in a search box fires overlapping
 *   requests, and they can finish in any order. Each load carries a generation
 *   and only the newest one is allowed to write, or a slow "ad" reply would
 *   overwrite the rows for "admin".
 * * **The search resets the page.** A search that keeps the current offset shows
 *   page 4 of a result set that now has one page, which reads as "no matches".
 * * **Clamping after a shrink.** Deleting the last row of the last page leaves
 *   `page` past the end, and the next render shows an empty table.
 */
export function useServerList<T>(options: {
  /** Fetches one page. The composable owns the window and the reload. */
  load: (query: PageQuery) => Promise<PageResult<T>>;
  initialSort: string;
  initialDir?: SortDir;
  initialPageSize?: number;
  /** Search text, watched with a debounce. */
  search?: Ref<string>;
  /** Debounce for the search, in milliseconds. */
  searchDelay?: number;
}) {
  const page = ref(1);
  const pageSize = ref(options.initialPageSize ?? 20);
  const sortKey = ref(options.initialSort);
  const sortDir = ref<SortDir>(options.initialDir ?? "desc");
  const pageItems = ref<T[]>([]) as Ref<T[]>;
  const total = ref(0);
  const loading = ref(false);
  const error = ref<string | null>(null);
  /** True once a load has come back, successfully or not. */
  const loaded = ref(false);

  let generation = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  /**
   * Only the first load replaces the table.
   *
   * A search box fires a load per pause in typing, and a view that swaps the
   * whole table for "Loading…" each time is unreadable while the operator is
   * typing. Later loads keep the previous rows on screen and are surfaced some
   * other way (`loading`).
   */
  const initialLoading = computed(() => loading.value && !loaded.value);

  const pageCount = computed(() =>
    Math.max(1, Math.ceil(total.value / pageSize.value) || 1),
  );

  const rangeLabel = computed(() => {
    if (total.value === 0) return "0 of 0";
    const start = (page.value - 1) * pageSize.value + 1;
    const end = Math.min(page.value * pageSize.value, total.value);
    return `${start}–${end} of ${total.value}`;
  });

  async function load() {
    const mine = ++generation;
    loading.value = true;
    try {
      const result = await options.load({
        q: options.search?.value.trim() ?? "",
        sort: sortKey.value,
        dir: sortDir.value,
        limit: pageSize.value,
        offset: (page.value - 1) * pageSize.value,
      });
      if (mine !== generation) return;
      pageItems.value = result.items;
      total.value = result.total;
      error.value = null;
      loaded.value = true;
      // The requested page can be past the end once rows are gone.
      const last = Math.max(1, Math.ceil(result.total / pageSize.value) || 1);
      if (page.value > last) page.value = last;
    } catch (e) {
      if (mine !== generation) return;
      error.value = e instanceof Error ? e.message : String(e);
      pageItems.value = [];
      total.value = 0;
    } finally {
      if (mine === generation) {
        loading.value = false;
        loaded.value = true;
      }
    }
  }

  function reload() {
    return load();
  }

  function toggleSort(key: string) {
    if (sortKey.value === key) {
      sortDir.value = sortDir.value === "asc" ? "desc" : "asc";
    } else {
      sortKey.value = key;
      sortDir.value = "asc";
    }
  }

  function sortIndicator(key: string): "" | SortDir {
    if (sortKey.value !== key) return "";
    return sortDir.value;
  }

  watch([page, pageSize, sortKey, sortDir], () => void load(), { immediate: true });

  if (options.search) {
    watch(options.search, () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        // A new search is a new result set; page 1 is the only sensible offset.
        if (page.value !== 1) {
          page.value = 1; // triggers the main watcher
        } else {
          void load();
        }
      }, options.searchDelay ?? 250);
    });
  }

  return {
    page,
    pageSize,
    pageCount,
    total,
    pageItems,
    rangeLabel,
    loading,
    initialLoading,
    error,
    sortKey,
    sortDir,
    toggleSort,
    sortIndicator,
    reload,
  };
}

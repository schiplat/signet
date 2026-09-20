# Directory source — field mapping interaction spec

Status: **accepted** — implemented in `dashboard/src/components/directory/{MappingPanel,MappingTable,FieldPicker}.vue` and `dashboard/src/lib/valueShape.ts`.
Scope: the "Field mapping" section of the directory source modal (`dashboard/src/views/DirectoryView.vue`, `dashboard/src/components/directory/MappingPanel.vue`, `MappingTable.vue`).

### Decisions taken

| Open decision | Chosen |
|---|---|
| Direction | Expand **in place**; the floating `absolute` dropdown and `ui/Combobox.vue` were removed |
| LDAP shapes | **Attribute vocabulary** plus value heuristics, in `lib/valueShape.ts` |
| Advance on assign | **Stay put.** The assigned row flashes; focus is not moved |
| Rank severity | **Rank, never filter** — non-likely candidates stay visible under their own heading |
| Persist the paste | Unchanged: in-memory for the modal session |
| Reference list | **Manual** disclosure, open by default. The spec proposed auto-collapsing once every row passed; that was dropped because collapsing on its own moves the layout while the list is being read |
| Row table | **Paged** (`offset`/`page_size`, 25 entries), while every verdict stays computed across the whole sample — see §4.6.1 |
| Scope inputs | The §7 scope lives **in the `scope` row**, next to `base_dn`/`user_filter`, because the server reports one verdict per row and the verdict has to sit under the inputs that caused it. Domain and department lists are the row's only **list** inputs (`shape: "list"`): a set of values has no counterpart in a sample of entries, so there is nothing to pick and they are typed by hand |

Deviations from the proposal are limited to the last three rows: everything else is as specified.

---

## 1. Vocabulary

Two roles, and almost every problem below comes from the UI not being explicit about which is which:

| Role | What it is | Example | Who decides it |
|---|---|---|---|
| **Target** | A field Signet stores | `Email`, `External ID`, `Display name` | fixed (§3 of `directory-sync.md`) |
| **Candidate** | A field the source returns | `mail`, `profile.name`, `uid` | the directory |

A mapping row answers exactly one question: **"which candidate fills this target?"**

---

## 2. Current interaction, and why it fails

As-is:

1. A sample is pasted into the left column.
2. Each target row has an input. Clicking it opens a floating list of candidates (path, sample value, occurrence badge).
3. Choosing one closes the list and writes the path into the input.

### Defects

**D1 — The candidate list is clipped by the modal.** The modal is `max-h-[90vh] overflow-y-auto`; the list is `absolute` inside it. An `overflow: auto` ancestor clips absolutely-positioned descendants, so the list is cut off at the modal's edge and scrolls with the content instead of staying anchored. For the last rows (`Groups`) the list is partially unreachable. *Root cause: overlay rendered in flow inside a scroll container; no portal, no flip.*

**D2 — Choosing something covers the thing being chosen for.** The list is `w-full` under the input, so it covers the rows below and — once the modal scrolls — the row's own label and hint too. The target's name and purpose are small, sit above the input, and are not carried into the list. *Root cause: the picker does not restate its target, and overlays instead of displacing.*

**D3 — A candidate has no stated meaning.** The list shows `id`, `login`, `profile.name` with a sample value and a `2/3 entries` badge. Nothing says "this is an email address" or "this is a stable ID". From a user's view these are arbitrary names. *Root cause: evidence is limited to one example value; no type/shape reading, no relevance to the target.*

**D4 — Nothing marks the likely answer.** For `Email`, `mail` is the answer; for `External ID`, `entryUUID`/`id` is. The list presents all candidates with equal weight, so the user has to know the answer already — which is the one thing they came here for. *Root cause: no ranking against the target's expected shape.*

**D5 — Assigning produces no acknowledgement.** The list closes, the input's mono text changes, and the verdict pill only updates after a 400 ms debounce plus a round trip. There is no moment that confirms "this is now Email". *Root cause: no local, immediate result state; the only signal is async.*

**D6 — The same field can silently be assigned twice.** Mapping `mail` to both `Email` and `Username` is accepted without comment. *Root cause: candidates are not checked against the other rows.*

---

## 3. Principles

1. **The target is never out of sight.** At every moment of choosing, the target's name and purpose are on screen.
2. **Show the answer before the alternatives.** Rank by evidence; the likely candidate is first and marked as such, with the reason visible.
3. **Choosing is a state change, not a transaction.** The row visibly moves from *unmapped* → *mapped*, immediately and locally.
4. **Nothing optional is hidden behind a hover or a keypress.** Everything needed to decide is rendered.
5. **Displace, don't overlay.** The picker takes space in the layout, so nothing is covered and nothing is clipped.

---

## 4. Target interaction

### 4.1 Row anatomy

```
┌─────────────────────────────────────────────────────────────┐
│ Email                                    3/3 entries  ✓     │  ← target + verdict
│ Required: an entry without one is skipped by the sync.      │  ← purpose (always shown)
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ mail                                                      │ │  ← the choice
│ └─────────────────────────────────────────────────────────┘ │
│ → "ada.lovelace@corp.example"                    Change ⌄   │  ← proof + affordance
└─────────────────────────────────────────────────────────────┘
```

- The **purpose line is always visible**, not replaced by the proof line. It is the answer to "what is this field for?", and the current version hides it as soon as a value is chosen.
- The **proof line** (`→ "…"`) shows one real value from the sample, so a mapping can be verified by reading.
- The **verdict** is right-aligned on the target line.

### 4.2 States

| State | Rendered as |
|---|---|
| **Unmapped** | Purpose line + a full-width button-style control reading `Choose the field…` |
| **Mapped** | The chosen path + proof line + `Change` |
| **Assigning** | The row expands in place (see 4.3); everything else stays put |
| **Checking** | Verdict pill shows `checking…` while the preview is in flight |

An unmapped row is a **button**, not an empty text input: an empty input looks like it wants typing, and invites the wrong action.

### 4.3 The assign panel (in place, not an overlay)

```
┌─────────────────────────────────────────────────────────────┐
│ Email                                            3/3 entries │
│ Required: an entry without one is skipped by the sync.      │
│                                                             │
│  ┌─ Choose the field that holds Email ────────────────────┐ │
│  │ ⌕ [ filter…                                        ]   │ │
│  │                                                        │ │
│  │ LIKELY                                                 │ │
│  │ ● mail        Email    "ada.lovelace@corp.example"  3/3│ │
│  │                                                        │ │
│  │ OTHER FIELDS ON THIS ENTRY                             │ │
│  │ ○ id          ID       "u-1024"                     3/3│ │
│  │ ○ login       Text     "ada"                        3/3│ │
│  │ ○ profile.name Name    "Ada Lovelace"               2/3│ │
│  │ ○ groups      List·2   "engineering, oncall"        3/3│ │
│  │                                                        │ │
│  │ ⌨ Use a custom path…                                   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

- Rendered **in flow**, replacing nothing: the target line and purpose stay above it (Principle 1), and the rows below are pushed down, not covered (Principle 5, fixes D1/D2).
- Header restates the target: `Choose the field that holds Email`.
- **Likely** group first, in its own labelled bucket, with the reason visible via the shape label (fixes D4).
- Only one row is open at a time; opening another closes the first.
- The modal grows and scrolls; the left sample column stays pinned, so the raw sample remains readable while choosing.
- `Esc` closes without assigning; clicking outside closes without assigning.

### 4.4 Evidence on a candidate

Each candidate renders four things:

| Slot | Content | Why |
|---|---|---|
| Path | `profile.name` (mono) | what gets stored |
| **Shape** | `Email`, `ID`, `Name`, `Text`, `DN`, `URL`, `Date`, `List · 2`, `Flag` | answers "what *is* this field?" (fixes D3) |
| Example | one real value, truncated | recognition |
| Badge | `3/3`, `2/3` (amber), `groups` | coverage; amber means "patchy" |

**Shape is inferred from the value**, and is therefore a hint, never a verdict:

- string matching an email pattern → `Email`
- UUID → `ID`; `k=v,` repeated → `DN`; `http(s)://` → `URL`; ISO-8601 → `Date`
- array → `List · N`; bool → `Flag`; number → `Number`
- otherwise → `Text`

For LDAP, shapes are read from the attribute's sample value the same way, and the badge also carries provenance (`groups` when the attribute only appears on group entries).

**Ranking.** Each target declares the shapes it expects:

| Target | Expected shapes |
|---|---|
| External ID | `ID`, `DN` |
| Email | `Email` |
| Username | `Email`, `Text` |
| Display name | `Name`, `Text` |
| Groups | `List` |

Candidates whose shape is expected go in **Likely**; the rest follow under **Other fields on this entry**. Rank, never filter — the correct answer is sometimes the unexpected one, and hiding it would be worse than mis-ordering it.

**Already used by another row** is marked inline (`used for Username`) in a muted style, still selectable. Fixes D6 with information rather than a block.

### 4.5 Feedback on assign

Three signals, in this order:

1. **Immediate (local, no round trip)** — the panel collapses and the row becomes **Mapped**, showing the path and the proof line. This is the acknowledgement (fixes D5).
2. **Momentary** — a 1 s ring highlight on the row that changed, so the eye can confirm *which* row moved. Suppressed under `prefers-reduced-motion`.
3. **Async** — the verdict pill goes `checking…` → `3/3 entries` / `needs attention`.

Plus one section-level signal: a progress line above the rows — `4 of 6 fields mapped` — with any failing rows listed as jump links. It answers "what did I do, and what is left?" at a glance.

### 4.6 Layout

- Two columns, unchanged in spirit: sample + reference on the left (pinned), rows on the right.
- The left column's reference list is **collapsible**, collapsed by default once every row is mapped and passing: its content is now duplicated inside the assign panels.
- The paste textarea is always visible — it is the input the whole section depends on.
- One column below `lg`; the sample moves above the rows and the assign panel scrolls into view on open.
- The normalized row table is **paged** (`120 entries, showing 26–50`, `Prev`/`Next`), 25 entries per page. A paste of a large directory should not have to be carried across the wire in one response just to render a sample.
- The range is stated in **entries**, and its end is the page edge rather than the number of rows returned. A page can return fewer rows than it spans (an entry with no external id produces none), so numbering by row count would label page 2 `26–34` while it covers entries 26–50, and would disagree with the step the buttons use.

### 4.6.1 Why paging and checking are different numbers

The row table is paged; the verdicts are not. Every `resolved/total` and every `n/m entries` badge is computed across the **whole** sample, whatever page is on screen — `total` always equals `entry_count`.

This is not an optimisation detail, it is the difference between a useful signal and a misleading one. When both were capped at the same 50 entries, a 120-entry paste rendered `120 entries` in the header next to `10/50` on the `display_name` row: two denominators in one panel, and the smaller one was wrong in the reassuring direction — an attribute carried by 8% of the directory read as 20%, and an attribute whose only instance sat past entry 50 would have read as a passing `0/50`. The count exists to talk an admin out of mapping a patchy attribute, so it has to be honest about the patchiness.

Paging therefore lives entirely in `offset` and touches only `rows`.

### 4.7 Keyboard and accessibility

- `Enter` / `Space` on a row opens the assign panel; focus moves into the filter box.
- `↑`/`↓` move the active candidate, `Enter` assigns and returns focus to the row, `Esc` closes.
- The control is a `combobox` + `listbox`; the header is the accessible name, so a screen reader hears the target before the options.
- The shape and badge are text, not colour alone.
- `aria-live="polite"` on the verdict pill, so `needs attention` is announced.

---

## 5. Copy deck

| Where | String |
|---|---|
| Unmapped control | `Choose the field…` |
| Assign panel header | `Choose the field that holds {Target}` |
| Likely bucket | `Likely` |
| Other bucket | `Other fields on this entry` |
| Free text | `Use a custom path…` |
| Mapped affordance | `Change` |
| In-use marker | `used for {Target}` |
| Patchy badge tooltip | `Present in {n} of {m} sampled entries` |
| Progress | `{n} of {m} fields mapped` |
| Pending verdict | `checking…` |

---

## 6. Edge cases

| Case | Behaviour |
|---|---|
| No sample pasted | Rows stay unmapped; the assign panel offers only `Use a custom path…` and says `Paste a sample to see the source's fields`. Verdicts are syntax-only. |
| Sample is not valid JSON / not LDIF | Error on the paste, reference list hidden, rows unaffected. |
| `users_path` not an array | Error naming the path; no candidates offered, because there is no entry to read. |
| Candidate present in only some entries | Amber `2/3` badge in the list **and** on the mapped row. |
| Source returns a field the target set does not use | Visible in the reference list; never offered as a candidate. |
| Two rows share one candidate | Allowed, marked `used for …`. |

---

## 7. Acceptance criteria

1. With the last row's assign panel open, every candidate is reachable — nothing is clipped by the modal. *(D1)*
2. While a picker is open, the target's name and purpose are both on screen without scrolling. *(D2)*
3. Every candidate shows a shape label and an example value. *(D3)*
4. For `Email`, an email-shaped candidate appears under **Likely**; for `External ID`, an ID-shaped one does. *(D4)*
5. Assigning updates the row to **Mapped** before any network response arrives. *(D5)*
6. Assigning a candidate already used elsewhere marks that in the list. *(D6)*
7. No interactive element depends on hover to reveal information.
8. The section is usable at 360 px width and by keyboard alone.
9. A sample larger than one page shows `n/m entries` counts computed across the whole sample, and the count does not change when paging.
10. The `scope` row accepts a domain list and a department list, and its verdict says how many sampled entries the scope admits; a scope that admits none is reported as a failure, not as a passing zero. *(D7)*
11. A source with no scope configured reports the same `scope` verdict it did before scoping existed.

### Terminology note (D7)

The `scope` row's purpose line changed as part of D7, and the change is the point: it used to read *"Everything outside it is left alone"*, which was wrong once a scope could disable on absence. It now says the scope is what the source **owns**, and that leaving it disables the account — because that is what actually happens (§7.2.1 of `directory-sync.md`). A hint that reassures the admin about the wrong behaviour is worse than no hint.

---

## 8. Open decisions

1. **Advance on assign?** After assigning, should focus move to the next unmapped row (fast for a linear fill) or stay put (safer for review)? Proposal: stay put, and highlight the next unmapped row without stealing focus.
2. **Rank severity.** Sink non-likely candidates behind a `Show all` toggle, or always list them? Proposal: always list — a wrong-but-visible option costs less than an invisible right one.
3. **Persist the paste?** The sample is in-memory per modal session. Should it survive a modal close within the same page visit, to save re-pasting while iterating?
4. **LDAP shape confidence.** Attribute values give weaker shape evidence than JSON names (`uid` vs `mail` both read as `Text`). Is an attribute-name vocabulary (`mail`→Email, `cn`/`displayName`→Name, `entryUUID`/`objectGUID`→ID) worth maintaining, or is the value-only heuristic enough?

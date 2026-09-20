<script setup lang="ts">
import { AppWindow, History, LayoutDashboard, PanelLeft, Plug, ScrollText, Settings, UserRound, Waypoints } from "@lucide/vue";
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth";
import { useUiStore } from "@/stores/ui";

const ui = useUiStore();
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const appVersion = __APP_VERSION__;

type NavLink = {
  kind: "link";
  name: string;
  label: string;
  icon: typeof UserRound;
  to: string;
  staffOnly?: boolean;
  adminOnly?: boolean;
};

type NavSection = {
  kind: "section";
  label: string;
  staffOnly?: boolean;
  adminOnly?: boolean;
};

type NavEntry = NavLink | NavSection;

const allEntries: NavEntry[] = [
  {
    kind: "link",
    name: "overview",
    label: "Overview",
    icon: LayoutDashboard,
    to: "/overview",
    staffOnly: true,
  },
  { kind: "section", label: "Access", staffOnly: true },
  {
    kind: "link",
    name: "users",
    label: "Users",
    icon: UserRound,
    to: "/users",
    staffOnly: true,
  },
  { kind: "section", label: "Applications", staffOnly: true },
  {
    kind: "link",
    name: "clients",
    label: "Clients",
    icon: AppWindow,
    to: "/clients",
    staffOnly: true,
  },
  { kind: "section", label: "Observability", staffOnly: true },
  {
    kind: "link",
    name: "audit-logs",
    label: "Audit logs",
    icon: ScrollText,
    to: "/audit-logs",
    staffOnly: true,
  },
  { kind: "section", label: "System" },
  {
    kind: "link",
    name: "activity",
    label: "My security",
    icon: History,
    to: "/activity",
  },
  {
    kind: "link",
    name: "settings",
    label: "Settings",
    icon: Settings,
    to: "/settings",
    adminOnly: true,
  },
  {
    kind: "link",
    name: "integrations",
    label: "Integrations",
    icon: Plug,
    to: "/integrations",
    adminOnly: true,
  },
  {
    kind: "link",
    name: "directory",
    label: "Directory sync",
    icon: Waypoints,
    to: "/directory",
    adminOnly: true,
  },
];

const entries = computed(() =>
  allEntries.filter((e) => {
    if (e.kind === "link" && e.name === "overview" && !auth.isStaff) return false;
    if (e.adminOnly && !auth.isAdmin) return false;
    if (e.staffOnly && !auth.isStaff) return false;
    return true;
  }),
);

function isActive(name: string) {
  return route.name === name;
}

function onNavClick(e: MouseEvent, to: string) {
  if (e.defaultPrevented) return;
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
  e.preventDefault();
  void router.push(to);
}

function onLogoClick(e: MouseEvent) {
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
  e.preventDefault();
  void router.push(auth.isStaff ? "/overview" : "/activity");
}
</script>

<template>
  <aside
    :class="
      cn(
        'sticky top-0 z-20 flex h-screen shrink-0 flex-col bg-sidebar text-sidebar-foreground',
        'transition-[width] duration-200 ease-out',
        ui.isCollapsed ? 'w-[4.25rem]' : 'w-[15.5rem]',
      )
    "
  >
    <div
      :class="
        cn(
          'flex h-16 items-center px-3',
          ui.isCollapsed ? 'justify-center' : 'justify-between gap-2',
        )
      "
    >
      <a
        href="/"
        class="group flex min-w-0 items-center gap-2.5 rounded-xl px-1 py-1 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring/25"
        :title="ui.isCollapsed ? 'Signet' : undefined"
        @click="onLogoClick"
      >
        <span
          class="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-primary text-xs font-semibold tracking-wide text-primary-foreground"
        >
          Sg
        </span>
        <span v-if="!ui.isCollapsed" class="min-w-0">
          <span class="block truncate text-sm font-semibold tracking-tight">Signet</span>
          <span class="block truncate text-xs text-muted-foreground">Identity</span>
        </span>
      </a>
      <button
        v-if="!ui.isCollapsed"
        type="button"
        class="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-foreground"
        title="Collapse sidebar (⌘B)"
        @click="ui.toggleSidebar()"
      >
        <PanelLeft class="h-4 w-4" />
      </button>
    </div>

    <div class="mx-3 mt-3 border-t border-sidebar-border/80" />

    <nav class="flex flex-1 flex-col gap-1 overflow-y-auto px-2.5 pb-3 pt-6">
      <template
        v-for="(entry, idx) in entries"
        :key="entry.kind === 'section' ? `s-${entry.label}` : entry.name"
      >
        <p
          v-if="entry.kind === 'section' && !ui.isCollapsed"
          :class="cn('type-eyebrow px-2.5', idx === 0 ? 'mb-2.5' : 'mb-2.5 mt-6')"
        >
          {{ entry.label }}
        </p>
        <div
          v-else-if="entry.kind === 'section' && ui.isCollapsed"
          class="mx-auto my-4 h-px w-6 bg-sidebar-border"
        />
        <a
          v-else-if="entry.kind === 'link'"
          :href="entry.to"
          :title="ui.isCollapsed ? entry.label : undefined"
          :class="
            cn(
              'group flex items-center gap-3 rounded-xl px-2.5 py-2 text-sm font-medium text-muted-foreground transition-colors',
              'hover:bg-sidebar-accent hover:text-foreground',
              ui.isCollapsed && 'justify-center px-0',
              isActive(entry.name) && 'bg-sidebar-accent text-foreground',
            )
          "
          @click="onNavClick($event, entry.to)"
        >
          <component
            :is="entry.icon"
            :class="
              cn(
                'h-4 w-4 shrink-0',
                isActive(entry.name)
                  ? 'text-foreground'
                  : 'text-muted-foreground group-hover:text-foreground',
              )
            "
          />
          <span v-if="!ui.isCollapsed">{{ entry.label }}</span>
        </a>
      </template>
    </nav>

    <div v-if="!ui.isCollapsed" class="space-y-0.5 px-4 pb-4">
      <p class="px-1 text-xs leading-relaxed text-muted-foreground/80">
        © 2026 Signetproject
      </p>
      <p class="px-1 font-mono text-xs text-muted-foreground/60" :title="`v${appVersion}`">
        v{{ appVersion }}
      </p>
    </div>
  </aside>
</template>

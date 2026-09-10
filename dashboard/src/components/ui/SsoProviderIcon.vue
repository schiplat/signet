<script setup lang="ts">
import type { SsoProviderType } from "@/lib/api";

defineProps<{
  type: SsoProviderType;
  /** Tailwind size classes, e.g. "h-11 w-11" */
  class?: string;
}>();
</script>

<template>
  <!-- Feishu icon: https://cdn.jsdelivr.net/gh/callback-io/allogo@main/public/logos/feishu/icon.svg -->
  <img
    v-if="type === 'feishu'"
    src="/sso-feishu.svg"
    alt=""
    :class="['shrink-0 object-contain', $props.class ?? 'h-11 w-11']"
    width="48"
    height="48"
    draggable="false"
  />

  <span
    v-else-if="type === 'github'"
    :class="[
      'flex shrink-0 items-center justify-center rounded-xl bg-[hsl(217_30%_20%)] text-[11px] font-bold text-white',
      $props.class ?? 'h-11 w-11',
    ]"
    aria-hidden="true"
  >
    GH
  </span>
  <span
    v-else-if="type === 'google'"
    :class="[
      'flex shrink-0 items-center justify-center rounded-xl bg-[hsl(0_70%_55%)] text-[11px] font-bold text-white',
      $props.class ?? 'h-11 w-11',
    ]"
    aria-hidden="true"
  >
    G
  </span>
  <span
    v-else-if="type === 'wechat'"
    :class="[
      'flex shrink-0 items-center justify-center rounded-xl bg-[hsl(142_70%_40%)] text-[11px] font-bold text-white',
      $props.class ?? 'h-11 w-11',
    ]"
    aria-hidden="true"
  >
    WX
  </span>
  <span
    v-else
    :class="[
      'flex shrink-0 items-center justify-center rounded-xl bg-primary text-[11px] font-bold text-primary-foreground',
      $props.class ?? 'h-11 w-11',
    ]"
    aria-hidden="true"
  >
    ID
  </span>
</template>

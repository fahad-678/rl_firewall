<template>
  <div class="relative flex h-screen overflow-hidden text-slate-100">
    <transition name="fade">
      <div
        v-if="isMobileMenuOpen"
        @click="isMobileMenuOpen = false"
        class="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm md:hidden"
      ></div>
    </transition>

    <aside
      :class="[
        'soc-glass fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r border-[var(--soc-border)] transition-transform duration-300 ease-in-out md:relative md:translate-x-0',
        isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
      ]"
    >
      <div class="border-b border-[var(--soc-border)] p-6">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-xs uppercase tracking-[0.35em] text-[var(--soc-accent)]">Autonomous Firewall</p>
            <h1 class="mt-2 text-2xl font-semibold tracking-wide text-slate-50">RL Firewall</h1>
            <p class="soc-muted mt-1 text-xs">Adaptive policy engine with analyst feedback</p>
          </div>
          <button @click="isMobileMenuOpen = false" class="text-slate-300 hover:text-white md:hidden">
            <X class="h-5 w-5" />
          </button>
        </div>

        <div class="mt-5 grid gap-3">
          <div class="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3">
            <p class="text-xs uppercase tracking-[0.25em] text-emerald-300">Telemetry</p>
            <div class="mt-2 flex items-center gap-2 text-sm font-medium text-emerald-200">
              <span class="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_14px_rgba(16,185,129,0.8)]"></span>
              Live feed active
            </div>
          </div>

          <div class="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3">
            <p class="text-xs uppercase tracking-[0.25em] text-cyan-300">Learning</p>
            <div class="mt-2 flex items-center gap-2 text-sm font-medium text-cyan-100">
            <span class="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_14px_rgba(16,185,129,0.8)]"></span>
              DQN policy loop
            </div>
          </div>
        </div>
      </div>

      <nav class="flex-1 space-y-2 overflow-y-auto p-4">
        <router-link
          v-for="item in navigation"
          :key="item.name"
          :to="item.href"
          class="group flex items-center gap-3 rounded-xl border border-transparent px-3 py-3 transition-all duration-200 hover:border-[var(--soc-border)] hover:bg-slate-900/50"
          active-class="border-cyan-400/30 bg-cyan-400/10 text-cyan-100 shadow-[inset_0_0_0_1px_rgba(46,196,182,0.2)]"
        >
          <component
            :is="item.icon"
            class="h-5 w-5 text-slate-400 transition-colors group-hover:text-slate-100"
            :class="{ 'text-cyan-200': $route.path === item.href }"
          />
          <div>
            <p class="text-sm font-medium">{{ item.name }}</p>
            <p class="text-xs text-slate-400">{{ item.description }}</p>
          </div>
        </router-link>
      </nav>

      <div class="border-t border-[var(--soc-border)] p-4">
        <div class="rounded-xl border border-[var(--soc-border)] bg-slate-900/60 p-3">
          <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Operator</p>
          <p class="mt-1 text-sm font-medium text-slate-100">Security Admin</p>
          <p class="text-xs text-slate-400">Human-in-the-loop enabled</p>
        </div>
      </div>
    </aside>

    <main class="flex min-w-0 flex-1 flex-col overflow-hidden">
      <header class="soc-glass flex h-16 shrink-0 items-center justify-between border-b border-[var(--soc-border)] px-4 sm:px-6 lg:px-8">
        <div class="flex items-center gap-4">
          <button @click="isMobileMenuOpen = true" class="text-slate-400 hover:text-slate-100 md:hidden">
            <Menu class="h-6 w-6" />
          </button>
          <div>
            <p class="text-xs uppercase tracking-[0.24em] text-[var(--soc-accent)]">Control Plane</p>
            <h2 class="text-lg font-semibold tracking-wide text-slate-100">{{ pageTitle }}</h2>
          </div>
        </div>

        <div class="flex items-center gap-3">
          <div class="hidden rounded-lg border border-[var(--soc-border)] bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 sm:block">
            Control State: <span class="font-semibold text-emerald-300">Connected</span>
          </div>
          <button class="relative rounded-lg border border-[var(--soc-border)] bg-slate-900/60 p-2 text-slate-300 transition-colors hover:text-slate-100">
            <span class="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-rose-500"></span>
            <Bell class="h-5 w-5" />
          </button>

          <button
            @click="handleLogout"
            class="rounded-lg border border-[var(--soc-border)] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-800"
          >
            Sign Out
          </button>
        </div>
      </header>

      <div class="relative flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
        <div class="mb-4 flex flex-wrap items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-slate-400">
          <span class="rounded-full border border-[var(--soc-border)] bg-slate-950/50 px-3 py-1">Realtime defense</span>
          <span class="rounded-full border border-[var(--soc-border)] bg-slate-950/50 px-3 py-1">Policy learning</span>
          <span class="rounded-full border border-[var(--soc-border)] bg-slate-950/50 px-3 py-1">Audit ready</span>
        </div>

        <router-view v-slot="{ Component }">
          <transition name="page" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  LayoutDashboard,
  Activity,
  BrainCircuit,
  ClipboardList,
  ShieldAlert,
  Menu,
  X,
  Bell
} from 'lucide-vue-next'
import authService from '../services/authService.js'

const router = useRouter()

// Mobile menu state
const isMobileMenuOpen = ref(false)

// Data-Driven Navigation
const navigation = [
  { name: 'Threat Triage', href: '/', icon: LayoutDashboard, description: 'Live queue and response controls' },
  { name: 'AI Performance', href: '/performance', icon: Activity, description: 'Reward curve and exploration' },
  { name: 'Training History', href: '/training', icon: BrainCircuit, description: 'Epoch-level learning ledger' },
  { name: 'Audit Logs', href: '/audit', icon: ClipboardList, description: 'Operator intervention trail' },
  { name: 'Manual Rules', href: '/manual-rules', icon: ShieldAlert, description: 'Block/allow specific IPs' },
]

const pageTitle = computed(() => {
  if (router.currentRoute.value.name === 'Dashboard') return 'Threat Triage Workspace'
  if (router.currentRoute.value.name === 'AiPerformance') return 'Learning Analytics'
  if (router.currentRoute.value.name === 'TrainingHistory') return 'Training Ledger'
  if (router.currentRoute.value.name === 'AuditLogs') return 'Audit & Compliance'
  return 'RL Firewall'
})

// Handle logout
const handleLogout = async () => {
  await authService.logout()
  router.push('/login')
}
</script>

<style scoped>
/* Smooth page transitions */
.page-enter-active,
.page-leave-active {
  transition: opacity 0.26s ease, transform 0.26s ease;
}

.page-enter-from {
  opacity: 0;
  transform: translateY(12px);
}

.page-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}

/* Mobile overlay transition */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.25s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
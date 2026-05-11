<template>
  <div class="space-y-6">
    <section class="grid grid-cols-1 gap-4 md:grid-cols-4">
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Epochs Loaded</p>
        <p class="mt-2 text-2xl font-semibold text-cyan-100">{{ logs.length }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Latest Epsilon</p>
        <p class="mt-2 text-2xl font-semibold text-amber-200">{{ latestEpsilon }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Block Efficiency</p>
        <p class="mt-2 text-2xl font-semibold text-emerald-200">{{ blockEfficiency }}%</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Average Reward</p>
        <p class="mt-2 text-2xl font-semibold text-sky-200">{{ averageReward }}</p>
      </article>
    </section>

    <div class="soc-panel overflow-hidden rounded-2xl">
      <div class="flex flex-col gap-3 border-b border-[var(--soc-border)] p-6 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p class="text-xs uppercase tracking-[0.32em] text-[var(--soc-accent)]">Training Ledger</p>
          <h3 class="mt-2 text-lg font-semibold text-slate-100">Historical training logs</h3>
        </div>
        <button @click="fetchLogs" class="flex items-center gap-2 rounded-lg border border-[var(--soc-border)] bg-slate-900/70 px-3 py-1.5 text-sm text-slate-200 transition-colors hover:bg-slate-800" :disabled="isLoading">
          <RefreshCw :class="{'animate-spin': isLoading}" class="w-4 h-4" />
          Refresh
        </button>
      </div>

      <div v-if="error" class="flex items-center gap-2 p-6 text-sm text-rose-300">
        <AlertCircle class="w-5 h-5" /> {{ error }}
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--soc-border)] bg-slate-950/40 text-sm text-slate-300">
              <th class="p-4 font-medium">Epoch</th>
              <th class="p-4 font-medium">Epsilon (Exploration)</th>
              <th class="p-4 font-medium">Cumulative Reward</th>
              <th class="p-4 font-medium">Avg Loss</th>
              <th class="p-4 font-medium">Threats Blocked</th>
              <th class="p-4 font-medium">Threats Allowed</th>
              <th class="p-4 font-medium">Timestamp</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-[var(--soc-border)]">
            <tr v-if="isLoading && logs.length === 0">
              <td colspan="7" class="p-8 text-center text-slate-400">Loading metrics...</td>
            </tr>
            <tr v-else-if="logs.length === 0">
              <td colspan="7" class="p-8 text-center text-slate-400">No training data recorded yet.</td>
            </tr>
            <tr v-for="log in logs" :key="log.epoch" class="transition-colors hover:bg-slate-900/40">
              <td class="p-4 font-medium text-slate-100">{{ log.epoch }}</td>
              <td class="p-4 font-mono text-sm text-slate-300">{{ log.epsilon.toFixed(4) }}</td>
              <td class="p-4 text-sm">
                <span :class="log.cumulative_reward >= 0 ? 'font-semibold text-emerald-300' : 'text-rose-300'">
                  {{ log.cumulative_reward }}
                </span>
              </td>
              <td class="p-4 text-sm text-slate-300">{{ log.loss ? log.loss.toFixed(4) : 'N/A' }}</td>
              <td class="p-4 text-sm text-slate-300">{{ log.threats_blocked }}</td>
              <td class="p-4 text-sm text-slate-300">{{ log.threats_allowed }}</td>
              <td class="p-4 text-xs text-slate-400">{{ new Date(log.created_at).toLocaleString() }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { RefreshCw, AlertCircle } from 'lucide-vue-next'
import { formatError } from '../utils/formatError'

const REFRESH_MS = 30_000
let refreshTimer = null

const logs = ref([])
const isLoading = ref(true)
const error = ref(null)

const latestEpsilon = computed(() => {
  if (logs.value.length === 0) return 'N/A'
  return logs.value[0].epsilon.toFixed(4)
})

const averageReward = computed(() => {
  if (logs.value.length === 0) return 'N/A'
  const total = logs.value.reduce((sum, log) => sum + Number(log.cumulative_reward || 0), 0)
  return (total / logs.value.length).toFixed(2)
})

const blockEfficiency = computed(() => {
  if (logs.value.length === 0) return 0

  const totals = logs.value.reduce((sum, log) => {
    sum.blocked += Number(log.threats_blocked || 0)
    sum.allowed += Number(log.threats_allowed || 0)
    return sum
  }, { blocked: 0, allowed: 0 })

  const total = totals.blocked + totals.allowed
  if (total === 0) return 0
  return Math.round((totals.blocked / total) * 100)
})

const fetchLogs = async ({ silent = false } = {}) => {
  if (!silent) {
    isLoading.value = true
    error.value = null
  }

  try {
    const response = await axios.get('/api/ai/logs')
    logs.value = response.data
    error.value = null
  } catch (err) {
    console.error("Failed to fetch training logs:", err)
    if (!silent) error.value = formatError(err, 'Failed to load historical data.')
  } finally {
    if (!silent) isLoading.value = false
  }
}

const silentRefresh = () => fetchLogs({ silent: true }).catch(() => {})

onMounted(() => {
  fetchLogs()
  refreshTimer = setInterval(silentRefresh, REFRESH_MS)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>
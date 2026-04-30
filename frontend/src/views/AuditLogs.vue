<template>
  <div class="space-y-6">
    <section class="grid grid-cols-1 gap-4 md:grid-cols-4">
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Total Records</p>
        <p class="mt-2 text-2xl font-semibold text-cyan-100">{{ pagination.total }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Block Decisions</p>
        <p class="mt-2 text-2xl font-semibold text-rose-200">{{ blockDecisions }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Allow Decisions</p>
        <p class="mt-2 text-2xl font-semibold text-emerald-200">{{ allowDecisions }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Reviewed Notes</p>
        <p class="mt-2 text-2xl font-semibold text-sky-200">{{ notedDecisions }}</p>
      </article>
    </section>

    <div class="soc-panel overflow-hidden rounded-2xl">
      <div class="flex flex-col gap-3 border-b border-[var(--soc-border)] p-6 lg:flex-row lg:items-center lg:justify-between">
        <div class="flex items-center gap-3">
          <div class="rounded-lg bg-cyan-500/15 p-2 text-cyan-300">
            <ClipboardList class="w-5 h-5" />
          </div>
          <div>
            <p class="text-xs uppercase tracking-[0.32em] text-[var(--soc-accent)]">Compliance</p>
            <h3 class="mt-1 text-lg font-semibold text-slate-100">Analyst audit trail</h3>
          </div>
        </div>
        <button @click="fetchAuditLogs" class="flex items-center gap-2 rounded-lg border border-[var(--soc-border)] bg-slate-900/70 px-3 py-1.5 text-sm text-slate-200 transition-colors hover:bg-slate-800" :disabled="isLoading">
          <RefreshCw :class="{'animate-spin': isLoading}" class="w-4 h-4" />
          Refresh
        </button>
      </div>

      <div v-if="error" class="p-6 text-sm text-rose-300 flex items-center gap-2">
        <AlertCircle class="w-5 h-5" /> {{ error }}
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--soc-border)] bg-slate-950/40 text-sm text-slate-300">
              <th class="p-4 font-medium">Timestamp</th>
              <th class="p-4 font-medium">Target IP</th>
              <th class="p-4 font-medium">Analyst Decision</th>
              <th class="p-4 font-medium">Context</th>
              <th class="p-4 font-medium">Notes</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-[var(--soc-border)]">
            <tr v-if="isLoading && logs.length === 0">
              <td colspan="5" class="p-8 text-center text-slate-400">Loading audit trail...</td>
            </tr>
            <tr v-else-if="logs.length === 0">
              <td colspan="5" class="p-8 text-center text-slate-400">No human interventions recorded yet.</td>
            </tr>
            <tr v-for="log in logs" :key="log.id" class="transition-colors hover:bg-slate-900/40">
              <td class="p-4 text-sm text-slate-400">{{ new Date(log.created_at).toLocaleString() }}</td>
              <td class="p-4 font-mono text-sm font-semibold text-slate-100">{{ log.ip_address }}</td>
              <td class="p-4">
                <span :class="{
                  'px-3 py-1 text-xs font-semibold rounded-md uppercase tracking-[0.08em]': true,
                  'border border-rose-400/40 bg-rose-500/15 text-rose-200': log.decision === 'BLOCK',
                  'border border-emerald-400/40 bg-emerald-500/15 text-emerald-200': log.decision === 'ALLOW'
                }">
                  {{ log.decision }}
                </span>
              </td>
              <td class="p-4 text-sm text-slate-300">
                <div class="space-y-1">
                  <p>{{ describeContext(log) }}</p>
                  <p class="font-mono text-[11px] text-slate-500">{{ log.flow_key || 'No flow key captured' }}</p>
                </div>
              </td>
              <td class="p-4 text-sm italic text-slate-400">
                {{ log.notes || '—' }}
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="pagination.lastPage > 1" class="p-4 border-t border-[var(--soc-border)] flex items-center justify-between bg-slate-950/40">
        <p class="text-sm text-slate-400">
          Showing page <span class="font-medium text-slate-100">{{ pagination.currentPage }}</span> of <span class="font-medium text-slate-100">{{ pagination.lastPage }}</span>
          ({{ pagination.total }} total records)
        </p>
        <div class="flex gap-2">
          <button 
            @click="changePage(pagination.currentPage - 1)" 
            :disabled="pagination.currentPage === 1"
            class="px-3 py-1.5 text-sm font-medium text-slate-200 bg-slate-900 border border-[var(--soc-border)] rounded-md hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            Previous
          </button>
          <button 
            @click="changePage(pagination.currentPage + 1)" 
            :disabled="pagination.currentPage === pagination.lastPage"
            class="px-3 py-1.5 text-sm font-medium text-slate-200 bg-slate-900 border border-[var(--soc-border)] rounded-md hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            Next
          </button>
        </div>
      </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import axios from 'axios'
import { RefreshCw, AlertCircle, ClipboardList } from 'lucide-vue-next'

const logs = ref([])
const isLoading = ref(true)
const error = ref(null)

// Store the pagination metadata from Laravel
const pagination = ref({
  currentPage: 1,
  lastPage: 1,
  total: 0
})

const blockDecisions = computed(() => logs.value.filter(log => log.decision === 'BLOCK').length)
const allowDecisions = computed(() => logs.value.filter(log => log.decision === 'ALLOW').length)
const notedDecisions = computed(() => logs.value.filter(log => Boolean(log.notes)).length)

const fetchAuditLogs = async (page = 1) => {
  isLoading.value = true
  error.value = null
  
  try {
    // Pass the page number to Laravel
    const response = await axios.get(`/api/firewall/interventions?page=${page}`)
    
    // Extract the actual array of logs from Laravel's 'data' wrapper
    logs.value = response.data.data
    
    // Update our local pagination state
    pagination.value = {
      currentPage: response.data.current_page,
      lastPage: response.data.last_page,
      total: response.data.total
    }
  } catch (err) {
    console.error("Failed to fetch audit logs:", err)
    error.value = "Failed to load the audit trail."
  } finally {
    isLoading.value = false
  }
}

const changePage = (newPage) => {
  if (newPage >= 1 && newPage <= pagination.value.lastPage) {
    fetchAuditLogs(newPage)
  }
}

const describeContext = (log) => {
  const parts = []

  if (log.port !== null && log.port !== undefined) {
    parts.push(`Port ${log.port}`)
  }

  if (log.confidence !== null && log.confidence !== undefined) {
    const confidence = Number(log.confidence)
    parts.push(`Confidence ${(confidence <= 1 ? confidence * 100 : confidence).toFixed(1)}%`)
  }

  if (log.action) {
    parts.push(log.action.replace('_', ' '))
  }

  return parts.length > 0 ? parts.join(' • ') : 'Manual intervention'
}

onMounted(() => {
  fetchAuditLogs()
})
</script>
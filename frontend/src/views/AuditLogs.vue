<template>
  <div class="space-y-6">
    <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
      <div class="p-6 border-b border-gray-100 flex items-center justify-between bg-white">
        <div class="flex items-center gap-3">
          <div class="p-2 bg-indigo-50 rounded-lg text-indigo-600">
            <ClipboardList class="w-5 h-5" />
          </div>
          <h3 class="text-lg font-semibold text-gray-800">Analyst Audit Trail</h3>
        </div>
        <button @click="fetchAuditLogs" class="flex items-center gap-2 text-sm text-blue-600 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-md transition-colors" :disabled="isLoading">
          <RefreshCw :class="{'animate-spin': isLoading}" class="w-4 h-4" />
          Refresh
        </button>
      </div>

      <div v-if="error" class="p-6 text-red-500 text-sm flex items-center gap-2">
        <AlertCircle class="w-5 h-5" /> {{ error }}
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-gray-50 text-gray-600 text-sm border-b border-gray-200">
              <th class="p-4 font-medium">Timestamp</th>
              <th class="p-4 font-medium">Target IP</th>
              <th class="p-4 font-medium">Analyst Decision</th>
              <th class="p-4 font-medium">Notes</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-if="isLoading && logs.length === 0">
              <td colspan="4" class="p-8 text-center text-gray-400">Loading audit trail...</td>
            </tr>
            <tr v-else-if="logs.length === 0">
              <td colspan="4" class="p-8 text-center text-gray-400">No human interventions recorded yet.</td>
            </tr>
            <tr v-for="log in logs" :key="log.id" class="hover:bg-gray-50 transition-colors">
              <td class="p-4 text-sm text-gray-500">{{ new Date(log.created_at).toLocaleString() }}</td>
              <td class="p-4 font-mono text-sm font-semibold text-gray-800">{{ log.ip_address }}</td>
              <td class="p-4">
                <span :class="{
                  'px-3 py-1 text-xs font-semibold rounded-full': true,
                  'bg-red-100 text-red-700': log.decision === 'BLOCK',
                  'bg-green-100 text-green-700': log.decision === 'ALLOW'
                }">
                  {{ log.decision }}
                </span>
              </td>
              <td class="p-4 text-sm text-gray-500 italic">
                {{ log.notes || '—' }}
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="pagination.lastPage > 1" class="p-4 border-t border-gray-100 flex items-center justify-between bg-gray-50">
        <p class="text-sm text-gray-500">
          Showing page <span class="font-medium text-gray-900">{{ pagination.currentPage }}</span> of <span class="font-medium text-gray-900">{{ pagination.lastPage }}</span>
          ({{ pagination.total }} total records)
        </p>
        <div class="flex gap-2">
          <button 
            @click="changePage(pagination.currentPage - 1)" 
            :disabled="pagination.currentPage === 1"
            class="px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            Previous
          </button>
          <button 
            @click="changePage(pagination.currentPage + 1)" 
            :disabled="pagination.currentPage === pagination.lastPage"
            class="px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition"
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
import { ref, onMounted } from 'vue'
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

onMounted(() => {
  fetchAuditLogs()
})
</script>
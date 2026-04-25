<template>
  <div class="space-y-6">
    <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
      <div class="p-6 border-b border-gray-100 flex items-center justify-between bg-white">
        <h3 class="text-lg font-semibold text-gray-800">Historical Training Logs</h3>
        <button @click="fetchLogs" class="flex items-center gap-2 text-sm text-blue-600 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-md transition-colors" :disabled="isLoading">
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
              <th class="p-4 font-medium">Epoch</th>
              <th class="p-4 font-medium">Epsilon (Exploration)</th>
              <th class="p-4 font-medium">Cumulative Reward</th>
              <th class="p-4 font-medium">Avg Loss</th>
              <th class="p-4 font-medium">Threats Blocked</th>
              <th class="p-4 font-medium">Threats Allowed</th>
              <th class="p-4 font-medium">Timestamp</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-if="isLoading && logs.length === 0">
              <td colspan="7" class="p-8 text-center text-gray-400">Loading metrics...</td>
            </tr>
            <tr v-else-if="logs.length === 0">
              <td colspan="7" class="p-8 text-center text-gray-400">No training data recorded yet.</td>
            </tr>
            <tr v-for="log in logs" :key="log.id" class="hover:bg-gray-50 transition-colors">
              <td class="p-4 font-medium text-gray-900">{{ log.epoch }}</td>
              <td class="p-4 text-sm text-gray-600 font-mono">{{ log.epsilon.toFixed(4) }}</td>
              <td class="p-4 text-sm">
                <span :class="log.cumulative_reward >= 0 ? 'text-green-600 font-semibold' : 'text-red-600'">
                  {{ log.cumulative_reward }}
                </span>
              </td>
              <td class="p-4 text-sm text-gray-600">{{ log.loss ? log.loss.toFixed(4) : 'N/A' }}</td>
              <td class="p-4 text-sm text-gray-600">{{ log.threats_blocked }}</td>
              <td class="p-4 text-sm text-gray-600">{{ log.threats_allowed }}</td>
              <td class="p-4 text-xs text-gray-500">{{ new Date(log.created_at).toLocaleString() }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { RefreshCw, AlertCircle } from 'lucide-vue-next'

const logs = ref([])
const isLoading = ref(true)
const error = ref(null)

const fetchLogs = async () => {
  isLoading.value = true
  error.value = null
  
  try {
    const response = await axios.get('/api/ai/logs')
    logs.value = response.data
  } catch (err) {
    console.error("Failed to fetch training logs:", err)
    error.value = "Failed to load historical data."
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchLogs()
})
</script>
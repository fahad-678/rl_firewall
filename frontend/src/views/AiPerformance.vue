<template>
  <div class="space-y-6">
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
      <div class="flex items-center justify-between mb-6">
        <h3 class="text-lg font-semibold text-gray-800">Agent Reward Trajectory</h3>
        
        <button @click="fetchPerformanceData" class="flex items-center gap-2 text-sm text-blue-600 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-md transition-colors" :disabled="isLoading">
          <RefreshCw :class="{'animate-spin': isLoading}" class="w-4 h-4" />
          {{ isLoading ? 'Loading...' : 'Refresh Data' }}
        </button>
      </div>

      <div class="h-96 relative flex items-center justify-center">
        <div v-if="error" class="text-red-500 text-sm flex flex-col items-center">
          <AlertCircle class="w-8 h-8 mb-2" />
          {{ error }}
        </div>
        
        <Line v-else-if="!isLoading && chartData.labels.length > 0" :data="chartData" :options="chartOptions" />
        
        <div v-else-if="!isLoading" class="text-gray-400 text-sm">
          No training data available yet.
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue' // Added onUnmounted
import axios from 'axios'
import { RefreshCw, AlertCircle } from 'lucide-vue-next'
import { Line } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend)

const isLoading = ref(true)
const error = ref(null)
let refreshInterval = null // Variable to store our timer ID

const chartData = ref({
  labels: [],
  datasets: [
    {
      label: 'Cumulative Reward',
      backgroundColor: '#3b82f6',
      borderColor: '#3b82f6',
      data: [],
      tension: 0.4,
      pointBackgroundColor: '#ffffff',
      pointBorderWidth: 2,
      pointRadius: 4
    }
  ]
})

const chartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  animation: {
    duration: 0 // Disable animations on data refresh so the chart doesn't bounce constantly
  },
  plugins: {
    legend: { position: 'top' },
    tooltip: { mode: 'index', intersect: false }
  },
  scales: {
    y: { title: { display: true, text: 'Reward Score' }, grid: { color: '#f3f4f6' } },
    x: { title: { display: true, text: 'Training Epoch' }, grid: { display: false } }
  }
})

// Added 'isBackground' parameter to prevent UI flickering
const fetchPerformanceData = async (isBackground = false) => {
  if (!isBackground) {
    isLoading.value = true
  }
  error.value = null
  
  try {
    const response = await axios.get('/api/ai/performance')
    
    chartData.value = {
      ...chartData.value,
      labels: response.data.epochs,
      datasets: [
        {
          ...chartData.value.datasets[0],
          data: response.data.rewards
        }
      ]
    }
  } catch (err) {
    console.error("Failed to fetch AI performance data:", err)
    // Only show the hard error UI if we don't already have chart data displayed
    if (!isBackground || chartData.value.labels.length === 0) {
      error.value = "Failed to load training metrics. Is the backend running?"
    }
  } finally {
    if (!isBackground) {
      isLoading.value = false
    }
  }
}

// Fetch data on load, then set up the background polling
onMounted(() => {
  fetchPerformanceData() // Initial explicit load with spinner
  
  // Poll the API every 3 seconds (3000 ms) silently
  refreshInterval = setInterval(() => {
    fetchPerformanceData(true) 
  }, 3000)
})

// CRITICAL: Clean up the interval when leaving the page
onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
})
</script>
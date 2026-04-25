<template>
  <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
    <div class="flex justify-between items-center mb-6">
      <div>
        <h3 class="text-lg font-semibold text-gray-800">DQN Learning Curve</h3>
        <p class="text-sm text-gray-500">Cumulative reward per 100-packet epoch</p>
      </div>
      <button @click="fetchData" class="text-sm bg-blue-50 text-blue-600 px-3 py-1.5 rounded-md hover:bg-blue-100 transition">
        Refresh Data
      </button>
    </div>

    <div class="h-80 w-full relative">
      <div v-if="isLoading" class="absolute inset-0 flex items-center justify-center bg-white/80 z-10">
        <span class="animate-pulse text-gray-500 font-medium">Aggregating Training Logs...</span>
      </div>
      <Line v-if="chartData.labels.length > 0" :data="chartData" :options="chartOptions" />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from 'axios'
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, Filler
} from 'chart.js'
import { Line } from 'vue-chartjs'

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

const isLoading = ref(true)
const chartData = ref({ labels: [], datasets: [] })

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    y: {
      title: { display: true, text: 'Cumulative Reward' },
      grid: { color: '#f3f4f6' }
    },
    x: {
      grid: { display: false }
    }
  },
  plugins: {
    legend: { display: false },
    tooltip: { mode: 'index', intersect: false }
  }
}

const fetchData = async () => {
  isLoading.value = true
  try {
    const response = await axios.get('/api/ai/performance')
    
    chartData.value = {
      labels: response.data.epochs, // e.g., ["Epoch 1", "Epoch 2", ...]
      datasets: [
        {
          label: 'Reward Signal',
          data: response.data.rewards, // e.g., [-150, 40, 120, 210, ...]
          borderColor: '#2563eb', // Blue-600
          backgroundColor: 'rgba(37, 99, 235, 0.1)',
          borderWidth: 2,
          pointBackgroundColor: '#ffffff',
          pointBorderColor: '#2563eb',
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true,
          tension: 0.3 // Smooth curves
        }
      ]
    }
  } catch (error) {
    console.error("Failed to load AI performance data:", error)
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchData()
})
</script>
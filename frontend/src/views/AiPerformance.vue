<template>
  <div class="space-y-5">
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Latest Reward</p>
        <p class="mt-2 text-2xl font-semibold text-cyan-100">{{ latestReward }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Best Reward</p>
        <p class="mt-2 text-2xl font-semibold text-emerald-200">{{ bestReward }}</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Reward Delta</p>
        <p class="mt-2 text-2xl font-semibold" :class="rewardDelta >= 0 ? 'text-emerald-200' : 'text-rose-200'">
          {{ rewardDelta >= 0 ? '+' : '' }}{{ rewardDelta }}
        </p>
      </article>
    </div>

    <div class="soc-panel rounded-xl p-6">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h3 class="text-lg font-semibold text-slate-100">DQN Reward Curve</h3>
          <p class="mt-1 text-sm text-slate-400">Cumulative reward trajectory across recent training epochs</p>
        </div>
        <button
          @click="fetchData"
          class="rounded-lg border border-[var(--soc-border)] bg-slate-900/70 px-3 py-1.5 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-800"
        >
          Refresh Data
        </button>
      </div>

      <div class="relative h-80 w-full">
        <div v-if="isLoading" class="absolute inset-0 z-10 flex items-center justify-center bg-slate-950/40 backdrop-blur-sm">
          <span class="animate-pulse text-sm font-medium text-slate-300">Aggregating training telemetry...</span>
        </div>
        <Line v-if="chartData.labels.length > 0" :data="chartData" :options="chartOptions" />
        <div v-else-if="!isLoading" class="flex h-full items-center justify-center text-sm text-slate-400">
          No reward history available yet.
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
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
const rewardValues = ref([])

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    y: {
      title: { display: true, text: 'Cumulative Reward', color: '#9fb2c8' },
      ticks: { color: '#8ca0b8' },
      grid: { color: 'rgba(76, 94, 118, 0.35)' }
    },
    x: {
      ticks: { color: '#8ca0b8' },
      grid: { color: 'rgba(76, 94, 118, 0.2)' }
    }
  },
  plugins: {
    legend: { display: false },
    title: {
      display: false
    },
    tooltip: { mode: 'index', intersect: false }
  }
}

const latestReward = computed(() => {
  if (rewardValues.value.length === 0) return 'N/A'
  return rewardValues.value[rewardValues.value.length - 1]
})

const bestReward = computed(() => {
  if (rewardValues.value.length === 0) return 'N/A'
  return Math.max(...rewardValues.value)
})

const rewardDelta = computed(() => {
  if (rewardValues.value.length < 2) return 0
  const current = rewardValues.value[rewardValues.value.length - 1]
  const previous = rewardValues.value[rewardValues.value.length - 2]
  return Number((current - previous).toFixed(2))
})

const fetchData = async () => {
  isLoading.value = true
  try {
    const response = await axios.get('/api/ai/performance')
    
    rewardValues.value = response.data.rewards || []

    chartData.value = {
      labels: response.data.epochs, // e.g., ["Epoch 1", "Epoch 2", ...]
      datasets: [
        {
          label: 'Reward Signal',
          data: rewardValues.value,
          borderColor: '#2ec4b6',
          backgroundColor: 'rgba(46, 196, 182, 0.14)',
          borderWidth: 2.5,
          pointBackgroundColor: '#0f172a',
          pointBorderColor: '#2ec4b6',
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true,
          tension: 0.32
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
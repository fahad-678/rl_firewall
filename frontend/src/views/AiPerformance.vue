<template>
  <div class="space-y-6">
    <section class="soc-panel rounded-2xl p-5 sm:p-6">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p class="text-xs uppercase tracking-[0.32em] text-[var(--soc-accent)]">Learning Analytics</p>
          <h2 class="mt-2 text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">Reward signal over time</h2>
          <p class="mt-2 max-w-2xl text-sm text-slate-400">
            Monitor how the firewall policy converges as analysts confirm blocks and allow exceptions.
          </p>
        </div>

        <button
          @click="fetchData"
          class="rounded-xl border border-[var(--soc-border)] bg-slate-900/70 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-800"
        >
          Refresh Data
        </button>
      </div>
    </section>

    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Latest Reward</p>
        <p class="mt-2 text-2xl font-semibold text-cyan-100">{{ latestReward }}</p>
        <p class="mt-1 text-xs text-slate-400">Most recent training epoch</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Best Reward</p>
        <p class="mt-2 text-2xl font-semibold text-emerald-200">{{ bestReward }}</p>
        <p class="mt-1 text-xs text-slate-400">Peak cumulative reward</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Reward Delta</p>
        <p class="mt-2 text-2xl font-semibold" :class="rewardDelta >= 0 ? 'text-emerald-200' : 'text-rose-200'">
          {{ rewardDelta >= 0 ? '+' : '' }}{{ rewardDelta }}
        </p>
        <p class="mt-1 text-xs text-slate-400">Change vs. previous epoch</p>
      </article>
      <article class="soc-panel rounded-xl p-4">
        <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Average Reward</p>
        <p class="mt-2 text-2xl font-semibold text-sky-200">{{ averageReward }}</p>
        <p class="mt-1 text-xs text-slate-400">Rolling mean across loaded history</p>
      </article>
    </div>

    <div class="soc-panel rounded-2xl p-5 sm:p-6">
      <div class="mb-5 flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h3 class="text-lg font-semibold text-slate-100">DQN Reward Curve</h3>
          <p class="mt-1 text-sm text-slate-400">Cumulative reward trajectory across recent training epochs</p>
        </div>
        <div class="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-400">
          <span class="rounded-full border border-[var(--soc-border)] bg-slate-950/50 px-3 py-1">{{ learningMomentum }} momentum</span>
          <span class="rounded-full border border-[var(--soc-border)] bg-slate-950/50 px-3 py-1">{{ rewardValues.length }} epochs</span>
        </div>
      </div>

      <div class="relative h-80 w-full">
        <div v-if="isLoading" class="absolute inset-0 z-10 flex items-center justify-center rounded-2xl bg-slate-950/40 backdrop-blur-sm">
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
  return Number(rewardValues.value[rewardValues.value.length - 1]).toFixed(2)
})

const bestReward = computed(() => {
  if (rewardValues.value.length === 0) return 'N/A'
  return Math.max(...rewardValues.value).toFixed(2)
})

const rewardDelta = computed(() => {
  if (rewardValues.value.length < 2) return 0
  const current = rewardValues.value[rewardValues.value.length - 1]
  const previous = rewardValues.value[rewardValues.value.length - 2]
  return Number((current - previous).toFixed(2))
})

const averageReward = computed(() => {
  if (rewardValues.value.length === 0) return 'N/A'
  const total = rewardValues.value.reduce((sum, value) => sum + Number(value), 0)
  return (total / rewardValues.value.length).toFixed(2)
})

const learningMomentum = computed(() => {
  if (rewardValues.value.length < 4) return 'stable'

  const recent = rewardValues.value.slice(-4)
  const slope = recent[recent.length - 1] - recent[0]

  if (slope > 0) return 'upward'
  if (slope < 0) return 'downward'
  return 'stable'
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
          borderColor: '#3dd6c6',
          backgroundColor: 'rgba(61, 214, 198, 0.12)',
          borderWidth: 2.5,
          pointBackgroundColor: '#09131b',
          pointBorderColor: '#3dd6c6',
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
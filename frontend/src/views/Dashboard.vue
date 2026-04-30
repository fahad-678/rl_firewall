<template>
  <div class="relative space-y-6">
    <transition name="fade">
      <div
        v-if="errorMessage"
        class="fixed bottom-5 right-5 z-50 flex items-center gap-3 rounded-lg border border-rose-500/30 bg-rose-500/15 px-4 py-3 text-rose-100 shadow-lg"
      >
        <AlertTriangle class="h-5 w-5" />
        <span class="text-sm font-medium">{{ errorMessage }}</span>
      </div>
    </transition>

    <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article class="soc-panel stagger-in rounded-xl p-4" style="animation-delay: 60ms">
        <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Active Queue</p>
        <p class="mt-2 text-3xl font-semibold text-cyan-100">{{ filteredThreats.length }}</p>
        <p class="mt-1 text-xs text-slate-400">Filtered incidents ready for analyst action</p>
      </article>

      <article class="soc-panel stagger-in rounded-xl p-4" style="animation-delay: 120ms">
        <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Blocked Threats</p>
        <p class="mt-2 text-3xl font-semibold text-rose-300">{{ blockedCount }}</p>
        <p class="mt-1 text-xs text-slate-400">Containment decisions enforced</p>
      </article>

      <article class="soc-panel stagger-in rounded-xl p-4" style="animation-delay: 180ms">
        <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Pending Review</p>
        <p class="mt-2 text-3xl font-semibold text-amber-300">{{ pendingReviewCount }}</p>
        <p class="mt-1 text-xs text-slate-400">Human-in-the-loop interventions required</p>
      </article>

      <article class="soc-panel stagger-in rounded-xl p-4" style="animation-delay: 240ms">
        <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Avg Confidence</p>
        <p class="mt-2 text-3xl font-semibold text-emerald-300">{{ avgConfidence }}%</p>
        <p class="mt-1 text-xs text-slate-400">Model certainty across visible queue</p>
      </article>
    </section>

    <section class="soc-panel rounded-xl p-4 sm:p-5">
      <div class="grid grid-cols-1 gap-3 lg:grid-cols-4">
        <div>
          <label class="text-xs uppercase tracking-[0.2em] text-slate-400">Action</label>
          <select
            v-model="filters.action"
            class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:ring-0"
          >
            <option value="ALL">All Actions</option>
            <option value="NEEDS_REVIEW">Needs Review</option>
            <option value="BLOCKED">Blocked</option>
            <option value="ACCEPTED">Accepted</option>
            <option value="RATE_LIMITED">Rate Limited</option>
          </select>
        </div>

        <div>
          <label class="text-xs uppercase tracking-[0.2em] text-slate-400">Port</label>
          <input
            v-model="filters.port"
            type="text"
            placeholder="e.g. 22"
            class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500"
          />
        </div>

        <div>
          <label class="text-xs uppercase tracking-[0.2em] text-slate-400">IP Contains</label>
          <input
            v-model="filters.ip"
            type="text"
            placeholder="192.168"
            class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500"
          />
        </div>

        <div class="flex items-end gap-3">
          <button
            @click="resetFilters"
            class="w-full rounded-lg border border-[var(--soc-border)] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-800"
          >
            Reset Filters
          </button>
        </div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-6 xl:grid-cols-[1.6fr_1fr]">
      <article class="soc-panel rounded-xl overflow-hidden">
        <div class="border-b border-[var(--soc-border)] px-5 py-4">
          <h3 class="text-lg font-semibold text-slate-100">Live Threat Queue</h3>
          <p class="mt-1 text-xs text-slate-400">Streaming from firewall telemetry and intervention history</p>
        </div>

        <div class="max-h-[560px] overflow-y-auto">
          <div v-if="isLoading" class="p-8 text-center text-sm text-slate-400">Synchronizing telemetry feed...</div>
          <div v-else-if="filteredThreats.length === 0" class="p-8 text-center text-sm text-slate-400">No incidents match the current filters.</div>

          <transition-group name="list" tag="div" class="divide-y divide-[var(--soc-border)]">
            <button
              v-for="threat in filteredThreats"
              :key="threat.id"
              @click="selectedThreatId = threat.id"
              class="w-full px-5 py-4 text-left transition-colors"
              :class="selectedThreatId === threat.id ? 'bg-cyan-500/10' : 'hover:bg-slate-800/50'"
            >
              <div class="flex items-start justify-between gap-4">
                <div>
                  <p class="font-mono text-sm font-semibold text-slate-100">{{ threat.src_ip }}</p>
                  <p class="mt-1 text-xs text-slate-400">Port {{ threat.port ?? 'N/A' }} • {{ formatTime(threat.timestamp) }}</p>
                </div>
                <span :class="getStatusBadge(threat.action)" class="rounded-md px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.07em]">
                  {{ threat.actionLabel }}
                </span>
              </div>

              <div class="mt-3 flex items-center gap-3">
                <div class="h-1.5 w-24 overflow-hidden rounded-full bg-slate-800">
                  <div
                    :class="getConfidenceColor(threat.confidence)"
                    class="h-full rounded-full transition-all duration-500"
                    :style="{ width: `${threat.confidencePercent}%` }"
                  ></div>
                </div>
                <p class="text-xs font-semibold text-slate-300">{{ threat.confidencePercent }}% confidence</p>
              </div>
            </button>
          </transition-group>
        </div>
      </article>

      <article class="soc-panel rounded-xl p-5">
        <h3 class="text-lg font-semibold text-slate-100">Incident Detail</h3>
        <p class="mt-1 text-xs text-slate-400">Review context and trigger containment actions</p>

        <div v-if="selectedThreat" class="mt-5 space-y-4">
          <div class="rounded-lg border border-[var(--soc-border)] bg-slate-900/70 p-4">
            <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Source IP</p>
            <p class="mt-2 font-mono text-xl font-semibold text-slate-100">{{ selectedThreat.src_ip }}</p>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div class="rounded-lg border border-[var(--soc-border)] bg-slate-900/70 p-3">
              <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Port</p>
              <p class="mt-2 text-lg font-semibold text-slate-200">{{ selectedThreat.port ?? 'N/A' }}</p>
            </div>
            <div class="rounded-lg border border-[var(--soc-border)] bg-slate-900/70 p-3">
              <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Confidence</p>
              <p class="mt-2 text-lg font-semibold text-slate-200">{{ selectedThreat.confidencePercent }}%</p>
            </div>
          </div>

          <div class="rounded-lg border border-[var(--soc-border)] bg-slate-900/70 p-3">
            <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Current Status</p>
            <span :class="getStatusBadge(selectedThreat.action)" class="mt-2 inline-flex rounded-md px-2 py-1 text-xs font-semibold uppercase tracking-[0.06em]">
              {{ selectedThreat.actionLabel }}
            </span>
          </div>

          <div class="rounded-lg border border-[var(--soc-border)] bg-slate-900/70 p-3">
            <p class="text-xs uppercase tracking-[0.2em] text-slate-400">Detected At</p>
            <p class="mt-2 text-sm text-slate-200">{{ formatTime(selectedThreat.timestamp) }}</p>
          </div>

          <div class="grid grid-cols-2 gap-3 pt-2">
            <button
              @click="submitReview(selectedThreat, 'BLOCK')"
              :disabled="selectedThreat.action !== 'NEEDS_REVIEW'"
              class="rounded-lg bg-rose-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-rose-500 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Block Source
            </button>
            <button
              @click="submitReview(selectedThreat, 'ALLOW')"
              :disabled="selectedThreat.action !== 'NEEDS_REVIEW'"
              class="rounded-lg border border-[var(--soc-border)] px-4 py-2 text-sm font-semibold text-slate-100 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Allow Source
            </button>
          </div>

          <button
            @click="overrideBlock(selectedThreat.src_ip)"
            :disabled="selectedThreat.action !== 'BLOCKED'"
            class="w-full rounded-lg border border-amber-400/30 bg-amber-400/10 px-4 py-2 text-sm font-semibold text-amber-200 transition-colors hover:bg-amber-400/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Revoke Block
          </button>
        </div>

        <div v-else class="mt-10 rounded-lg border border-dashed border-[var(--soc-border)] p-6 text-center text-sm text-slate-400">
          Select an incident from the queue to review details and apply actions.
        </div>
      </article>
    </section>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { AlertTriangle } from 'lucide-vue-next';
import echo from '../services/echo';
import axios from 'axios';

// --- STATE ---
const threatLog = ref([]);
const errorMessage = ref('');
const isLoading = ref(true);
const selectedThreatId = ref(null);
const filters = ref({
  action: 'ALL',
  port: '',
  ip: ''
});

let fallbackId = 0;

// --- COMPUTED ---
const blockedCount = computed(() => threatLog.value.filter(t => t.action === 'BLOCKED').length);
const pendingReviewCount = computed(() => threatLog.value.filter(t => t.action === 'NEEDS_REVIEW').length);
const avgConfidence = computed(() => {
  if (threatLog.value.length === 0) return 0;
  const total = threatLog.value.reduce((sum, item) => sum + item.confidence, 0);
  return Math.round((total / threatLog.value.length) * 100);
});

const filteredThreats = computed(() => {
  return threatLog.value.filter((threat) => {
    const actionMatch = filters.value.action === 'ALL' || threat.action === filters.value.action;
    const portMatch = filters.value.port.trim() === '' || String(threat.port ?? '').includes(filters.value.port.trim());
    const ipMatch = filters.value.ip.trim() === '' || String(threat.src_ip ?? '').includes(filters.value.ip.trim());
    return actionMatch && portMatch && ipMatch;
  });
});

const selectedThreat = computed(() => {
  return threatLog.value.find((threat) => threat.id === selectedThreatId.value) || null;
});

const normalizeAction = (threat) => {
  if (threat.action) return threat.action;
  if (threat.decision === 'BLOCK') return 'BLOCKED';
  if (threat.decision === 'ALLOW') return 'ACCEPTED';
  return 'UNKNOWN';
};

const normalizeThreat = (threat) => {
  const action = normalizeAction(threat);
  const confidenceRaw = Number(threat.confidence);
  const confidence = Number.isFinite(confidenceRaw)
    ? confidenceRaw > 1 ? Math.min(confidenceRaw / 100, 1) : Math.max(confidenceRaw, 0)
    : 0;

  const id = threat.id || `${threat.src_ip || threat.ip_address || 'unknown'}-${threat.timestamp || threat.created_at || Date.now()}-${fallbackId++}`;
  const srcIp = threat.src_ip || threat.ip_address || 'Unknown source';
  const timestamp = threat.timestamp || threat.created_at || new Date().toISOString();

  return {
    ...threat,
    id,
    src_ip: srcIp,
    action,
    actionLabel: action.replace('_', ' '),
    confidence,
    confidencePercent: Math.round(confidence * 100),
    timestamp
  };
};

const resetFilters = () => {
  filters.value.action = 'ALL';
  filters.value.port = '';
  filters.value.ip = '';
};

// --- LIFECYCLE & DATA HYDRATION ---
const fetchInitialTelemetry = async () => {
  try {
    isLoading.value = true;
    const response = await axios.get('/api/firewall/recent-telemetry');

    threatLog.value = response.data.map((threat) => normalizeThreat(threat));
    if (threatLog.value.length > 0) {
      selectedThreatId.value = threatLog.value[0].id;
    }
  } catch (error) {
    console.error("Failed to fetch historical telemetry", error);
    showError("Could not load recent threat history. Connecting to live feed only.");
  } finally {
    isLoading.value = false;
  }
};

onMounted(async () => {
  await fetchInitialTelemetry();

  echo.channel('firewall-telemetry')
      .listen('.threat.detected', (e) => {
          const threat = normalizeThreat(e.telemetryData);
          threatLog.value.unshift(threat);

          if (!selectedThreatId.value) {
            selectedThreatId.value = threat.id;
          }

          if (threatLog.value.length > 50) {
              threatLog.value.pop();
          }
      });
});

// --- UI HELPER FUNCTIONS ---
const formatTime = (dateStringOrDate) => {
  const date = typeof dateStringOrDate === 'string' ? new Date(dateStringOrDate) : dateStringOrDate;
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

const getConfidenceColor = (confidence) => {
  if (confidence >= 0.85) return 'bg-blue-500';
  if (confidence >= 0.50) return 'bg-yellow-400';
  return 'bg-red-400';
};

const getStatusBadge = (action) => {
  const baseClasses = 'inline-flex items-center';
  switch (action) {
    case 'BLOCKED': return `${baseClasses} border border-rose-400/40 bg-rose-500/15 text-rose-200`;
    case 'ACCEPTED': return `${baseClasses} border border-emerald-400/40 bg-emerald-500/15 text-emerald-200`;
    case 'RATE_LIMITED': return `${baseClasses} border border-amber-400/40 bg-amber-500/15 text-amber-200`;
    case 'NEEDS_REVIEW': return `${baseClasses} border border-yellow-400/40 bg-yellow-400/15 text-yellow-200`;
    default: return `${baseClasses} border border-slate-500/40 bg-slate-600/25 text-slate-200`;
  }
};

const showError = (msg) => {
  errorMessage.value = msg;
  setTimeout(() => { errorMessage.value = ''; }, 4000);
};

// --- API ACTIONS ---
const submitReview = async (threat, decision) => {
  const originalAction = threat.action;

  threat.action = decision === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED';
  threat.actionLabel = threat.action.replace('_', ' ');

  try {
    await axios.post('/api/firewall/review', { 
      ip: threat.src_ip, 
      decision: decision 
    });
  } catch (error) {
    console.error("Failed to submit analyst review", error);
    threat.action = originalAction;
    threat.actionLabel = threat.action.replace('_', ' ');
    showError(`Failed to apply decision for ${threat.src_ip}. Check network connection.`);
  }
};

const overrideBlock = async (ipAddress) => {
  const threat = threatLog.value.find(t => t.src_ip === ipAddress);
  if (!threat) return;

  const originalAction = threat.action;

  threat.action = 'ACCEPTED';
  threat.actionLabel = 'ACCEPTED';

  try {
    await axios.post('/api/firewall/override', { ip: ipAddress });
  } catch (error) {
    console.error("Failed to override block", error);
    threat.action = originalAction;
    threat.actionLabel = threat.action.replace('_', ' ');
    showError(`Failed to revoke block for ${ipAddress}.`);
  }
};
</script>

<style scoped>
.list-enter-active,
.list-leave-active {
  transition: all 0.22s ease;
}

.list-enter-from {
  opacity: 0;
  transform: translateY(-8px);
}

.list-leave-to {
  opacity: 0;
  transform: translateY(8px);
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(8px);
}
</style>
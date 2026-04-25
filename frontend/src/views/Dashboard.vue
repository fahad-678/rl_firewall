<template>
  <div class="space-y-6 relative">
    
    <transition name="fade">
      <div v-if="errorMessage" class="fixed bottom-4 right-4 bg-red-600 text-white px-4 py-3 rounded-lg shadow-lg flex items-center gap-3 z-50">
        <AlertTriangle class="w-5 h-5" />
        <span class="text-sm font-medium">{{ errorMessage }}</span>
      </div>
    </transition>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between hover:-translate-y-1 hover:shadow-md transition-all duration-200">
        <div>
          <p class="text-sm text-gray-500 font-medium">Total Threats Blocked</p>
          <p class="text-3xl font-bold text-red-600 mt-2">{{ blockedCount }}</p>
        </div>
        <div class="p-3 bg-red-50 rounded-full text-red-600"><ShieldAlert /></div>
      </div>
      
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between hover:-translate-y-1 hover:shadow-md transition-all duration-200">
        <div>
          <p class="text-sm text-gray-500 font-medium">Pending Analyst Review</p>
          <p class="text-3xl font-bold text-yellow-600 mt-2">{{ pendingReviewCount }}</p>
        </div>
        <div class="p-3 bg-yellow-50 rounded-full text-yellow-600"><AlertTriangle /></div>
      </div>

      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between hover:-translate-y-1 hover:shadow-md transition-all duration-200">
        <div>
          <p class="text-sm text-gray-500 font-medium">System Status</p>
          <p class="text-xl font-bold text-green-600 mt-2 flex items-center gap-2">
            <span class="w-2.5 h-2.5 bg-green-500 rounded-full animate-pulse"></span> Active
          </p>
        </div>
        <div class="p-3 bg-green-50 rounded-full text-green-600"><Activity /></div>
      </div>
    </div>

    <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
      <div class="p-6 border-b border-gray-100 flex justify-between items-center">
        <h3 class="text-lg font-semibold text-gray-800">Live Threat Feed</h3>
        <span class="text-xs font-medium text-gray-400">Monitoring Port Traffic...</span>
      </div>
      
      <div class="overflow-x-auto min-h-[300px]">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-gray-50 text-gray-600 text-sm border-b border-gray-100">
              <th class="p-4 font-medium w-32">Timestamp</th>
              <th class="p-4 font-medium">Source IP</th>
              <th class="p-4 font-medium">Target Port</th>
              <th class="p-4 font-medium w-48">AI Confidence</th>
              <th class="p-4 font-medium w-40">Status</th>
              <th class="p-4 font-medium w-48">Analyst Action</th>
            </tr>
          </thead>
          
          <transition-group name="list" tag="tbody" class="divide-y divide-gray-100 relative">
            
            <tr v-if="isLoading" key="loading-state">
              <td colspan="6" class="p-8 text-center text-gray-400 text-sm animate-pulse">
                Fetching recent telemetry...
              </td>
            </tr>
            <tr v-else-if="threatLog.length === 0" key="empty-state">
              <td colspan="6" class="p-8 text-center text-gray-400 text-sm">
                No threats detected yet. Awaiting live telemetry...
              </td>
            </tr>

            <tr v-for="threat in threatLog" :key="threat.id || threat.timestamp || threat.src_ip + Math.random()" 
                :class="[
                  threat.action === 'NEEDS_REVIEW' ? 'bg-yellow-50/30' : 'hover:bg-gray-50',
                  'transition-colors duration-200'
                ]">
              <td class="p-4 text-sm text-gray-500 whitespace-nowrap">{{ formatTime(new Date()) }}</td>
              <td class="p-4 font-mono text-sm font-semibold text-gray-700">{{ threat.src_ip }}</td>
              <td class="p-4 text-sm text-gray-600">{{ threat.port }}</td>
              <td class="p-4">
                <div class="flex items-center gap-3">
                  <div class="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                    <div :class="getConfidenceColor(threat.confidence)" 
                         class="h-full transition-all duration-500 rounded-full" 
                         :style="{ width: `${threat.confidence * 100}%` }"></div>
                  </div>
                  <span class="text-xs font-medium text-gray-600">{{ (threat.confidence * 100).toFixed(0) }}%</span>
                </div>
              </td>
              <td class="p-4">
              <span :class="getStatusBadge(threat.action)" class="px-3 py-1 text-xs font-semibold rounded-md inline-block">
                {{ (threat.action || 'UNKNOWN').replace('_', ' ') }}
              </span>
            </td>
              <td class="p-4">
                <div v-if="threat.action === 'NEEDS_REVIEW'" class="flex gap-2">
                  <button @click="submitReview(threat, 'BLOCK')" class="text-xs bg-red-600 text-white px-3 py-1.5 rounded-md hover:bg-red-700 shadow-sm transition transform hover:scale-105 active:scale-95 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-1">
                    Block
                  </button>
                  <button @click="submitReview(threat, 'ALLOW')" class="text-xs bg-white border border-gray-200 text-gray-700 px-3 py-1.5 rounded-md hover:bg-gray-50 shadow-sm transition transform hover:scale-105 active:scale-95 focus:outline-none focus:ring-2 focus:ring-gray-200 focus:ring-offset-1">
                    Allow
                  </button>
                </div>
                <button v-else-if="threat.action === 'BLOCKED'" @click="overrideBlock(threat.src_ip)" class="text-xs text-red-600 font-medium hover:text-red-800 underline underline-offset-2 transition focus:outline-none">
                  Revoke Block
                </button>
                <span v-else class="text-xs text-gray-400 italic flex items-center gap-1">
                  Resolved
                </span>
              </td>
            </tr>
          </transition-group>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { ShieldAlert, AlertTriangle, Activity } from 'lucide-vue-next';
import echo from '../services/echo';
import axios from 'axios';

// --- STATE ---
const threatLog = ref([]);
const errorMessage = ref('');
const isLoading = ref(true); // Track initial data load

// --- COMPUTED ---
const blockedCount = computed(() => threatLog.value.filter(t => t.action === 'BLOCKED').length);
const pendingReviewCount = computed(() => threatLog.value.filter(t => t.action === 'NEEDS_REVIEW').length);

// --- LIFECYCLE & DATA HYDRATION ---
const fetchInitialTelemetry = async () => {
  try {
    isLoading.value = true;
    
    // Fetch the last 50 threats from Laravel
    const response = await axios.get('/api/firewall/recent-telemetry');
    
    // Populate the array, ensuring unique IDs for the Vue transition-group animations
    threatLog.value = response.data.map(threat => ({
      ...threat,
      id: threat.id || crypto.randomUUID()
    }));
    
  } catch (error) {
    console.error("Failed to fetch historical telemetry", error);
    showError("Could not load recent threat history. Connecting to live feed only.");
  } finally {
    isLoading.value = false;
  }
};

onMounted(async () => {
  // 1. Hydrate the dashboard with historical data first
  await fetchInitialTelemetry();

  // 2. Attach WebSocket listener for real-time events
  echo.channel('firewall-telemetry')
      .listen('.threat.detected', (e) => {
          const threat = {
            ...e.telemetryData,
            // Ensure new live rows get a unique ID
            id: crypto.randomUUID() 
          };
          
          threatLog.value.unshift(threat);
          
          // Enforce a maximum of 50 items in the UI memory
          if (threatLog.value.length > 50) {
              threatLog.value.pop();
          }
      });
});

// --- UI HELPER FUNCTIONS ---
const formatTime = (dateStringOrDate) => {
  // Handle both backend ISO strings and frontend Date objects
  const date = typeof dateStringOrDate === 'string' ? new Date(dateStringOrDate) : dateStringOrDate;
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

const getConfidenceColor = (confidence) => {
  if (confidence >= 0.85) return 'bg-blue-500';
  if (confidence >= 0.50) return 'bg-yellow-400';
  return 'bg-red-400';
};

const getStatusBadge = (action) => {
  const baseClasses = 'px-3 py-1 text-xs font-semibold rounded-md inline-block';
  switch (action) {
    case 'BLOCKED': return `${baseClasses} bg-red-50 text-red-700 border border-red-100`;
    case 'ACCEPTED': return `${baseClasses} bg-green-50 text-green-700 border border-green-100`;
    case 'RATE_LIMITED': return `${baseClasses} bg-orange-50 text-orange-700 border border-orange-100`;
    case 'NEEDS_REVIEW': return `${baseClasses} bg-yellow-50 text-yellow-800 animate-pulse border border-yellow-200`;
    default: return `${baseClasses} bg-gray-100 text-gray-700`;
  }
};

const showError = (msg) => {
  errorMessage.value = msg;
  setTimeout(() => { errorMessage.value = ''; }, 4000);
};

// --- API ACTIONS ---
const submitReview = async (threat, decision) => {
  const originalAction = threat.action;
  
  // Optimistic UI Update: Instantly change row status
  threat.action = decision === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED';

  try {
    await axios.post('/api/firewall/review', { 
      ip: threat.src_ip, 
      decision: decision 
    });
  } catch (error) {
    console.error("Failed to submit analyst review", error);
    // CRITICAL FIX: Revert the UI state if the backend request fails
    threat.action = originalAction;
    showError(`Failed to apply decision for ${threat.src_ip}. Check network connection.`);
  }
};

const overrideBlock = async (ipAddress) => {
  const threat = threatLog.value.find(t => t.src_ip === ipAddress);
  if (!threat) return;

  const originalAction = threat.action;
  
  // Optimistic UI Update
  threat.action = 'ACCEPTED';

  try {
    await axios.post('/api/firewall/override', { ip: ipAddress });
  } catch (error) {
    console.error("Failed to override block", error);
    // Revert if failed
    threat.action = originalAction;
    showError(`Failed to revoke block for ${ipAddress}.`);
  }
};
</script>

<style scoped>
/* 1. Force the table to keep strict column widths so it doesn't jiggle */
table {
  table-layout: fixed;
}

/* 2. Speed up the transition so it finishes before the next packet arrives */
.list-enter-active,
.list-leave-active {
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

/* 3. Smooth slide down and fade in */
.list-enter-from {
  opacity: 0;
  transform: translateY(-10px);
  background-color: #fefce8; /* Flash yellow */
}

/* 4. Simple fade out for leaving items */
.list-leave-to {
  opacity: 0;
  transform: scale(0.98);
}

/* CRITICAL FIX: We completely removed .list-leave-active { position: absolute; } 
   and .list-move. This stops the table rows from collapsing and overlapping! */

/* Toast Animation (Keep this as is) */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease, transform 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(10px);
}
</style>
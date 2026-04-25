<template>
  <div class="space-y-6">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between">
        <div>
          <p class="text-sm text-gray-500 font-medium">Total Threats Blocked</p>
          <p class="text-3xl font-bold text-red-600 mt-2">{{ blockedCount }}</p>
        </div>
        <div class="p-3 bg-red-50 rounded-full text-red-600"><ShieldAlert /></div>
      </div>
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between">
        <div>
          <p class="text-sm text-gray-500 font-medium">Pending Analyst Review</p>
          <p class="text-3xl font-bold text-yellow-600 mt-2">{{ pendingReviewCount }}</p>
        </div>
        <div class="p-3 bg-yellow-50 rounded-full text-yellow-600"><AlertTriangle /></div>
      </div>
    </div>

    <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
      <div class="p-6 border-b border-gray-100">
        <h3 class="text-lg font-semibold text-gray-800">Live Threat Feed</h3>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-gray-50 text-gray-600 text-sm">
              <th class="p-4 font-medium">Timestamp</th>
              <th class="p-4 font-medium">Source IP</th>
              <th class="p-4 font-medium">Target Port</th>
              <th class="p-4 font-medium">AI Confidence</th>
              <th class="p-4 font-medium">Status</th>
              <th class="p-4 font-medium">Analyst Action</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="(threat, index) in threatLog" :key="index" 
                :class="{'bg-yellow-50/50': threat.action === 'NEEDS_REVIEW', 'hover:bg-gray-50': threat.action !== 'NEEDS_REVIEW'}" 
                class="transition-colors">
              <td class="p-4 text-sm text-gray-500">{{ new Date().toLocaleTimeString() }}</td>
              <td class="p-4 font-mono text-sm font-semibold">{{ threat.src_ip }}</td>
              <td class="p-4 text-sm">{{ threat.port }}</td>
              <td class="p-4">
                <div class="flex items-center gap-2">
                  <div class="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                    <div :class="threat.confidence < 0.85 ? 'bg-yellow-400' : 'bg-blue-500'" 
                         class="h-full transition-all duration-500" 
                         :style="{ width: `${threat.confidence * 100}%` }"></div>
                  </div>
                  <span class="text-xs text-gray-500">{{ (threat.confidence * 100).toFixed(0) }}%</span>
                </div>
              </td>
              <td class="p-4">
                <span :class="{
                  'px-3 py-1 text-xs font-semibold rounded-full inline-block': true,
                  'bg-red-100 text-red-700': threat.action === 'BLOCKED',
                  'bg-green-100 text-green-700': threat.action === 'ACCEPTED',
                  'bg-orange-100 text-orange-700': threat.action === 'RATE_LIMITED',
                  'bg-yellow-200 text-yellow-800 animate-pulse ring-2 ring-yellow-400': threat.action === 'NEEDS_REVIEW'
                }">
                  {{ threat.action.replace('_', ' ') }}
                </span>
              </td>
              <td class="p-4">
                <div v-if="threat.action === 'NEEDS_REVIEW'" class="flex gap-2">
                  <button @click="submitReview(threat, 'BLOCK')" class="text-xs bg-red-600 text-white px-3 py-1.5 rounded-md hover:bg-red-700 shadow-sm transition">
                    Block
                  </button>
                  <button @click="submitReview(threat, 'ALLOW')" class="text-xs bg-white border border-gray-300 text-gray-700 px-3 py-1.5 rounded-md hover:bg-gray-50 shadow-sm transition">
                    Allow
                  </button>
                </div>
                <button v-else-if="threat.action === 'BLOCKED'" @click="overrideBlock(threat.src_ip)" class="text-xs text-red-600 hover:text-red-800 underline transition">
                  Revoke Block
                </button>
                <span v-else class="text-xs text-gray-400">Resolved</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { ShieldAlert, AlertTriangle } from 'lucide-vue-next'; // Ensure you import AlertTriangle
import echo from '../services/echo';
import axios from 'axios';

const threatLog = ref([]);

// Computed properties to keep stats accurate
const blockedCount = computed(() => threatLog.value.filter(t => t.action === 'BLOCKED').length);
const pendingReviewCount = computed(() => threatLog.value.filter(t => t.action === 'NEEDS_REVIEW').length);

onMounted(() => {
  echo.channel('firewall-telemetry')
      .listen('.threat.detected', (e) => {
          const threat = e.telemetryData;
          threatLog.value.unshift(threat);
          
          if (threatLog.value.length > 50) {
              threatLog.value.pop();
          }
      });
});

// Handles the new manual review buttons
const submitReview = async (threat, decision) => {
  const originalAction = threat.action;
  
  // Optimistic UI Update: Instantly change the row so the user doesn't wait for HTTP latency
  threat.action = decision === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED';

  try {
    // Send the human decision back to Laravel
    await axios.post('/api/firewall/review', { 
      ip: threat.src_ip, 
      decision: decision // 'BLOCK' or 'ALLOW'
    });
  } catch (error) {
    console.error("Failed to submit analyst review", error);
    // Revert the UI if the backend failed
    threat.action = originalAction;
    alert(`Failed to apply decision for ${threat.src_ip}`);
  }
};

// Your existing override method
const overrideBlock = async (ipAddress) => {
  try {
    await axios.post('/api/firewall/override', { ip: ipAddress });
    // Update local state if successful
    const threat = threatLog.value.find(t => t.src_ip === ipAddress);
    if(threat) threat.action = 'ACCEPTED';
  } catch (error) {
    console.error("Failed to override block", error);
  }
};
</script>
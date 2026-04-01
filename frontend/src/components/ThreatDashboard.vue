<template>
  <div class="dashboard">
    <h2>Real-Time Firewall Telemetry</h2>
    
    <div class="stats-grid">
      <div class="stat-card">
        <h3>Total Threats Blocked</h3>
        <p class="large-number">{{ blockedCount }}</p>
      </div>
    </div>

    <h3>Live Threat Feed</h3>
    <table class="threat-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Source IP</th>
          <th>Target Port</th>
          <th>AI Confidence</th>
          <th>Action Taken</th>
          <th>Manual Override</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(threat, index) in threatLog" :key="index" :class="threat.action.toLowerCase()">
          <td>{{ new Date().toLocaleTimeString() }}</td>
          <td>{{ threat.src_ip }}</td>
          <td>{{ threat.port }}</td>
          <td>{{ threat.confidence }}</td>
          <td>{{ threat.action }}</td>
          <td>
             <button v-if="threat.action === 'BLOCKED'" @click="overrideBlock(threat.src_ip)">
              Revoke Block
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import echo from '../services/echo';
import axios from 'axios';

const threatLog = ref([]);
const blockedCount = ref(0);

onMounted(() => {
  // Subscribe to the Reverb WebSocket channel
  echo.channel('firewall-telemetry')
      .listen('.threat.detected', (e) => {
          const threat = e.telemetryData;
          
          // Unshift to add new threats to the top of the list
          threatLog.value.unshift(threat);
          
          if (threat.action === 'BLOCKED') {
              blockedCount.value++;
          }
          
          // Keep array size manageable
          if (threatLog.value.length > 50) {
              threatLog.value.pop();
          }
      });
});

const overrideBlock = async (ipAddress) => {
  try {
    // Phase 4: Human-in-the-loop intervention
    // Sends a request to Laravel, which will push a command back to Python to unblock
    await axios.post('/api/firewall/override', { ip: ipAddress });
    alert(`Override command sent for ${ipAddress}`);
  } catch (error) {
    console.error("Failed to override block", error);
  }
};
</script>

<style scoped>
/* Basic styling for visibility */
.blocked { color: #dc2626; font-weight: bold; }
.accepted { color: #16a34a; }
.rate_limited { color: #d97706; }
.threat-table { width: 100%; text-align: left; margin-top: 20px; }
</style>
<template>
  <div class="min-h-screen bg-slate-950 text-white">
    <div class="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 class="text-3xl font-bold">AI Rules</h1>
          <p class="text-slate-400 mt-2">
            Read-only view of firewall rules the AI is currently enforcing. These rules are
            ephemeral and expire automatically. Manual rules take precedence and are listed
            separately under Manual Rules.
          </p>
        </div>
        <div class="flex items-center gap-3">
          <span
            :class="[
              'inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border',
              agentOnline
                ? 'bg-emerald-900/30 text-emerald-300 border-emerald-700'
                : 'bg-red-900/30 text-red-300 border-red-700',
            ]"
          >
            <span
              :class="[
                'h-2 w-2 rounded-full',
                agentOnline ? 'bg-emerald-400' : 'bg-red-400',
              ]"
            ></span>
            {{ agentOnline ? 'Agent online' : 'Agent offline' }}
          </span>
          <span v-if="lastHeartbeat" class="text-xs text-slate-500">
            Heartbeat {{ formatHeartbeat(lastHeartbeat) }}
          </span>
        </div>
      </div>

      <div class="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
        <div v-if="loading" class="flex items-center justify-center h-64">
          <div class="text-center">
            <div class="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
            <p class="text-slate-400 mt-4">Loading AI rules...</p>
          </div>
        </div>

        <div v-else-if="error" class="p-6 bg-red-900/20 border-l-4 border-red-500">
          <p class="text-red-200">{{ error }}</p>
          <button
            @click="fetchRules"
            class="mt-3 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-sm transition"
          >
            Retry
          </button>
        </div>

        <div v-else-if="!agentOnline" class="p-12 text-center">
          <h3 class="text-lg font-medium text-slate-300">Agent is not reporting</h3>
          <p class="text-slate-400 mt-2 max-w-md mx-auto">
            The AI agent hasn't published a snapshot recently. If the agent is running, check
            the Redis connection or the publish thread logs.
          </p>
        </div>

        <div v-else-if="rules.length === 0" class="p-12 text-center">
          <h3 class="text-lg font-medium text-slate-300">No AI rules active</h3>
          <p class="text-slate-400 mt-1">The AI hasn't deployed any rules right now.</p>
        </div>

        <table v-else class="w-full divide-y divide-slate-800">
          <thead class="bg-slate-800/50 border-b border-slate-700">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">IP / CIDR</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Verdict</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Expires</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Port</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Rule ID</th>
              <th class="px-6 py-3 text-right text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800">
            <tr v-for="rule in rules" :key="rule.rule_id || rule.cidr" class="hover:bg-slate-800/50 transition">
              <td class="px-6 py-4 whitespace-nowrap">
                <span class="font-mono text-sm text-cyan-400">{{ rule.cidr || rule.ip_address }}</span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span
                  :class="[
                    'px-3 py-1 rounded-full text-xs font-semibold border',
                    verdictClass(rule.verdict),
                  ]"
                >
                  {{ (rule.verdict || '').toUpperCase() }}
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                {{ formatExpires(rule.expires_in) }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-slate-300">
                {{ rule.port ? rule.port : '-' }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-xs text-slate-500 font-mono">
                {{ rule.rule_id || '-' }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-right">
                <div class="flex justify-end gap-2">
                  <button
                    @click="onAllow(rule)"
                    :disabled="busyRows[rule.ip_address]"
                    class="px-3 py-1 text-xs bg-emerald-900/30 hover:bg-emerald-900/50 text-emerald-300 border border-emerald-700 rounded transition disabled:opacity-50"
                    title="Permanently allow this IP (creates a manual ALLOW rule, AI cannot re-block)"
                  >
                    Allow
                  </button>
                  <button
                    @click="onBlock(rule)"
                    :disabled="busyRows[rule.ip_address]"
                    class="px-3 py-1 text-xs bg-red-900/30 hover:bg-red-900/50 text-red-300 border border-red-700 rounded transition disabled:opacity-50"
                    title="Permanently block this IP (makes the AI block permanent and immune to AI changes)"
                  >
                    Block
                  </button>
                  <button
                    @click="onDismiss(rule)"
                    :disabled="busyRows[rule.ip_address]"
                    class="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 rounded transition disabled:opacity-50"
                    title="Remove the current AI rule (AI may re-decide on future flows)"
                  >
                    Dismiss
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue';
import aiRulesService from '../services/aiRulesService';

export default {
  name: 'AIRules',
  setup() {
    const rules = ref([]);
    const agentOnline = ref(false);
    const lastHeartbeat = ref(null);
    const loading = ref(true);
    const error = ref(null);
    const busyRows = ref({});
    let refreshInterval = null;

    const fetchRules = async () => {
      error.value = null;
      try {
        const response = await aiRulesService.fetchRules();
        rules.value = response.data.rules || [];
        agentOnline.value = !!response.data.agent_online;
        lastHeartbeat.value = response.data.last_heartbeat || null;
      } catch (err) {
        error.value = err.response?.data?.message || 'Failed to load AI rules';
        console.error(err);
      } finally {
        loading.value = false;
      }
    };

    const verdictClass = (verdict) => {
      const v = (verdict || '').toLowerCase();
      if (v === 'block') return 'bg-red-900/30 text-red-300 border-red-700';
      if (v === 'throttle' || v === 'rate_limit') return 'bg-amber-900/30 text-amber-300 border-amber-700';
      if (v === 'allow') return 'bg-emerald-900/30 text-emerald-300 border-emerald-700';
      return 'bg-slate-700/30 text-slate-300 border-slate-600';
    };

    const formatExpires = (secondsRemaining) => {
      if (secondsRemaining === null || secondsRemaining === undefined) return 'No TTL';
      const secs = Math.max(0, Math.floor(secondsRemaining));
      if (secs >= 3600) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
      if (secs >= 60) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
      return `${secs}s`;
    };

    const formatHeartbeat = (epochSeconds) => {
      if (!epochSeconds) return '';
      const date = new Date(epochSeconds * 1000);
      return date.toLocaleTimeString();
    };

    const runRowAction = async (rule, action) => {
      const ip = rule.ip_address || (rule.cidr || '').split('/')[0];
      if (!ip) return;
      busyRows.value = { ...busyRows.value, [ip]: true };
      error.value = null;
      try {
        if (action === 'allow') {
          await aiRulesService.promoteToManualAllow(ip, { port: rule.port || null });
        } else if (action === 'block') {
          await aiRulesService.promoteToManualBlock(ip, { port: rule.port || null });
        } else if (action === 'dismiss') {
          await aiRulesService.dismiss(ip);
        }
        await fetchRules();
      } catch (err) {
        error.value = err.response?.data?.message || `Failed to ${action} rule for ${ip}`;
        console.error(err);
      } finally {
        const next = { ...busyRows.value };
        delete next[ip];
        busyRows.value = next;
      }
    };

    const onAllow = (rule) => runRowAction(rule, 'allow');
    const onBlock = (rule) => runRowAction(rule, 'block');
    const onDismiss = (rule) => runRowAction(rule, 'dismiss');

    onMounted(() => {
      fetchRules();
      refreshInterval = setInterval(fetchRules, 10000);
    });

    onUnmounted(() => {
      if (refreshInterval) clearInterval(refreshInterval);
    });

    return {
      rules,
      agentOnline,
      lastHeartbeat,
      loading,
      error,
      busyRows,
      fetchRules,
      verdictClass,
      formatExpires,
      formatHeartbeat,
      onAllow,
      onBlock,
      onDismiss,
    };
  },
};
</script>

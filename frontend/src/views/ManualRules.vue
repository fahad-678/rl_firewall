<template>
  <div class="min-h-screen bg-slate-950 text-white">
    <div class="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <h1 class="text-3xl font-bold">Manual IP Rules</h1>
          <p class="text-slate-400 mt-2">Create and manage firewall rules for blocking or allowing specific IP addresses</p>
        </div>
        <button
          @click="showCreateModal = true"
          class="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg font-semibold transition"
        >
          + New Rule
        </button>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <!-- Rules Table -->
        <div class="lg:col-span-4">
          <div class="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
            <div class="border-b border-slate-800 bg-slate-950/60 p-4 sm:p-5">
              <div class="grid gap-3 lg:grid-cols-[1.4fr_repeat(4,minmax(0,1fr))_auto] lg:items-end">
                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Search</label>
                  <input
                    v-model="filters.ip"
                    @input="debouncedFetchRules"
                    @keyup.enter="fetchRules"
                    type="text"
                    placeholder="Search IP or CIDR"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Action</label>
                  <select
                    v-model="filters.action"
                    @change="fetchRules"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="">All Actions</option>
                    <option value="BLOCK">Block</option>
                    <option value="ALLOW">Allow</option>
                  </select>
                </div>

                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Status</label>
                  <select
                    v-model="filters.status"
                    @change="fetchRules"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="">All Status</option>
                    <option value="ACTIVE">Active</option>
                    <option value="EXPIRED">Expired</option>
                    <option value="DELETED">Deleted</option>
                  </select>
                </div>

                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Port</label>
                  <input
                    v-model.number="filters.port"
                    @input="debouncedFetchRules"
                    type="number"
                    placeholder="Any"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Date Range</label>
                  <div class="mt-2 flex gap-2">
                    <input
                      v-model="filters.dateFrom"
                      @change="fetchRules"
                      type="date"
                      class="w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    />
                    <input
                      v-model="filters.dateTo"
                      @change="fetchRules"
                      type="date"
                      class="w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <button
                  @click="clearFilters"
                  class="rounded-lg border border-[var(--soc-border)] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-800"
                >
                  Clear
                </button>
              </div>
            </div>

            <!-- Loading State -->
            <div v-if="loading" class="flex items-center justify-center h-64">
              <div class="text-center">
                <div class="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
                <p class="text-slate-400 mt-4">Loading rules...</p>
              </div>
            </div>

            <!-- Error State -->
            <div v-else-if="error" class="p-6 bg-red-900/20 border-l-4 border-red-500">
              <p class="text-red-200">{{ error }}</p>
              <button
                @click="fetchRules"
                class="mt-3 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-sm transition"
              >
                Retry
              </button>
            </div>

            <!-- Empty State -->
            <div v-else-if="rules.length === 0" class="p-12 text-center">
              <svg class="mx-auto h-12 w-12 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4v.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              <h3 class="mt-4 text-lg font-medium text-slate-300">No rules found</h3>
              <p class="text-slate-400 mt-1">Try adjusting your filters or create a new rule.</p>
            </div>

            <!-- Rules Table -->
            <table v-else class="w-full divide-y divide-slate-800">
              <thead class="bg-slate-800/50 border-b border-slate-700">
                <tr>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">IP Address</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Action</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Port</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Created</th>
                  <th class="px-6 py-3 text-right text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800">
                <tr v-for="rule in rules" :key="rule.id" class="hover:bg-slate-800/50 transition">
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class="font-mono text-sm text-cyan-400">{{ rule.ip_address }}</span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span
                      :class="[
                        'px-3 py-1 rounded-full text-xs font-semibold',
                        rule.action === 'BLOCK'
                          ? 'bg-red-900/30 text-red-300 border border-red-700'
                          : 'bg-emerald-900/30 text-emerald-300 border border-emerald-700',
                      ]"
                    >
                      {{ rule.action }}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span
                      :class="[
                        'px-3 py-1 rounded-full text-xs font-semibold',
                        rule.status === 'ACTIVE'
                          ? 'bg-emerald-900/30 text-emerald-300 border border-emerald-700'
                          : 'bg-slate-700/30 text-slate-400 border border-slate-600',
                      ]"
                    >
                      {{ rule.status }}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center gap-2">
                      <span class="text-sm text-slate-300">{{ rule.rule_type }}</span>
                      <span v-if="rule.rule_type === 'TEMPORARY' && rule.expiration_at" class="text-xs text-slate-500">
                        {{ formatExpirationTime(rule.expiration_at) }}
                      </span>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-slate-300">
                    {{ rule.port ? rule.port : '-' }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                    {{ formatDate(rule.created_at) }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-right">
                    <div class="flex justify-end gap-2">
                      <button
                        @click="openEditModal(rule)"
                        class="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 rounded transition"
                      >
                        Edit
                      </button>
                      <button
                        @click="confirmDelete(rule)"
                        class="px-3 py-1 text-xs bg-red-900/30 hover:bg-red-900/50 text-red-300 rounded transition border border-red-700"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>

            <!-- Pagination -->
            <div v-if="pagination && pagination.last_page > 1" class="bg-slate-800/50 px-6 py-4 border-t border-slate-700">
              <div class="flex items-center justify-between">
                <div class="text-sm text-slate-400">
                  Showing page {{ pagination.current_page }} of {{ pagination.last_page }}
                </div>
                <div class="flex gap-2">
                  <button
                    @click="previousPage"
                    :disabled="pagination.current_page === 1"
                    class="px-3 py-1 text-sm bg-slate-700 hover:bg-slate-600 text-slate-200 rounded disabled:opacity-50 disabled:cursor-not-allowed transition"
                  >
                    Previous
                  </button>
                  <button
                    @click="nextPage"
                    :disabled="pagination.current_page === pagination.last_page"
                    class="px-3 py-1 text-sm bg-slate-700 hover:bg-slate-600 text-slate-200 rounded disabled:opacity-50 disabled:cursor-not-allowed transition"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>

            <div class="border-t border-slate-800 bg-slate-950/60 p-4 sm:p-5">
              <div class="grid gap-3 lg:grid-cols-[1.2fr_repeat(2,minmax(0,1fr))_auto] lg:items-end">
                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Quick Search</label>
                  <input
                    v-model="filters.ip"
                    @input="debouncedFetchRules"
                    @keyup.enter="fetchRules"
                    type="text"
                    placeholder="Search IP or CIDR"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Action</label>
                  <select
                    v-model="filters.action"
                    @change="fetchRules"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="">All Actions</option>
                    <option value="BLOCK">Block</option>
                    <option value="ALLOW">Allow</option>
                  </select>
                </div>

                <div>
                  <label class="block text-xs font-medium uppercase tracking-[0.2em] text-slate-400">Status</label>
                  <select
                    v-model="filters.status"
                    @change="fetchRules"
                    class="mt-2 w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
                  >
                    <option value="">All Status</option>
                    <option value="ACTIVE">Active</option>
                    <option value="EXPIRED">Expired</option>
                    <option value="DELETED">Deleted</option>
                  </select>
                </div>

                <button
                  @click="clearFilters"
                  class="rounded-lg border border-[var(--soc-border)] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-800"
                >
                  Reset Filters
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create/Edit Rule Modal -->
    <teleport to="body">
      <RuleFormModal
        v-if="showCreateModal || showEditModal"
        :rule="editingRule"
        :is-edit="showEditModal"
        @save="handleRuleSave"
        @close="closeModals"
      />

      <!-- Delete Confirmation Modal -->
      <div v-if="showDeleteConfirm" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div class="bg-slate-900 rounded-lg border border-slate-800 p-6 max-w-sm">
          <h3 class="text-lg font-semibold text-white mb-4">Delete Rule?</h3>
          <p class="text-slate-300 mb-6">
            Are you sure you want to delete this rule for <span class="font-mono text-cyan-400">{{ ruleToDelete?.ip_address }}</span>?
            This action cannot be undone.
          </p>
          <div class="flex gap-3 justify-end">
            <button
              @click="showDeleteConfirm = false"
              class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded transition"
            >
              Cancel
            </button>
            <button
              @click="deleteRule"
              class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded transition"
            >
              Delete
            </button>
          </div>
        </div>
      </div>
    </teleport>
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue';
import manualRulesService from '../services/manualRulesService';
import RuleFormModal from '../components/RuleFormModal.vue';

export default {
  name: 'ManualRules',
  components: {
    RuleFormModal,
  },
  setup() {
    const rules = ref([]);
    const loading = ref(false);
    const error = ref(null);
    const pagination = ref(null);
    const showCreateModal = ref(false);
    const showEditModal = ref(false);
    const showDeleteConfirm = ref(false);
    const editingRule = ref(null);
    const ruleToDelete = ref(null);

    const filters = ref({
      ip: '',
      action: '',
      status: '',
      port: null,
      dateFrom: '',
      dateTo: '',
      page: 1,
      perPage: 25,
    });

    let debounceTimeout = null;

    const debouncedFetchRules = () => {
      clearTimeout(debounceTimeout);
      debounceTimeout = setTimeout(() => {
        filters.value.page = 1;
        fetchRules();
      }, 500);
    };

    const fetchRules = async () => {
      loading.value = true;
      error.value = null;
      try {
        const response = await manualRulesService.fetchRules(filters.value);
        rules.value = response.data.data;
        pagination.value = {
          current_page: response.data.current_page,
          last_page: response.data.last_page,
          total: response.data.total,
        };
      } catch (err) {
        error.value = err.response?.data?.message || 'Failed to load rules';
        console.error(err);
      } finally {
        loading.value = false;
      }
    };

    const clearFilters = () => {
      filters.value = {
        ip: '',
        action: '',
        status: '',
        port: null,
        dateFrom: '',
        dateTo: '',
        page: 1,
        perPage: 25,
      };
      fetchRules();
    };

    const nextPage = () => {
      if (pagination.value && filters.value.page < pagination.value.last_page) {
        filters.value.page++;
        fetchRules();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    };

    const previousPage = () => {
      if (pagination.value && filters.value.page > 1) {
        filters.value.page--;
        fetchRules();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    };

    const openEditModal = (rule) => {
      editingRule.value = { ...rule };
      showEditModal.value = true;
    };

    const closeModals = () => {
      showCreateModal.value = false;
      showEditModal.value = false;
      editingRule.value = null;
    };

    const handleRuleSave = async () => {
      await fetchRules();
      closeModals();
      // Show success toast (implement as needed)
    };

    const confirmDelete = (rule) => {
      ruleToDelete.value = rule;
      showDeleteConfirm.value = true;
    };

    const deleteRule = async () => {
      if (!ruleToDelete.value) return;

      try {
        await manualRulesService.deleteRule(ruleToDelete.value.id);
        showDeleteConfirm.value = false;
        ruleToDelete.value = null;
        await fetchRules();
      } catch (err) {
        error.value = err.response?.data?.message || 'Failed to delete rule';
        console.error(err);
      }
    };

    const formatDate = (dateString) => {
      const date = new Date(dateString);
      return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(date);
    };

    const formatExpirationTime = (dateString) => {
      const date = new Date(dateString);
      const now = new Date();
      const diffMs = date - now;

      if (diffMs < 0) return 'Expired';

      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffDays > 0) return `${diffDays}d left`;
      if (diffHours > 0) return `${diffHours}h left`;
      return `${diffMins}m left`;
    };

    onMounted(() => {
      fetchRules();
      // Auto-refresh every 30 seconds
      const refreshInterval = setInterval(() => {
        if (!showCreateModal.value && !showEditModal.value) {
          fetchRules();
        }
      }, 30000);

      return () => clearInterval(refreshInterval);
    });

    return {
      rules,
      loading,
      error,
      pagination,
      filters,
      showCreateModal,
      showEditModal,
      showDeleteConfirm,
      editingRule,
      ruleToDelete,
      fetchRules,
      debouncedFetchRules,
      clearFilters,
      nextPage,
      previousPage,
      openEditModal,
      closeModals,
      handleRuleSave,
      confirmDelete,
      deleteRule,
      formatDate,
      formatExpirationTime,
    };
  },
};
</script>

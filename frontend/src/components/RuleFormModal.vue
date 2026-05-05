<template>
  <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
    <div class="bg-slate-900 rounded-lg border border-slate-800 p-6 max-w-lg w-full max-h-[90vh] overflow-y-auto">
      <h2 class="text-2xl font-bold text-white mb-6">
        {{ isEdit ? 'Edit Rule' : 'Create New Rule' }}
      </h2>

      <form @submit.prevent="submitForm" class="space-y-5">
        <!-- IP Address -->
        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">IP Address or CIDR *</label>
          <input
            v-model="form.ip_address"
            type="text"
            placeholder="e.g., 192.168.1.1 or 10.0.0.0/24"
            :disabled="isEdit"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed"
            @input="clearError"
          />
          <p v-if="errors.ip_address" class="mt-1 text-sm text-red-400">{{ errors.ip_address }}</p>
        </div>

        <!-- Action -->
        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">Action *</label>
          <div class="flex gap-4">
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                v-model="form.action"
                type="radio"
                value="BLOCK"
                class="w-4 h-4 accent-red-500"
                @change="clearError"
              />
              <span class="text-slate-300">Block IP</span>
            </label>
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                v-model="form.action"
                type="radio"
                value="ALLOW"
                class="w-4 h-4 accent-emerald-500"
                @change="clearError"
              />
              <span class="text-slate-300">Allow IP</span>
            </label>
          </div>
          <p v-if="errors.action" class="mt-1 text-sm text-red-400">{{ errors.action }}</p>
        </div>

        <!-- Rule Type -->
        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">Rule Type *</label>
          <div class="flex gap-4">
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                v-model="form.rule_type"
                type="radio"
                value="PERMANENT"
                class="w-4 h-4 accent-cyan-500"
                @change="clearError"
              />
              <span class="text-slate-300">Permanent</span>
            </label>
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                v-model="form.rule_type"
                type="radio"
                value="TEMPORARY"
                class="w-4 h-4 accent-cyan-500"
                @change="clearError"
              />
              <span class="text-slate-300">Temporary</span>
            </label>
          </div>
          <p v-if="errors.rule_type" class="mt-1 text-sm text-red-400">{{ errors.rule_type }}</p>
        </div>

        <!-- Duration (for temporary rules) -->
        <div v-if="form.rule_type === 'TEMPORARY'">
          <label class="block text-sm font-medium text-slate-300 mb-2">Duration (hours) *</label>
          <input
            v-model.number="form.duration_hours"
            type="number"
            placeholder="e.g., 24"
            min="1"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            @input="clearError"
          />
          <p class="mt-1 text-xs text-slate-400">The rule will automatically expire after this duration</p>
          <p v-if="errors.duration_hours" class="mt-1 text-sm text-red-400">{{ errors.duration_hours }}</p>
        </div>

        <!-- Port (optional) -->
        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">Port (optional)</label>
          <input
            v-model.number="form.port"
            type="number"
            placeholder="e.g., 443"
            min="1"
            max="65535"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            @input="clearError"
          />
          <p class="mt-1 text-xs text-slate-400">Leave empty to apply to all ports</p>
          <p v-if="errors.port" class="mt-1 text-sm text-red-400">{{ errors.port }}</p>
        </div>

        <!-- Notes -->
        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">Notes (optional)</label>
          <textarea
            v-model="form.notes"
            placeholder="Add a reason or context for this rule"
            rows="3"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 resize-none"
            @input="clearError"
          ></textarea>
          <p v-if="errors.notes" class="mt-1 text-sm text-red-400">{{ errors.notes }}</p>
        </div>

        <!-- Form Error -->
        <div v-if="formError" class="p-3 bg-red-900/20 border border-red-700 rounded text-red-200 text-sm">
          {{ formError }}
        </div>

        <!-- Buttons -->
        <div class="flex gap-3 justify-end pt-4 border-t border-slate-700">
          <button
            type="button"
            @click="closeModal"
            class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded transition"
          >
            Cancel
          </button>
          <button
            type="submit"
            :disabled="submitting"
            class="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <span v-if="submitting" class="inline-block animate-spin">⟳</span>
            {{ isEdit ? 'Update Rule' : 'Create Rule' }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>

<script>
import { ref, computed, watch } from 'vue';
import manualRulesService from '../services/manualRulesService';

export default {
  name: 'RuleFormModal',
  props: {
    rule: {
      type: Object,
      default: null,
    },
    isEdit: {
      type: Boolean,
      default: false,
    },
  },
  emits: ['save', 'close'],
  setup(props, { emit }) {
    const submitting = ref(false);
    const formError = ref(null);
    const errors = ref({});

    const form = ref({
      ip_address: '',
      action: 'BLOCK',
      rule_type: 'PERMANENT',
      duration_hours: 24,
      port: null,
      notes: '',
    });

    // Initialize form with editing rule data
    if (props.isEdit && props.rule) {
      form.value = {
        ip_address: props.rule.ip_address,
        action: props.rule.action,
        rule_type: props.rule.rule_type,
        duration_hours: 24, // Not used in edit, but kept for form consistency
        port: props.rule.port,
        notes: props.rule.notes || '',
      };
    }

    const clearError = () => {
      formError.value = null;
      errors.value = {};
    };

    const submitForm = async () => {
      clearError();
      submitting.value = true;

      try {
        if (props.isEdit && props.rule) {
          // Update existing rule
          await manualRulesService.updateRule(props.rule.id, {
            port: form.value.port,
            notes: form.value.notes,
            duration_hours: form.value.rule_type === 'TEMPORARY' ? form.value.duration_hours : null,
          });
        } else {
          // Create new rule
          await manualRulesService.createRule({
            ip_address: form.value.ip_address,
            action: form.value.action,
            rule_type: form.value.rule_type,
            duration_hours: form.value.rule_type === 'TEMPORARY' ? form.value.duration_hours : null,
            port: form.value.port,
            notes: form.value.notes,
          });
        }

        emit('save');
      } catch (err) {
        if (err.response?.data?.errors) {
          errors.value = err.response.data.errors;
        } else if (err.response?.data?.message) {
          formError.value = err.response.data.message;
        } else {
          formError.value = err.message || 'An error occurred';
        }
        console.error(err);
      } finally {
        submitting.value = false;
      }
    };

    const closeModal = () => {
      emit('close');
    };

    return {
      form,
      submitting,
      formError,
      errors,
      clearError,
      submitForm,
      closeModal,
    };
  },
};
</script>

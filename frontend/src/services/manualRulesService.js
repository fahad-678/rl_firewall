import axios from 'axios';

const API_URL = '/api/firewall/rules';

const manualRulesService = {
  /**
   * Fetch all manual firewall rules with optional filters
   */
  fetchRules(filters = {}) {
    const params = {
      per_page: filters.perPage || 25,
      page: filters.page || 1,
    };

    if (filters.ip) params.ip = filters.ip;
    if (filters.action) params.action = filters.action;
    if (filters.status) params.status = filters.status;
    if (filters.port) params.port = filters.port;
    if (filters.dateFrom) params.date_from = filters.dateFrom;
    if (filters.dateTo) params.date_to = filters.dateTo;

    return axios.get(API_URL, { params });
  },

  /**
   * Get currently active rules only (for real-time display)
   */
  fetchActiveRules() {
    return axios.get(`${API_URL}/active`);
  },

  /**
   * Get a specific rule by ID
   */
  getRule(id) {
    return axios.get(`${API_URL}/${id}`);
  },

  /**
   * Create a new manual firewall rule
   */
  createRule(ruleData) {
    return axios.post(API_URL, ruleData);
  },

  /**
   * Update an existing rule
   */
  updateRule(id, ruleData) {
    return axios.put(`${API_URL}/${id}`, ruleData);
  },

  /**
   * Delete (soft delete) a rule
   */
  deleteRule(id) {
    return axios.delete(`${API_URL}/${id}`);
  },

  /**
   * Delete all currently active rules
   */
  clearActiveRules() {
    return axios.delete(`${API_URL}/active`);
  },
};

export default manualRulesService;

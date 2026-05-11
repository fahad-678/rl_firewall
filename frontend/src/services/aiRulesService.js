import axios from 'axios';

const API_URL = '/api/firewall/ai-rules';
const MANUAL_RULES_URL = '/api/firewall/rules';
const OVERRIDE_URL = '/api/firewall/override';

const aiRulesService = {
  fetchRules() {
    return axios.get(API_URL);
  },

  fetchRecent() {
    return axios.get(`${API_URL}/recent`);
  },

  /**
   * Promote an AI rule to a permanent manual ALLOW rule. The backend creates
   * the manual rule and broadcasts; the agent evicts the AI rule and inserts
   * an explicit ACCEPT so the AI cannot re-block this IP.
   */
  promoteToManualAllow(ipAddress, { port = null, notes = null } = {}) {
    return axios.post(MANUAL_RULES_URL, {
      ip_address: ipAddress,
      action: 'ALLOW',
      rule_type: 'PERMANENT',
      port,
      notes: notes || 'Promoted from AI Rules view',
    });
  },

  /**
   * Promote an AI rule to a permanent manual BLOCK rule (makes the temporary
   * AI block permanent and immune to AI changes).
   */
  promoteToManualBlock(ipAddress, { port = null, notes = null } = {}) {
    return axios.post(MANUAL_RULES_URL, {
      ip_address: ipAddress,
      action: 'BLOCK',
      rule_type: 'PERMANENT',
      port,
      notes: notes || 'Promoted from AI Rules view',
    });
  },

  /**
   * Dismiss the current AI rule for this IP. Uses the existing override path
   * (Redis 'firewall-overrides' channel) so the agent removes the rule; the
   * AI may re-decide on future flows.
   */
  dismiss(ipAddress) {
    return axios.post(OVERRIDE_URL, {
      ip: ipAddress,
      notes: 'Dismissed from AI Rules view',
    });
  },
};

export default aiRulesService;

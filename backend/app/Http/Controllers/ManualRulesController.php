<?php

namespace App\Http\Controllers;

use App\Models\InterventionLog;
use App\Models\User;
use App\Models\ManualFirewallRule;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class ManualRulesController extends Controller
{
    /**
     * Display a paginated list of all manual firewall rules with optional filtering.
     */
    public function index(Request $request)
    {
        // Update any expired rules before returning
        ManualFirewallRule::updateExpiredRules();

        $query = ManualFirewallRule::with('creator:id,email,name');

        // Apply filters
        if ($request->filled('ip')) {
            $query->byIp($request->input('ip'));
        }

        if ($request->filled('action')) {
            $query->byAction($request->input('action'));
        }

        if ($request->filled('status')) {
            $query->byStatus($request->input('status'));
        }

        if ($request->filled('port')) {
            $query->byPort($request->input('port'));
        }

        if ($request->filled('date_from') || $request->filled('date_to')) {
            $query->byDateRange(
                $request->input('date_from'),
                $request->input('date_to')
            );
        }

        // Paginate results
        $perPage = $request->input('per_page', 25);
        $rules = $query->orderBy('created_at', 'desc')->paginate($perPage);

        return response()->json($rules);
    }

    /**
     * Store a newly created manual firewall rule.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'ip_address' => [
                'required',
                'string',
                function ($attribute, $value, $fail) {
                    // Validate IP or CIDR format
                    if (!$this->isValidIpOrCidr($value)) {
                        $fail('The ' . $attribute . ' must be a valid IP address or CIDR notation.');
                    }
                },
            ],
            'action' => 'required|in:BLOCK,ALLOW',
            'rule_type' => 'required|in:PERMANENT,TEMPORARY',
            'duration_hours' => 'nullable|integer|min:1|required_if:rule_type,TEMPORARY',
            'port' => 'nullable|integer|min:1|max:65535',
            'notes' => 'nullable|string|max:500',
        ]);

        // Calculate expiration time for temporary rules
        $expirationAt = null;
        if ($validated['rule_type'] === 'TEMPORARY') {
            $durationHours = $validated['duration_hours'];
            $expirationAt = now()->addHours($durationHours);
        }

        // Create the rule
        $creator = $this->resolveCreatorUser($request);

        $rule = ManualFirewallRule::create([
            'ip_address' => $validated['ip_address'],
            'action' => $validated['action'],
            'rule_type' => $validated['rule_type'],
            'expiration_at' => $expirationAt,
            'port' => $validated['port'] ?? null,
            'notes' => $validated['notes'] ?? null,
            'created_by' => $creator->id,
            'status' => 'ACTIVE',
        ]);

        // Broadcast to agent via Redis
        $this->broadcastRuleChange('created', $rule);
        $this->recordIntervention($rule, 'created');

        return response()->json($rule->load('creator'), 201);
    }

    /**
     * Display the specified manual firewall rule.
     */
    public function show(ManualFirewallRule $rule)
    {
        $rule->checkAndUpdateExpiration();
        return response()->json($rule->load('creator'));
    }

    /**
     * Update the specified manual firewall rule.
     */
    public function update(Request $request, ManualFirewallRule $rule)
    {
        $validated = $request->validate([
            'duration_hours' => 'nullable|integer|min:1|required_if:rule_type,TEMPORARY',
            'port' => 'nullable|integer|min:1|max:65535',
            'notes' => 'nullable|string|max:500',
            'status' => 'nullable|in:ACTIVE,EXPIRED,DELETED',
        ]);

        // If updating duration for a temporary rule
        if (
            $rule->rule_type === 'TEMPORARY'
            && $request->filled('duration_hours')
            && $rule->status === 'ACTIVE'
        ) {
            $durationHours = $validated['duration_hours'];
            $validated['expiration_at'] = now()->addHours($durationHours);
        }

        // Update rule
        $rule->update($validated);
        $rule->refresh();

        // Broadcast change to agent
        $this->broadcastRuleChange('updated', $rule);
        $this->recordIntervention($rule, 'updated');

        return response()->json($rule->load('creator'));
    }

    /**
     * Soft delete the specified manual firewall rule.
     */
    public function destroy(ManualFirewallRule $rule)
    {
        $rule->update(['status' => 'DELETED']);

        // Broadcast deletion to agent so it can remove the rule
        $this->broadcastRuleChange('deleted', $rule);
        $this->recordIntervention($rule, 'deleted');

        return response()->json(['message' => 'Rule deleted successfully']);
    }

    /**
     * Import ACL rules discovered on the switch into the manual rules table.
     */
    public function importSwitchRules(Request $request)
    {
        $token = (string) $request->header('X-Rule-Sync-Token', '');
        $expectedToken = (string) config('app.rule_sync_token', env('RULE_SYNC_TOKEN', ''));

        if ($expectedToken === '' || !hash_equals($expectedToken, $token)) {
            return response()->json([
                'message' => 'Unauthorized rule import request.',
            ], 401);
        }

        $validated = $request->validate([
            'rules' => 'required|array',
            'rules.*.ip_address' => 'required|ip',
            'rules.*.action' => 'required|in:BLOCK,ALLOW',
            'rules.*.rule_type' => 'nullable|in:PERMANENT,TEMPORARY',
            'rules.*.port' => 'nullable|integer|min:1|max:65535',
            'rules.*.notes' => 'nullable|string|max:500',
            'rules.*.status' => 'nullable|in:ACTIVE,EXPIRED,DELETED',
        ]);

        $systemUser = User::firstOrCreate(
            ['email' => 'system@rl-firewall.local'],
            [
                'name' => 'System',
                'password' => bcrypt(bin2hex(random_bytes(16))),
            ]
        );

        $imported = 0;

        foreach ($validated['rules'] as $incomingRule) {
            $rule = ManualFirewallRule::updateOrCreate(
                [
                    'ip_address' => $incomingRule['ip_address'],
                    'action' => $incomingRule['action'],
                    'port' => $incomingRule['port'] ?? null,
                ],
                [
                    'rule_type' => $incomingRule['rule_type'] ?? 'PERMANENT',
                    'expiration_at' => null,
                    'notes' => $incomingRule['notes'] ?? 'Imported from switch ACL',
                    'created_by' => $systemUser->id,
                    'status' => $incomingRule['status'] ?? 'ACTIVE',
                ]
            );

            $this->recordIntervention($rule, 'imported');
            $imported++;
        }

        return response()->json([
            'message' => 'Switch ACL rules imported successfully.',
            'imported' => $imported,
        ]);
    }

    /**
     * Get only currently active rules (for agent polling).
     */
    public function getActive()
    {
        // Update expired rules first
        ManualFirewallRule::updateExpiredRules();

        $rules = ManualFirewallRule::currentlyActive()
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json(['rules' => $rules]);
    }

    /**
     * Get active rules for the agent sync poller using the shared sync token.
     */
    public function getActiveSync(Request $request)
    {
        $token = (string) $request->header('X-Rule-Sync-Token', '');
        $expectedToken = (string) config('app.rule_sync_token', env('RULE_SYNC_TOKEN', ''));

        if ($expectedToken === '' || !hash_equals($expectedToken, $token)) {
            return response()->json([
                'message' => 'Unauthorized rule sync request.',
            ], 401);
        }

        return $this->getActive();
    }

    /**
     * Validate IP or CIDR format.
     */
    private function isValidIpOrCidr($value)
    {
        // Check if it's a valid IPv4 address or CIDR
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return true;
        }

        // Check if it's a valid CIDR notation
        if (strpos($value, '/') !== false) {
            [$ip, $prefix] = explode('/', $value, 2);
            if (
                filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                && is_numeric($prefix)
                && (int)$prefix >= 0
                && (int)$prefix <= 32
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Broadcast rule change to agent via Redis.
     */
    private function broadcastRuleChange($action, ManualFirewallRule $rule)
    {
        $payload = [
            'action' => $action,
            'rule_id' => $rule->id,
            'rule_data' => [
                'ip_address' => $rule->ip_address,
                'action' => $rule->action,
                'port' => $rule->port,
                'status' => $rule->status,
                'rule_type' => $rule->rule_type,
                'expiration_at' => $rule->expiration_at,
            ],
            'timestamp' => now()->toIso8601String(),
        ];

        // Publish to Redis channel for agent to listen
        try {
            Redis::publish('manual-firewall-rules', json_encode($payload));
        } catch (\Exception $e) {
            // Log error but don't fail the response
            \Log::warning('Failed to broadcast rule change to agent: ' . $e->getMessage());
        }
    }

    /**
     * Mirror manual rule changes into the existing intervention log stream.
     */
    private function recordIntervention(ManualFirewallRule $rule, string $eventType): void
    {
        try {
            InterventionLog::create([
                'ip_address' => $rule->ip_address,
                'port' => $rule->port,
                'confidence' => null,
                'decision' => $rule->action,
                'action' => $rule->action === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED',
                'flow_key' => 'manual-rule:' . $rule->id,
                'reward' => null,
                'latency_ms' => null,
                'notes' => trim(($rule->notes ? $rule->notes . ' | ' : '') . 'Manual firewall rule ' . $eventType),
            ]);
        } catch (\Throwable $e) {
            \Log::warning('Failed to record manual firewall intervention: ' . $e->getMessage());
        }
    }

    /**
     * Resolve or create the admin user tied to the session-based login.
     */
    private function resolveCreatorUser(Request $request): User
    {
        $email = session('admin_email') ?? $request->user()?->email;

        if (!$email) {
            abort(response()->json([
                'message' => 'Unable to determine the current admin user.',
            ], 401));
        }

        return User::firstOrCreate(
            ['email' => $email],
            [
                'name' => 'Admin',
                'password' => bcrypt(bin2hex(random_bytes(16))),
            ]
        );
    }
}

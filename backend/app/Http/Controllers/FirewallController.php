<?php

namespace App\Http\Controllers;

use App\Events\ThreatDetected;
use App\Models\InterventionLog;
use App\Models\TelemetryLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class FirewallController extends Controller
{
    /**
     * Receive live telemetry from Python and broadcast to Vue via Reverb.
     */
    public function receiveTelemetry(Request $request)
    {
        $token = (string) $request->header('X-Rule-Sync-Token', '');
        $expectedToken = (string) config('app.rule_sync_token', env('RULE_SYNC_TOKEN', ''));

        if ($expectedToken === '' || !hash_equals($expectedToken, $token)) {
            return response()->json([
                'message' => 'Unauthorized telemetry request.',
            ], 401);
        }

        $validated = $request->validate([
            'src_ip'       => 'required|string',
            'port'         => 'nullable|integer',
            'confidence'   => 'required|numeric',
            'action'       => 'required|string',
            'flow_key'     => 'nullable|string',
            'reward'       => 'nullable|numeric',
            'latency_ms'   => 'nullable|numeric',
            'is_malicious' => 'nullable|boolean',
            'terminal'     => 'nullable|boolean',
        ]);

        // Persist raw telemetry for audit and historical queries
        try {
            TelemetryLog::create([
                'src_ip'       => $validated['src_ip'],
                'port'         => $validated['port'] ?? null,
                'confidence'   => $validated['confidence'] ?? null,
                'action'       => $validated['action'] ?? null,
                'flow_key'     => $validated['flow_key'] ?? null,
                'reward'       => $validated['reward'] ?? null,
                'latency_ms'   => $validated['latency_ms'] ?? null,
                'is_malicious' => $validated['is_malicious'] ?? null,
                'terminal'     => $validated['terminal'] ?? null,
                'raw_payload'  => $request->all(),
            ]);
        } catch (\Exception $e) {
            // Do not block broadcasting on DB errors; log and continue
            logger()->error('Failed to store telemetry: ' . $e->getMessage());
        }

        // Broadcast the event instantly
        broadcast(new ThreatDetected($validated));

        return response()->json(['status' => 'Event broadcasted']);
    }

    /**
     * Paginated historical telemetry records.
     */
    public function getTelemetry(Request $request)
    {
        $perPage = (int) $request->query('per_page', 25);
        $logs = TelemetryLog::orderBy('created_at', 'desc')->paginate($perPage);
        return response()->json($logs);
    }

    /**
     * Fetch recent telemetry for dashboard hydration on load.
     */
    public function getRecentTelemetry()
    {
        $logs = InterventionLog::orderBy('created_at', 'desc')
            ->limit(50)
            ->get();

        $telemetry = $logs->map(function ($log) {
            $action = $log->decision === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED';

            return [
                'id'          => $log->id,
                'src_ip'      => $log->ip_address,
                'ip_address'  => $log->ip_address,
                'port'        => $log->port,
                'confidence'  => $log->confidence !== null ? (float) $log->confidence : 0.0,
                'action'      => $action,
                'actionLabel' => str_replace('_', ' ', $action),
                'decision'    => $log->decision,
                'notes'       => $log->notes,
                'flow_key'    => $log->flow_key,
                'reward'      => $log->reward !== null ? (float) $log->reward : null,
                'latency_ms'  => $log->latency_ms !== null ? (float) $log->latency_ms : null,
                'timestamp'   => $log->created_at->toIso8601String(),
            ];
        });

        return response()->json($telemetry);
    }

    /**
     * Handle manual allow/block decisions from the dashboard.
     */
    public function review(Request $request)
    {
        $request->validate([
            'ip'         => 'required|ip',
            'decision'   => 'required|in:BLOCK,ALLOW',
            'notes'      => 'nullable|string|max:1000',
            'port'       => 'nullable|integer',
            'confidence' => 'nullable|numeric',
            'reward'     => 'nullable|numeric',
            'latency_ms' => 'nullable|numeric',
            'flow_key'   => 'nullable|string',
        ]);

        $ip = $request->input('ip');
        $decision = $request->input('decision');

        $entry = $this->storeIntervention($ip, $decision, [
            'notes'      => $request->input('notes'),
            'port'       => $request->input('port'),
            'confidence' => $request->input('confidence'),
            'reward'     => $request->input('reward'),
            'latency_ms' => $request->input('latency_ms'),
            'flow_key'   => $request->input('flow_key'),
        ]);

        // Publish to the Python AI Agent via Redis
        Redis::publish('firewall-overrides', json_encode([
            'ip'         => $ip,
            'decision'   => $decision,
            'notes'      => $request->input('notes'),
            'port'       => $request->input('port'),
            'confidence' => $request->input('confidence'),
            'reward'     => $request->input('reward'),
            'latency_ms' => $request->input('latency_ms'),
            'flow_key'   => $request->input('flow_key'),
        ]));

        return response()->json([
            'message'  => 'Feedback sent to AI agent',
            'entry_id' => $entry->id,
        ]);
    }

    /**
     * Revoke an active block.
     */
    public function override(Request $request)
    {
        $request->validate([
            'ip'         => 'required|ip',
            'notes'      => 'nullable|string|max:1000',
            'port'       => 'nullable|integer',
            'confidence' => 'nullable|numeric',
            'reward'     => 'nullable|numeric',
            'latency_ms' => 'nullable|numeric',
            'flow_key'   => 'nullable|string',
        ]);

        $ip = $request->input('ip');

        $entry = $this->storeIntervention($ip, 'ALLOW', [
            'notes'      => $request->input('notes', 'Operator revoked block from dashboard'),
            'port'       => $request->input('port'),
            'confidence' => $request->input('confidence'),
            'reward'     => $request->input('reward'),
            'latency_ms' => $request->input('latency_ms'),
            'flow_key'   => $request->input('flow_key'),
        ]);

        Redis::publish('firewall-overrides', json_encode([
            'ip'         => $ip,
            'decision'   => 'ALLOW',
            'notes'      => $request->input('notes', 'Operator revoked block from dashboard'),
            'port'       => $request->input('port'),
            'confidence' => $request->input('confidence'),
            'reward'     => $request->input('reward'),
            'latency_ms' => $request->input('latency_ms'),
            'flow_key'   => $request->input('flow_key'),
        ]));

        return response()->json([
            'message'  => 'Override command sent to AI agent',
            'entry_id' => $entry->id,
        ]);
    }

    /**
     * Fetch the audit trail of human interventions.
     */
    public function getInterventions(Request $request)
    {
        // Paginate with 15 records per page.
        $logs = InterventionLog::orderBy('id', 'desc')->paginate(15);
        return response()->json($logs);
    }

    private function storeIntervention(string $ip, string $decision, array $metadata = []): InterventionLog
    {
        return InterventionLog::create([
            'ip_address' => $ip,
            'decision'   => $decision,
            'notes'      => $metadata['notes'] ?? null,
            'port'       => $metadata['port'] ?? null,
            'confidence' => $metadata['confidence'] ?? null,
            'action'     => $decision === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED',
            'reward'     => $metadata['reward'] ?? null,
            'latency_ms' => $metadata['latency_ms'] ?? null,
            'flow_key'   => $metadata['flow_key'] ?? null,
        ]);
    }
}
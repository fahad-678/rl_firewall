<?php

namespace App\Http\Controllers;

use App\Events\ThreatDetected;
use App\Models\InterventionLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class FirewallController extends Controller
{
    /**
     * Receive live telemetry from Python and broadcast to Vue via Reverb.
     */
    public function receiveTelemetry(Request $request)
    {
        $validated = $request->validate([
            'src_ip'     => 'required|string',
            'port'       => 'required|integer',
            'confidence' => 'required|numeric',
            'action'     => 'required|string',
        ]);

        // Broadcast the event instantly
        broadcast(new ThreatDetected($validated));

        return response()->json(['status' => 'Event broadcasted']);
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
            return [
                'id'         => $log->id,
                'src_ip'     => $log->src_ip,
                'port'       => $log->port,
                'confidence' => (float) $log->confidence,
                'action'     => $log->action,
                'timestamp'  => $log->created_at->toIso8601String(),
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
            'ip'       => 'required|ip',
            'decision' => 'required|in:BLOCK,ALLOW'
        ]);

        $ip = $request->input('ip');
        $decision = $request->input('decision');

        // 1. Update the local Laravel Database for the UI
        $log = InterventionLog::where('src_ip', $ip)->latest()->first();
        if ($log) {
            $log->action = $decision === 'BLOCK' ? 'BLOCKED' : 'ACCEPTED';
            $log->save();
        }

        // 2. Publish to the Python AI Agent via Redis
        Redis::publish('firewall-overrides', json_encode([
            'ip'       => $ip,
            'decision' => $decision
        ]));

        return response()->json(['message' => 'Feedback sent to AI agent']);
    }

    /**
     * Revoke an active block.
     */
    public function override(Request $request)
    {
        $request->validate([
            'ip' => 'required|ip'
        ]);

        $ip = $request->input('ip');

        $log = InterventionLog::where('src_ip', $ip)->latest()->first();
        if ($log) {
            $log->action = 'ACCEPTED';
            $log->save();
        }

        Redis::publish('firewall-overrides', json_encode([
            'ip'       => $ip,
            'decision' => 'ALLOW'
        ]));

        return response()->json(['message' => 'Override command sent to AI agent']);
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
}
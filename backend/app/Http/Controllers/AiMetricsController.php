<?php

namespace App\Http\Controllers;

use App\Events\ThreatDetected;
use App\Models\InterventionLog;
use Illuminate\Http\Request;
use App\Models\TrainingLog;
use Illuminate\Support\Facades\Redis;

class AiMetricsController extends Controller
{
    /**
     * Fetch historical reward metrics for the AI training chart.
     */
    public function getPerformanceData(Request $request)
    {
        // Fetch up to the last 50 epochs, ensuring they are ordered chronologically
        // If you want ALL data, remove ->take(50), but this is better for UI performance
        $logs = TrainingLog::orderBy('epoch', 'desc')->take(50)->get()->reverse()->values();

        // If there is no data yet, return empty arrays to prevent frontend errors
        if ($logs->isEmpty()) {
            return response()->json([
                'epochs' => [],
                'rewards' => []
            ]);
        }

        // Map the database rows to the exact structure expected by Vue and Chart.js
        return response()->json([
            'epochs'  => $logs->map(fn($log) => 'Epoch ' . $log->epoch),
            'rewards' => $logs->pluck('cumulative_reward')
        ]);
    }

    /**
     * Store a new training epoch log from the Python RL Agent.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'epoch'             => 'required|integer',
            'epsilon'           => 'required|numeric',
            'cumulative_reward' => 'required|numeric',
            'loss'              => 'nullable|numeric',
            'threats_blocked'   => 'nullable|integer',
            'threats_allowed'   => 'nullable|integer',
        ]);

        $log = TrainingLog::create($validated);

        return response()->json([
            'message' => 'Epoch metrics saved successfully',
            'log_id'  => $log->id
        ], 201);
    }

    public function getTrainingLogs(Request $request)
    {
        // Fetch the 100 most recent epochs, newest first
        $logs = TrainingLog::orderBy('epoch', 'desc')->take(100)->get();
        
        return response()->json($logs);
    }

    public function receiveTelemetry(Request $request)
    {
        // 1. Validate incoming data from Python
        $validated = $request->validate([
            'src_ip'     => 'required|string',
            'port'       => 'required|integer',
            'confidence' => 'required|numeric',
            'action'     => 'required|string',
        ]);

        // 2. Dispatch the event to Reverb instantly
        broadcast(new ThreatDetected($validated));

        return response()->json(['status' => 'Event broadcasted']);
    }

    public function submitReview(Request $request)
    {
        $validated = $request->validate([
            'ip'       => 'required|ip',
            'decision' => 'required|in:BLOCK,ALLOW',
            'notes'    => 'nullable|string'
        ]);

        // 1. Log the intervention to the database for auditing
        InterventionLog::create([
            'ip_address' => $validated['ip'],
            'decision'   => $validated['decision'],
            'notes'      => $validated['notes'] ?? null,
        ]);

        // 2. Broadcast the command to the Python RL Agent
        Redis::publish('firewall-overrides', json_encode([
            'ip'       => $validated['ip'],
            'decision' => $validated['decision']
        ]));

        return response()->json([
            'message' => "Decision {$validated['decision']} logged and dispatched for {$validated['ip']}"
        ]);
    }

    /**
     * Fetch the audit trail of human interventions with pagination.
     */
    public function getInterventions(Request $request)
    {
        // Paginate with 15 records per page. 
        // Laravel automatically reads the ?page=X query parameter from the request.
        $logs = InterventionLog::orderBy('id', 'desc')->paginate(15);
        
        return response()->json($logs);
    }

    

    
}
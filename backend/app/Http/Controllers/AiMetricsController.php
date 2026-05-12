<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\TrainingLog;

class AiMetricsController extends Controller
{
    /**
     * Fetch historical reward metrics for the AI training chart.
     */
    public function getPerformanceData(Request $request)
    {
        $logs = TrainingLog::orderBy('epoch', 'desc')->take(50)->get()->reverse()->values();

        if ($logs->isEmpty()) {
            return response()->json([
                'epochs' => [],
                'rewards' => []
            ]);
        }

        return response()->json([
            'epochs'  => $logs->map(fn($log) => 'Epoch ' . $log->epoch),
            'rewards' => $logs->pluck('cumulative_reward')
        ]);
    }

    /**
     * Store a new training epoch log from the Python RL Agent.
     *
     * Called by the agent without a browser session, so this endpoint sits
     * outside the admin middleware group and authenticates via the shared
     * X-Rule-Sync-Token header — same pattern as POST /firewall/telemetry.
     */
    public function store(Request $request)
    {
        $token = (string) $request->header('X-Rule-Sync-Token', '');
        $expectedToken = (string) config('app.rule_sync_token', env('RULE_SYNC_TOKEN', ''));

        if ($expectedToken === '' || !hash_equals($expectedToken, $token)) {
            return response()->json([
                'message' => 'Unauthorized AI metrics request.',
            ], 401);
        }

        $validated = $request->validate([
            'epoch'             => 'required|integer',
            'epsilon'           => 'required|numeric',
            'cumulative_reward' => 'required|numeric',
            'loss'              => 'nullable|numeric',
            'threats_blocked'   => 'nullable|integer',
            'threats_allowed'   => 'nullable|integer',
        ]);

        // Use updateOrCreate to avoid unique primary-key insert errors
        // (some deployments previously used `epoch` as the primary key).
        $log = TrainingLog::updateOrCreate(
            ['epoch' => $validated['epoch']],
            $validated
        );

        return response()->json([
            'message' => 'Epoch metrics saved successfully',
            'log_id'  => $log->id ?? null
        ], 201);
    }

    /**
     * Fetch raw training logs for the Training History view.
     */
    public function getTrainingLogs(Request $request)
    {
        $logs = TrainingLog::orderBy('epoch', 'desc')->take(100)->get();
        return response()->json($logs);
    }
}
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

    /**
     * Fetch raw training logs for the Training History view.
     */
    public function getTrainingLogs(Request $request)
    {
        $logs = TrainingLog::orderBy('epoch', 'desc')->take(100)->get();
        return response()->json($logs);
    }
}
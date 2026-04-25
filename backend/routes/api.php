<?php

use App\Http\Controllers\AiMetricsController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Route;

Route::post('/firewall/override', function (Request $request) {
    $ip = $request->input('ip');
    // Send command back to Python Agent via Redis
    Redis::publish('firewall-commands', json_encode(['action' => 'revoke_block', 'ip' => $ip]));
    return response()->json(['status' => 'Override command dispatched']);
});

Route::get('/ai/performance', [AiMetricsController::class, 'getPerformanceData']);
Route::post('/ai/performance', [AiMetricsController::class, 'store']);
Route::get('/ai/logs', [AiMetricsController::class, 'getTrainingLogs']);
Route::post('/firewall/telemetry', [AiMetricsController::class, 'receiveTelemetry']);
Route::post('/firewall/review', [AiMetricsController::class, 'submitReview']);
Route::get('/firewall/interventions', [AiMetricsController::class, 'getInterventions']);
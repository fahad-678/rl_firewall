<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AiMetricsController;
use App\Http\Controllers\FirewallController;

// AI Performance & Training Routes
Route::prefix('ai')->group(function () {
    Route::get('/performance', [AiMetricsController::class, 'getPerformanceData']);
    Route::post('/performance', [AiMetricsController::class, 'store']);
    Route::get('/logs', [AiMetricsController::class, 'getTrainingLogs']);
});

// Real-Time Firewall & Telemetry Routes
Route::prefix('firewall')->group(function () {
    Route::get('/recent-telemetry', [FirewallController::class, 'getRecentTelemetry']);
    Route::post('/telemetry', [FirewallController::class, 'receiveTelemetry']);
    
    // Human-in-the-loop actions
    Route::post('/review', [FirewallController::class, 'review']);
    Route::post('/override', [FirewallController::class, 'override']);
    
    // Audit logs
    Route::get('/interventions', [FirewallController::class, 'getInterventions']);
});
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AiMetricsController;
use App\Http\Controllers\AIRulesController;
use App\Http\Controllers\FirewallController;
use App\Http\Controllers\ManualRulesController;

// Protected routes (require authentication via admin middleware + web session)
Route::middleware(['web', 'admin'])->group(function () {
    // AI Performance & Training Routes
    Route::prefix('ai')->group(function () {
        Route::get('/performance', [AiMetricsController::class, 'getPerformanceData']);
        Route::post('/performance', [AiMetricsController::class, 'store']);
        Route::get('/logs', [AiMetricsController::class, 'getTrainingLogs']);
    });

    // Real-Time Firewall & Telemetry Routes
    Route::prefix('firewall')->group(function () {
        Route::get('/recent-telemetry', [FirewallController::class, 'getRecentTelemetry']);
        Route::get('/telemetry', [FirewallController::class, 'getTelemetry']);
        
        // Human-in-the-loop actions
        Route::post('/review', [FirewallController::class, 'review']);
        Route::post('/override', [FirewallController::class, 'override']);
        
        // Audit logs
        Route::get('/interventions', [FirewallController::class, 'getInterventions']);

        // Manual firewall rules management
        Route::prefix('rules')->group(function () {
            Route::get('/', [ManualRulesController::class, 'index']);
            Route::post('/', [ManualRulesController::class, 'store']);
            Route::get('/active', [ManualRulesController::class, 'getActive']);
            Route::delete('/active', [ManualRulesController::class, 'destroyActive']);
            Route::get('/{rule}', [ManualRulesController::class, 'show']);
            Route::put('/{rule}', [ManualRulesController::class, 'update']);
            Route::delete('/{rule}', [ManualRulesController::class, 'destroy']);
        });

        // Read-only view of AI-applied rules (snapshot published by the agent).
        Route::prefix('ai-rules')->group(function () {
            Route::get('/', [AIRulesController::class, 'index']);
            Route::get('/recent', [AIRulesController::class, 'recent']);
        });
    });
});

// Telemetry ingestion is called by the Python agent, so it uses the shared sync token
// instead of browser session auth.
Route::post('/firewall/telemetry', [FirewallController::class, 'receiveTelemetry']);

Route::post('/firewall/rules/import-switch', [ManualRulesController::class, 'importSwitchRules']);
Route::get('/firewall/rules/active-sync', [ManualRulesController::class, 'getActiveSync']);

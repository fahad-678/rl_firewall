<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

// Auth POST routes: skip CSRF validation via middleware exception
Route::middleware(['web'])->group(function () {
    // Post routes with CSRF handled via exception list
    Route::post('/auth/login', [AuthController::class, 'login']);
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    
    // GET - no CSRF needed
    Route::get('/auth/me', [AuthController::class, 'me']);
});

Route::get('/', function () {
    return view('welcome');
});

// Catch-all for Vue SPA - serve the index for any non-API route
Route::get('{any}', function () {
    return view('app');
})->where('any', '.*');


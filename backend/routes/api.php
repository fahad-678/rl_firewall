<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Route;

Route::post('/firewall/override', function (Request $request) {
    $ip = $request->input('ip');
    // Send command back to Python Agent via Redis
    Redis::publish('firewall-commands', json_encode(['action' => 'revoke_block', 'ip' => $ip]));
    return response()->json(['status' => 'Override command dispatched']);
});
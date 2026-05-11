<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class AIRulesController extends Controller
{
    /**
     * Return the agent's current AI-applied rules snapshot.
     *
     * Source: Redis key 'ai-active-rules' (JSON), refreshed by the agent every
     * ~10s with a 30s TTL. If the key is missing the agent is offline.
     */
    public function index()
    {
        $rawRules = null;
        $heartbeatRaw = null;

        try {
            $rawRules = Redis::get('ai-active-rules');
            $heartbeatRaw = Redis::get('ai-agent-heartbeat');
        } catch (\Throwable $e) {
            \Log::warning('Failed to read AI rules snapshot from Redis: ' . $e->getMessage());
        }

        $rules = [];
        if (is_string($rawRules) && $rawRules !== '') {
            $decoded = json_decode($rawRules, true);
            if (is_array($decoded)) {
                $rules = $decoded;
            }
        }

        $lastHeartbeat = null;
        if (is_string($heartbeatRaw) && $heartbeatRaw !== '') {
            $lastHeartbeat = (int) $heartbeatRaw;
        }

        $agentOnline = $lastHeartbeat !== null && (time() - $lastHeartbeat) <= 60;

        return response()->json([
            'rules' => $rules,
            'agent_online' => $agentOnline,
            'last_heartbeat' => $lastHeartbeat,
        ]);
    }

    /**
     * Return recently-expired AI rules (last 50, newest first).
     */
    public function recent()
    {
        $items = [];

        try {
            $raw = Redis::lrange('ai-rules-recent-expirations', 0, 49);
            foreach ($raw as $entry) {
                $decoded = json_decode($entry, true);
                if (is_array($decoded)) {
                    $items[] = $decoded;
                }
            }
        } catch (\Throwable $e) {
            \Log::warning('Failed to read recent AI rule expirations: ' . $e->getMessage());
        }

        return response()->json(['rules' => $items]);
    }
}

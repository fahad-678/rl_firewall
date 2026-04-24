<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Redis;
use App\Events\ThreatDetected;

class ListenToPythonAgent extends Command
{
    protected $signature = 'firewall:listen';
    protected $description = 'Listen to Redis for Python Agent telemetry and broadcast via Reverb';

    public function handle()
    {
        Redis::connection()->client()->setOption(\Redis::OPT_READ_TIMEOUT, -1);
        $this->info('Listening for firewall telemetry on Redis...');

        // Subscribe to the exact Redis channel the Python script publishes to
        Redis::subscribe(['firewall-telemetry'], function ($message) {
            $data = json_decode($message, true);
            
            if ($data) {
                // Fire the WebSocket broadcast event
                event(new ThreatDetected($data));
                $this->info("Broadcasted threat from IP: " . $data['src_ip']);
            }
        });
    }
}
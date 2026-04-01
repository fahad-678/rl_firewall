<?php

namespace App\Events;

use Illuminate\Broadcasting\Channel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcastNow;
use Illuminate\Queue\SerializesModels;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Broadcasting\InteractsWithSockets;

// Using ShouldBroadcastNow to avoid queueing delays for real-time telemetry
class ThreatDetected implements ShouldBroadcastNow
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public $telemetryData;

    public function __construct(array $telemetryData)
    {
        $this->telemetryData = $telemetryData;
    }

    public function broadcastOn()
    {
        // Broadcasting on a public channel for the dashboard
        return new Channel('firewall-telemetry');
    }

    public function broadcastAs()
    {
        return 'threat.detected';
    }
}
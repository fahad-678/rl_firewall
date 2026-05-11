<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TelemetryLog extends Model
{
    use HasFactory;

    protected $table = 'telemetry_logs';

    protected $fillable = [
        'src_ip',
        'port',
        'confidence',
        'action',
        'flow_key',
        'reward',
        'latency_ms',
        'terminal',
        'raw_payload',
    ];

    protected $casts = [
        'confidence'  => 'float',
        'reward'      => 'float',
        'latency_ms'  => 'float',
        'terminal'    => 'boolean',
        'raw_payload' => 'array',
        'created_at'  => 'datetime',
        'updated_at'  => 'datetime',
    ];
}

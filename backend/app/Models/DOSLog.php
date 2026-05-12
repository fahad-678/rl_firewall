<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class DOSLog extends Model
{
    protected $table = 'dos_logs';

    protected $fillable = [
        'attack_source_ip',
        'dos_type',
        'packets_per_sec',
        'connection_count',
        'severity',
        'mitigation_action',
        'mitigation_details',
    ];

    protected $casts = [
        'packets_per_sec' => 'integer',
        'connection_count' => 'integer',
        'severity' => 'float',
        'mitigation_details' => 'array',
    ];
}

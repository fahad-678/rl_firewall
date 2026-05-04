<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class InterventionLog extends Model
{
    use HasFactory;

    protected $fillable = [
        'ip_address',
        'port',
        'confidence',
        'decision',
        'action',
        'flow_key',
        'reward',
        'latency_ms',
        'notes'
    ];
}
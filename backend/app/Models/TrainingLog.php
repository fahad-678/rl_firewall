<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class TrainingLog extends Model
{
    protected $fillable = [
            'epoch',
            'epsilon',
            'cumulative_reward',
            'loss',
            'threats_blocked',
            'threats_allowed',
        ];
}

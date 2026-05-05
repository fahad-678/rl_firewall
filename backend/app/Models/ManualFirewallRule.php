<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ManualFirewallRule extends Model
{
    use HasFactory;

    protected $fillable = [
        'ip_address',
        'action',
        'rule_type',
        'expiration_at',
        'port',
        'notes',
        'created_by',
        'status',
    ];

    protected $casts = [
        'expiration_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Get the user who created this rule.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Scope: Get only active rules.
     */
    public function scopeActive($query)
    {
        return $query->where('status', 'ACTIVE');
    }

    /**
     * Scope: Get only expired rules.
     */
    public function scopeExpired($query)
    {
        return $query->where('status', 'EXPIRED');
    }

    /**
     * Scope: Get only deleted rules.
     */
    public function scopeDeleted($query)
    {
        return $query->where('status', 'DELETED');
    }

    /**
     * Scope: Filter by IP address (supports partial matching).
     */
    public function scopeByIp($query, $ip)
    {
        return $query->where('ip_address', 'like', "%{$ip}%");
    }

    /**
     * Scope: Filter by action (BLOCK/ALLOW).
     */
    public function scopeByAction($query, $action)
    {
        return $query->where('action', strtoupper($action));
    }

    /**
     * Scope: Filter by port.
     */
    public function scopeByPort($query, $port)
    {
        if ($port !== null) {
            return $query->where('port', $port);
        }
        return $query;
    }

    /**
     * Scope: Filter by status.
     */
    public function scopeByStatus($query, $status)
    {
        return $query->where('status', strtoupper($status));
    }

    /**
     * Scope: Filter by date range (created_at).
     */
    public function scopeByDateRange($query, $dateFrom, $dateTo)
    {
        if ($dateFrom) {
            $query->whereDate('created_at', '>=', $dateFrom);
        }
        if ($dateTo) {
            $query->whereDate('created_at', '<=', $dateTo);
        }
        return $query;
    }

    /**
     * Scope: Get currently active rules (not expired, status is ACTIVE).
     */
    public function scopeCurrentlyActive($query)
    {
        return $query
            ->where('status', 'ACTIVE')
            ->where(function ($q) {
                $q->whereNull('expiration_at')
                  ->orWhere('expiration_at', '>', now());
            });
    }

    /**
     * Check if rule has expired and update status if needed.
     */
    public function checkAndUpdateExpiration()
    {
        if (
            $this->rule_type === 'TEMPORARY' 
            && $this->expiration_at 
            && $this->expiration_at <= now() 
            && $this->status === 'ACTIVE'
        ) {
            $this->update(['status' => 'EXPIRED']);
            return true;
        }
        return false;
    }

    /**
     * Static method to check and update all expired rules.
     */
    public static function updateExpiredRules()
    {
        $expiredRules = self::where('status', 'ACTIVE')
            ->where('rule_type', 'TEMPORARY')
            ->where('expiration_at', '<=', now())
            ->get();

        foreach ($expiredRules as $rule) {
            $rule->update(['status' => 'EXPIRED']);
        }

        return $expiredRules->count();
    }
}

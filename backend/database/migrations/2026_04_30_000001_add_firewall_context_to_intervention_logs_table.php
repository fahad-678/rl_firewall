<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('intervention_logs', function (Blueprint $table) {
            $table->integer('port')->nullable()->after('ip_address');
            $table->decimal('confidence', 6, 4)->nullable()->after('port');
            $table->string('action')->nullable()->after('decision');
            $table->string('flow_key')->nullable()->after('action');
            $table->decimal('reward', 10, 2)->nullable()->after('flow_key');
            $table->decimal('latency_ms', 10, 2)->nullable()->after('reward');
        });
    }

    public function down(): void
    {
        Schema::table('intervention_logs', function (Blueprint $table) {
            $table->dropColumn([
                'port',
                'confidence',
                'action',
                'flow_key',
                'reward',
                'latency_ms',
            ]);
        });
    }
};
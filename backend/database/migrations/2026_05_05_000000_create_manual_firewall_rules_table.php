<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('manual_firewall_rules', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address')->index(); // Can be single IP or CIDR
            $table->enum('action', ['BLOCK', 'ALLOW']);
            $table->enum('rule_type', ['PERMANENT', 'TEMPORARY']);
            $table->timestamp('expiration_at')->nullable(); // For temporary rules
            $table->integer('port')->nullable(); // Optional port-specific rule
            $table->text('notes')->nullable();
            $table->foreignId('created_by')->constrained('users')->cascadeOnDelete();
            $table->enum('status', ['ACTIVE', 'EXPIRED', 'DELETED'])->default('ACTIVE')->index();
            $table->timestamps();

            // Composite indexes for common queries
            $table->index(['status', 'action']);
            $table->index(['created_at', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('manual_firewall_rules');
    }
};

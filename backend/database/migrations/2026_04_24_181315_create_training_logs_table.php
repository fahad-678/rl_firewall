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
        Schema::create('training_logs', function (Blueprint $table) {
            $table->integer('epoch')->primary();
            $table->float('epsilon', 8, 4)->comment('Exploration rate');
            $table->float('cumulative_reward', 10, 2);
            $table->float('loss', 10, 4)->nullable();
            $table->integer('threats_blocked')->default(0);
            $table->integer('threats_allowed')->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('training_logs');
    }
};

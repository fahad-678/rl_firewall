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
        Schema::create('dos_logs', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('attack_source_ip')->index();
            $table->string('dos_type');
            $table->integer('packets_per_sec')->nullable();
            $table->integer('connection_count')->nullable();
            $table->float('severity', 5, 4)->default(0.5);
            $table->string('mitigation_action')->nullable();
            $table->json('mitigation_details')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dos_logs');
    }
};

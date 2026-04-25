<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('intervention_logs', function (Blueprint $table) {
            $table->id();
            // If you add authentication later, you can link this to a User model
            // $table->foreignId('user_id')->nullable()->constrained(); 
            $table->string('ip_address')->index();
            $table->enum('decision', ['BLOCK', 'ALLOW']);
            $table->text('notes')->nullable(); // Optional field for analyst comments
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('intervention_logs');
    }
};
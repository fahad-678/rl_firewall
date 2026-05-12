<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // Drop the existing primary key on `epoch` and add an auto-increment `id`.
        // Use raw statements to ensure we can alter the primary key directly.
        DB::statement('ALTER TABLE training_logs DROP PRIMARY KEY');
        DB::statement('ALTER TABLE training_logs ADD COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST');
        DB::statement('CREATE INDEX idx_training_logs_epoch ON training_logs (epoch)');
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Attempt to revert: drop id and restore epoch as primary key.
        DB::statement('ALTER TABLE training_logs DROP PRIMARY KEY');
        DB::statement('ALTER TABLE training_logs DROP COLUMN id');
        DB::statement('ALTER TABLE training_logs ADD PRIMARY KEY (epoch)');
    }
};

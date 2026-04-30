<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateTelemetryLogsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('telemetry_logs', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('src_ip')->index();
            $table->unsignedInteger('port')->nullable()->index();
            $table->decimal('confidence', 6, 4)->nullable();
            $table->string('action')->nullable();
            $table->string('flow_key')->nullable()->index();
            $table->double('reward')->nullable();
            $table->double('latency_ms')->nullable();
            $table->boolean('is_malicious')->nullable();
            $table->boolean('terminal')->nullable();
            $table->json('raw_payload')->nullable();
            $table->timestamps();

            $table->index(['created_at']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('telemetry_logs');
    }
}

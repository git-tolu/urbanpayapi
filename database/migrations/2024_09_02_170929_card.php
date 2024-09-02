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
        Schema::create('card', function (Blueprint $table) {
            $table->id();
            $table->string('card_id');
            $table->string('user_id');
            $table->string('wallet_id');
            $table->string('fundingSource');
            $table->string('type');
            $table->string('currency');
            $table->string('maskedPan');
            $table->string('expiryMonth');
            $table->string('expiryYear');
            $table->string('is2FAEnrolled');
            $table->string('isDefaultPINChanged');
            $table->string('disposable');
            $table->string('refundAccount');
            $table->string('isDeleted');
            $table->string('createdAt');
            $table->string('updatedAt');
            $table->string('status')->nullable();             
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('card');
    }
};

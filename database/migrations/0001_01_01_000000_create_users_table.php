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
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('user_id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('username');
            $table->string('phoneno');
            $table->string('password');
            $table->string('pin');
            $table->string('otp');
            $table->string('firstName');
            $table->string('lastName');
            $table->string('middleName');
            $table->string('phoneNumber');
            $table->string('addressLine_1');
            $table->string('addressLine_2');
            $table->string('country');
            $table->string('city');
            $table->string('postalCode');
            $table->string('state');
            $table->string('isSoleProprietor');
            $table->string('description');
            $table->string('doingBusinessAs');
            $table->string('gender');
            $table->string('dateOfBirth');
            $table->string('selfieImage');
            $table->string('bvn');
            $table->string('idType');
            $table->string('idNumber');
            $table->string('expiryDate');
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamps();

            // $table->id();
            // $table->string('name');
            // $table->string('email')->unique();
            // $table->timestamp('email_verified_at')->nullable();
            // $table->string('password');
            // $table->rememberToken();
            // $table->timestamps();
        });

        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('sessions');
    }
};

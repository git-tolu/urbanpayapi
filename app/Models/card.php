<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class card extends Model
{
    use HasFactory;
    protected $fillable = [
        'card_id',
        'user_id',
        'wallet_id',
        'fundingSource',
        'type',
        'currency',
        'maskedPan',
        'expiryMonth',
        'expiryYear',
        'is2FAEnrolled',
        'isDefaultPINChanged',
        'disposable',
        'refundAccount',
        'isDeleted',
        'createdAt',
        'updatedAt',
        'status'
    ];
  
}

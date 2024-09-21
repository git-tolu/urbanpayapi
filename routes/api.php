<?php

use App\Http\Controllers\Api\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');

Route::post('/login', [UserController::class, 'login']);
Route::post('/register', [UserController::class, 'createUser']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [UserController::class, 'logout']);
    Route::post('/refresh', [UserController::class, 'refresh']);
    Route::get('/me', [UserController::class, 'me']);
    Route::post('/verifyOtp', [UserController::class, 'verifyOtp']);
    Route::post('/pin', [UserController::class, 'pin']);
    Route::delete('/deleteUser/{id}', [UserController::class, 'deleteUser']);
    Route::post('/singleUser', [UserController::class, 'singleUser']);
    Route::post('/singleUser2', [UserController::class, 'singleUser2']);
    Route::post('/listUser', [UserController::class, 'listUser']);
    Route::post('/updateUserProfile', [UserController::class, 'updateUserProfile']);
    Route::post('/updateUserProfilePinVerify', [UserController::class, 'updateUserProfilePinVerify']);
    Route::post('/updateUserProfilePasswordVerify', [UserController::class, 'updateUserProfilePasswordVerify']);
    Route::post('/updateUserProfilePin', [UserController::class, 'updateUserProfilePin']);
    Route::post('/updateUserProfilePassword', [UserController::class, 'updateUserProfilePassword']);
    Route::post('/getbankList', [UserController::class, 'getbankList']);
    Route::post('/verifyBank', [UserController::class, 'verifyBank']);
    Route::post('/sendMoney', [UserController::class, 'sendMoney']);
    Route::post('/sendMoneyWithTag', [UserController::class, 'sendMoneyWithTag']);
    Route::post('/addMoney', [UserController::class, 'addMoney']);
    Route::post('/transactionGet', [UserController::class, 'transactionGet']);
    Route::post('/transactionGetALL', [UserController::class, 'transactionGetALL']);
    Route::post('/createCard', [UserController::class, 'createCard']);
    Route::post('/depositByCard', [UserController::class, 'depositViaCard']);
    Route::post('/transferToBankAccount', [UserController::class, 'transferToBankAccount1']);
    Route::post('/wallet/remita/callback', [UserController::class, 'handleWebhook']);
    Route::post('/cardGetTransactions', [UserController::class, 'cardGetTransactions']);
    Route::post('/cardGetSingleTransactions', [UserController::class, 'cardGetSingleTransactions']);
    Route::post('/getCardById', [UserController::class, 'getCardById']);
    Route::post('/getCustomerCards', [UserController::class, 'getCustomerCards']);
    Route::post('/customerCardGetDetails', [UserController::class, 'customerCardGetDetails']);
    Route::post('/UserdetailsByteBridge', [UserController::class, 'UserdetailsByteBridge']);
    Route::post('/BuyData', [UserController::class, 'BuyData']);
    Route::post('/fetchDataTransaction', [UserController::class, 'fetchDataTransaction']);
    Route::post('/fetchDataTransactionSingle', [UserController::class, 'fetchDataTransactionSingle']);
    Route::post('/topUp', [UserController::class, 'topUp']);
    Route::post('/FetchAirtimeTransactionSingle', [UserController::class, 'FetchAirtimeTransactionSingle']);
    Route::post('/billPayment', [UserController::class, 'billPayment']);
    Route::post('/subscribeToCable', [UserController::class, 'subscribeToCable']);
    Route::post('/getCableSubscription', [UserController::class, 'getCableSubscription']);
    Route::post('/validateIUC', [UserController::class, 'validateIUC']);
    Route::post('/validateMeter', [UserController::class, 'validateMeter']);
});

<?php

namespace App\Http\Controllers\Api;


use App\Models\User;
use App\Models\deleteduser;
use App\Models\otp;
use App\Models\wallet;
use App\Models\transaction;
use App\Models\beneficiary;
use App\Models\notifications;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use App\Mail\OtpVerificationMail;
use App\Mail\pinVerification;
use App\Mail\notificationMail;
use Illuminate\Support\Facades\Http;
use GuzzleHttp\Client;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Session;


class UserController extends Controller
{
    /**
     * Create User
     * @param Request $request
     * @return user
     */

    public function createUser(Request $request)
    {
        try {

            $validatedData = $request->validate([
                'name' => 'nullable|string|max:255',
                'email' => 'nullable|string|email|max:255|unique:users',
                'username' => 'nullable|string|max:255',
                'phoneno' => 'nullable|max:255',
                'password' => 'nullable',
                'pin' => 'nullable|string',
                'firstName' => 'required',
                'lastName'   => 'required',
                'middleName' => 'nullable',
                'phoneNumber' => 'required',
                'addressLine_1'   => 'required',
                'addressLine_2' => 'nullable',
                'country' => 'required',
                'city' => 'required',
                'postalCode' => 'required',
                'state' => 'required',
                'gender' => 'required',
                'dateOfBirth'   => 'required',
                'bvn' => 'required',
            ]);

            if (strlen($request->pin) == 5) {

                // Generate random OTP
                $otp = mt_rand(100000, 999999);

                // Send email to user containing the OTP
                // $validatedData['email'] = "adejumobitoluwanimi11@gmail.com";
                Mail::to($validatedData['email'])->send(new OtpVerificationMail($otp));

                try {

                    // create customers

                    // spliting fullname
                    $string = $validatedData['name'];
                    $words = explode(' ', $string); // Split the string into an array of words
                    $firstname = $words[0]; // First word
                    $lastname = $words[1]; // Second word

                    $url = 'https://api.sandbox.sudo.cards/customers';
                    $headers = [
                        'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
                        'accept' => 'application/json',
                        'content-type' => 'application/json',
                    ];

                    $body = [
                        "type" => "individual",
                        "name" => "" . $validatedData['name'] . "",
                        "phoneNumber" => "" . $validatedData['phoneno'] . "",
                        "emailAddress" => "" . $validatedData['email'] . "",
                        "individual" => [
                            "firstName" => "{$firstname}",
                            "lastName" => "{$lastname}",
                            "otherNames" => "" . $validatedData['middleName'] . "",
                            "dob" => "" . $validatedData['dateOfBirth'] . "",
                            "identity" => [
                                "type" => "BVN",
                                "number" => "string"
                            ],
                            "documents" => [
                                "idFrontUrl" => "string",
                                "idBackUrl" => "string",
                                "incorporationCertificateUrl" => "string",
                                "addressVerificationUrl" => "string"
                            ]
                        ],
                        "status" => "active",
                        "billingAddress" => [
                            "line1" => "" . $validatedData['addressLine_1'] . "",
                            "line2" => "" . $validatedData['addressLine_2'] . "",
                            "city" => "" . $validatedData['city'] . "",
                            "state" => "" . $validatedData['state'] . "",
                            "postalCode" => "" . $validatedData['postalCode'] . "",
                            "country" => "" . $validatedData['country'] . ""
                        ]
                    ];

                    $response = Http::withHeaders($headers)->post($url, $body);
                    $responseData = $response->json(); // Return JSON response from the API


                    // create deposit account
                    $url = 'https://api.sandbox.sudo.cards/accounts';

                    $body = [
                        'type' => 'wallet',
                        'currency' => 'NGN',
                        'accountType' => 'Current',
                        'customerId' => '' . $responseData['data']['_id'] . '',
                    ];

                    $response1 = Http::withHeaders([
                        'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
                        'accept' => 'application/json',
                        'content-type' => 'application/json',
                    ])->post($url, $body);


                    $responseData1 = $response1->json(); // Return JSON response from the API

                    // save data to database
                    // Session::put('user', [
                    //     'balance' => 0,
                    //     'user_id' => $responseData['data']['_id'],
                    //     'wallet_id' => $responseData1['data']['_id'],
                    //     // Add other fields as needed
                    // ]);

                    // $request->session()->put('balance', 0);
                    // $request->session()->put('user_id', $responseData['data']['_id']);
                    // $request->session()->put('wallet_id', $responseData1['data']['_id']);
                    // $request->session()->put('bearer', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI');

                    // insert user
                    $user = User::create([
                        'user_id' => $responseData['data']['_id'],
                        'name' => $validatedData['name'],
                        'email' => $validatedData['email'],
                        'username' => $validatedData['username'],
                        'phoneno' => $validatedData['phoneno'],
                        'password' => Hash::make($validatedData['password']),
                        'pin' => Hash::make($validatedData['pin']),
                        'otp' => $otp,
                        'firstName' => $firstname,
                        'lastName'   => $lastname,
                        'middleName' => $validatedData['middleName'],
                        'phoneNumber' => $validatedData['phoneNumber'],
                        'addressLine_1'   => $validatedData['addressLine_1'],
                        'addressLine_2' => $validatedData['addressLine_2'],
                        'country' => $validatedData['country'],
                        'city' => $validatedData['city'],
                        'postalCode' => $validatedData['postalCode'],
                        'state' => $validatedData['state'],
                        'isSoleProprietor' => true,
                        'description' => 'null',
                        'doingBusinessAs' => 'null',
                        'gender' => $validatedData['gender'],
                        'dateOfBirth'   => $validatedData['dateOfBirth'],
                        'bvn' => 'null',
                        'idType' => 'null',
                        'idNumber' => 'null',
                        'expiryDate' => 'null',
                        'selfieImage' => 'null',
                    ]);

                    // save to session
                    // Session::put('user', [
                    //     'username' => $user->username,
                    //     'name' => $user->name,
                    //     'email' => $user->email,
                    //     // Add other fields as needed
                    // ]);

                    // $request->session()->put('email', $user->email);
                    // $request->session()->put('name', $user->name);
                    // $request->session()->put('username', $user->username);

                    // generate token
                    // $token = JWTAuth::fromUser($user);

                    $token = $user->createToken('AuthToken')->plainTextToken;

                    // email otp
                    $user = User::where('email', $user->email)->first();


                    if (!$user) {
                        return response()->json(['message' => 'User not found'], 404);
                    }

                    // Store OTP in the database with the user's email
                    $user->save();
                    // $user->delete();

                    $wallet = wallet::create([
                        'user_id' => $responseData['data']['_id'],
                        'wallet_id' => $responseData1['data']['_id'],
                        'transaction_id' => rand(),
                        'acct_id' => $responseData1['data']['_id'],
                        'account_name' => $responseData1['data']['accountName'],
                        'urbanPayTag' => $validatedData['username'],
                        'account_email' => $responseData['data']['emailAddress'],
                        'account_number' => $responseData1['data']['accountNumber'],
                        'currency' => $responseData1['data']['currency'],
                        'bank_id' => null,
                        'bank_name' => $responseData1['data']['provider'],
                        'bank_code' => $responseData1['data']['bankCode'],
                        'balance' => $responseData1['data']['currentBalance'],
                        'account_reference' => $responseData1['data']['providerReference'],
                        'status' => $responseData['data']['status'],
                    ]);

                    $notification = notifications::create([
                        'user_id' => $responseData['data']['emailAddress'],
                        'title' => 'Account Creation',
                        'message' => 'Your Account has been created succesfully.'
                    ]);
                    // Send notfication email to user containing the OTP
                    Mail::to($user->email)->send(new notificationMail('Account Creation', 'Your Account has been created succesfully.'));
                    // Create a Sanctum token
                    // $token = $user->createToken('auth_token')->plainTextToken;

                    return response()->json([
                        'message' => 'User registered successfully',
                        'access_token' => $token,
                        'token_type' => 'Bearer',
                        'data' => $responseData,
                        'data1' => $responseData1,
                    ]);
                } catch (\GuzzleHttp\Exception\RequestException $e) {
                    if ($e->hasResponse()) {
                        $response = $e->getResponse();
                        $statusCode = $response->getStatusCode();
                        $errorMessage = $response->getBody()->getContents();
                    } else {
                        // Handle other request exceptions
                        $statusCode = $e->getCode();
                        $errorMessage = $e->getMessage();
                    }

                    return response()->json([
                        'error' => $errorMessage,
                        'status' => $statusCode
                    ], $statusCode);
                }
            } else {
                return response()->json([
                    'status' => 401,
                    'message' => 'pin must be 5 digits'
                ], 500);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    /**
     * Create User
     * @param Request $request
     * @return user
     */

    public function login(Request $request)
    {
   
        // Validate the request data
        $credentials = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Attempt to log the user in
        if ($token = Auth::attempt($credentials)) {
            // Authentication passed...
            // Store user details in session
            /** @var \App\Models\User $user **/
            $user = Auth::user();
            // Session::put('user', [
            //     'username' => $user->username,
            //     'name' => $user->name,
            //     'email' => $user->email,
            //     // Add other fields as needed
            // ]);

            // saving wallet details to session
            $wallet = wallet::where('account_email', $user->email)->first();
            // Session::put('user', [
            //     'balance' => $wallet->balance,
            //     'user_id' => $wallet->user_id,
            //     'wallet_id' => $wallet->wallet_id,
            //     'transaction_id' => $wallet->transaction_id,
            //     // Add other fields as needed
            // ]);

            // Generate random OTP
            $otp = mt_rand(100000, 999999);

            // Store OTP in the database with the user's email
            $user->otp = $otp;


            // // Send email to user containing the OTP
            Mail::to($user->email)->send(new OtpVerificationMail($user->otp));

            // inserting notifcation
            $title = "Welcome back, {$user->name}";
            $msg = 'You have successfully logged in.';
            $notification = notifications::create([
                'user_id' => $wallet->user_id,
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($user->email)->send(new notificationMail($title, $msg));
            // Create a Sanctum token
            $token = $user->createToken('auth_token')->plainTextToken;

            // Return success response
            return response()->json([
                'otp' => $otp,
                'message' => 'Login successful',
                'user' => $user,
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 200);
        }

        // Authentication failed...
        return response()->json([
            'message' => 'Invalid credentials'
        ], 401);
    }

    public function me()
    {
        return response()->json(Auth::user());
    }


    public function logout(Request $request)
    {
        // Revoke the token that was used to authenticate the current request
        $request->user()->currentAccessToken()->delete();
        // // Log out the user
        Auth::logout();

        return response()->json([
            'message' => 'Logout successful'
        ], 200);
    }


    public function pin(Request $request)
    {
        try {

            $email = $request->session()->get('email');

            if ($email) {
                # code...
                $credentials = $request->validate([
                    'pin' => 'required|string',
                ]);

                $user = User::where('email', $email)->first();

                if (!$user || !password_verify($credentials['pin'], $user->pin)) {
                    return response()->json(['message' => 'Invalid email or PIN'], 401);
                }

                // User is authenticated, return success response
                // inserting notifcation
                $title = "Welcome back, {$user->firstName} {$user->lastName}";
                $msg = 'You have successfully logged in.';
                $notification = notifications::create([
                    'user_id' => $request->session()->get('user_id'),
                    'title' => $title,
                    'message' => $msg
                ]);
                // Send notfication email to user containing the OTP
                Mail::to($user->email)->send(new notificationMail($title, $msg));

                return response()->json(['message' => 'Login successful', 'user' => $user]);
            } else {
                # code...
                return response()->json([
                    'message' => 'email required',
                ]);
            }
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ], 500);
        }
        # code...
    }

    public function verifyOtp(Request $request)
    {
        $email = $request->session()->get('email');

        $user = User::where('email', $email)->first();
        $request->validate([
            'otp' => 'required',
        ]);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        if ($request->otp == $user->otp) {
            // OTP is valid
            // Perform necessary actions (e.g., mark email as verified)
            $user->email_verified_at = now();
            $user->save();
            return response()->json(['message' => 'OTP verified successfully']);
        } else {
            // OTP is invalid
            return response()->json(['message' => 'Invalid OTP'], 401);
        }
    }


    public function deleteUser(Request $request, $id)
    {

        try {
            // Retrieve the user from the current database
            $user = User::findOrFail($id);

            // Backup user data before deleting
            $userData = $user->toArray();

            // Delete the user from the current database
            $user->delete();
            // Delete the user from the anchor database
            // $response = Http::withHeaders([
            //     'accept' => 'application/json',
            //     'content-type' => 'application/json',
            //     'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8'
            // ])->get('https://api.sandbox.getanchor.co/api/v1/customers/' . $request->session()->get('user_id') . '');
            // $responseData = $response->json();
            // inserting notifcation
            $title = "User Deleted";
            $msg = 'The user has been successfully deleted.';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($user->email)->send(new notificationMail($title, $msg));

            // Upload the user data to another database
            //  DB::connection('urbanPayApi')->table('deletedusers')->insert($userData);
            //    $deleteduser = deleteduser::create([
            //         'name' => $user->name,
            //         'email' => $user->email,
            //         'username' => $user->username,
            //         'phoneno' => $user->phoneno,
            //         'password' => $user->password,
            //         'pin' => $user->pin
            //     ]);
            return response()->json(['message' => 'Deleted successfully', 'data' => null]);
        } catch (\Exception $e) {
            // Handle upload failure

            return response()->json(['message' => 'Failed to upload user data'], 500);
        }
    }

    // show one
    public function listUser(Request $request)
    {
        $user = DB::select('select * from users ');
        $wallet = DB::select('select * from wallets ');

        // $request->validate([
        //     'id' => 'required|string',
        //     'acct' => 'required|string',
        // ]);
        // $url = 'https://api.sandbox.sudo.cards/customers/'.$request->id.'';


        // $response = Http::withHeaders([
        //     'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
        //     'accept' => 'application/json',
        //     'content-type' => 'application/json',
        // ])->get($url);

        // $responseData =  $response->json(); // Return the JSON response from the API

        // $url = 'https://api.sandbox.sudo.cards/accounts/'.$request->acct.'';


        // $response1 = Http::withHeaders([
        //     'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
        //     'accept' => 'application/json',
        //     'content-type' => 'application/json',
        // ])->get($url);

        // $responseData1 =  $response1->json(); // Return the JSON response from the API
        $responseData =  $user; // Return the JSON response from the API
        $responseData1 =  $wallet; // Return the JSON response from the API
        return response()->json([
            'data' => $responseData,
            'data1' => $responseData1
        ]);
    }


    public function singleUser(Request $request)
    {

        // $user = User::find($id);
        // if ($user) {
        //     return response()->json([$user], 202);
        // } else {
        //     return response()->json([
        //         'message' => "User not found"
        //     ], 404);
        // }

        $session = Auth::user();

        $email =$session['email'];
        // $id = Session::get('user.user_id');
        // $acct = Session::get('user.wallet_id');

        // $url = 'https://api.sandbox.sudo.cards/customers/'.$id.'';

        // $response = Http::withHeaders([
        //     'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
        //     'accept' => 'application/json',
        //     'content-type' => 'application/json',
        // ])->get($url);

        // $responseData =  $response->json(); // Return the JSON response from the API

        // $url = 'https://api.sandbox.sudo.cards/accounts/' . $acct;

        // $response1 = Http::withHeaders([
        //     'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
        //     'accept' => 'application/json',
        // ])->get($url);
        // $responseData1 =  $response1->json(); // Return the JSON response from the API

        // $user = DB::select("select * from users where `user_id` = '{$id}'");
        // $wallet = DB::select("select * from wallets where `wallet_id` = '{$acct}'");
        $user = User::where('email', "{$email}")->first();
        $wallet = wallet::where('account_email', "{$email}")->first();

        $responseData =  $user; // Return the JSON response from the API
        $responseData1 =  $wallet; // Return the JSON response from the API
        return response()->json([
            // '$acct' => $acct,
            'email' => $email,
            'data' => $responseData,
            'data1' => $responseData1
        ]);

    }

    public function singleUser2(Request $request)
    {
        $credentials = $request->validate([
            'user_id' => 'required|string',
            'wallet_id' => 'required|string',
        ]);

        $id = $request->user_id;
        $acct = $request->wallet_id;

        $user = DB::select("select * from users where `user_id` = '{$id}'");
        $wallet = DB::select("select * from wallets where `wallet_id` = '{$acct}'");
        $responseData =  $user; // Return the JSON response from the API
        $responseData1 =  $wallet; // Return the JSON response from the API
        return response()->json([
            'data' => $responseData,
            'data1' => $responseData1
        ]);
    }


    public function updateUserProfile(Request $request)
    {
        $email = $request->session()->get('email');
        $request->validate([
            'name' => 'required',
            'email' => 'required',
            'username' => 'required',
            'phoneno' => 'required',
        ]);

        if (User::where('email', $email)->exists()) {
            // $user = User::find($email);
            // $user->name = is_null($request->name) ? $user->name :  $request->name;
            // $user->email = is_null($request->email) ? $user->email :  $request->email;
            // $user->username = is_null($request->username) ? $user->username :  $request->username;
            // $user->phoneno = is_null($request->phoneno) ? $user->phoneno :  $request->phoneno;
            // $user->save();

            User::where('email', $email)->update([
                'name' => $request->name,
                'email' => $request->email,
                'username' => $request->username,
                'phoneno' => $request->phoneno,
            ]);

            // inserting notifcation
            $title = "Profile Updated Successfully!";
            $msg = 'Profile Updated Successfully!';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));


            return response()->json([
                "message" => "Profile Updated"
            ], 200);
        } else {
            return response()->json([
                "message" => "User not found"
            ], 404);
        }
    }



    public function updateUserProfilePinVerify(Request $request)
    {
        $email = $request->session()->get('email');
        $request->validate([
            'pin' => 'required',
        ]);

        if (strlen($request->pin) == 5) {

            $user = User::where('email', $email)->first();
            $otp = new otp;

            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

            // Generate random OTP
            $rand = mt_rand(0, 999999);

            // Store OTP in the database with the user's email
            $otp->email = $email;
            $otp->otp = $rand;
            $otp->save();

            // Send email to user containing the OTP
            Mail::to($user->email)->send(new pinVerification($rand));
            $request->session()->put('pin', $request->pin);
            $request->session()->put('otp', $rand);
            return response()->json(['message' => 'otp sent succcessfully'], 404);
        } else {
            return response()->json([
                'status' => 401,
                'message' => 'pin must be 5 digits'
            ], 500);
        }
    }


    public function updateUserProfilePasswordVerify(Request $request)
    {
        $email = $request->session()->get('email');

        $request->validate([
            'password' => 'required',
        ]);


        $user = User::where('email', $email)->first();
        $otp = new otp;

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        // Generate random OTP
        $rand = mt_rand(100000, 999999);

        // Store OTP in the database with the user's email
        $otp->email = $email;
        $otp->otp = $rand;
        $otp->save();

        // Send email to user containing the OTP
        Mail::to($user->email)->send(new pinVerification($rand));
        $request->session()->put('password', $request->password);
        $request->session()->put('otp', $rand);
        return response()->json(['message' => 'otp sent succcessfully'], 404);
    }


    public function updateUserProfilePin(Request $request)
    {
        $email = $request->session()->get('email');
        $pin = $request->session()->get('pin');

        $otp = otp::where('otp', $request->otp)->first();
        $request->validate([
            'otp' => 'required',
        ]);

        // if (!$otp) {
        //     return response()->json(['message' => 'User not found'], 404);
        // }

        if ($otp) {
            // OTP is valid
            // Perform necessary actions (e.g., mark email as verified)
            $otp->verify = 'yes';
            $otp->save();
            // inserting notifcation
            $title = "Profile Updated Successfully!";
            $msg = 'Profile Updated Successfully!';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));
            // inserting notifcation
            $title = "Pin Updated Successfully!";
            $msg = 'Pin Updated Successfully!';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));

            if (User::where('email', $email)->exists()) {
                User::where('email', $email)->update([
                    'pin' => Hash::make($pin),
                ]);
                // $user = User::find($email);
                // $user->pin = Hash::make($pin);
                // $user->save();
                return response()->json([
                    "message" => "Pin Updated"
                ], 200);
            } else {
                return response()->json([
                    "message" => "User not found"
                ], 404);
            }
        } else {
            // OTP is invalid
            return response()->json(['message' => 'Invalid OTP'], 401);
        }
    }


    public function updateUserProfilePassword(Request $request)
    {

        $email = $request->session()->get('email');
        $password = $request->session()->get('password');

        $otp = otp::where('otp',  $request->otp)->first();
        $request->validate([
            'otp' => 'required',
        ]);

        // if (!$otp) {
        //     return response()->json(['message' => 'User not found'], 404);
        // }

        if ($otp) {
            // OTP is valid
            // Perform necessary actions (e.g., mark email as verified)
            $otp->verify = 'yes';
            $otp->save();
            if (User::where('email', $email)->exists()) {
                User::where('email', $email)->update([
                    'password' => Hash::make($password),
                ]);
                // $user = User::find($email);
                // $user->password = is_null($password) ? $user->password :  Hash::make($password);
                // $user->save();
                return response()->json([
                    "message" => "Password Updated"
                ], 200);
            } else {
                return response()->json([
                    "message" => "User not found"
                ], 404);
            }
        } else {
            // OTP is invalid
            return response()->json(['message' => 'Invalid OTP'], 401);
        }
    }

    public function getbankList(Request $request)
    {

        try {

            // get list of bank
            $url = 'https://api.sandbox.sudo.cards/accounts/banks';

            $response = Http::withHeaders([
                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI', // Replace with your actual API key
                'accept' => 'application/json',
                'content-type' => 'application/json',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                'msg' => $responseData
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function verifyBank(Request $request)
    {

        try {
            $validatedData = $request->validate([
                'bankIdOrBankCode' => 'required|string',
                'accountNumber' => 'required|string'

            ]);


            $url = 'https://api.sandbox.sudo.cards/accounts/transfer/name-enquiry';
            $body = [
                'bankCode' => $request->input('bankIdOrBankCode'),
                'accountNumber' => $request->input('accountNumber'),
            ];
            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
            ])->post($url, $body);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                'msg' => $responseData
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function sendMoney(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'bankIdOrBankCode' => 'required|string',
                'accountNumber' => 'required|string',
                'reference' => 'required|string',
                'bank_name' => 'required|string',
                'account_name' => 'required|string',
                'amount' => 'required|string',
                'narration' => 'required|string',
            ]);
            // get accountid from session
            $acct_id = $request->session()->get('wallet_id');

            $wallet = wallet::where('wallet_id', $acct_id);


            $url = 'https://api.sandbox.sudo.cards/accounts/transfer';

            $headers = [
                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI', // Replace with your actual API key
                'accept' => 'application/json',
                'content-type' => 'application/json',
            ];


            $body = [
                'debitAccountId' => $acct_id,
                'creditAccountId' => $request->input('creditAccountId'),
                'beneficiaryBankCode' => $request->input('bankIdOrBankCode'),
                'beneficiaryAccountNumber' => $request->input('accountNumber'),
                'amount' => $request->input('amount'),
                'narration' => $request->input('narration'),
                'paymentReference' => $request->input('reference'),
            ];

            $response = Http::withHeaders($headers)->post($url, $body);

            $responseData = $response->json(); // Return the JSON response from the API


            $transaction = transaction::create([

                'user_id' => $request->session()->get('user_id'),
                'wallet_id' => $request->session()->get('wallet_id'),
                'transaction_id' => $request->session()->get('transaction_id'),
                'reference' => $request->reference,
                'toBank_code' => $request->bankIdOrBankCode,
                'toBank_name' => $request->bank_name,
                'toAccount_number' => $request->accountNumber,
                'toAccount_name' => $request->account_name,
                'account_number' => $wallet['account_number'],
                'account_name' => $wallet['account_name'],
                'bank_code' => $wallet['bank_code'],
                'bank_name' => $wallet['bank_name'],
                'amount' => $request->amount,
                'narration' => $request->narration,
                'status' => 'success',
            ]);

            $beneficiary = beneficiary::create([

                'user_id' => $request->session()->get('user_id'),
                'wallet_id' => $request->session()->get('wallet_id'),
                'transaction_id' => $request->session()->get('transaction_id'),
                'reference' => $request->reference,
                'bank_code' => $request->bankIdOrBankCode,
                'bank_name' => $request->bank_name,
                'account_number' => $request->accountNumber,
                'account_name' => $request->account_name,
                'urbanPayTag' => $wallet->urbanPayTag,
            ]);

            // fetching balance
            $url = "https://api.sandbox.sudo.cards/accounts/{$acct_id}/balance";

            $response1 = Http::withHeaders([
                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI', // Replace with your actual API key
                'accept' => 'application/json',
                'content-type' => 'application/json',
            ])->get($url);

            $responseData1 = $response1->json(); // Return the JSON response from the API

            // inserting notifcation
            $title = "Transfer Successful";
            $msg = "Your payment of NGN {$request->amount} to " . $request->account_name . " has been processed successfully. Your new balance is NGN " . $responseData1['data']['currentBalance'] . " ";
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);

            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));
            return response()->json([
                'data' => $responseData,
                'data1' => $responseData1,
            ], 500);
        } catch (\Throwable $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function sendMoneyWithTag(Request $request)
    {

        try {

            $request->validate([
                'reference' => 'required|string',
                'bank_code' => 'required|string',
                'amount' => 'required|string',
                'urbanPayTag' => 'nullable|string',
                'narration' => 'required|string',
            ]);
            try {

                // get acount details
                $wallets = DB::table('wallets')
                    ->where('urbanPayTag', '=', $request->urbanPayTag)
                    ->get();


                // verify bank account
                $client = new Client();
                $access_token = $request->session()->get('bearer');

                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . '',
                ];
                $body = '{
                  "bank_code": "' . $request->bank_code . '",
                  "account_number": ""' . $wallets['account_number'] . '"
                }';
                $request1 = $client->request('POST', 'https://sagecloud.ng/api/v2/transfer/verify-bank-account', [
                    'headers' =>  $headers,
                    'json' => $body
                ]);
                $ress = $request1->getBody()->getContents();
                $ressArray = json_decode($ress, true);


                // send  money
                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . ''
                ];
                $body = '{
                    "reference": "' . $wallets['reference'] . '",
                    "bank_code": "' . $request->bank_code . '",
                    "account_number": "' . $wallets['account_number'] . '",
                    "account_name": "' . $wallets['account_name'] . '",
                    "amount": "' . $request->amount . '",
                    "narration": "' . $request->narration . '"
                }';
                // $body = '{
                //     "reference": "6A3EKXI5M6U7DAVL_tf1",
                //     "bank_code": "044",
                //     "account_number": "0058381844",
                //     "account_name": "Samson Okemakinde",
                //     "amount": "100",
                //     "narration": "Test Transfer"
                // }';
                $request2 = $client->request('POST', 'https://sagecloud.ng/api/v2/transfer/fund-transfer', [
                    'headers' => $headers,
                    'json' => $body
                ]);
                $response = $request2->getBody()->getContents();




                $transaction = transaction::create([
                    'user_id' => $request->session()->get('user_id'),
                    'wallet_id' => $request->session()->get('wallet_id'),
                    'transaction_id' => $request->session()->get('transaction_id'),
                    'reference' => $wallets['reference'],
                    'bank_code' => $request->bank_code,
                    'bank_name' => $wallets['bank_name'],
                    'account_number' => $wallets['account_number'],
                    'account_name' => $wallets['account_name'],
                    'amount' => $request->amount,
                    'urbanPayTag' => $request->urbanPayTag,
                    'narration' => $request->narration,
                    'status' => 'success',
                ]);

                $beneficiary = beneficiary::create([
                    'user_id' => $request->session()->get('user_id'),
                    'wallet_id' => $request->session()->get('wallet_id'),
                    'transaction_id' => $request->session()->get('transaction_id'),
                    'reference' => $wallets['reference'],
                    'bank_code' => $request->bank_code,
                    'bank_name' => $wallets['bank_name'],
                    'account_number' => $wallets['account_number'],
                    'account_name' => $wallets['account_name'],
                    'urbanPayTag' => $request->urbanPayTag,
                ]);
                return response()->json([
                    'message' => $ress,
                    'msg' => $response,
                    'wallets' => $wallets,
                ], 500);
            } catch (\Throwable $e) {
                return response()->json([
                    'status' => false,
                    'message' => $e->getMessage()
                ], 500);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function addMoney(Request $request)
    {
        try {
            # code...
            // $user_id = $request->session()->get('user_id');
            $wallet_id = $request->session()->get('wallet_id');
            $wallets = wallet::where('wallet_id', $wallet_id)->first();
            // $wallets = DB::table('wallets')
            //     ->where('user_id', '=', $user_id)
            //     ->where('wallet_id', '=', $wallet_id)
            //     ->get();

            return response()->json([
                'data' => $wallets
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function createCard(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'brand' => 'string',
                'type' => 'string|required',
                'number' => 'string',
                'currency' => 'string|required',
                'issuerCountry' => 'string',
                'metadata' => 'string',
                'allowedCategories' => 'string',
                'blockedCategories' => 'string',
                'spendinglimitamount' => 'string',
                'spendinglimitinterval' => 'string',
                'bankCode' => 'string',
                'accountNumber' => 'string',
                'replacementFor' => 'string',
                'replacementReason' => 'string',
                'debitAccountId' => 'string',
                'amount' => 'string',
                'sendPINSMS' => 'string',
                'expirationDate' => 'string',

            ]);
            $url = 'https://api.sandbox.sudo.cards/cards';
            $email = $request->session()->get('email');
            $name = $request->session()->get('name');
            $username = $request->session()->get('username');

            // saving wallet details to session
            // $wallet = wallet::where('email', $user->email)->first();
            $balance = $request->session()->get('balance');
            $user_id = $request->session()->get('user_id');
            $wallet_id = $request->session()->get('wallet_id');
            $transaction_id = $request->session()->get('transaction_id');


            $body = [
                "customerId" => "{$user_id}",
                "fundingSourceId" => "string",
                "type" => "physical",
                "brand" => "Verve",
                "number" => "string",
                "currency" => "NGN",
                "issuerCountry" => "NGA",
                "status" => "active",
                "metadata" => "string",
                "spendingControls" => [
                    "allowedCategories" => ["string"],
                    "blockedCategories" => ["string"],
                    "channels" => [
                        "atm" => true,
                        "pos" => true,
                        "web" => true,
                        "mobile" => true,
                    ],
                    "spendingLimits" => [
                        [
                            "amount" => 0,
                            "interval" => "daily"
                        ]
                    ]
                ],
                "bankCode" => "string",
                "accountNumber" => "string",
                "replacementFor" => "string",
                "replacementReason" => "lost",
                "debitAccountId" => "string",
                "amount" => 0,
                "sendPINSMS" => false,
                "expirationDate" => "string"
            ];

            $response = Http::withHeaders([
                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
                'accept' => 'application/json',
                'content-type' => 'application/json',
            ])->post($url, $body);
            $responseData = $response->json(); // Return JSON response from the API

            $request->session()->put('card_id', $responseData['name']);

            return $response->json(); // Return the JSON response from the API
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function transactionGetALL(Request $request)
    {
        try {
            # code...
            // $user_id = $request->session()->get('user_id');
            // $wallet_id = $request->session()->get('wallet_id');
            // // $wallets = wallet::where('user_id', $user_id)->first();
            // $transactions = DB::table('transactions')
            //     ->where('user_id', '=', $user_id)
            //     ->where('wallet_id', '=', $wallet_id)
            //     ->get();

            $url = 'https://api.sandbox.getanchor.co/api/v1/transfers';

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            ])->get($url);

            // $url = 'https://api.sandbox.getanchor.co/api/v1/transactions';

            // $response = Http::withHeaders([
            //     'accept' => 'application/json',
            //     'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            // ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                // 'data' => $transactions,
                'data1' => $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function transactionGet(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'transactionId' => 'required|string',
            ]);
            $acct_id = $request->session()->get('wallet_id');
            $validatedData['transactionId'] = $acct_id;

            $url = 'https://api.sandbox.sudo.cards/accounts/' . $validatedData['transactionId'] . '/transactions?page=0&limit=100';

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                // 'data' => $transactions,
                'data1' => $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function cardGetDetails(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'transactionId' => 'required|string',
            ]);
            $acct_id = $request->session()->get('card_id');
            $validatedData['transactionId'] = $acct_id;

            $url = 'https://api.sandbox.sudo.cards/cards/' . $validatedData['transactionId'];

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                // 'data' => $transactions,
                'data1' => $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function customerCardGetDetails(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'transactionId' => 'required|string',
            ]);
            $acct_id = $request->session()->get('user_id');
            $validatedData['transactionId'] = $acct_id;

            $url = 'https://api.sandbox.sudo.cards/cards/customer/' . $validatedData['transactionId'];

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb0B1c2V1cmJhbnBheS5jb20iLCJqdGkiOiI2NjdlZTYyZjU3YzFiMjBiYTI2YTE1MmQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMzMyIsImJ1c2luZXNzIjp7Il9pZCI6IjY0ZGFhZjhlNThjMGE1ZjRhYmE0ZGMyZSIsIm5hbWUiOiJVUkJBTiBVTklWRVJTRSBMSU1JVEVEIiwiaXNBcHByb3ZlZCI6dHJ1ZX0sInVzZXIiOiI2NGRhYWY4ZTU4YzBhNWY0YWJhNGRjMzAiLCJyb2xlIjoiQVBJS2V5In0sImlhdCI6MTcxOTU5MjQ5NSwiZXhwIjoxNzUxMTUwMDk1fQ.ZeHZHsbRn-o3cVeO3cjCuHld5ET4Nq8ft9wTPoGxDcI',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                // 'data' => $transactions,
                'data1' => $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function UserdetailsByteBridge(Request $request)
    {
        try {
            $url = 'https://bytebridge.com.ng/api/user/';
            $token = 'e3822593c7c9f818b613cbd9d5bd078d3fdf7de4';
            $response = Http::withHeaders([
                'Authorization' => "Token {$token}",
                'Content-Type' => 'application/json',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function BuyData(Request $request)
    {
        try {
            $url = 'https://bytebridge.com.ng/api/data/';

            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ];

            $request->validate([
                'network_id' => 'required|string',
                'mobile_number' => 'required|string',
                'plan_id' => 'required|string',
            ]);

            $body = [
                'network' => $request->input('network_id'),
                'mobile_number' => $request->input('mobile_number'),
                'plan' => $request->input('plan_id'),
                'Ported_number' => true,
            ];

            $response = Http::withHeaders($headers)->post($url, $body);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function fetchDataTransaction()
    {
        try {
            $url = 'https://bytebridge.com.ng/api/data/';

            $response = Http::get($url);

            // return $response->json(); // Return the JSON response from the API
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function fetchDataTransactionSingle(Request $request)
    {
        try {
            $request->validate([
                'id' => 'required|string',

            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/data/$id";

            $response = Http::get($url);

            // return $response->json(); // Return the JSON response from the API
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function topUp(Request $request)
    {

        try {
            $request->validate([
                'network_id' => 'required|string',
                'mobile_number' => 'required|string',
                'plan_id' => 'required|string',
            ]);
            $url = 'https://bytebridge.com.ng/api/topup/';

            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json'
            ];

            $body = [
                'network' => $request->input('network_id'),
                'amount' => $request->input('amount'),
                'mobile_number' => $request->input('phone'),
                'Ported_number' => true,
                'airtime_type' => 'VTU'
            ];

            $response = Http::withHeaders($headers)->post($url, $body);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function FetchAirtimeTransactionSingle(Request $request)
    {
        try {
            $request->validate([
                'id' => 'required|string',

            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/data/{$id}";

            $response = Http::withHeaders([
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ])->get($url);

            // return $response->json(); // Return the JSON response from the API
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function billPayment(Request $request)
    {
        try {
            $request->validate([
                'disco_name' => 'required|string',
                'amount' => 'required|string',
                'meter_number' => 'required|string',
                'MeterType' => 'required|string',

            ]);

            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json'
            ];

            $body = json_encode([
                'disco_name' => $request->disco_name,
                'amount' => $request->amount,
                'meter_number' => $request->meter_number,
                'MeterType' => $request->MeterType // Replace with meter type id (PREPAID:1, POSTPAID:2)
            ]);

            $response = Http::withHeaders($headers)->post('https://bytebridge.com.ng/api/billpayment/', json_decode($body, true));

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function getBillPayment(Request $request)
    {
        try {
            # code...
            $request->validate([
                'id' => 'required|string',

            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/billpayment/{$id}";
            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
            ];

            $response = Http::withHeaders($headers)->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function subscribeToCable(Request $request)
    {
        try {
            # code...
            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ];
            $request->validate([
                'cablename' => 'required|string',
                'cableplan' => 'required|string',
                'smart_card_number' => 'required|string',


            ]);

            $body = json_encode([
                'cablename' => 'cablename id', // Replace with actual cablename id
                'cableplan' => 'cableplan id', // Replace with actual cableplan id
                'smart_card_number' => 'meter', // Replace with actual meter value
            ]);

            $response = Http::withHeaders($headers)
                ->post('https://bytebridge.com.ng/api/cablesub/', json_decode($body, true));

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function getCableSubscription(Request $request)
    {

        try {
            # code...
            $request->validate([
                'id' => 'required|string',
            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/cablesub/{$id}";

            $response = Http::withHeaders([
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function validateIUC(Request $request)
    {
        try {
            # code...
            $request->validate([
                'smart_card_number' => 'required|string',
                'cablename' => 'required|string',
            ]);
            $url = 'https://bytebridge.com.ng/ajax/validate_iuc';
            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ];

            $queryParams = [
                'smart_card_number' => $request->input('smart_card_number'),
                'cablename' => $request->input('cablename'),
            ];

            $response = Http::withHeaders($headers)->get($url, $queryParams);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function validateMeter(Request $request)
    {
        try {
            # code...
            $request->validate([
                'meternumber' => 'required|string',
                'disconame' => 'required|string',
                'metertype' => 'required|string',
            ]);
            $url = 'https://bytebridge.com.ng/ajax/validate_meter_number';
            $headers = [
                'Authorization' => 'Token 66f2e5c39ac8640f13cd888f161385b12f7e5e92',
                'Content-Type' => 'application/json',
            ];

            $query = [
                'meternumber' => $request->input('meternumber'),
                'disconame' => $request->input('disconame'),
                'mtype' => $request->input('metertype'),
            ];

            $response = Http::withHeaders($headers)->get($url, $query);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
}

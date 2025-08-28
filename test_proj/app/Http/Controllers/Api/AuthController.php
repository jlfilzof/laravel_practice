<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller {
    public function login(Request $request): JsonResponse {
        $request->validate([
            'email' => 'required|email|max:255',
            'password' => 'required|string|min:8|max:255',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }
        
        // if credentials is valid
        $token = $user->createToken($user->name . 'Auth-Token')->plainTextToken;

        return response()->json([
            'message' => 'Login successful',
            'token_type' => 'Bearer',
            'token' => $token], 200);
    }

    public function register(Request $request): JsonResponse {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users,email',
            'password' => 'required|string|min:8|max:255',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        if ($user) {
            $token = $user->createToken($user->name . 'Auth-Token')->plainTextToken;

            return response()->json([
                'message' => 'Registration successful',
                'token_type' => 'Bearer',
                'token' => $token], 201);
        }
        else {
            return response()->json(['message' => 'Registration failed'], 500);
        } 
    }

    public function profile(Request $request) {
        if ($request->user()) {
            return response()->json([
                'message' => 'Profile fetched successfully',
                'data' => $request->user()
            ], 200);
        }
        else {
            return response()->json(['message' => 'Not Authenticated'], 401);
        }
    }

    public function logout(Request $request): JsonResponse {
        $user = User::where('id', $request->user()->id)->first();
        if ($user) {
            $user->tokens()->delete();
            return response()->json(['message' => 'Logout successful'], 200);
        }
        else {
            return response()->json(['message' => 'No user found'], 404);
        }
    }
}

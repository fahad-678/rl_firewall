<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    /**
     * Handle admin login with email and password from .env
     */
    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:1',
        ]);

        $adminEmail = config('auth.admin_email') ?? env('ADMIN_EMAIL');
        $adminPassword = config('auth.admin_password') ?? env('ADMIN_PASSWORD');

        // Validate credentials against .env values
        if ($validated['email'] === $adminEmail && $validated['password'] === $adminPassword) {
            // Create a session for the authenticated admin
            session(['admin_authenticated' => true, 'admin_email' => $adminEmail]);

            return response()->json([
                'success' => true,
                'message' => 'Login successful',
                'user' => [
                    'email' => $adminEmail,
                    'role' => 'admin',
                ],
            ], 200);
        }

        return response()->json([
            'success' => false,
            'message' => 'Invalid email or password',
        ], 401);
    }

    /**
     * Logout the admin user
     */
    public function logout(Request $request)
    {
        session()->forget(['admin_authenticated', 'admin_email']);
        
        return response()->json([
            'success' => true,
            'message' => 'Logout successful',
        ], 200);
    }

    /**
     * Get the current authenticated user/session
     */
    public function me(Request $request)
    {
        if (session('admin_authenticated')) {
            return response()->json([
                'user' => [
                    'email' => session('admin_email'),
                    'role' => 'admin',
                ],
            ], 200);
        }

        return response()->json([
            'user' => null,
        ], 200);
    }
}

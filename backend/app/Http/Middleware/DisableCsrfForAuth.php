<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class DisableCsrfForAuth
{
    public function handle(Request $request, Closure $next)
    {
        // If this is an auth endpoint, disable CSRF token verification
        if ($request->is('auth/*')) {
            $request->setMethod(strtoupper($request->method()));
        }
        return $next($request);
    }
}

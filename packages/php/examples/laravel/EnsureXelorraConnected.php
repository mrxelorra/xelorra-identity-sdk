<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;
use Xelorra\Identity\XelorraClient;

class EnsureXelorraConnected
{
    public function __construct(private readonly XelorraClient $xelorra)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $token = (string) $request->session()->get('xelorra_access_token', '');
        if ($token === '') {
            return redirect()->route('xelorra.login');
        }

        // Short 15-second cache reduces introspection calls while keeping sync near real-time
        $cacheKey = 'xelorra_introspect_' . hash('sha256', $token);
        $connected = Cache::remember($cacheKey, 15, fn (): bool => $this->xelorra->isUserConnected($token));

        if (!$connected) {
            Cache::forget($cacheKey);
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return redirect()->route('xelorra.login')->with('status', 'Your Xelorra ID connection was revoked.');
        }

        return $next($request);
    }
}

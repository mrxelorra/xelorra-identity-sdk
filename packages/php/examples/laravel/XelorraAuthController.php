<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Xelorra\Identity\Exceptions\XelorraException;
use Xelorra\Identity\XelorraClient;

class XelorraAuthController extends Controller
{
    public function __construct(private readonly XelorraClient $xelorra)
    {
    }

    public function redirectToSignIn(Request $request): RedirectResponse
    {
        $result = $this->xelorra->buildSignInUrl();
        $request->session()->put('xelorra_pkce_state', $result['pkce']['state']);
        $request->session()->put('xelorra_pkce_verifier', $result['pkce']['codeVerifier']);

        return redirect()->away($result['url']);
    }

    public function redirectToSignUp(Request $request): RedirectResponse
    {
        // Sends new users straight to Xelorra ID registration via prompt=create
        $result = $this->xelorra->buildSignUpUrl();
        $request->session()->put('xelorra_pkce_state', $result['pkce']['state']);
        $request->session()->put('xelorra_pkce_verifier', $result['pkce']['codeVerifier']);

        return redirect()->away($result['url']);
    }

    public function callback(Request $request): RedirectResponse
    {
        if ($request->filled('error')) {
            return redirect()->route('login')->withErrors([
                'xelorra' => (string) $request->query('error_description', 'Authorization denied.'),
            ]);
        }

        $expectedState = (string) $request->session()->pull('xelorra_pkce_state', '');
        $codeVerifier = (string) $request->session()->pull('xelorra_pkce_verifier', '');
        $state = (string) $request->query('state', '');
        $code = (string) $request->query('code', '');

        if ($code === '' || $expectedState === '' || !hash_equals($expectedState, $state)) {
            abort(400, 'Invalid OAuth state.');
        }

        try {
            $tokens = $this->xelorra->exchangeCodeForTokens($code, $codeVerifier);
            $claims = $this->xelorra->getUserInfo($tokens['access_token']);
        } catch (XelorraException $e) {
            return redirect()->route('login')->withErrors(['xelorra' => $e->getMessage()]);
        }

        // Persist user by pairwise $claims['sub'] and store encrypted tokens server-side
        $request->session()->regenerate();
        $request->session()->put('xelorra_access_token', $tokens['access_token']);
        $request->session()->put('xelorra_refresh_token', $tokens['refresh_token'] ?? null);
        $request->session()->put('xelorra_sub', $claims['sub']);

        return redirect()->intended('/dashboard');
    }

    public function disconnect(Request $request): RedirectResponse
    {
        $token = (string) ($request->session()->get('xelorra_refresh_token')
            ?? $request->session()->get('xelorra_access_token')
            ?? '');

        if ($token !== '') {
            $this->xelorra->revokeToken($token);
        }

        $request->session()->forget(['xelorra_access_token', 'xelorra_refresh_token', 'xelorra_sub']);
        return redirect()->route('login')->with('status', 'Disconnected from Xelorra ID.');
    }
}

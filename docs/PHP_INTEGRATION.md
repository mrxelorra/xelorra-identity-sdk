# PHP Integration Guide (Vanilla PHP, Laravel, WordPress, Symfony)

The official PHP SDK (`packages/php`, Composer package `xelorra/identity-php`) requires **PHP 8.1+** and zero external runtime packages. It relies solely on built-in `curl`, `json`, `random_bytes`, `hash`, `hash_hmac`, and `hash_equals`, making it drop-in compatible with shared hosting, cPanel, Laravel, Symfony, and WordPress.

## Installation

```bash
composer require xelorra/identity-php
```

## 1. Vanilla PHP (Shared Hosting / cPanel)

Complete working scripts are available in `packages/php/examples/vanilla/`:

- `config.php`: Initializes hardened PHP sessions and `XelorraClient`.
- `login.php`: Generates PKCE `S256` and redirects to `/oauth/authorize`.
- `signup.php`: Redirects new users with `prompt=create`.
- `callback.php`: Verifies `state` with `hash_equals()`, exchanges the code, and loads `/oauth/userinfo`.
- `dashboard.php`: Guards routes using `isUserConnected()` (`POST /oauth/introspect`) and catches `AccessRevokedException`.
- `disconnect.php`: Calls `revokeToken()` (`POST /oauth/revoke`) and destroys the local PHP session.
- `webhook.php`: Reads raw bytes from `php://input`, verifies `X-Xelorra-Signature` (`t=<ts>,v1=<hex>`), and handles `user.access_revoked`.

## 2. Laravel 10 / 11

Complete Laravel files live in `packages/php/examples/laravel/`:

1. Add your Xelorra credentials to `config/services.php`:

```php
'xelorra' => [
    'client_id' => env('XELORRA_CLIENT_ID'),
    'client_secret' => env('XELORRA_CLIENT_SECRET'),
    'redirect_uri' => env('XELORRA_REDIRECT_URI'),
    'webhook_secret' => env('XELORRA_WEBHOOK_SECRET'),
    'issuer' => env('XELORRA_ISSUER', 'https://one.xelorra.app'),
],
```

2. Register `XelorraServiceProvider` so `XelorraClient` is resolved as a singleton.
3. Add routes from `examples/laravel/routes.php` (remember to exclude `/webhooks/xelorra` from CSRF verification or place it in `routes/api.php`).
4. Attach `EnsureXelorraConnected` middleware to protected routes for near real-time disconnect synchronization.

## 3. WordPress & Symfony

See `packages/php/examples/wordpress-and-symfony.md` for copy-ready WordPress REST API (`register_rest_route`) and Symfony 6/7 controller examples.

## 4. Reusable KYC & Digital Passport Verification in PHP

```php
use Xelorra\Identity\Exceptions\InsufficientScopeException;

try {
    $kyc = $client->verifyKycAssertion($accessToken);
    if ($kyc['verification_status'] === 'verified') {
        // $kyc['verification_reference'] -> "xvr_..."
    }
} catch (InsufficientScopeException $e) {
    // Request kyc.assertion.read scope
}

// Public zero-PII QR passport verification
$passport = $client->verifyPassportToken($qrToken);
```

# `xelorra/identity-php`

Official PHP 8.1+ SDK for **Xelorra Identity** (`https://one.xelorra.app`). Zero heavy dependencies: uses only native PHP `curl`, `json`, `random_bytes`, `hash`, `hash_hmac`, and `hash_equals`.

## Installation

```bash
composer require xelorra/identity-php
```

## Quick Start

```php
<?php

use Xelorra\Identity\Constants;
use Xelorra\Identity\XelorraClient;

$client = new XelorraClient(
    clientId: getenv('XELORRA_CLIENT_ID') ?: '',
    redirectUri: 'https://your-app.com/auth/callback.php',
    clientSecret: getenv('XELORRA_CLIENT_SECRET') ?: null,
    scopes: [
        Constants::SCOPE_PROFILE_READ,
        Constants::SCOPE_PASSPORT_READ,
        Constants::SCOPE_EMAIL_READ,
    ],
);

// Returning users (Sign In)
$signIn = $client->buildSignInUrl();

// New users (Sign Up via prompt=create)
$signUp = $client->buildSignUpUrl();
```

## Examples Included

- `examples/vanilla/`: Ready-to-copy standard PHP scripts (`session_start()`, shared hosting / cPanel friendly) for login, signup, callback, dashboard introspection guard, disconnect, and `webhook.php`.
- `examples/laravel/`: `XelorraServiceProvider`, routes, `XelorraAuthController`, `EnsureXelorraConnected` middleware, and `XelorraWebhookController`.
- `examples/wordpress-and-symfony.md`: Quickstart snippets for WordPress and Symfony.

## Running Tests

```bash
composer install
composer test
```

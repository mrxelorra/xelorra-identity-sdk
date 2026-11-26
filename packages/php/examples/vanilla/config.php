<?php

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use Xelorra\Identity\Constants;
use Xelorra\Identity\XelorraClient;

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'cookie_samesite' => 'Lax',
    ]);
}

function xelorra_client(): XelorraClient
{
    return new XelorraClient(
        clientId: getenv('XELORRA_CLIENT_ID') ?: '',
        redirectUri: getenv('XELORRA_REDIRECT_URI') ?: 'https://your-site.com/callback.php',
        clientSecret: getenv('XELORRA_CLIENT_SECRET') ?: null,
        issuer: getenv('XELORRA_ISSUER') ?: Constants::DEFAULT_ISSUER,
        scopes: [
            Constants::SCOPE_PROFILE_READ,
            Constants::SCOPE_PASSPORT_READ,
            Constants::SCOPE_EMAIL_READ,
        ],
    );
}

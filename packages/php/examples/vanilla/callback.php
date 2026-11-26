<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

use Xelorra\Identity\Exceptions\XelorraException;

if (!empty($_GET['error'])) {
    http_response_code(400);
    echo 'Authorization failed: ' . htmlspecialchars((string) ($_GET['error_description'] ?? $_GET['error']), ENT_QUOTES, 'UTF-8');
    exit;
}

$code = (string) ($_GET['code'] ?? '');
$state = (string) ($_GET['state'] ?? '');
$expectedState = (string) ($_SESSION['xelorra_pkce_state'] ?? '');
$codeVerifier = (string) ($_SESSION['xelorra_pkce_verifier'] ?? '');

unset($_SESSION['xelorra_pkce_state'], $_SESSION['xelorra_pkce_verifier']);

if ($code === '' || $state === '' || $expectedState === '' || !hash_equals($expectedState, $state)) {
    http_response_code(400);
    echo 'Invalid OAuth state or missing authorization code.';
    exit;
}

try {
    $client = xelorra_client();
    $tokens = $client->exchangeCodeForTokens($code, $codeVerifier);
    $user = $client->getUserInfo($tokens['access_token']);

    session_regenerate_id(true);
    $_SESSION['xelorra_access_token'] = $tokens['access_token'];
    $_SESSION['xelorra_refresh_token'] = $tokens['refresh_token'] ?? null;
    $_SESSION['xelorra_user'] = $user;

    header('Location: /dashboard.php', true, 302);
    exit;
} catch (XelorraException $e) {
    http_response_code($e->httpStatus ?? 400);
    echo 'Sign-in error: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    exit;
}

<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

use Xelorra\Identity\Exceptions\AccessRevokedException;

$accessToken = (string) ($_SESSION['xelorra_access_token'] ?? '');
if ($accessToken === '') {
    header('Location: /login.php', true, 302);
    exit;
}

$client = xelorra_client();

// Active two-way disconnect sync via POST /oauth/introspect
if (!$client->isUserConnected($accessToken)) {
    session_destroy();
    header('Location: /login.php?reason=disconnected', true, 302);
    exit;
}

try {
    $user = $client->getUserInfo($accessToken);
} catch (AccessRevokedException) {
    session_destroy();
    header('Location: /login.php?reason=disconnected', true, 302);
    exit;
}

$displayName = htmlspecialchars((string) ($user['name'] ?? $user['sub']), ENT_QUOTES, 'UTF-8');
echo "<h1>Welcome, {$displayName}</h1>";
echo '<p><a href="/disconnect.php">Disconnect Xelorra ID</a></p>';

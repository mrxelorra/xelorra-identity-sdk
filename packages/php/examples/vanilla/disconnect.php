<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

$client = xelorra_client();
$tokenToRevoke = (string) ($_SESSION['xelorra_refresh_token'] ?? $_SESSION['xelorra_access_token'] ?? '');

if ($tokenToRevoke !== '') {
    // Notify Xelorra One so both platforms stay synchronized
    $client->revokeToken($tokenToRevoke);
}

session_destroy();
header('Location: /login.php?disconnected=1', true, 302);
exit;

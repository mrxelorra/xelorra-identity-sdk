<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

$client = xelorra_client();
$result = $client->buildSignInUrl();

$_SESSION['xelorra_pkce_state'] = $result['pkce']['state'];
$_SESSION['xelorra_pkce_verifier'] = $result['pkce']['codeVerifier'];

header('Location: ' . $result['url'], true, 302);
exit;

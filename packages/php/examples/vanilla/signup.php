<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

$client = xelorra_client();
// Uses prompt=create so new users go directly to Xelorra ID registration
$result = $client->buildSignUpUrl();

$_SESSION['xelorra_pkce_state'] = $result['pkce']['state'];
$_SESSION['xelorra_pkce_verifier'] = $result['pkce']['codeVerifier'];

header('Location: ' . $result['url'], true, 302);
exit;

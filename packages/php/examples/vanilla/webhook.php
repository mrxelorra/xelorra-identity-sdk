<?php

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use Xelorra\Identity\Constants;
use Xelorra\Identity\Exceptions\WebhookSignatureException;
use Xelorra\Identity\Webhook;

// Read exact raw request bytes before any JSON parsing
$rawBody = file_get_contents('php://input') ?: '';
$signatureHeader = (string) ($_SERVER['HTTP_X_XELORRA_SIGNATURE'] ?? '');
$signingSecret = (string) (getenv('XELORRA_WEBHOOK_SECRET') ?: '');

header('Content-Type: application/json');

try {
    $event = Webhook::parseEvent($rawBody, $signatureHeader, $signingSecret);

    if ($event['type'] === Constants::EVENT_USER_ACCESS_REVOKED) {
        $sub = (string) ($event['data']['sub'] ?? '');
        // Delete local sessions and stored tokens for $sub in your database
        error_log("Xelorra access revoked for subject: {$sub}");
    }

    http_response_code(200);
    echo json_encode(['received' => true, 'event_type' => $event['type']]);
} catch (WebhookSignatureException $e) {
    http_response_code(401);
    echo json_encode(['error' => $e->errorCode, 'message' => $e->getMessage()]);
}

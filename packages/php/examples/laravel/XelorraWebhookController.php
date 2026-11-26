<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Xelorra\Identity\Constants;
use Xelorra\Identity\Exceptions\WebhookSignatureException;
use Xelorra\Identity\Webhook;

class XelorraWebhookController extends Controller
{
    public function handle(Request $request): JsonResponse
    {
        // Always read raw unparsed bytes via $request->getContent()
        $rawBody = $request->getContent();
        $signatureHeader = (string) $request->header(Constants::HEADER_SIGNATURE, '');
        $signingSecret = (string) config('services.xelorra.webhook_secret');

        try {
            $event = Webhook::parseEvent($rawBody, $signatureHeader, $signingSecret);
        } catch (WebhookSignatureException $e) {
            return response()->json([
                'error' => $e->errorCode,
                'message' => $e->getMessage(),
            ], 401);
        }

        if ($event['type'] === Constants::EVENT_USER_ACCESS_REVOKED) {
            $sub = (string) ($event['data']['sub'] ?? '');
            Log::info('Revoking local Laravel sessions for Xelorra subject', ['sub' => $sub]);
            // Delete stored OAuth tokens and active sessions for $sub here
        }

        return response()->json([
            'received' => true,
            'event_type' => $event['type'],
        ]);
    }
}

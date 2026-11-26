<?php

declare(strict_types=1);

namespace Xelorra\Identity;

use Xelorra\Identity\Exceptions\WebhookSignatureException;

final class Webhook
{
    /**
     * Generates a signed X-Xelorra-Signature header (`t=<unix_seconds>,v1=<hmac_sha256_hex>`)
     * for local development and automated testing.
     */
    public static function createSignatureHeader(
        string $rawBody,
        string $signingSecret,
        ?int $timestampSeconds = null
    ): string {
        if ($signingSecret === '') {
            throw new WebhookSignatureException(
                'missing_webhook_secret',
                'signingSecret is required to compute a webhook signature.'
            );
        }

        $ts = $timestampSeconds ?? time();
        $hex = hash_hmac('sha256', $ts . '.' . $rawBody, $signingSecret);

        return sprintf('t=%d,v1=%s', $ts, $hex);
    }

    /**
     * Verifies `X-Xelorra-Signature: t=<unix_seconds>,v1=<hmac_sha256_hex>` against
     * the exact raw request body using hash_equals() and replay-window validation.
     */
    public static function verifySignature(
        string $rawBody,
        string $signatureHeader,
        string $signingSecret,
        int $toleranceSeconds = Constants::DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        ?int $nowSeconds = null
    ): bool {
        try {
            self::assertValidSignature(
                $rawBody,
                $signatureHeader,
                $signingSecret,
                $toleranceSeconds,
                $nowSeconds
            );
            return true;
        } catch (WebhookSignatureException) {
            return false;
        }
    }

    /**
     * Verifies the signature and parses the JSON webhook event envelope.
     *
     * @return array<string, mixed>
     * @throws WebhookSignatureException
     */
    public static function parseEvent(
        string $rawBody,
        string $signatureHeader,
        string $signingSecret,
        int $toleranceSeconds = Constants::DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        ?int $nowSeconds = null
    ): array {
        self::assertValidSignature(
            $rawBody,
            $signatureHeader,
            $signingSecret,
            $toleranceSeconds,
            $nowSeconds
        );

        try {
            $decoded = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new WebhookSignatureException(
                'invalid_payload',
                'Webhook payload is not valid JSON.'
            );
        }

        if (
            !is_array($decoded)
            || !isset($decoded['type'])
            || !is_string($decoded['type'])
            || !isset($decoded['data'])
            || !is_array($decoded['data'])
        ) {
            throw new WebhookSignatureException(
                'invalid_payload',
                "Webhook payload must be a JSON object with string 'type' and object 'data'."
            );
        }

        return $decoded;
    }

    /**
     * @throws WebhookSignatureException
     */
    private static function assertValidSignature(
        string $rawBody,
        string $signatureHeader,
        string $signingSecret,
        int $toleranceSeconds,
        ?int $nowSeconds
    ): void {
        if ($signingSecret === '') {
            throw new WebhookSignatureException(
                'missing_webhook_secret',
                'signingSecret is required to verify Xelorra webhooks.'
            );
        }

        $trimmed = trim($signatureHeader);
        if ($trimmed === '') {
            throw new WebhookSignatureException(
                'missing_signature',
                'Missing X-Xelorra-Signature header.'
            );
        }

        $parsed = self::parseHeader($trimmed);
        if ($parsed === null) {
            throw new WebhookSignatureException(
                'malformed_signature',
                "X-Xelorra-Signature header must follow 't=<unix_timestamp>,v1=<hmac_sha256_hex>'."
            );
        }

        $now = $nowSeconds ?? time();
        if ($toleranceSeconds > 0 && abs($now - $parsed['timestamp']) > $toleranceSeconds) {
            throw new WebhookSignatureException(
                'expired_timestamp',
                sprintf('Webhook timestamp is outside the allowed %ds tolerance window.', $toleranceSeconds)
            );
        }

        $signedPayload = $parsed['rawTimestamp'] . '.' . $rawBody;
        $expectedHex = hash_hmac('sha256', $signedPayload, $signingSecret);

        $matched = false;
        foreach ($parsed['v1'] as $candidate) {
            if (hash_equals($expectedHex, $candidate)) {
                $matched = true;
            }
        }

        if (!$matched) {
            throw new WebhookSignatureException(
                'invalid_signature',
                'X-Xelorra-Signature verification failed.'
            );
        }
    }

    /**
     * @return array{timestamp: int, rawTimestamp: string, v1: list<string>}|null
     */
    private static function parseHeader(string $header): ?array
    {
        $rawTimestamp = null;
        $signatures = [];

        foreach (explode(',', $header) as $segment) {
            $part = trim($segment);
            if ($part === '') {
                continue;
            }
            $eqPos = strpos($part, '=');
            if ($eqPos === false || $eqPos === 0) {
                return null;
            }
            $key = trim(substr($part, 0, $eqPos));
            $value = trim(substr($part, $eqPos + 1));
            if ($value === '') {
                return null;
            }

            if ($key === 't') {
                if ($rawTimestamp !== null || preg_match('/^\d+$/', $value) !== 1) {
                    return null;
                }
                $rawTimestamp = $value;
            } elseif ($key === 'v1') {
                if (preg_match('/^[0-9a-fA-F]{64}$/', $value) !== 1) {
                    return null;
                }
                $signatures[] = strtolower($value);
            }
        }

        if ($rawTimestamp === null || $signatures === []) {
            return null;
        }

        $timestamp = (int) $rawTimestamp;
        if ($timestamp <= 0) {
            return null;
        }

        return [
            'timestamp' => $timestamp,
            'rawTimestamp' => $rawTimestamp,
            'v1' => $signatures,
        ];
    }
}

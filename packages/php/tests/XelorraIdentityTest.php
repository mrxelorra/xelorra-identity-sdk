<?php

declare(strict_types=1);

namespace Xelorra\Identity\Tests;

use PHPUnit\Framework\TestCase;
use Xelorra\Identity\Constants;
use Xelorra\Identity\Exceptions\AccessRevokedException;
use Xelorra\Identity\Exceptions\InsufficientScopeException;
use Xelorra\Identity\Exceptions\WebhookSignatureException;
use Xelorra\Identity\Pkce;
use Xelorra\Identity\Webhook;
use Xelorra\Identity\XelorraClient;

final class XelorraIdentityTest extends TestCase
{
    public function testPkceGeneratesUnpaddedS256Challenge(): void
    {
        $pkce = Pkce::generate();

        $this->assertSame('S256', $pkce['codeChallengeMethod']);
        $this->assertGreaterThanOrEqual(43, strlen($pkce['codeVerifier']));
        $this->assertStringNotContainsString('=', $pkce['codeVerifier']);
        $this->assertStringNotContainsString('=', $pkce['codeChallenge']);

        $expectedChallenge = Pkce::base64UrlEncode(hash('sha256', $pkce['codeVerifier'], true));
        $this->assertSame($expectedChallenge, $pkce['codeChallenge']);
    }

    public function testBuildSignInAndSignUpUrlsWithPromptCreate(): void
    {
        $client = new XelorraClient(
            clientId: 'acme-php-app',
            redirectUri: 'https://acme.example.com/auth/callback',
            scopes: [Constants::SCOPE_PROFILE_READ, Constants::SCOPE_EMAIL_READ]
        );

        $signIn = $client->buildSignInUrl();
        parse_str((string) parse_url($signIn['url'], PHP_URL_QUERY), $signInQuery);

        $this->assertStringStartsWith('https://one.xelorra.app/oauth/authorize?', $signIn['url']);
        $this->assertSame('code', $signInQuery['response_type']);
        $this->assertSame('acme-php-app', $signInQuery['client_id']);
        $this->assertSame('S256', $signInQuery['code_challenge_method']);
        $this->assertArrayNotHasKey('prompt', $signInQuery);

        $signUp = $client->buildSignUpUrl(['loginHint' => 'adaeze.4821']);
        parse_str((string) parse_url($signUp['url'], PHP_URL_QUERY), $signUpQuery);

        $this->assertSame('create', $signUpQuery['prompt']);
        $this->assertSame('adaeze.4821', $signUpQuery['login_hint']);
    }

    public function testOAuthLifecycleIntrospectionKycAndPassportVerify(): void
    {
        $transport = function (string $method, string $url, array $headers, ?string $body): array {
            if (str_ends_with($url, '/oauth/token')) {
                $decoded = json_decode((string) $body, true);
                if (($decoded['grant_type'] ?? '') === 'authorization_code') {
                    return [
                        'status' => 200,
                        'body' => json_encode([
                            'access_token' => 'xc_at_php_1',
                            'refresh_token' => 'xlr_rt_php_1',
                            'token_type' => 'Bearer',
                            'expires_in' => 3600,
                            'scope' => 'profile.read kyc.assertion.read',
                            'xid' => 'XLR-9284-1039',
                        ]),
                    ];
                }
                return [
                    'status' => 200,
                    'body' => json_encode([
                        'access_token' => 'xc_at_php_2',
                        'refresh_token' => 'xlr_rt_php_2',
                        'token_type' => 'Bearer',
                        'expires_in' => 3600,
                        'scope' => 'profile.read kyc.assertion.read',
                    ]),
                ];
            }

            if (str_ends_with($url, '/oauth/introspect')) {
                return [
                    'status' => 200,
                    'body' => json_encode([
                        'active' => true,
                        'connected' => true,
                        'client_id' => 'acme-php-app',
                        'sub' => 'xapp_php_123',
                        'xid' => 'XLR-9284-1039',
                        'scope' => 'profile.read kyc.assertion.read',
                        'exp' => 1900000000,
                    ]),
                ];
            }

            if (str_ends_with($url, '/api/v1/verify/assertion') && $method === 'POST') {
                return [
                    'status' => 200,
                    'body' => json_encode([
                        'verification_status' => 'verified',
                        'verification_type' => 'government_identity',
                        'verification_reference' => 'xvr_987654321',
                        'verified_at' => '2026-11-26T00:00:00Z',
                        'credential_category' => 'nin',
                    ]),
                ];
            }

            if (str_ends_with($url, '/api/v1/public/verify/qr_123')) {
                return [
                    'status' => 200,
                    'body' => json_encode([
                        'valid' => true,
                        'xid' => 'XLR-9284-1039',
                        'verified' => true,
                    ]),
                ];
            }

            if (str_ends_with($url, '/oauth/revoke')) {
                return ['status' => 200, 'body' => json_encode(['revoked' => true])];
            }

            return ['status' => 404, 'body' => json_encode(['error' => 'not_found'])];
        };

        $client = new XelorraClient(
            clientId: 'acme-php-app',
            redirectUri: 'https://acme.example.com/auth/callback',
            httpTransport: $transport
        );

        $tokens = $client->exchangeCodeForTokens('xc_code', 'verifier_12345');
        $this->assertSame('xc_at_php_1', $tokens['access_token']);

        $this->assertTrue($client->isUserConnected('xc_at_php_1'));

        $kyc = $client->verifyKycAssertion('xc_at_php_1');
        $this->assertSame('verified', $kyc['verification_status']);
        $this->assertSame('government_identity', $kyc['verification_type']);

        $passport = $client->verifyPassportToken('qr_123');
        $this->assertTrue($passport['valid']);

        $revoked = $client->revokeToken('xc_at_php_1');
        $this->assertTrue($revoked['revoked']);
    }

    public function testThrowsAccessRevokedAndInsufficientScopeExceptions(): void
    {
        $transport = function (string $method, string $url): array {
            if (str_ends_with($url, '/oauth/userinfo')) {
                return [
                    'status' => 401,
                    'body' => json_encode([
                        'error' => 'access_revoked',
                        'error_description' => 'User disconnected app on Xelorra One.',
                        'reason' => 'user_disconnected',
                    ]),
                ];
            }
            return [
                'status' => 403,
                'body' => json_encode([
                    'error' => 'insufficient_scope',
                    'error_description' => 'Missing kyc.assertion.read scope.',
                ]),
            ];
        };

        $client = new XelorraClient(clientId: 'acme-php-app', httpTransport: $transport);

        try {
            $client->getUserInfo('xc_at_revoked');
            $this->fail('Expected AccessRevokedException');
        } catch (AccessRevokedException $e) {
            $this->assertSame('access_revoked', $e->errorCode);
            $this->assertSame('user_disconnected', $e->reason);
            $this->assertSame(401, $e->httpStatus);
        }

        $this->expectException(InsufficientScopeException::class);
        $client->verifyKycAssertion('xc_at_basic');
    }

    public function testWebhookSignatureVerificationEnforcesFormatAndReplayWindow(): void
    {
        $secret = 'whsec_php_test_secret_12345';
        $now = 1764150000;
        $rawBody = json_encode([
            'id' => 'evt_php_1',
            'type' => Constants::EVENT_USER_ACCESS_REVOKED,
            'created_at' => '2026-11-26T12:00:00Z',
            'client_id' => 'acme-php-app',
            'data' => [
                'xid' => 'XLR-9284-1039',
                'sub' => 'xapp_php_123',
                'client_id' => 'acme-php-app',
                'revoked_at' => '2026-11-26T12:00:00Z',
                'reason' => 'user_disconnected',
            ],
        ], JSON_THROW_ON_ERROR);

        $header = Webhook::createSignatureHeader($rawBody, $secret, $now);
        $this->assertStringStartsWith("t={$now},v1=", $header);

        // Valid within window
        $this->assertTrue(Webhook::verifySignature($rawBody, $header, $secret, 300, $now + 60));

        // Tampered body rejected
        $tampered = str_replace('acme-php-app', 'evil-app', $rawBody);
        $this->assertFalse(Webhook::verifySignature($tampered, $header, $secret, 300, $now));

        // Expired timestamp rejected
        $this->assertFalse(Webhook::verifySignature($rawBody, $header, $secret, 300, $now + 301));

        // Malformed header rejected
        $this->assertFalse(Webhook::verifySignature($rawBody, 'sha256=deadbeef', $secret, 300, $now));

        // parseEvent returns decoded array
        $event = Webhook::parseEvent($rawBody, $header, $secret, 300, $now);
        $this->assertSame('user.access_revoked', $event['type']);
        $this->assertSame('xapp_php_123', $event['data']['sub']);

        // Expired throws WebhookSignatureException
        $this->expectException(WebhookSignatureException::class);
        Webhook::parseEvent($rawBody, $header, $secret, 300, $now + 500);
    }
}

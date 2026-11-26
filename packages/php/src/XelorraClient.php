<?php

declare(strict_types=1);

namespace Xelorra\Identity;

use Closure;
use Xelorra\Identity\Exceptions\AccessRevokedException;
use Xelorra\Identity\Exceptions\InsufficientScopeException;
use Xelorra\Identity\Exceptions\XelorraException;

class XelorraClient
{
    public readonly string $clientId;
    public readonly ?string $redirectUri;
    public readonly string $issuer;

    /** @var list<string> */
    public readonly array $scopes;

    private readonly ?string $clientSecret;
    private readonly int $timeoutSeconds;

    /**
     * Optional custom HTTP transport for unit testing:
     * fn(string $method, string $url, array $headers, ?string $body): array{status: int, body: string}
     */
    private readonly ?Closure $httpTransport;

    /**
     * @param list<string> $scopes
     * @param ?Closure(string, string, array<string, string>, ?string): array{status: int, body: string} $httpTransport
     */
    public function __construct(
        string $clientId,
        ?string $redirectUri = null,
        ?string $clientSecret = null,
        string $issuer = Constants::DEFAULT_ISSUER,
        array $scopes = Constants::DEFAULT_SCOPES,
        int $timeoutSeconds = 15,
        ?Closure $httpTransport = null
    ) {
        $trimmedClientId = trim($clientId);
        if ($trimmedClientId === '') {
            throw new XelorraException('invalid_config', 'clientId is required.');
        }

        $normalizedIssuer = self::normalizeIssuer($issuer);

        $this->clientId = $trimmedClientId;
        $this->redirectUri = $redirectUri !== null && trim($redirectUri) !== '' ? trim($redirectUri) : null;
        $this->clientSecret = $clientSecret !== null && trim($clientSecret) !== '' ? trim($clientSecret) : null;
        $this->issuer = $normalizedIssuer;
        $this->scopes = $scopes !== [] ? array_values($scopes) : Constants::DEFAULT_SCOPES;
        $this->timeoutSeconds = max(1, $timeoutSeconds);
        $this->httpTransport = $httpTransport;
    }

    /**
     * Fetches GET /.well-known/openid-configuration.
     *
     * @return array<string, mixed>
     */
    public function fetchDiscovery(): array
    {
        return $this->requestJson('GET', '/.well-known/openid-configuration');
    }

    /**
     * Fetches GET /.well-known/jwks.json.
     *
     * @return array<string, mixed>
     */
    public function fetchJwks(): array
    {
        return $this->requestJson('GET', '/.well-known/jwks.json');
    }

    /**
     * Builds a Sign In authorization URL with PKCE S256.
     *
     * @param array{
     *   scopes?: list<string>,
     *   state?: string,
     *   pkce?: array{codeVerifier: string, codeChallenge: string, codeChallengeMethod: 'S256', state: string},
     *   redirectUri?: string,
     *   prompt?: string,
     *   loginHint?: string,
     *   extraParams?: array<string, string>
     * } $options
     * @return array{
     *   url: string,
     *   pkce: array{codeVerifier: string, codeChallenge: string, codeChallengeMethod: 'S256', state: string}
     * }
     */
    public function buildSignInUrl(array $options = []): array
    {
        return $this->buildAuthorizeUrl($options);
    }

    /**
     * Builds a Sign Up authorization URL (`prompt=create`) with PKCE S256 so new users
     * go straight to Xelorra ID registration and return automatically to OAuth consent.
     *
     * @param array<string, mixed> $options
     * @return array{
     *   url: string,
     *   pkce: array{codeVerifier: string, codeChallenge: string, codeChallengeMethod: 'S256', state: string}
     * }
     */
    public function buildSignUpUrl(array $options = []): array
    {
        $options['prompt'] = 'create';
        return $this->buildAuthorizeUrl($options);
    }

    /**
     * Builds an OAuth 2.0 + PKCE S256 authorization URL targeting GET /oauth/authorize.
     *
     * @param array<string, mixed> $options
     * @return array{
     *   url: string,
     *   pkce: array{codeVerifier: string, codeChallenge: string, codeChallengeMethod: 'S256', state: string}
     * }
     */
    public function buildAuthorizeUrl(array $options = []): array
    {
        $redirectUri = $this->resolveRedirectUri(
            isset($options['redirectUri']) && is_string($options['redirectUri']) ? $options['redirectUri'] : null
        );
        $pkce = isset($options['pkce']) && is_array($options['pkce']) ? $options['pkce'] : Pkce::generate();
        $state = isset($options['state']) && is_string($options['state']) && $options['state'] !== ''
            ? $options['state']
            : $pkce['state'];
        $scopes = isset($options['scopes']) && is_array($options['scopes']) && $options['scopes'] !== []
            ? $options['scopes']
            : $this->scopes;

        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'code_challenge' => $pkce['codeChallenge'],
            'code_challenge_method' => 'S256',
        ];

        if (isset($options['prompt']) && is_string($options['prompt']) && $options['prompt'] !== '') {
            $params['prompt'] = $options['prompt'];
        }
        if (isset($options['loginHint']) && is_string($options['loginHint']) && $options['loginHint'] !== '') {
            $params['login_hint'] = $options['loginHint'];
        }
        if (isset($options['extraParams']) && is_array($options['extraParams'])) {
            foreach ($options['extraParams'] as $key => $value) {
                $params[(string) $key] = (string) $value;
            }
        }

        $pkce['state'] = $state;

        return [
            'url' => $this->issuer . '/oauth/authorize?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986),
            'pkce' => $pkce,
        ];
    }

    /**
     * Exchanges an authorization code and PKCE code_verifier via POST /oauth/token.
     *
     * @return array<string, mixed>
     */
    public function exchangeCodeForTokens(
        string $code,
        string $codeVerifier,
        ?string $redirectUri = null
    ): array {
        $trimmedCode = trim($code);
        $trimmedVerifier = trim($codeVerifier);
        if ($trimmedCode === '') {
            throw new XelorraException('missing_code', 'Authorization code is required.');
        }
        if ($trimmedVerifier === '') {
            throw new XelorraException('missing_pkce_verifier', 'PKCE codeVerifier is required.');
        }

        $payload = [
            'grant_type' => 'authorization_code',
            'code' => $trimmedCode,
            'client_id' => $this->clientId,
            'redirect_uri' => $this->resolveRedirectUri($redirectUri),
            'code_verifier' => $trimmedVerifier,
        ];
        if ($this->clientSecret !== null) {
            $payload['client_secret'] = $this->clientSecret;
        }

        return $this->requestJson('POST', '/oauth/token', [], $payload);
    }

    /**
     * Rotates a single-use refresh token via POST /oauth/token.
     *
     * @return array<string, mixed>
     */
    public function refreshTokens(string $refreshToken, ?string $scope = null): array
    {
        $trimmed = trim($refreshToken);
        if ($trimmed === '') {
            throw new XelorraException('missing_refresh_token', 'Refresh token is required.');
        }

        $payload = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $trimmed,
            'client_id' => $this->clientId,
        ];
        if ($this->clientSecret !== null) {
            $payload['client_secret'] = $this->clientSecret;
        }
        if ($scope !== null && trim($scope) !== '') {
            $payload['scope'] = trim($scope);
        }

        return $this->requestJson('POST', '/oauth/token', [], $payload);
    }

    /**
     * Fetches granted identity claims from GET /oauth/userinfo.
     * Throws AccessRevokedException when Xelorra One returns HTTP 401 access_revoked.
     *
     * @return array<string, mixed>
     */
    public function getUserInfo(string $accessToken): array
    {
        $trimmed = trim($accessToken);
        if ($trimmed === '') {
            throw new XelorraException('unauthenticated', 'Access token is required.');
        }

        return $this->requestJson('GET', '/oauth/userinfo', [
            'Authorization' => 'Bearer ' . $trimmed,
        ]);
    }

    /**
     * Checks live token and connection status via POST /oauth/introspect.
     *
     * @return array<string, mixed>
     */
    public function introspectToken(string $accessToken): array
    {
        $trimmed = trim($accessToken);
        if ($trimmed === '') {
            return [
                'active' => false,
                'connected' => false,
                'reason' => 'missing_token',
            ];
        }

        $payload = [
            'token' => $trimmed,
            'client_id' => $this->clientId,
        ];
        if ($this->clientSecret !== null) {
            $payload['client_secret'] = $this->clientSecret;
        }

        $body = $this->requestJson('POST', '/oauth/introspect', [], $payload);
        $active = (bool) ($body['active'] ?? false);
        $connected = array_key_exists('connected', $body) ? (bool) $body['connected'] : $active;
        $body['active'] = $active;
        $body['connected'] = $connected;

        return $body;
    }

    /**
     * Returns true only when POST /oauth/introspect confirms active=true and connected=true.
     */
    public function isUserConnected(string $accessToken): bool
    {
        $result = $this->introspectToken($accessToken);
        return ($result['active'] ?? false) === true && ($result['connected'] ?? false) === true;
    }

    /**
     * Revokes a token on Xelorra One via POST /oauth/revoke (RFC 7009).
     *
     * @return array{revoked: bool}
     */
    public function revokeToken(string $token): array
    {
        $trimmed = trim($token);
        if ($trimmed === '') {
            return ['revoked' => true];
        }

        $payload = [
            'token' => $trimmed,
            'client_id' => $this->clientId,
        ];
        if ($this->clientSecret !== null) {
            $payload['client_secret'] = $this->clientSecret;
        }

        $body = $this->requestJson('POST', '/oauth/revoke', [], $payload);
        return ['revoked' => (bool) ($body['revoked'] ?? true)];
    }

    /**
     * Ends a session via POST /oauth/logout (and optionally revokes the supplied token first).
     *
     * @return array{loggedOut: bool, message?: string}
     */
    public function logout(?string $accessToken = null): array
    {
        $headers = [];
        if ($accessToken !== null && trim($accessToken) !== '') {
            $this->revokeToken($accessToken);
            $headers['Authorization'] = 'Bearer ' . trim($accessToken);
        }

        $body = $this->requestJson('POST', '/oauth/logout', $headers, [
            'client_id' => $this->clientId,
        ]);

        $result = ['loggedOut' => (bool) ($body['loggedOut'] ?? true)];
        if (isset($body['message']) && is_string($body['message'])) {
            $result['message'] = $body['message'];
        }

        return $result;
    }

    /**
     * Retrieves a minimum-disclosure Reusable KYC assertion via POST /api/v1/verify/assertion.
     *
     * @return array<string, mixed>
     */
    public function verifyKycAssertion(string $accessToken): array
    {
        $trimmed = trim($accessToken);
        if ($trimmed === '') {
            throw new XelorraException('unauthenticated', 'Access token is required.');
        }

        return $this->requestJson(
            'POST',
            '/api/v1/verify/assertion',
            ['Authorization' => 'Bearer ' . $trimmed],
            new \stdClass()
        );
    }

    /**
     * Verifies a rotating Digital Passport QR token without authentication.
     * Pass $selective = true to call GET /api/v1/verify/:token instead of GET /api/v1/public/verify/:token.
     *
     * @return array<string, mixed>
     */
    public function verifyPassportToken(string $token, bool $selective = false): array
    {
        $trimmed = trim($token);
        if ($trimmed === '') {
            throw new XelorraException('invalid_token', 'Passport QR token is required.');
        }

        $path = $selective
            ? '/api/v1/verify/' . rawurlencode($trimmed)
            : '/api/v1/public/verify/' . rawurlencode($trimmed);

        return $this->requestJson('GET', $path, [], null, true);
    }

    /**
     * Checks memorable XID handle availability via GET /api/v1/xid/check?username=<handle>.
     *
     * @return array<string, mixed>
     */
    public function checkXidAvailability(string $username): array
    {
        $trimmed = trim($username);
        if ($trimmed === '') {
            throw new XelorraException('invalid_request', 'username is required.');
        }

        $query = http_build_query(['username' => $trimmed], '', '&', PHP_QUERY_RFC3986);
        return $this->requestJson('GET', '/api/v1/xid/check?' . $query);
    }

    private function resolveRedirectUri(?string $override): string
    {
        $resolved = trim($override ?? $this->redirectUri ?? '');
        if ($resolved === '') {
            throw new XelorraException(
                'invalid_config',
                'redirectUri is required for OAuth authorization and code exchange.'
            );
        }
        return $resolved;
    }

    private static function normalizeIssuer(string $issuer): string
    {
        $trimmed = rtrim(trim($issuer), '/');
        $parsed = parse_url($trimmed);
        $scheme = is_array($parsed) && isset($parsed['scheme']) ? strtolower((string) $parsed['scheme']) : '';
        if (!in_array($scheme, ['https', 'http'], true) || empty($parsed['host'])) {
            throw new XelorraException('invalid_config', 'issuer must be a valid http(s) URL.');
        }
        return $trimmed;
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed>|object|null $jsonBody
     * @return array<string, mixed>
     */
    private function requestJson(
        string $method,
        string $path,
        array $headers = [],
        array|object|null $jsonBody = null,
        bool $allowInvalidPassportResponse = false
    ): array {
        $url = $this->issuer . $path;
        $requestHeaders = array_merge(['Accept' => 'application/json'], $headers);
        $encodedBody = null;

        if ($jsonBody !== null) {
            $requestHeaders['Content-Type'] = 'application/json';
            $encodedBody = json_encode($jsonBody, JSON_THROW_ON_ERROR);
        }

        $response = $this->sendHttp($method, $url, $requestHeaders, $encodedBody);
        $status = $response['status'];
        $rawBody = $response['body'];

        $decoded = [];
        if (trim($rawBody) !== '') {
            $parsed = json_decode($rawBody, true);
            if (is_array($parsed)) {
                $decoded = $parsed;
            }
        }

        if ($status >= 200 && $status < 300) {
            return $decoded;
        }

        if ($allowInvalidPassportResponse && array_key_exists('valid', $decoded)) {
            return $decoded;
        }

        $errorCode = is_string($decoded['error'] ?? null) ? $decoded['error'] : 'request_failed';
        $errorMessage = is_string($decoded['error_description'] ?? null)
            ? $decoded['error_description']
            : (is_string($decoded['message'] ?? null) ? $decoded['message'] : 'Xelorra API request failed.');

        if ($status === 401 && $errorCode === 'access_revoked') {
            $reason = is_string($decoded['reason'] ?? null) ? $decoded['reason'] : null;
            throw new AccessRevokedException($errorMessage, $reason, $decoded);
        }

        if ($status === 403 && $errorCode === 'insufficient_scope') {
            $required = is_array($decoded['required_scopes'] ?? null)
                ? array_values(array_map('strval', $decoded['required_scopes']))
                : [];
            throw new InsufficientScopeException($errorMessage, $required, $decoded);
        }

        throw new XelorraException($errorCode, $errorMessage, $status, $decoded);
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string}
     */
    private function sendHttp(
        string $method,
        string $url,
        array $headers,
        ?string $body
    ): array {
        if ($this->httpTransport !== null) {
            return ($this->httpTransport)($method, $url, $headers, $body);
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new XelorraException('http_error', 'Unable to initialize cURL session.');
        }

        $formattedHeaders = [];
        foreach ($headers as $name => $value) {
            $formattedHeaders[] = $name . ': ' . $value;
        }

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $formattedHeaders,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => min(10, $this->timeoutSeconds),
            CURLOPT_FOLLOWLOCATION => false,
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $result = curl_exec($ch);
        if ($result === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new XelorraException('network_error', 'HTTP request to Xelorra failed: ' . $err);
        }

        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ['status' => $status, 'body' => (string) $result];
    }
}

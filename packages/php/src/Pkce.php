<?php

declare(strict_types=1);

namespace Xelorra\Identity;

final class Pkce
{
    /**
     * Generates a cryptographically secure RFC 7636 PKCE S256 verifier,
     * unpadded base64url code_challenge, and CSRF state nonce.
     *
     * @return array{
     *   codeVerifier: string,
     *   codeChallenge: string,
     *   codeChallengeMethod: 'S256',
     *   state: string
     * }
     */
    public static function generate(): array
    {
        $codeVerifier = self::base64UrlEncode(random_bytes(48));
        $challengeDigest = hash('sha256', $codeVerifier, true);
        $codeChallenge = self::base64UrlEncode($challengeDigest);
        $state = self::base64UrlEncode(random_bytes(18));

        return [
            'codeVerifier' => $codeVerifier,
            'codeChallenge' => $codeChallenge,
            'codeChallengeMethod' => 'S256',
            'state' => $state,
        ];
    }

    /**
     * Encodes raw bytes to RFC 4648 base64url with no '=' padding.
     */
    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

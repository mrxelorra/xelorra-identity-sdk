# Changelog

All notable changes to `xelorra-identity-sdk` are documented in this file.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-26

### Added
- **TypeScript / JavaScript SDK (`@xelorra/identity`)**:
  - Dual ESM and CommonJS build with zero runtime dependencies for browsers, Node.js 18+, Bun, Deno, and Edge runtimes.
  - Full OAuth 2.0, OIDC, and RFC 7636 PKCE (`S256` unpadded) client supporting `https://one.xelorra.app` (configurable via `issuer` or `baseUrl`), including `prompt=create` sign-up URLs.
  - Complete 14-scope catalog across Levels 1 to 5 and all 11 signed webhook event constants.
  - Token exchange, rotating refresh tokens, pairwise `userinfo`, token introspection, RFC 7009 token revocation, logout, Reusable KYC minimum-disclosure assertion (`POST /api/v1/verify/assertion`), public Digital Passport QR verification, and XID availability check.
  - Timing-safe HMAC-SHA256 webhook verification (`X-Xelorra-Signature: t=<unix_seconds>,v1=<hex>`) with 300-second replay window protection.
  - Two-way disconnect sync guard (`createDisconnectGuard`) and typed error hierarchy (`XelorraError`, `XelorraAuthError`, `XelorraAccessRevokedError`, `XelorraInsufficientScopeError`, `XelorraWebhookSignatureError`).
  - Framework adapters: `@xelorra/identity/react`, `@xelorra/identity/next`, and `@xelorra/identity/express`.
- **PHP SDK (`packages/php`, `xelorra/identity-php`)**:
  - PSR-4 PHP 8.1+ library using native `curl`, `json`, `random_bytes`, `hash`, `hash_hmac`, and `hash_equals`.
  - Complete OAuth/PKCE, Reusable KYC assertion, Passport verification, XID check, and signed webhook verification.
  - Vanilla PHP, Laravel, WordPress, and Symfony integration examples plus PHPUnit test suite.
- **Python SDK (`packages/python`, `xelorra-identity`)**:
  - Standard-library-only Python 3.10+ SDK with typed dataclasses and exceptions.
  - FastAPI, Django, and Flask integration examples plus `unittest` test suite.
- **Go SDK (`packages/go`)**:
  - Standard-library-only Go 1.21+ package with full client, PKCE, webhook verification, and `go test` suite.
- **Documentation & Mobile/REST Guides (`docs/`)**:
  - Complete documentation suite covering quickstart, sign-up and sign-in, two-way sync, 14-scope catalog and KYC assertions, webhooks, Passport QR verification, PHP, Python, Go, React Native/Expo, Flutter, Android Kotlin, iOS Swift, cURL/REST, and troubleshooting.

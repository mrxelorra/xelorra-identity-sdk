# Security Policy

## Supported Versions

Security updates are provided for the latest release of each SDK package in this repository:

| Package | Version | Supported |
| --- | --- | --- |
| `@xelorra/identity` (TypeScript / JavaScript) | 1.x | Yes |
| `xelorra/identity-php` (PHP) | 1.x | Yes |
| `xelorra-identity` (Python) | 1.x | Yes |
| `packages/go` (Go) | 1.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in any Xelorra Identity SDK or documentation example, please report it responsibly instead of opening a public GitHub issue.

- **Email**: [security@xelorra.app](mailto:security@xelorra.app)
- **Include**: Affected package and version, reproduction steps, impact assessment, and any suggested remediation.

We acknowledge vulnerability reports within 48 hours and work with reporters on a coordinated disclosure timeline once a fix is ready.

## SDK Security Guarantees

- **PKCE S256 Required**: Every authorization flow generates a high-entropy `code_verifier` and unpadded base64url SHA-256 `code_challenge`.
- **In-Memory Browser Tokens**: Browser adapters keep access tokens in memory only and never write OAuth tokens to `localStorage` or `sessionStorage`.
- **Server-Only Secrets**: `clientSecret` and webhook `signingSecret` values must remain strictly in server-side environment variables.
- **Timing-Safe Webhook Verification**: Webhook verification checks `X-Xelorra-Signature` (`t=<unix_seconds>,v1=<hmac_sha256_hex>`) over `${t}.${rawBody}` using constant-time comparison and rejects timestamps outside the configured replay window (default 300 seconds).
- **Minimum-Disclosure KYC**: The Reusable KYC assertion API returns verification status and reference metadata only; raw government identifiers and biometric data are never exposed.

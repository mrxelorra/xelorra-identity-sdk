# Errors, HTTP Status Codes & Troubleshooting

This reference covers every HTTP status code returned by `https://one.xelorra.app`, common integration pitfalls, and zero-downtime secret rotation.

## HTTP Status & Error Code Reference

| HTTP Status | Error Code | Cause | Recommended Action |
| --- | --- | --- | --- |
| `400` | `invalid_request` | Missing required parameter, invalid `code_challenge_method` (must be `S256`), or mismatched `redirect_uri`. | Verify every parameter against your Developer Console app settings. |
| `400` | `invalid_grant` | Expired/already-used authorization code, wrong `code_verifier`, or replayed refresh token (family reuse triggered). | Restart the authorization flow with a fresh PKCE pair. |
| `400` | `unsupported_grant_type` | `grant_type` is not `authorization_code` or `refresh_token`. | Pass a supported `grant_type` to `POST /oauth/token`. |
| `401` | `invalid_client` | Wrong `client_id` or `client_secret`. | Confirm server env vars match **console.one.xelorra.app**. |
| `401` | `invalid_token` | Access token is malformed, expired, or unknown. | Attempt a single refresh with `refreshTokens()`, or re-authenticate. |
| `401` | `access_revoked` | Member disconnected your app in Xelorra One or account was suspended. | Immediately clear local session and prompt user to reconnect. |
| `403` | `insufficient_scope` | Access token lacks a required scope (for example calling `POST /api/v1/verify/assertion` without `kyc.assertion.read`, `verification.read`, `gov.nin.verify`, or `gov.bvn.verify`). | Re-authorize requesting the needed scope (ensure Level 4/5 scopes are approved in Console). |
| `404` | `not_found` | Invalid endpoint path or unknown Passport QR token. | Check `issuer` / `baseUrl` has no extra path segment and confirm token validity. |
| `409` | `conflict` | Resource state conflict (for example duplicate registration or already-linked identifier). | Surface a clear message and guide the user to sign in instead. |
| `429` | `rate_limited` | Request rate limit exceeded. | Respect `Retry-After` header and apply exponential backoff with jitter. |
| `501` | `not_implemented` | Requested endpoint or grant flow is not enabled on this deployment. | Check `GET /.well-known/openid-configuration` for advertised capabilities. |

## Common Mistakes & Fast Fixes

### 1. PKCE Base64url Padding (`=`) Mistakes

**Symptom**: `400 invalid_grant` or `400 invalid_request` during `POST /oauth/token` even though you hashed `code_verifier` with SHA-256.

**Cause**: Standard Base64 includes `+`, `/`, and trailing `=` padding characters. RFC 7636 requires **unpadded base64url**:
- Replace `+` with `-`
- Replace `/` with `_`
- Strip all trailing `=` characters

Always use the SDK's `createPkcePair()` / `Pkce::generate()` / `generate_pkce_pair()` / `GeneratePKCE()` helpers rather than hand-rolling Base64 encoding.

### 2. Redirect URI Mismatch

**Symptom**: `400 invalid_request` on `/oauth/authorize` or `/oauth/token`.

**Checklist**:
- Scheme matches (`https://` vs `http://`).
- Port matches (`http://localhost:3000/callback` is different from `http://localhost:3001/callback`).
- Trailing slash matches (`/auth/callback` is different from `/auth/callback/`).
- The exact same `redirect_uri` sent to `GET /oauth/authorize` is sent to `POST /oauth/token`.

### 3. Webhook Signature Fails Even With Correct Secret

**Symptom**: `verifyWebhookSignature` returns `false` or throws `invalid_signature`.

**Checklist**:
- **Use exact raw bytes**: Do NOT call `JSON.stringify(req.body)` after a JSON body-parser middleware has already parsed the request. Re-serialization changes whitespace and key order.
  - Express: Mount `express.raw({ type: "application/json" })` on the webhook route.
  - Next.js App Router: Use `await request.text()`.
  - PHP: Use `file_get_contents('php://input')` or Laravel's `$request->getContent()`.
  - Python: Use `await request.body()` (FastAPI), `request.body` (Django), or `request.get_data(cache=False)` (Flask).
- **Check server clock drift**: `X-Xelorra-Signature` enforces a default `300`-second timestamp window (`|nowSeconds - Number(t)| <= 300`). Ensure NTP time synchronization is enabled on your server.
- **Check exact signed payload**: The HMAC input is `"${t}.${rawRequestBody}"`, NOT `rawRequestBody` alone.

### 4. Rotating Client & Webhook Secrets Without Downtime

#### Rotating `XELORRA_WEBHOOK_SECRET`
1. During rotation, keep both `XELORRA_WEBHOOK_SECRET_PRIMARY` and `XELORRA_WEBHOOK_SECRET_PREVIOUS` in your server environment.
2. Verify incoming webhooks against the primary secret first; if `verifyWebhookSignature` returns `false`, try the previous secret.
3. Generate the new secret in **console.one.xelorra.app**, update `XELORRA_WEBHOOK_SECRET_PRIMARY`, deploy, and remove the previous secret once all in-flight retries have completed.

#### Rotating `XELORRA_CLIENT_SECRET`
1. Rotate the secret in **console.one.xelorra.app**.
2. Update your backend secret store (`XELORRA_CLIENT_SECRET`) and perform a rolling restart of backend instances.
3. Existing access tokens remain valid until expiry; only new `/oauth/token` calls require the updated secret.

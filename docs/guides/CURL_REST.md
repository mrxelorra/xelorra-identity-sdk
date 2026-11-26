# Universal cURL & REST API Reference (`https://one.xelorra.app`)

Use these exact HTTP requests to integrate Xelorra ID from **Ruby, Java, C#/.NET, Rust, Elixir**, or any custom HTTP client, or to debug live flows from your terminal.

## 1. Discovery & JWKS

```bash
curl -s https://one.xelorra.app/.well-known/openid-configuration | jq
curl -s https://one.xelorra.app/.well-known/jwks.json | jq
```

## 2. Authorization URL (Browser Redirect)

```text
# Sign In (returning members)
https://one.xelorra.app/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=https%3A%2F%2Fyour-app.com%2Fcallback&scope=profile.read%20passport.read%20email.read&code_challenge=UNPADDED_BASE64URL_SHA256&code_challenge_method=S256&state=CSRF_NONCE

# Sign Up (new members -> direct registration via prompt=create)
https://one.xelorra.app/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=https%3A%2F%2Fyour-app.com%2Fcallback&scope=profile.read%20passport.read%20email.read&code_challenge=UNPADDED_BASE64URL_SHA256&code_challenge_method=S256&state=CSRF_NONCE&prompt=create
```

## 3. Authorization Code Exchange (`POST /oauth/token`)

Accepts `application/json` or `application/x-www-form-urlencoded`:

```bash
curl -s -X POST https://one.xelorra.app/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTHORIZATION_CODE",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET_IF_CONFIDENTIAL",
    "redirect_uri": "https://your-app.com/callback",
    "code_verifier": "ORIGINAL_PKCE_CODE_VERIFIER"
  }'
```

## 4. Rotating Refresh Token Exchange (`POST /oauth/token`)

```bash
curl -s -X POST https://one.xelorra.app/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "CURRENT_REFRESH_TOKEN",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET_IF_CONFIDENTIAL"
  }'
```

## 5. Fetch Scoped User Claims (`GET /oauth/userinfo`)

```bash
curl -s https://one.xelorra.app/oauth/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## 6. Introspect Active Connection (`POST /oauth/introspect`)

```bash
curl -s -X POST https://one.xelorra.app/oauth/introspect \
  -H "Content-Type: application/json" \
  -d '{
    "token": "ACCESS_TOKEN",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET_IF_CONFIDENTIAL"
  }'
```

`GET /oauth/introspect` with `Authorization: Bearer ACCESS_TOKEN` is also supported.

## 7. Revoke Token & Logout (`POST /oauth/revoke`, `POST /oauth/logout`)

```bash
curl -s -X POST https://one.xelorra.app/oauth/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "token": "REFRESH_OR_ACCESS_TOKEN",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET_IF_CONFIDENTIAL"
  }'

curl -s -X POST https://one.xelorra.app/oauth/logout \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## 8. Reusable KYC Minimum-Disclosure Assertion (`POST /api/v1/verify/assertion`)

```bash
curl -s -X POST https://one.xelorra.app/api/v1/verify/assertion \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

## 9. Public Digital Passport QR Verification & Memorable XID Check (Zero Auth)

```bash
# Public verifier (logs scan to member's "Who checked my passport" history)
curl -s https://one.xelorra.app/api/v1/public/verify/PASSPORT_QR_TOKEN

# Selective-disclosure verifier
curl -s https://one.xelorra.app/api/v1/verify/PASSPORT_QR_TOKEN

# Memorable XID handle availability check
curl -s "https://one.xelorra.app/api/v1/xid/check?username=adaeze"
```

## 10. Verifying Webhook Signatures in Any Language

Given raw body `RAW_BODY`, header `X-Xelorra-Signature: t=1764150000,v1=<hex>`, and `SIGNING_SECRET`:

```bash
TS="1764150000"
printf '%s.%s' "$TS" "$RAW_BODY" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" -hex
```

Compare the lowercase hex digest with `v1` using a constant-time equality function and reject timestamps older than `300` seconds.

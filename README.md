# Xelorra Identity SDK (`xelorra-identity-sdk`)

Official multi-stack SDK and developer documentation suite for **Xelorra Identity** (`https://one.xelorra.app`).

Integrate OAuth 2.0 + OpenID Connect + PKCE (`S256`), direct new-user sign-up (`prompt=create`), two-way disconnect synchronization, Reusable KYC minimum-disclosure assertions, public Digital Passport QR verification, and timing-safe signed webhooks (`t=<unix_ts>,v1=<hmac_sha256_hex>`) across every modern web, backend, and mobile stack.

## Supported Stacks & Packages

| Stack / Ecosystem | Package / Location | Runtime Requirements | Adapter / Examples Included |
| --- | --- | --- | --- |
| **TypeScript / JavaScript** | `@xelorra/identity` (repo root, dual ESM + CJS) | Browser, Node.js 18+, Bun, Deno, Edge / Cloudflare Workers | React, Next.js App Router, Express |
| **PHP** | `xelorra/identity-php` (`packages/php`) | PHP 8.1+ (native `curl`, `json`, `hash_hmac`) | Vanilla PHP (cPanel/shared hosting), Laravel, WordPress, Symfony |
| **Python** | `xelorra-identity` (`packages/python`) | Python 3.10+ (stdlib only) | FastAPI, Django, Flask |
| **Go** | `packages/go` (`xelorra`) | Go 1.21+ (stdlib only) | `net/http`, Gin/Chi compatible |
| **Mobile & Universal REST** | `docs/guides/` | Any HTTP client | React Native / Expo, Flutter, Android (Kotlin), iOS (Swift), cURL / REST |

## Live API Endpoints (`https://one.xelorra.app`)

| Capability | Method & Endpoint | Auth |
| --- | --- | --- |
| OIDC Discovery | `GET /.well-known/openid-configuration` | Public |
| Public Signing Keys | `GET /.well-known/jwks.json` | Public |
| Authorize / Sign In / Sign Up | `GET /oauth/authorize` (`code_challenge_method=S256`, optional `prompt=create`) | Browser redirect |
| Token Exchange & Rotation | `POST /oauth/token` (`authorization_code` / `refresh_token`) | Client credentials + PKCE |
| Scoped User Claims | `GET /oauth/userinfo` | `Bearer <access_token>` |
| Connection Introspection | `POST /oauth/introspect` (also `GET` with Bearer header) | Token + Client credentials |
| Token Revocation | `POST /oauth/revoke` (RFC 7009) | Token + Client credentials |
| Session Logout | `POST /oauth/logout` | Optional Bearer token |
| Reusable KYC Assertion | `POST /api/v1/verify/assertion` | `Bearer <access_token>` (KYC scope) |
| Public Passport QR Verify | `GET /api/v1/public/verify/:token` | Public (zero PII, logs scan) |
| Selective Passport Verify | `GET /api/v1/verify/:token` | Public (zero PII) |
| Memorable XID Check | `GET /api/v1/xid/check?username=<handle>` | Public |

## 5-Minute Quickstarts

### 1. TypeScript / JavaScript (`@xelorra/identity`)

```bash
npm install @xelorra/identity
```

```ts
import { XelorraClient, XELORRA_SCOPES } from "@xelorra/identity";

export const xelorra = new XelorraClient({
  clientId: process.env.XELORRA_CLIENT_ID!,
  clientSecret: process.env.XELORRA_CLIENT_SECRET, // server-only
  redirectUri: "https://your-app.com/auth/callback",
  scopes: [
    XELORRA_SCOPES.PROFILE_READ,
    XELORRA_SCOPES.PASSPORT_READ,
    XELORRA_SCOPES.EMAIL_READ,
  ],
});

// Returning members
const { url: signInUrl, pkce: signInPkce } = await xelorra.buildSignInUrl();

// New members (sends directly to registration via prompt=create)
const { url: signUpUrl, pkce: signUpPkce } = await xelorra.buildSignUpUrl();
```

#### React (`@xelorra/identity/react`)

```tsx
import { XelorraClient } from "@xelorra/identity";
import {
  XelorraProvider,
  XelorraSignInButton,
  XelorraSignUpButton,
  useXelorraCallback,
} from "@xelorra/identity/react";

const client = new XelorraClient({
  clientId: import.meta.env.VITE_XELORRA_CLIENT_ID,
  redirectUri: `${window.location.origin}/auth/callback`,
});

export function AuthButtons() {
  return (
    <XelorraProvider client={client}>
      <XelorraSignInButton theme="dark" variant="solid" />
      <XelorraSignUpButton theme="dark" variant="outline" />
    </XelorraProvider>
  );
}

export function CallbackPage() {
  const { isLoading, error } = useXelorraCallback({
    onSuccess: () => window.location.assign("/dashboard"),
  });
  if (isLoading) return <p>Signing you in...</p>;
  if (error) return <p>Sign-in failed: {error.message}</p>;
  return null;
}
```

#### Next.js App Router (`@xelorra/identity/next`)

```ts
import { XelorraClient } from "@xelorra/identity";
import {
  createNextAuthRedirectHandler,
  createNextCallbackHandler,
  createNextWebhookHandler,
} from "@xelorra/identity/next";

const xelorra = new XelorraClient({
  clientId: process.env.XELORRA_CLIENT_ID!,
  clientSecret: process.env.XELORRA_CLIENT_SECRET,
  redirectUri: `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/xelorra/callback`,
});

// app/api/auth/xelorra/signup/route.ts
export const GET = createNextAuthRedirectHandler({
  client: xelorra,
  mode: "signup",
  saveCodeVerifier: async (pkce) => {
    await storeVerifierByState(pkce.state, pkce.codeVerifier);
  },
});

// app/api/webhooks/xelorra/route.ts
export const POST = createNextWebhookHandler({
  signingSecret: process.env.XELORRA_WEBHOOK_SECRET!,
  onAccessRevoked: async (event) => {
    await revokeLocalSessionsForSub(event.data.sub);
  },
});
```

#### Express (`@xelorra/identity/express`)

```ts
import express from "express";
import { XelorraClient } from "@xelorra/identity";
import {
  createExpressAuthMiddleware,
  createExpressCallbackHandler,
  createExpressWebhookHandler,
} from "@xelorra/identity/express";

const app = express();
const xelorra = new XelorraClient({
  clientId: process.env.XELORRA_CLIENT_ID!,
  clientSecret: process.env.XELORRA_CLIENT_SECRET,
  redirectUri: "https://api.your-app.com/auth/xelorra/callback",
});

app.post(
  "/webhooks/xelorra",
  express.raw({ type: "application/json" }),
  createExpressWebhookHandler({
    signingSecret: process.env.XELORRA_WEBHOOK_SECRET!,
    onAccessRevoked: async (event) => {
      await destroySessionsBySub(event.data.sub);
    },
  }),
);
```

### 2. PHP (`packages/php`)

```bash
composer require xelorra/identity-php
```

```php
use Xelorra\Identity\XelorraClient;
use Xelorra\Identity\Webhook;

$client = new XelorraClient(
    clientId: getenv('XELORRA_CLIENT_ID'),
    redirectUri: 'https://your-site.com/callback.php',
    clientSecret: getenv('XELORRA_CLIENT_SECRET'),
);

$auth = $client->buildSignUpUrl(); // prompt=create
$event = Webhook::parseEvent($rawBody, $_SERVER['HTTP_X_XELORRA_SIGNATURE'], getenv('XELORRA_WEBHOOK_SECRET'));
```

### 3. Python (`packages/python`)

```bash
pip install xelorra-identity
```

```python
import os
from xelorra_identity import XelorraClient, parse_webhook_event

client = XelorraClient(
    client_id=os.environ["XELORRA_CLIENT_ID"],
    client_secret=os.getenv("XELORRA_CLIENT_SECRET"),
    redirect_uri="https://your-app.com/auth/xelorra/callback",
)

url, pkce = client.build_sign_up_url()
```

### 4. Go (`packages/go`)

```bash
go get github.com/xelorra/xelorra-identity-sdk/packages/go
```

```go
client, _ := xelorra.NewClient(xelorra.ClientConfig{
    ClientID:     os.Getenv("XELORRA_CLIENT_ID"),
    ClientSecret: os.Getenv("XELORRA_CLIENT_SECRET"),
    RedirectURI:  "https://your-app.com/auth/xelorra/callback",
})
signUpURL, pkce, _ := client.BuildSignUpURL(nil)
```

## Developer Documentation Index

- **[Quickstart Guide](docs/QUICKSTART.md)**: End-to-end setup from Developer Console (`console.one.xelorra.app`) registration to your first authenticated session.
- **[Sign Up vs Sign In](docs/SIGNUP_AND_SIGNIN.md)**: Using `prompt=create` for new members, plus how email, system Xelorra ID (`XLR-XXXX-XXXX`), and memorable XID (`username.4821`) sign-in work.
- **[Two-Way Connection Sync](docs/TWO_WAY_SYNC.md)**: Combining `user.access_revoked` webhooks, `POST /oauth/introspect`, `401 access_revoked` handling, and `POST /oauth/revoke`.
- **[Scopes & Reusable KYC](docs/SCOPES_AND_KYC.md)**: All 14 scopes across Levels 1 to 5, pairwise `sub` isolation, NDPA consent withdrawal, and `POST /api/v1/verify/assertion`.
- **[Signed Webhooks](docs/WEBHOOKS.md)**: All 11 webhook events, `t=<ts>,v1=<hex>` signature verification in Node.js, PHP, Python, and Go, and replay protection.
- **[Digital Passport QR Verification](docs/PASSPORT_VERIFICATION.md)**: Zero-auth, zero-PII verification via `/api/v1/public/verify/:token` and `/api/v1/verify/:token`, plus memorable XID availability checks.
- **[PHP Integration Guide](docs/PHP_INTEGRATION.md)**: Vanilla PHP, Laravel, WordPress, and Symfony.
- **[Python Integration Guide](docs/PYTHON_INTEGRATION.md)**: FastAPI, Django, and Flask.
- **[Go Integration Guide](docs/GO_INTEGRATION.md)**: `net/http` handlers, middleware, and webhook verification.
- **[Mobile & Universal REST Guide](docs/MOBILE_AND_REST.md)**: Overview and links to [React Native / Expo](docs/guides/REACT_NATIVE_EXPO.md), [Flutter](docs/guides/FLUTTER.md), [Android (Kotlin)](docs/guides/ANDROID_KOTLIN.md), [iOS (Swift)](docs/guides/IOS_SWIFT.md), and [cURL / REST](docs/guides/CURL_REST.md).
- **[Errors & Troubleshooting](docs/ERRORS_AND_TROUBLESHOOTING.md)**: HTTP status reference (`400`, `401`, `403`, `404`, `409`, `429`, `501`), PKCE padding traps, redirect URI rules, and zero-downtime secret rotation.

## Local Development & Verification

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build
npm run dev   # Launches the local interactive SDK playground on http://localhost:3000
```

## License

MIT

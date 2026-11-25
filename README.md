# `@xelorra/identity`

Official TypeScript, JavaScript, React, Express, and Next.js SDK for **Xelorra Identity** (`https://one.xelorra.app`).

`@xelorra/identity` implements every live OAuth 2.0, OIDC, and PKCE (`S256`) endpoint on Xelorra One, including direct new-user sign-up (`prompt=create`), token introspection, token revocation, timing-safe HMAC-SHA256 webhook verification, and two-way connection synchronization when users disconnect an app from Xelorra One.

## Highlights

- **OAuth 2.0 + OIDC + PKCE (`S256`)**: Universal Web Crypto + Node `crypto` PKCE generation targeting `https://one.xelorra.app` by default.
- **Dedicated Sign Up vs Sign In**: `buildSignUpUrl()` and `signUp()` set `prompt=create` so new users go straight to Xelorra ID registration and return automatically to the OAuth consent screen.
- **Zero Browser Token Persistence**: Access and refresh tokens are held strictly in memory by default and are never written to `localStorage` or `sessionStorage`.
- **Two-Way Disconnect Sync**: Built-in `XelorraAccessRevokedError`, `introspectToken()`, `revokeToken()`, `createDisconnectGuard()`, and timing-safe HMAC-SHA256 webhook verification (`X-Xelorra-Signature`).
- **Modular Framework Sub-Exports**:
  - `@xelorra/identity` (React-free core client, functional helpers, webhooks, disconnect guard)
  - `@xelorra/identity/react` (`XelorraProvider`, `useXelorraAuth`, `XelorraAuthButton`)
  - `@xelorra/identity/express` (callback route, revocation-aware auth middleware, webhook handler)
  - `@xelorra/identity/next` (Next.js App Router OAuth callback and webhook route handlers)

## Installation

```bash
npm install @xelorra/identity
```

## Quick Start

Create a `XelorraClient` instance with your registered `clientId` and `redirectUri`. By default, `issuer` points to `https://one.xelorra.app`.

```ts
import { XelorraClient } from "@xelorra/identity";

export const xelorra = new XelorraClient({
  clientId: "your-client-id",
  redirectUri: "https://your-app.com/auth/callback",
  scopes: ["profile.read", "passport.read", "email.read"],
});
```

## Sign In vs Sign Up (`prompt=create`)

Use `buildAuthorizeUrl()` / `loginWithRedirect()` for returning users, and `buildSignUpUrl()` / `signUp()` for new users who need to create a Xelorra ID first. Setting `prompt=create` routes users directly to registration on Xelorra One and returns them seamlessly to the OAuth consent screen.

```ts
// Existing users (Sign In)
const { url: signInUrl, pkce: signInPkce } = await xelorra.buildAuthorizeUrl();

// New users (Sign Up -> automatic return to OAuth consent)
const { url: signUpUrl, pkce: signUpPkce } = await xelorra.buildSignUpUrl();
```

In a browser app, call `xelorra.loginWithRedirect()` or `xelorra.signUp()` directly:

```ts
await xelorra.loginWithRedirect(); // Sign in
await xelorra.signUp();            // Sign up (adds prompt=create)
```

## Browser / React / Vite Integration

Wrap your app with `<XelorraProvider>` from `@xelorra/identity/react`, render sign-in or sign-up buttons with `<XelorraAuthButton>`, and complete the PKCE callback on your redirect route.

```tsx
import { useEffect } from "react";
import { XelorraClient } from "@xelorra/identity";
import {
  XelorraAuthButton,
  XelorraProvider,
  useXelorraAuth,
} from "@xelorra/identity/react";

const xelorra = new XelorraClient({
  clientId: import.meta.env.VITE_XELORRA_CLIENT_ID,
  redirectUri: `${window.location.origin}/auth/callback`,
  scopes: ["profile.read", "passport.read", "email.read"],
});

export function App({ children }: { children: React.ReactNode }) {
  return (
    <XelorraProvider
      client={xelorra}
      onAccessRevoked={() => {
        // Triggered automatically if Xelorra One revokes access
        window.location.assign("/login?reason=disconnected");
      }}
    >
      {children}
    </XelorraProvider>
  );
}

export function AuthButtons() {
  return (
    <div>
      <XelorraAuthButton mode="signin" theme="dark" variant="solid" />
      <XelorraAuthButton mode="signup" theme="dark" variant="outline" />
    </div>
  );
}

export function AuthCallbackPage() {
  const { handleCallback, isLoading, error } = useXelorraAuth();

  useEffect(() => {
    void handleCallback().then(() => {
      window.history.replaceState({}, "", "/dashboard");
    });
  }, [handleCallback]);

  if (isLoading) return <p>Completing sign-in...</p>;
  if (error) return <p>Authentication failed: {error.message}</p>;
  return null;
}
```

To verify that a browser session is still connected on Xelorra One, call `introspectSession()` from `useXelorraAuth()`. If the user revoked access on Xelorra One, `XelorraProvider` automatically clears local state and invokes `onAccessRevoked`.

## Node.js / Express Integration

Import server helpers from `@xelorra/identity/express`. Never expose `clientSecret` or `XELORRA_WEBHOOK_SECRET` in client code.

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

// 1. OAuth 2.0 + PKCE callback route
app.get(
  "/auth/xelorra/callback",
  createExpressCallbackHandler({
    client: xelorra,
    resolveCodeVerifier: async (state, req) => {
      // Look up the PKCE verifier stored when the login started
      return lookupPkceVerifier(state);
    },
    onSuccess: async ({ tokens, user }, _req, res) => {
      await saveUserSession(user.sub, tokens);
      res.status(200).json({ user });
    },
  }),
);

// 2. Protected route with real-time revocation sync via /oauth/introspect
const requireXelorraAuth = createExpressAuthMiddleware({
  client: xelorra,
  cacheTtlMs: 15_000,
  onRevoked: async ({ introspection }) => {
    if (introspection?.sub) {
      await destroyUserSessionBySub(introspection.sub);
    }
  },
});

app.get("/api/me", requireXelorraAuth, (req, res) => {
  res.json({ session: req.xelorra?.introspection });
});

// 3. Real-time webhook handler (MUST receive raw JSON bytes for HMAC verification)
app.post(
  "/webhooks/xelorra",
  express.raw({ type: "application/json" }),
  createExpressWebhookHandler({
    webhookSecret: process.env.XELORRA_WEBHOOK_SECRET!,
    onAccessRevoked: async (event) => {
      await destroyUserSessionBySub(event.data.sub);
    },
  }),
);
```

## Next.js App Router Integration

Import Web Standard route handlers from `@xelorra/identity/next`.

### OAuth Callback (`app/api/auth/xelorra/callback/route.ts`)

```ts
import { NextResponse } from "next/server";
import { XelorraClient } from "@xelorra/identity";
import { createNextCallbackHandler } from "@xelorra/identity/next";

const xelorra = new XelorraClient({
  clientId: process.env.XELORRA_CLIENT_ID!,
  clientSecret: process.env.XELORRA_CLIENT_SECRET,
  redirectUri: `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/xelorra/callback`,
});

export const GET = createNextCallbackHandler({
  client: xelorra,
  resolveCodeVerifier: async (state) => {
    return readVerifierCookie(state);
  },
  onSuccess: async ({ tokens, user }) => {
    await persistServerSession(user.sub, tokens);
    return NextResponse.redirect(new URL("/dashboard", process.env.NEXT_PUBLIC_APP_URL));
  },
});
```

### Signed Webhook Route (`app/api/webhooks/xelorra/route.ts`)

```ts
import { createNextWebhookHandler } from "@xelorra/identity/next";

export const POST = createNextWebhookHandler({
  webhookSecret: process.env.XELORRA_WEBHOOK_SECRET!,
  onAccessRevoked: async (event) => {
    // Runs only after X-Xelorra-Signature HMAC-SHA256 verification succeeds
    await revokeLocalSessionsForSub(event.data.sub);
  },
});
```

## Keeping Connections in Sync (Webhooks + Introspection)

Xelorra One supports two-way disconnect synchronization:

1. **User disconnects on Xelorra One (push)**: Xelorra One sends a signed `user.access_revoked` webhook to your endpoint with the `X-Xelorra-Signature` header. Use `parseWebhookEvent()` (or the Express/Next.js webhook handlers) to verify the signature and immediately terminate the user's local session.
2. **Active session checks (pull)**: Use `createDisconnectGuard()` to wrap protected API calls or check `POST /oauth/introspect`. Whenever a token is inactive, disconnected, or returns `401 access_revoked`, `onRevoked()` runs automatically.
3. **User disconnects inside your app**: Call `client.revokeToken(token)` (or `client.logout()`) to send `POST /oauth/revoke` so the connection is also removed cleanly on Xelorra One.

```ts
import { XelorraClient, createDisconnectGuard } from "@xelorra/identity";

const xelorra = new XelorraClient({ clientId: process.env.XELORRA_CLIENT_ID! });

const guard = createDisconnectGuard<{ userId: string }>({
  client: xelorra,
  getToken: ({ userId }) => loadAccessTokenForUser(userId),
  onRevoked: async ({ context, reason }) => {
    await clearLocalSession(context.userId, reason);
  },
});

// Check via POST /oauth/introspect
const status = await guard.check({ userId: "user_42" });

// Or guard a live API call (handles XelorraAccessRevokedError automatically)
const claims = await guard.run({ userId: "user_42" }, (token) =>
  xelorra.getUserInfo(token),
);
```

### Manual Webhook Verification

```ts
import {
  XelorraWebhookSignatureError,
  parseWebhookEvent,
  verifyWebhookSignature,
} from "@xelorra/identity";

const isValid = await verifyWebhookSignature(
  rawBody,
  req.headers["x-xelorra-signature"],
  process.env.XELORRA_WEBHOOK_SECRET!,
);

try {
  const event = await parseWebhookEvent(
    rawBody,
    req.headers["x-xelorra-signature"],
    process.env.XELORRA_WEBHOOK_SECRET!,
  );

  if (event.type === "user.access_revoked") {
    console.log("Revoked subject:", event.data.sub, "at", event.data.revoked_at);
  }
} catch (err) {
  if (err instanceof XelorraWebhookSignatureError) {
    // Reject with HTTP 401
  }
}
```

## Error Handling

All SDK errors extend `XelorraAuthError`:

- `XelorraAuthError`: Base error with `.code`, `.status`, and `.details`.
- `XelorraAccessRevokedError`: Thrown when Xelorra One returns HTTP `401` with `error: "access_revoked"`. Includes `.reason`.
- `XelorraWebhookSignatureError`: Thrown by `parseWebhookEvent()` when the webhook secret or `X-Xelorra-Signature` header is missing, invalid, or the JSON payload is malformed.

```ts
import {
  XelorraAccessRevokedError,
  XelorraAuthError,
} from "@xelorra/identity";

try {
  const user = await xelorra.getUserInfo(accessToken);
} catch (err) {
  if (err instanceof XelorraAccessRevokedError) {
    // Clear local session and ask the user to reconnect
  } else if (err instanceof XelorraAuthError) {
    console.error("Xelorra error:", err.code, err.status, err.message);
  }
}
```

## API Reference

### Core Client (`@xelorra/identity`)

| Export | Endpoint / Purpose |
| --- | --- |
| `new XelorraClient(config)` | Main OAuth 2.0 + OIDC + PKCE client (`XelorraAuth` is exported as an alias). Defaults `issuer` to `https://one.xelorra.app`. |
| `createPkcePair()` | Generates RFC 7636 `S256` `{ codeVerifier, codeChallenge, codeChallengeMethod, state }` using Web Crypto or Node `crypto`. |
| `client.buildAuthorizeUrl(options?)` | Builds a `GET /oauth/authorize` URL with PKCE `S256`. |
| `client.buildSignUpUrl(options?)` | Builds a `GET /oauth/authorize` URL with `prompt=create`. |
| `client.loginWithRedirect(options?)` | Browser redirect to `/oauth/authorize` storing only the ephemeral PKCE verifier in `sessionStorage`. |
| `client.signUp(options?)` | Browser redirect to `/oauth/authorize` with `prompt=create`. |
| `client.exchangeCodeForTokens(options)` | Calls `POST /oauth/token` (`grant_type: "authorization_code"`). |
| `client.refreshTokens(options?)` | Calls `POST /oauth/token` (`grant_type: "refresh_token"`). |
| `client.getUserInfo(accessToken?)` | Calls `GET /oauth/userinfo`. Throws `XelorraAccessRevokedError` on `401 access_revoked`. |
| `client.introspectToken(accessToken?)` | Calls `POST /oauth/introspect` and returns `{ active, connected, client_id, sub, xid, scope, exp, reason }`. |
| `client.revokeToken(token?)` | Calls `POST /oauth/revoke` to disconnect the user back on Xelorra One. |
| `client.getVerificationAssertion(accessToken?)` | Calls `GET /api/v1/verify/assertion` for Reusable KYC claims. |
| `client.handleCallback(input?)` | Extracts callback parameters, exchanges the PKCE code, and loads user claims. |
| `client.logout()` | Revokes the active token on Xelorra One and clears in-memory session state. |

Functional equivalents (`buildAuthorizeUrl`, `buildSignUpUrl`, `exchangeCodeForTokens`, `refreshTokens`, `getUserInfo`, `introspectToken`, `revokeToken`) are also exported from `@xelorra/identity`.

### Webhooks & Sync (`@xelorra/identity`)

| Export | Description |
| --- | --- |
| `verifyWebhookSignature(rawBody, signatureHeader, webhookSecret)` | Constant-time HMAC-SHA256 verification against `X-Xelorra-Signature`. Returns `Promise<boolean>`. |
| `parseWebhookEvent(rawBody, signatureHeader, webhookSecret)` | Verifies signature and returns a typed `XelorraWebhookEvent` (including `user.access_revoked`). |
| `computeWebhookSignature(rawBody, webhookSecret)` | Generates an HMAC-SHA256 hex digest for testing webhook endpoints. |
| `createDisconnectGuard({ client, getToken, onRevoked, cacheTtlMs? })` | Synchronizes session revocation using `introspectToken()` and `XelorraAccessRevokedError`. |

### Framework Adapters

- `@xelorra/identity/react`: `XelorraProvider`, `useXelorraAuth`, `XelorraAuthButton`
- `@xelorra/identity/express`: `createExpressCallbackHandler`, `createExpressAuthMiddleware`, `createExpressWebhookHandler`
- `@xelorra/identity/next`: `createNextCallbackHandler`, `createNextWebhookHandler`

## Development

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build
```

## License

MIT

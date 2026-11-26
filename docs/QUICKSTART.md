# Quickstart Guide: Zero to First Sign-In in 5 Minutes

This guide walks you from creating an application in the Xelorra Developer Console to completing your first PKCE `S256` OAuth 2.0 sign-in against `https://one.xelorra.app`.

## Step 1: Register Your App in Xelorra Developer Console

1. Open **[console.one.xelorra.app](https://console.one.xelorra.app)** and sign in with your Xelorra ID.
2. Select **Create Application** and enter your application name, logo, and homepage URL.
3. Add your exact **Redirect URI** (for example `http://localhost:3000/auth/callback` during local development and `https://your-app.com/auth/callback` in production).
   - Redirect URIs are matched **character-for-character** (scheme, host, port, path, and trailing slash must match exactly).
4. Select the minimum **Scopes** your application requires (start with Level 1 and Level 2: `profile.read`, `passport.read`, `email.read`).
5. Copy your **Client ID**. If your application has a backend server, also generate and store your **Client Secret** in your server environment variables (never put `clientSecret` in browser or mobile app binaries).

## Step 2: Configure Environment Variables

Add these variables to your server environment (`.env` locally, or your hosting provider's secret manager in production):

```bash
XELORRA_ISSUER=https://one.xelorra.app
XELORRA_CLIENT_ID=your_client_id
XELORRA_CLIENT_SECRET=your_client_secret
XELORRA_REDIRECT_URI=https://your-app.com/auth/callback
XELORRA_WEBHOOK_SECRET=your_webhook_signing_secret
```

## Step 3: Verify OIDC Discovery (Optional Sanity Check)

Confirm your server can reach the live OpenID Connect Discovery document:

```bash
curl -s https://one.xelorra.app/.well-known/openid-configuration | jq
```

You should see `issuer: "https://one.xelorra.app"`, `code_challenge_methods_supported: ["S256"]`, and every live OAuth endpoint.

## Step 4: Initialize the SDK & Start an OAuth Flow

```ts
import { XelorraClient, XELORRA_SCOPES } from "@xelorra/identity";

export const xelorra = new XelorraClient({
  clientId: process.env.XELORRA_CLIENT_ID!,
  clientSecret: process.env.XELORRA_CLIENT_SECRET,
  redirectUri: process.env.XELORRA_REDIRECT_URI!,
  scopes: [
    XELORRA_SCOPES.PROFILE_READ,
    XELORRA_SCOPES.PASSPORT_READ,
    XELORRA_SCOPES.EMAIL_READ,
  ],
});

// 1. Generate a fresh PKCE S256 pair and authorize URL
const { url, pkce } = await xelorra.buildSignInUrl();

// 2. Store pkce.codeVerifier and pkce.state in an HttpOnly session or Redis
// 3. Redirect the user's browser to `url`
```

## Step 5: Handle the Callback & Load User Claims

When Xelorra One redirects back to your `redirect_uri` with `?code=...&state=...`:

1. Verify that `state` matches the value stored in Step 4 (CSRF protection).
2. Retrieve and delete the stored `codeVerifier`.
3. Exchange the authorization code for tokens and fetch user claims:

```ts
const tokens = await xelorra.exchangeCodeForTokens({
  code,
  codeVerifier,
});

const user = await xelorra.getUserInfo(tokens.access_token);
// Always key your local user table by `user.sub` (pairwise ID: `xapp_...`)
console.log("Authenticated user:", user.sub, user.name);
```

## Step 6: Wire Up Two-Way Sync Before Launching

Before going to production:

1. Configure your webhook URL in **console.one.xelorra.app** and verify `X-Xelorra-Signature` (`t=<ts>,v1=<hex>`). See [Signed Webhooks](./WEBHOOKS.md).
2. Handle `user.access_revoked` webhooks and `401 access_revoked` responses. See [Two-Way Sync](./TWO_WAY_SYNC.md).
3. Call `POST /oauth/revoke` whenever a user disconnects Xelorra inside your app.

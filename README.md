# `@xelorra/identity`

Official JavaScript, TypeScript, and React SDK for integrating **Xelorra Identity** (`one.xelorra.app`) using OAuth 2.0 + PKCE (`S256`), refresh token rotation, and minimum-disclosure Reusable KYC assertions.

## Installation

```bash
npm install @xelorra/identity
```

## Quick Start (React)

```tsx
import { XelorraAuth } from "@xelorra/identity";
import { XelorraProvider, XelorraAuthButton, useXelorraAuth } from "@xelorra/identity/react";

const auth = new XelorraAuth({
  clientId: "your-client-id",
  redirectUri: "https://your-app.com/auth/callback",
  scopes: ["profile.read", "passport.read", "email.read"],
});

export function LoginPage() {
  return (
    <XelorraProvider client={auth}>
      <XelorraAuthButton
        theme="dark"
        variant="solid"
        label="Continue with Xelorra"
      />
    </XelorraProvider>
  );
}
```

`<XelorraAuth.Button />`, `XelorraProvider`, and `useXelorraAuth` are also available from the root `@xelorra/identity` entrypoint.

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## Security Guarantees

- Uses WebCrypto `SHA-256` PKCE (`S256`) with single-use authorization codes against `https://one.xelorra.app` by default.
- Keeps access and refresh tokens strictly in memory (never written to `localStorage` or `sessionStorage`).
- Supports pairwise app-isolated `sub` identifiers and zero-raw-PII Reusable KYC assertions.

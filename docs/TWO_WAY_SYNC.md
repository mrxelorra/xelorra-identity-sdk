# Two-Way Connection Synchronization

Members can disconnect a partner application from **either side**: inside **Xelorra One** (Security -> Connected Apps) or inside **your partner application** (Account Settings -> Disconnect Xelorra ID).

To keep both platforms 100% synchronized and remain compliant with NDPA consent-withdrawal requirements, combine four mechanisms:

1. **Push (Real-Time Webhooks)**: Listen for `user.access_revoked` (and `user.account_suspended`, `user.deleted`) webhooks.
2. **Pull (Active Introspection)**: Verify connection health with `POST /oauth/introspect`.
3. **Reactive (`401 access_revoked`)**: Catch `XelorraAccessRevokedError` whenever calling `GET /oauth/userinfo` or `POST /api/v1/verify/assertion`.
4. **Outbound Revocation (`POST /oauth/revoke`)**: Always revoke tokens when a user disconnects or logs out inside your app.

## 1. Push: Handling `user.access_revoked` Webhooks

When a user disconnects your app inside Xelorra One, Xelorra One immediately sends a signed `POST` request to your webhook URL:

```json
{
  "id": "evt_01JXYZ987654",
  "type": "user.access_revoked",
  "created_at": "2026-11-26T12:00:00.000Z",
  "client_id": "your-client-id",
  "data": {
    "xid": "XLR-9284-1039",
    "sub": "xapp_7c91e4f02b8a",
    "client_id": "your-client-id",
    "revoked_at": "2026-11-26T12:00:00.000Z",
    "reason": "user_disconnected"
  }
}
```

Verify `X-Xelorra-Signature` (`t=<unix_ts>,v1=<hmac_sha256_hex>`), then immediately delete all stored tokens and active sessions for `event.data.sub`.

```ts
import { createNextWebhookHandler } from "@xelorra/identity/next";

export const POST = createNextWebhookHandler({
  signingSecret: process.env.XELORRA_WEBHOOK_SECRET!,
  onAccessRevoked: async (event) => {
    await db.sessions.deleteMany({ where: { xelorraSub: event.data.sub } });
    await db.oauthTokens.deleteMany({ where: { xelorraSub: event.data.sub } });
  },
});
```

## 2. Pull: Checking Live Status with `POST /oauth/introspect`

Introspection always returns HTTP `200`:

- **Active connection**:
  ```json
  {
    "active": true,
    "connected": true,
    "client_id": "your-client-id",
    "sub": "xapp_7c91e4f02b8a",
    "xid": "XLR-9284-1039",
    "scope": "profile.read passport.read email.read",
    "exp": 1900000000
  }
  ```
- **Disconnected, suspended, expired, or revoked**:
  ```json
  {
    "active": false,
    "connected": false,
    "reason": "access_revoked"
  }
  ```
  Possible `reason` values include `"access_revoked"`, `"account_suspended"`, and `"missing_token"`.

Use `createDisconnectGuard()` in Node.js/TypeScript to combine introspection caching with automatic cleanup:

```ts
import { XelorraClient, createDisconnectGuard } from "@xelorra/identity";

const xelorra = new XelorraClient({
  clientId: process.env.XELORRA_CLIENT_ID!,
  clientSecret: process.env.XELORRA_CLIENT_SECRET,
});

export const disconnectGuard = createDisconnectGuard<{ userId: string }>({
  client: xelorra,
  cacheTtlMs: 15_000,
  getAccessToken: ({ userId }) => loadUserAccessToken(userId),
  onRevoked: async ({ context, reason }) => {
    await clearLocalSession(context.userId, reason);
  },
});

// Check before serving sensitive routes
const status = await disconnectGuard.check({ userId: "usr_42" });
if (!status.active) {
  // User was already logged out by onRevoked
}

// Or wrap any Xelorra API call
const claims = await disconnectGuard.run({ userId: "usr_42" }, (token) =>
  xelorra.getUserInfo(token),
);
```

## 3. Reactive: Handling `401 access_revoked`

Whenever you call `GET /oauth/userinfo` or `POST /api/v1/verify/assertion` with a token whose connection was revoked or suspended, Xelorra One responds with HTTP `401` and `{ "error": "access_revoked", "error_description": "..." }`.

Every SDK maps this directly to a typed exception:

- **JS / TS**: `XelorraAccessRevokedError`
- **PHP**: `Xelorra\Identity\Exceptions\AccessRevokedException`
- **Python**: `XelorraAccessRevokedError`
- **Go**: `*xelorra.AccessRevokedError`

Catch it, clear the user's local session, and prompt them to reconnect.

## 4. Outbound: Disconnecting from Your App (`POST /oauth/revoke`)

When a user clicks **Disconnect Xelorra ID** or **Sign Out** inside your application, always call `POST /oauth/revoke` so the connection is also removed from the user's Xelorra One dashboard:

```ts
await xelorra.revokeToken(storedRefreshOrAccessToken);
// Or revoke and call POST /oauth/logout in one step:
await xelorra.logout(storedAccessToken);
```

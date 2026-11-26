# Signed Webhooks Reference

Xelorra One delivers real-time HTTPS `POST` notifications whenever member lifecycle, authentication, verification, or consent events occur. Every webhook is signed with HMAC-SHA256 using your endpoint's **Webhook Signing Secret** from **console.one.xelorra.app**.

## All 11 Supported Webhook Events

| Category | Event Type | Typical Action in Partner App |
| --- | --- | --- |
| **Lifecycle** | `user.registered` | Provision onboarding metrics or welcome workflow. |
| **Lifecycle** | `user.updated` | Refresh cached profile claims from `/oauth/userinfo`. |
| **Lifecycle** | `user.deleted` | Purge or anonymize user records per retention policy. |
| **Lifecycle** | `user.account_suspended` | Immediately lock or revoke active local sessions. |
| **Authentication** | `user.login` | Record audit log of federated sign-in. |
| **Authentication** | `user.logout` | End active local browser/app session. |
| **Verification** | `user.email_verified` | Mark user email verified in local profile. |
| **Verification** | `user.phone_verified` | Mark user phone verified in local profile. |
| **Verification** | `user.identity_verified` | Re-query `POST /api/v1/verify/assertion` and unlock KYC-gated features. |
| **Consent** | `user.permissions_updated` | Re-sync granted scopes and drop removed claim fields. |
| **Consent** | `user.access_revoked` | Immediately destroy sessions and delete stored tokens for `data.sub`. |

## Outbound HTTP Headers & JSON Envelope

Every delivery includes these headers:

```http
Content-Type: application/json
X-Xelorra-Event: user.access_revoked
X-Xelorra-Event-Id: evt_01JXYZ987654
X-Xelorra-Signature: t=1764150000,v1=3f9c...64-char-lowercase-hex
```

Exact JSON envelope:

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

## Exact Signature Verification Algorithm

Always verify against the **exact raw request bytes** before parsing JSON:

1. Parse `t` (Unix timestamp in seconds) and `v1` (64-char lowercase hex HMAC digest) from `X-Xelorra-Signature`.
2. **Replay-attack protection**: Reject the request if `|nowSeconds - Number(t)| > toleranceSeconds` (default: `300` seconds / 5 minutes).
3. Construct the signed payload string: `"${t}.${rawRequestBody}"`.
4. Compute `HMAC-SHA256(signingSecret, "${t}.${rawRequestBody}")` as lowercase hex.
5. Compare computed hex against `v1` using a **constant-time comparison** (`crypto.timingSafeEqual`, `hash_equals`, `hmac.compare_digest`, or `hmac.Equal`).
6. Deduplicate deliveries using `X-Xelorra-Event-Id` (`event.id`) so retries are idempotent.

## Verification Examples by Stack

### Node.js / TypeScript

```ts
import { parseWebhookEvent, XelorraWebhookSignatureError } from "@xelorra/identity";

try {
  const event = await parseWebhookEvent({
    rawBody, // Buffer or exact UTF-8 string before JSON.parse
    signatureHeader: req.headers["x-xelorra-signature"] as string,
    signingSecret: process.env.XELORRA_WEBHOOK_SECRET!,
    toleranceSeconds: 300,
  });
  // Safe to process `event.type` and `event.data`
} catch (err) {
  if (err instanceof XelorraWebhookSignatureError) {
    res.status(401).json({ error: err.code });
    return;
  }
  throw err;
}
```

### PHP

```php
use Xelorra\Identity\Webhook;
use Xelorra\Identity\Exceptions\WebhookSignatureException;

$rawBody = file_get_contents('php://input') ?: '';
$sigHeader = (string) ($_SERVER['HTTP_X_XELORRA_SIGNATURE'] ?? '');

try {
    $event = Webhook::parseEvent($rawBody, $sigHeader, getenv('XELORRA_WEBHOOK_SECRET'));
} catch (WebhookSignatureException $e) {
    http_response_code(401);
    exit;
}
```

### Python

```python
from xelorra_identity import parse_webhook_event, XelorraWebhookSignatureError

try:
    event = parse_webhook_event(
        raw_body=raw_body_bytes,
        signature_header=request.headers.get("X-Xelorra-Signature"),
        signing_secret=os.environ["XELORRA_WEBHOOK_SECRET"],
        tolerance_seconds=300,
    )
except XelorraWebhookSignatureError:
    return Response(status_code=401)
```

### Go

```go
rawBody, _ := io.ReadAll(r.Body)
event, err := xelorra.ParseWebhookEvent(
    rawBody,
    r.Header.Get(xelorra.HeaderSignature),
    os.Getenv("XELORRA_WEBHOOK_SECRET"),
    300,
)
if err != nil {
    http.Error(w, "invalid signature", http.StatusUnauthorized)
    return
}
```

## Testing Webhooks via Developer Console

1. Open **console.one.xelorra.app** -> select your app -> **Webhooks**.
2. Register your HTTPS endpoint URL and subscribe to the events you need (at minimum `user.access_revoked` and `user.account_suspended`).
3. Click **Send Test Event** to deliver a signed `t=<ts>,v1=<hex>` payload and inspect the live HTTP response status and delivery logs.
4. Return HTTP `2xx` within 5 seconds; do heavy database or email work asynchronously in a background queue.

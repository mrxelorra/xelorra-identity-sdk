# Public Digital Passport QR Verification & Memorable XID Checks

Xelorra One provides zero-authentication, zero-PII endpoints for verifying a member's short-lived rotating **Digital Passport QR token** (for event check-ins, physical venues, peer trust checks, and partner kiosks) and for checking **memorable XID** handle availability.

## 1. Two Passport Verification Endpoints

| Endpoint | Behavior | Best For |
| --- | --- | --- |
| `GET /api/v1/public/verify/:token` | Public, CORS-enabled, verifies the rotating QR token and logs the scan to the member's **"Who checked my passport"** history. | Venue scanners, browser widgets, kiosks, and partner check-in tools. |
| `GET /api/v1/verify/:token` | Selective-disclosure public verifier returning `sharedFields`, `mode`, `expiresAt`, `checkedAt`, and `disclaimer`. | Applications displaying selective-disclosure badges and expiry metadata. |

Neither endpoint requires an OAuth access token or client secret, and neither endpoint exposes raw sensitive PII (such as NIN, BVN, or government document numbers).

## 2. Example Response

```json
{
  "valid": true,
  "xid": "XLR-9284-1039",
  "name": "Adaeze Okafor",
  "tier": "verified",
  "status": "active",
  "verified": true,
  "memberSince": "2025-01-15",
  "mode": "selective",
  "expiresAt": "2026-11-26T12:05:00.000Z",
  "checkedAt": "2026-11-26T12:00:00.000Z",
  "sharedFields": ["xid", "name", "tier", "verified"],
  "disclaimer": "Verification reflects live Xelorra One status at check time."
}
```

If the QR token has rotated, expired, or been revoked, `valid` is `false` and `reason` explains why (for example `"expired"` or `"invalid_token"`).

## 3. SDK Usage Across Stacks

### TypeScript / JavaScript (Works Directly in Browsers & Servers)

```ts
import { verifyPassportToken } from "@xelorra/identity";

// Public verifier (logs scan to "Who checked my passport")
const result = await verifyPassportToken(scannedQrToken);

// Selective-disclosure verifier (/api/v1/verify/:token)
const selective = await verifyPassportToken(scannedQrToken, {
  endpoint: "selective",
});

if (result.valid && result.verified) {
  console.log("Verified member:", result.name, result.xid);
}
```

### PHP

```php
$publicResult = $client->verifyPassportToken($qrToken);
$selectiveResult = $client->verifyPassportToken($qrToken, selective: true);
```

### Python

```python
public_result = client.verify_passport_token(qr_token)
selective_result = client.verify_passport_token(qr_token, selective=True)
```

### Go

```go
publicResult, err := client.VerifyPassportToken(ctx, qrToken, false)
selectiveResult, err := client.VerifyPassportToken(ctx, qrToken, true)
```

## 4. Checking Memorable XID Availability (`GET /api/v1/xid/check`)

Use `GET /api/v1/xid/check?username=<handle>` to check whether a memorable XID handle is available and retrieve suggested handles:

```ts
import { checkXidAvailability } from "@xelorra/identity";

const check = await checkXidAvailability("adaeze");
if (!check.available) {
  console.log("Try one of these:", check.suggestions);
}
```

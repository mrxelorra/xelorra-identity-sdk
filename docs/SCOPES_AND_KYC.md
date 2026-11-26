# Complete 14-Scope Catalog, Privacy Isolation & Reusable KYC

Xelorra One enforces strict least-privilege data minimization across **5 permission levels** and **14 scopes**. `GET /oauth/userinfo` returns **only** the claims explicitly approved by the member on the consent screen.

## Complete 14-Scope Catalog

| Level | Category | Scope | Admin Review Required | Purpose / Claims Returned |
| --- | --- | --- | --- | --- |
| **1** | Basic Identity | `profile.read` | No | Display name, given/family name, avatar. |
| **1** | Basic Identity | `passport.read` | No | Digital Passport tier, standing, and membership status. |
| **1** | Basic Identity | `rewards.read` | No | Ecosystem rewards balance and loyalty standing. |
| **2** | Contact Identity | `email.read` | No | Primary email address and `email_verified` flag. |
| **2** | Contact Identity | `phone.read` | No | Phone number and `phone_number_verified` flag. |
| **2** | Contact Identity | `wallet.read` | No | Linked Xelorra wallet metadata. |
| **3** | Extended Identity | `address.read` | No | Residential or mailing address claims. |
| **3** | Extended Identity | `personal.read` | No | Extended demographic profile attributes. |
| **3** | Extended Identity | `location.read` | No | Country, state/region, and timezone attributes. |
| **3** | Extended Identity | `account.read` | No | Account status, member creation date, and security metadata. |
| **4** | Verified Identity | `verification.read` | **Yes (Admin Review)** | Member identity verification level and status. |
| **4** | Verified Identity | `kyc.assertion.read` | **Yes (Admin Review)** | Reusable KYC minimum-disclosure assertion via `POST /api/v1/verify/assertion`. |
| **5** | Restricted Government Identity | `gov.nin.verify` | **Yes (Compliance Approval)** | NIN verification assertion status (never raw NIN). |
| **5** | Restricted Government Identity | `gov.bvn.verify` | **Yes (Compliance Approval)** | BVN verification assertion status (never raw BVN). |

## Pairwise Subject (`sub`) Isolation

To prevent cross-app tracking across unrelated partner services:

- **Third-party applications** receive a unique, tenant-isolated pairwise subject identifier prefixed with `xapp_...` (for example `xapp_7c91e4f02b8a`). The same member receives a different `sub` in every third-party application.
- **First-party Xelorra applications** receive the member's `xid`.
- Always use `sub` as your primary external account key in your database.

## NDPA Consent Withdrawal Behavior

Members can modify granted scopes or revoke consent at any time in Xelorra One:

- **Scope narrowing**: Xelorra One emits a `user.permissions_updated` webhook and immediately stops returning removed claims from `GET /oauth/userinfo`.
- **Full revocation**: Xelorra One invalidates active access and refresh tokens, returns `401 access_revoked` on protected calls, returns `{ active: false, connected: false, reason: "access_revoked" }` from `POST /oauth/introspect`, and emits a `user.access_revoked` webhook.

## Reusable KYC Minimum-Disclosure Assertion API

Instead of collecting, storing, and securing sensitive government ID documents yourself, call `POST /api/v1/verify/assertion` with the member's `Bearer` access token.

### Required Scopes

The token must hold **at least one** of:
- `kyc.assertion.read`
- `verification.read`
- `gov.nin.verify`
- `gov.bvn.verify`

### Response Schema (HTTP 200)

```json
{
  "verification_status": "verified",
  "verification_type": "government_identity",
  "verification_reference": "xvr_8492019482",
  "verified_at": "2026-11-26T09:14:22.000Z",
  "credential_category": "nin"
}
```

- `verification_status`: `"verified" | "pending" | "unverified"`
- `verification_type`: `"government_identity" | "ecosystem_identity"`
- `verification_reference`: Auditable reference ID (`"xvr_..."`) or `null`
- `verified_at`: ISO-8601 timestamp or `null`
- `credential_category` (optional): `"nin" | "bvn" | "national_id"`

**Strict minimum disclosure**: Raw NIN, raw BVN, passport numbers, document photos, and biometric templates are **never** returned by this endpoint.

### SDK Usage Examples

#### TypeScript / JavaScript

```ts
import { XelorraInsufficientScopeError } from "@xelorra/identity";

try {
  const assertion = await xelorra.verifyKycAssertion(accessToken);
  if (assertion.verification_status === "verified") {
    console.log("Verified reference:", assertion.verification_reference);
  }
} catch (err) {
  if (err instanceof XelorraInsufficientScopeError) {
    // Re-prompt user with kyc.assertion.read scope
  }
}
```

#### PHP

```php
$assertion = $client->verifyKycAssertion($accessToken);
if ($assertion['verification_status'] === 'verified') {
    // Allow high-trust action and record $assertion['verification_reference']
}
```

#### Python

```python
assertion = client.verify_kyc_assertion(access_token)
if assertion["verification_status"] == "verified":
    print("Reference:", assertion["verification_reference"])
```

#### Go

```go
assertion, err := client.VerifyKYCAssertion(ctx, accessToken)
if err == nil && assertion.VerificationStatus == "verified" {
    log.Println("Verified:", assertion.VerificationType)
}
```

### Error Responses

- `401 invalid_token` or `401 access_revoked`: Token is invalid, expired, or disconnected.
- `403 insufficient_scope`: Token lacks any of the four authorized KYC scopes.

# Sign Up vs Sign In (`prompt=create`) & Xelorra ID Formats

Xelorra One supports two distinct entry flows on `GET /oauth/authorize` so you can offer both **"Sign in with Xelorra ID"** for returning members and **"Sign up with Xelorra ID"** for brand-new users.

## 1. How Members Identify Themselves on Xelorra One

During authentication on `https://one.xelorra.app`, members can sign in with any of three identifiers:

| Identifier Type | Example | Notes |
| --- | --- | --- |
| **Email Address** | `adaeze@example.com` | Standard email sign-in. |
| **System Xelorra ID** | `XLR-9284-1039` | Immutable system-assigned member identifier. |
| **Memorable XID** | `adaeze.4821` | Human-friendly handle (`username.digits`). You can check availability ahead of time with `GET /api/v1/xid/check?username=<handle>`. |

You can optionally pre-fill any of these via the `loginHint` (`login_hint`) parameter.

## 2. Sign In vs Sign Up (`prompt=create`)

- **Sign In (default)**: Omit `prompt`. Returning users land directly on the Xelorra One sign-in screen, authenticate, and approve your requested scopes.
- **Sign Up (`prompt=create`)**: Include `prompt=create`. Users who do not yet have a Xelorra ID land directly on the Xelorra One account creation flow and are returned automatically to your OAuth consent screen once registration finishes.

### TypeScript / JavaScript

```ts
// Returning member ("Sign in with Xelorra ID")
const signIn = await xelorra.buildSignInUrl({
  scopes: ["profile.read", "passport.read", "email.read"],
});

// New member ("Sign up with Xelorra ID" -> adds prompt=create)
const signUp = await xelorra.buildSignUpUrl({
  scopes: ["profile.read", "passport.read", "email.read"],
  loginHint: "adaeze.4821",
});
```

### React

```tsx
import { XelorraSignInButton, XelorraSignUpButton } from "@xelorra/identity/react";

export function LoginCard() {
  return (
    <div>
      <XelorraSignInButton theme="dark" variant="solid" />
      <XelorraSignUpButton theme="dark" variant="outline" />
    </div>
  );
}
```

### PHP

```php
// Sign In
$signIn = $client->buildSignInUrl();

// Sign Up (prompt=create)
$signUp = $client->buildSignUpUrl(['loginHint' => 'adaeze.4821']);
```

### Python

```python
# Sign In
sign_in_url, sign_in_pkce = client.build_sign_in_url()

# Sign Up (prompt=create)
sign_up_url, sign_up_pkce = client.build_sign_up_url(login_hint="adaeze.4821")
```

### Go

```go
// Sign In
signInURL, signInPKCE, err := client.BuildSignInURL(nil)

// Sign Up (prompt=create)
signUpURL, signUpPKCE, err := client.BuildSignUpURL(&xelorra.AuthorizeOptions{
    LoginHint: "adaeze.4821",
})
```

## 3. Refresh Token Rotation & Family Reuse Detection

Xelorra One issues **single-use rotating refresh tokens** from `POST /oauth/token`:

1. Every refresh request (`grant_type=refresh_token`) returns a brand-new `access_token` and a brand-new `refresh_token`.
2. Immediately replace the stored `refresh_token` in your database before making another refresh call.
3. If an old, already-rotated refresh token is replayed, Xelorra One detects token family reuse and invalidates the entire token family to protect the member. When this happens, clear the local session and ask the user to sign in again.

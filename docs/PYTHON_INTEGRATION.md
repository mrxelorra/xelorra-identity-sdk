# Python Integration Guide (FastAPI, Django, Flask)

The official Python SDK (`packages/python`, PyPI package `xelorra-identity`) supports **Python 3.10+** with zero external runtime dependencies.

## Installation

```bash
pip install xelorra-identity
```

## Core Client Setup

```python
import os
from xelorra_identity import XELORRA_SCOPES, XelorraClient

client = XelorraClient(
    client_id=os.environ["XELORRA_CLIENT_ID"],
    client_secret=os.getenv("XELORRA_CLIENT_SECRET"),
    redirect_uri=os.environ["XELORRA_REDIRECT_URI"],
    scopes=[
        XELORRA_SCOPES["PROFILE_READ"],
        XELORRA_SCOPES["PASSPORT_READ"],
        XELORRA_SCOPES["EMAIL_READ"],
    ],
)
```

## Complete Flow Example

```python
from xelorra_identity import (
    XelorraAccessRevokedError,
    XelorraInsufficientScopeError,
)

# 1. Start Sign In or Sign Up (prompt=create)
sign_in_url, pkce = client.build_sign_in_url()
sign_up_url, signup_pkce = client.build_sign_up_url()

# 2. Exchange authorization code on callback
tokens = client.exchange_code(code=code, code_verifier=stored_verifier)

# 3. Fetch user claims (key your local user table by user["sub"])
try:
    user = client.get_userinfo(tokens["access_token"])
except XelorraAccessRevokedError:
    # Clear local session
    pass

# 4. Verify Reusable KYC assertion
try:
    kyc = client.verify_kyc_assertion(tokens["access_token"])
except XelorraInsufficientScopeError:
    # Request kyc.assertion.read scope
    pass

# 5. Introspect active connection and revoke on local disconnect
if not client.is_user_connected(tokens["access_token"]):
    # Connection was revoked on Xelorra One
    pass

client.revoke_token(tokens["refresh_token"])
```

## Webhook Verification in Python

Always pass the **raw request bytes** (`await request.body()` in FastAPI, `request.body` in Django, `request.get_data(cache=False)` in Flask) to `parse_webhook_event()`:

```python
from xelorra_identity import (
    HEADER_SIGNATURE,
    XelorraWebhookSignatureError,
    parse_webhook_event,
)

try:
    event = parse_webhook_event(
        raw_body=raw_bytes,
        signature_header=headers.get(HEADER_SIGNATURE),
        signing_secret=os.environ["XELORRA_WEBHOOK_SECRET"],
        tolerance_seconds=300,
    )
except XelorraWebhookSignatureError as exc:
    # Return HTTP 401
    print(exc.code, exc)
```

## Copy-Ready Framework Examples

- **FastAPI**: `packages/python/examples/fastapi_app.py`
- **Django**: `packages/python/examples/django_views.py`
- **Flask**: `packages/python/examples/flask_app.py`

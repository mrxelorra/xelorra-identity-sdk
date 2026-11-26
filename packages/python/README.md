# `xelorra-identity` (Python 3.10+)

Official zero-dependency Python SDK for **Xelorra Identity** (`https://one.xelorra.app`).

## Installation

```bash
pip install xelorra-identity
```

## Quick Start

```python
import os
from xelorra_identity import XELORRA_SCOPES, XelorraClient

client = XelorraClient(
    client_id=os.environ["XELORRA_CLIENT_ID"],
    client_secret=os.getenv("XELORRA_CLIENT_SECRET"),
    redirect_uri="https://your-app.com/auth/xelorra/callback",
    scopes=[
        XELORRA_SCOPES["PROFILE_READ"],
        XELORRA_SCOPES["PASSPORT_READ"],
        XELORRA_SCOPES["EMAIL_READ"],
    ],
)

sign_in_url, sign_in_pkce = client.build_sign_in_url()
sign_up_url, sign_up_pkce = client.build_sign_up_url()
```

## Framework Examples

- `examples/fastapi_app.py`
- `examples/django_views.py`
- `examples/flask_app.py`

## Running Tests

```bash
python3 -m unittest discover -s tests -v
# or
pytest
```

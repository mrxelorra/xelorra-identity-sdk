"""Official Python 3.10+ SDK for Xelorra Identity (https://one.xelorra.app)."""

from .client import (
    XelorraClient,
    build_sign_in_url,
    build_sign_up_url,
    exchange_code,
    get_userinfo,
    introspect_token,
    refresh_tokens,
    revoke_token,
    verify_kyc_assertion,
    verify_passport_token,
)
from .constants import (
    DEFAULT_ISSUER,
    DEFAULT_SCOPES,
    DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    HEADER_EVENT,
    HEADER_EVENT_ID,
    HEADER_SIGNATURE,
    XELORRA_SCOPES,
    XELORRA_WEBHOOK_EVENTS,
)
from .errors import (
    XelorraAccessRevokedError,
    XelorraAuthError,
    XelorraError,
    XelorraInsufficientScopeError,
    XelorraWebhookSignatureError,
)
from .pkce import PkcePair, base64url_encode, generate_pkce_pair
from .webhooks import (
    create_webhook_signature_header,
    parse_webhook_event,
    verify_webhook_signature,
)

__all__ = [
    "DEFAULT_ISSUER",
    "DEFAULT_SCOPES",
    "DEFAULT_WEBHOOK_TOLERANCE_SECONDS",
    "HEADER_EVENT",
    "HEADER_EVENT_ID",
    "HEADER_SIGNATURE",
    "PkcePair",
    "XELORRA_SCOPES",
    "XELORRA_WEBHOOK_EVENTS",
    "XelorraAccessRevokedError",
    "XelorraAuthError",
    "XelorraClient",
    "XelorraError",
    "XelorraInsufficientScopeError",
    "XelorraWebhookSignatureError",
    "base64url_encode",
    "build_sign_in_url",
    "build_sign_up_url",
    "create_webhook_signature_header",
    "exchange_code",
    "generate_pkce_pair",
    "get_userinfo",
    "introspect_token",
    "parse_webhook_event",
    "refresh_tokens",
    "revoke_token",
    "verify_kyc_assertion",
    "verify_passport_token",
    "verify_webhook_signature",
]

"""Timing-safe HMAC-SHA256 webhook signature verification with replay protection."""

import hashlib
import hmac
import json
import re
import time
from typing import Any

from .constants import DEFAULT_WEBHOOK_TOLERANCE_SECONDS
from .errors import XelorraWebhookSignatureError

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DIGITS_RE = re.compile(r"^\d+$")


def _body_to_str(raw_body: str | bytes) -> str:
    if isinstance(raw_body, bytes):
        return raw_body.decode("utf-8")
    return raw_body


def _parse_signature_header(header: str) -> tuple[int, str, list[str]] | None:
    raw_timestamp: str | None = None
    signatures: list[str] = []

    for segment in header.split(","):
        part = segment.strip()
        if not part:
            continue
        if "=" not in part:
            return None
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            return None

        if key == "t":
            if raw_timestamp is not None or not _DIGITS_RE.match(value):
                return None
            raw_timestamp = value
        elif key == "v1":
            if not _HEX64_RE.match(value):
                return None
            signatures.append(value.lower())

    if raw_timestamp is None or not signatures:
        return None

    timestamp = int(raw_timestamp)
    if timestamp <= 0:
        return None

    return timestamp, raw_timestamp, signatures


def create_webhook_signature_header(
    raw_body: str | bytes,
    signing_secret: str,
    timestamp_seconds: int | None = None,
) -> str:
    """Create a `t=<unix_seconds>,v1=<hmac_sha256_hex>` signature header for testing."""
    if not signing_secret:
        raise XelorraWebhookSignatureError(
            "missing_webhook_secret",
            "signing_secret is required to compute a webhook signature.",
        )

    ts = int(time.time()) if timestamp_seconds is None else int(timestamp_seconds)
    signed_payload = f"{ts}.{_body_to_str(raw_body)}".encode("utf-8")
    digest = hmac.new(
        signing_secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()
    return f"t={ts},v1={digest}"


def _assert_valid_signature(
    raw_body: str | bytes,
    signature_header: str | None,
    signing_secret: str,
    tolerance_seconds: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    now_seconds: int | None = None,
) -> None:
    if not signing_secret:
        raise XelorraWebhookSignatureError(
            "missing_webhook_secret",
            "signing_secret is required to verify Xelorra webhooks.",
        )

    if not signature_header or not signature_header.strip():
        raise XelorraWebhookSignatureError(
            "missing_signature",
            "Missing X-Xelorra-Signature header.",
        )

    parsed = _parse_signature_header(signature_header.strip())
    if parsed is None:
        raise XelorraWebhookSignatureError(
            "malformed_signature",
            "X-Xelorra-Signature must follow 't=<unix_timestamp>,v1=<hmac_sha256_hex>'.",
        )

    timestamp, raw_timestamp, signatures = parsed
    now = int(time.time()) if now_seconds is None else int(now_seconds)

    if tolerance_seconds > 0 and abs(now - timestamp) > tolerance_seconds:
        raise XelorraWebhookSignatureError(
            "expired_timestamp",
            f"Webhook timestamp is outside the allowed {tolerance_seconds}s tolerance window.",
        )

    signed_payload = f"{raw_timestamp}.{_body_to_str(raw_body)}".encode("utf-8")
    expected_hex = hmac.new(
        signing_secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    matched = False
    for candidate in signatures:
        if hmac.compare_digest(expected_hex, candidate):
            matched = True

    if not matched:
        raise XelorraWebhookSignatureError(
            "invalid_signature",
            "X-Xelorra-Signature verification failed.",
        )


def verify_webhook_signature(
    raw_body: str | bytes,
    signature_header: str | None,
    signing_secret: str,
    tolerance_seconds: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    now_seconds: int | None = None,
) -> bool:
    """Verify `X-Xelorra-Signature` using `hmac.compare_digest` and timestamp tolerance."""
    try:
        _assert_valid_signature(
            raw_body=raw_body,
            signature_header=signature_header,
            signing_secret=signing_secret,
            tolerance_seconds=tolerance_seconds,
            now_seconds=now_seconds,
        )
        return True
    except XelorraWebhookSignatureError:
        return False


def parse_webhook_event(
    raw_body: str | bytes,
    signature_header: str | None,
    signing_secret: str,
    tolerance_seconds: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    now_seconds: int | None = None,
) -> dict[str, Any]:
    """Verify the signature and parse the JSON webhook event envelope."""
    _assert_valid_signature(
        raw_body=raw_body,
        signature_header=signature_header,
        signing_secret=signing_secret,
        tolerance_seconds=tolerance_seconds,
        now_seconds=now_seconds,
    )

    try:
        decoded = json.loads(_body_to_str(raw_body))
    except json.JSONDecodeError as exc:
        raise XelorraWebhookSignatureError(
            "invalid_payload",
            "Webhook payload is not valid JSON.",
        ) from exc

    if (
        not isinstance(decoded, dict)
        or not isinstance(decoded.get("type"), str)
        or not isinstance(decoded.get("data"), dict)
    ):
        raise XelorraWebhookSignatureError(
            "invalid_payload",
            "Webhook payload must be a JSON object with string 'type' and object 'data'.",
        )

    return decoded

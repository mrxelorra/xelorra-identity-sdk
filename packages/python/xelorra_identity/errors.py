"""Typed exception hierarchy for the Xelorra Identity Python SDK."""

from typing import Any


class XelorraError(Exception):
    """Base error raised by xelorra-identity."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


class XelorraAuthError(XelorraError):
    """Raised when an OAuth 2.0, OIDC, or authenticated Xelorra API request fails."""


class XelorraAccessRevokedError(XelorraAuthError):
    """Raised when Xelorra One returns HTTP 401 with error='access_revoked'."""

    def __init__(
        self,
        message: str = "The user has revoked this application's access on Xelorra One.",
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__("access_revoked", message, status=401, details=details)
        self.reason = reason


class XelorraInsufficientScopeError(XelorraAuthError):
    """Raised when Xelorra One returns HTTP 403 with error='insufficient_scope'."""

    def __init__(
        self,
        message: str = "The access token does not include the required scope.",
        required_scopes: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__("insufficient_scope", message, status=403, details=details)
        self.required_scopes = required_scopes or []


class XelorraWebhookSignatureError(XelorraError):
    """Raised when incoming webhook signature verification or JSON parsing fails."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status=401)

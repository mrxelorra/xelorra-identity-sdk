"""Xelorra Identity OAuth 2.0, OIDC, PKCE S256, KYC, and Passport client."""

from __future__ import annotations

import json
from typing import Any, Callable, Sequence
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from .constants import DEFAULT_ISSUER, DEFAULT_SCOPES
from .errors import (
    XelorraAccessRevokedError,
    XelorraAuthError,
    XelorraInsufficientScopeError,
)
from .pkce import PkcePair, generate_pkce_pair

HttpTransport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, str]]


def _normalize_issuer(issuer: str | None = None, base_url: str | None = None) -> str:
    raw = (issuer or base_url or DEFAULT_ISSUER).strip().rstrip("/")
    parsed = urllib_parse.urlparse(raw)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise XelorraAuthError("invalid_config", "issuer / base_url must be a valid http(s) URL.")
    return raw


class XelorraClient:
    """Zero-dependency Python 3.10+ client for https://one.xelorra.app."""

    def __init__(
        self,
        client_id: str,
        redirect_uri: str | None = None,
        client_secret: str | None = None,
        issuer: str | None = None,
        base_url: str | None = None,
        scopes: Sequence[str] | None = None,
        timeout_seconds: float = 15.0,
        http_transport: HttpTransport | None = None,
    ) -> None:
        if not client_id or not client_id.strip():
            raise XelorraAuthError("invalid_config", "client_id is required.")

        self.client_id = client_id.strip()
        self.redirect_uri = redirect_uri.strip() if redirect_uri and redirect_uri.strip() else None
        self.client_secret = (
            client_secret.strip() if client_secret and client_secret.strip() else None
        )
        self.issuer = _normalize_issuer(issuer, base_url)
        self.base_url = self.issuer
        self.scopes = list(scopes) if scopes else list(DEFAULT_SCOPES)
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self._http_transport = http_transport

    def _resolve_redirect_uri(self, override: str | None = None) -> str:
        resolved = (override or self.redirect_uri or "").strip()
        if not resolved:
            raise XelorraAuthError(
                "invalid_config",
                "redirect_uri is required for OAuth authorization and code exchange.",
            )
        return resolved

    def _send_http(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> tuple[int, str]:
        if self._http_transport is not None:
            return self._http_transport(method, url, headers, body)

        req = urllib_request.Request(url=url, data=body, headers=headers, method=method)
        try:
            with urllib_request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return int(resp.status), resp.read().decode("utf-8")
        except urllib_error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            return int(exc.code), raw
        except urllib_error.URLError as exc:
            raise XelorraAuthError(
                "network_error",
                f"HTTP request to Xelorra failed: {exc.reason}",
            ) from exc

    def _request_json(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        allow_invalid_passport_response: bool = False,
    ) -> dict[str, Any]:
        url = f"{self.issuer}{path}"
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        encoded_body: bytes | None = None
        if json_body is not None:
            req_headers["Content-Type"] = "application/json"
            encoded_body = json.dumps(json_body).encode("utf-8")

        status, raw_body = self._send_http(method, url, req_headers, encoded_body)
        decoded: dict[str, Any] = {}
        if raw_body.strip():
            try:
                parsed = json.loads(raw_body)
                if isinstance(parsed, dict):
                    decoded = parsed
            except json.JSONDecodeError:
                decoded = {}

        if 200 <= status < 300:
            return decoded

        if allow_invalid_passport_response and isinstance(decoded.get("valid"), bool):
            return decoded

        err_code = str(decoded.get("error") or "request_failed")
        err_message = str(
            decoded.get("error_description")
            or decoded.get("message")
            or "Xelorra API request failed."
        )

        if status == 401 and err_code == "access_revoked":
            reason = decoded.get("reason")
            raise XelorraAccessRevokedError(
                message=err_message,
                reason=reason if isinstance(reason, str) else None,
                details=decoded,
            )

        if status == 403 and err_code == "insufficient_scope":
            required = decoded.get("required_scopes")
            raise XelorraInsufficientScopeError(
                message=err_message,
                required_scopes=[str(s) for s in required] if isinstance(required, list) else [],
                details=decoded,
            )

        raise XelorraAuthError(err_code, err_message, status=status, details=decoded)

    def fetch_discovery(self) -> dict[str, Any]:
        """Fetch GET /.well-known/openid-configuration."""
        return self._request_json("GET", "/.well-known/openid-configuration")

    def fetch_jwks(self) -> dict[str, Any]:
        """Fetch GET /.well-known/jwks.json."""
        return self._request_json("GET", "/.well-known/jwks.json")

    def build_authorize_url(
        self,
        *,
        scopes: Sequence[str] | None = None,
        state: str | None = None,
        pkce: PkcePair | None = None,
        redirect_uri: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> tuple[str, PkcePair]:
        """Build an OAuth 2.0 + PKCE S256 authorization URL targeting GET /oauth/authorize."""
        resolved_redirect = self._resolve_redirect_uri(redirect_uri)
        pair = pkce or generate_pkce_pair()
        final_state = state or pair.state
        final_scopes = list(scopes) if scopes else list(self.scopes)

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": resolved_redirect,
            "scope": " ".join(final_scopes),
            "state": final_state,
            "code_challenge": pair.code_challenge,
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint
        if extra_params:
            params.update(extra_params)

        final_pair = PkcePair(
            code_verifier=pair.code_verifier,
            code_challenge=pair.code_challenge,
            code_challenge_method="S256",
            state=final_state,
        )
        url = f"{self.issuer}/oauth/authorize?{urllib_parse.urlencode(params)}"
        return url, final_pair

    def build_sign_in_url(self, **kwargs: Any) -> tuple[str, PkcePair]:
        """Build a Sign In authorization URL with PKCE S256."""
        return self.build_authorize_url(**kwargs)

    def build_sign_up_url(self, **kwargs: Any) -> tuple[str, PkcePair]:
        """Build a Sign Up authorization URL (`prompt=create`) with PKCE S256."""
        kwargs["prompt"] = "create"
        return self.build_authorize_url(**kwargs)

    def exchange_code(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        """Exchange an authorization code and PKCE code_verifier via POST /oauth/token."""
        if not code.strip():
            raise XelorraAuthError("missing_code", "Authorization code is required.")
        if not code_verifier.strip():
            raise XelorraAuthError("missing_pkce_verifier", "code_verifier is required.")

        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code.strip(),
            "client_id": self.client_id,
            "redirect_uri": self._resolve_redirect_uri(redirect_uri),
            "code_verifier": code_verifier.strip(),
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        return self._request_json("POST", "/oauth/token", json_body=payload)

    def refresh_tokens(
        self,
        refresh_token: str,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Rotate a single-use refresh token via POST /oauth/token."""
        if not refresh_token.strip():
            raise XelorraAuthError("missing_refresh_token", "refresh_token is required.")

        payload: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token.strip(),
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        if scope and scope.strip():
            payload["scope"] = scope.strip()

        return self._request_json("POST", "/oauth/token", json_body=payload)

    def get_userinfo(self, access_token: str) -> dict[str, Any]:
        """Load granted identity claims from GET /oauth/userinfo."""
        if not access_token.strip():
            raise XelorraAuthError("unauthenticated", "access_token is required.")
        return self._request_json(
            "GET",
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token.strip()}"},
        )

    def introspect_token(self, access_token: str) -> dict[str, Any]:
        """Introspect an access token via POST /oauth/introspect."""
        if not access_token.strip():
            return {"active": False, "connected": False, "reason": "missing_token"}

        payload: dict[str, str] = {
            "token": access_token.strip(),
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        body = self._request_json("POST", "/oauth/introspect", json_body=payload)
        active = bool(body.get("active", False))
        connected = bool(body["connected"]) if "connected" in body else active
        body["active"] = active
        body["connected"] = connected
        return body

    def is_user_connected(self, access_token: str) -> bool:
        """Return True only when POST /oauth/introspect confirms active and connected."""
        result = self.introspect_token(access_token)
        return bool(result.get("active")) and bool(result.get("connected"))

    def revoke_token(self, token: str) -> dict[str, Any]:
        """Revoke an access or refresh token via POST /oauth/revoke (RFC 7009)."""
        if not token.strip():
            return {"revoked": True}

        payload: dict[str, str] = {
            "token": token.strip(),
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        body = self._request_json("POST", "/oauth/revoke", json_body=payload)
        return {"revoked": bool(body.get("revoked", True))}

    def logout(self, access_token: str | None = None) -> dict[str, Any]:
        """Revoke the token (when provided) and end the session via POST /oauth/logout."""
        headers: dict[str, str] = {}
        if access_token and access_token.strip():
            self.revoke_token(access_token)
            headers["Authorization"] = f"Bearer {access_token.strip()}"

        body = self._request_json(
            "POST",
            "/oauth/logout",
            headers=headers,
            json_body={"client_id": self.client_id},
        )
        return {
            "loggedOut": bool(body.get("loggedOut", True)),
            "message": body.get("message"),
        }

    def verify_kyc_assertion(self, access_token: str) -> dict[str, Any]:
        """Retrieve a Reusable KYC assertion via POST /api/v1/verify/assertion."""
        if not access_token.strip():
            raise XelorraAuthError("unauthenticated", "access_token is required.")

        return self._request_json(
            "POST",
            "/api/v1/verify/assertion",
            headers={"Authorization": f"Bearer {access_token.strip()}"},
            json_body={},
        )

    def verify_passport_token(self, token: str, *, selective: bool = False) -> dict[str, Any]:
        """Verify a rotating Digital Passport QR token without authentication."""
        if not token.strip():
            raise XelorraAuthError("invalid_token", "Passport QR token is required.")

        encoded = urllib_parse.quote(token.strip(), safe="")
        path = f"/api/v1/verify/{encoded}" if selective else f"/api/v1/public/verify/{encoded}"
        return self._request_json("GET", path, allow_invalid_passport_response=True)

    def check_xid_availability(self, username: str) -> dict[str, Any]:
        """Check memorable XID handle availability via GET /api/v1/xid/check?username=..."""
        if not username.strip():
            raise XelorraAuthError("invalid_request", "username is required.")

        query = urllib_parse.urlencode({"username": username.strip()})
        return self._request_json("GET", f"/api/v1/xid/check?{query}")


def build_sign_in_url(client_id: str, redirect_uri: str, **kwargs: Any) -> tuple[str, PkcePair]:
    issuer = kwargs.pop("issuer", None)
    base_url = kwargs.pop("base_url", None)
    return XelorraClient(
        client_id=client_id,
        redirect_uri=redirect_uri,
        issuer=issuer,
        base_url=base_url,
    ).build_sign_in_url(**kwargs)


def build_sign_up_url(client_id: str, redirect_uri: str, **kwargs: Any) -> tuple[str, PkcePair]:
    issuer = kwargs.pop("issuer", None)
    base_url = kwargs.pop("base_url", None)
    return XelorraClient(
        client_id=client_id,
        redirect_uri=redirect_uri,
        issuer=issuer,
        base_url=base_url,
    ).build_sign_up_url(**kwargs)


def exchange_code(
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    *,
    client_secret: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(
        client_id=client_id,
        redirect_uri=redirect_uri,
        client_secret=client_secret,
        issuer=issuer,
    ).exchange_code(code, code_verifier)


def refresh_tokens(
    client_id: str,
    refresh_token: str,
    *,
    client_secret: str | None = None,
    issuer: str | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
    ).refresh_tokens(refresh_token, scope=scope)


def get_userinfo(
    access_token: str,
    *,
    client_id: str = "public",
    issuer: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(client_id=client_id, issuer=issuer).get_userinfo(access_token)


def introspect_token(
    client_id: str,
    access_token: str,
    *,
    client_secret: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
    ).introspect_token(access_token)


def revoke_token(
    client_id: str,
    token: str,
    *,
    client_secret: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
    ).revoke_token(token)


def verify_kyc_assertion(
    access_token: str,
    *,
    client_id: str = "public",
    issuer: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(client_id=client_id, issuer=issuer).verify_kyc_assertion(access_token)


def verify_passport_token(
    token: str,
    *,
    selective: bool = False,
    issuer: str | None = None,
) -> dict[str, Any]:
    return XelorraClient(client_id="public", issuer=issuer).verify_passport_token(
        token,
        selective=selective,
    )

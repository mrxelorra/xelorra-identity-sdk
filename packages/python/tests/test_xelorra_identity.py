"""Comprehensive unit tests for the xelorra-identity Python SDK."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Allow running directly via `python3 -m unittest` without editable install
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from xelorra_identity import (  # noqa: E402
    XELORRA_SCOPES,
    XELORRA_WEBHOOK_EVENTS,
    XelorraAccessRevokedError,
    XelorraClient,
    XelorraInsufficientScopeError,
    XelorraWebhookSignatureError,
    base64url_encode,
    create_webhook_signature_header,
    generate_pkce_pair,
    parse_webhook_event,
    verify_webhook_signature,
)


class XelorraIdentityPythonTest(unittest.TestCase):
    def test_catalog_constants_complete(self) -> None:
        self.assertEqual(len(XELORRA_SCOPES), 14)
        self.assertEqual(len(XELORRA_WEBHOOK_EVENTS), 11)
        self.assertEqual(XELORRA_SCOPES["KYC_ASSERTION_READ"], "kyc.assertion.read")
        self.assertEqual(XELORRA_WEBHOOK_EVENTS["USER_ACCESS_REVOKED"], "user.access_revoked")

    def test_pkce_s256_unpadded_challenge(self) -> None:
        pair = generate_pkce_pair()
        self.assertEqual(pair.code_challenge_method, "S256")
        self.assertGreaterEqual(len(pair.code_verifier), 43)
        self.assertNotIn("=", pair.code_verifier)
        self.assertNotIn("=", pair.code_challenge)

        expected = base64url_encode(hashlib.sha256(pair.code_verifier.encode("ascii")).digest())
        self.assertEqual(pair.code_challenge, expected)

    def test_build_sign_in_and_sign_up_urls(self) -> None:
        client = XelorraClient(
            client_id="acme-py-app",
            redirect_uri="https://acme.example.com/auth/callback",
            scopes=[XELORRA_SCOPES["PROFILE_READ"], XELORRA_SCOPES["EMAIL_READ"]],
        )

        sign_in_url, sign_in_pkce = client.build_sign_in_url()
        parsed_in = urlparse(sign_in_url)
        q_in = parse_qs(parsed_in.query)
        self.assertEqual(parsed_in.scheme, "https")
        self.assertEqual(parsed_in.netloc, "one.xelorra.app")
        self.assertEqual(parsed_in.path, "/oauth/authorize")
        self.assertEqual(q_in["code_challenge_method"], ["S256"])
        self.assertEqual(q_in["code_challenge"], [sign_in_pkce.code_challenge])
        self.assertNotIn("prompt", q_in)

        sign_up_url, _ = client.build_sign_up_url(login_hint="adaeze.4821")
        q_up = parse_qs(urlparse(sign_up_url).query)
        self.assertEqual(q_up["prompt"], ["create"])
        self.assertEqual(q_up["login_hint"], ["adaeze.4821"])

    def test_oauth_flow_kyc_passport_and_xid_check(self) -> None:
        def mock_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> tuple[int, str]:
            if url.endswith("/.well-known/openid-configuration"):
                return 200, json.dumps({
                    "issuer": "https://one.xelorra.app",
                    "code_challenge_methods_supported": ["S256"],
                })
            if url.endswith("/.well-known/jwks.json"):
                return 200, json.dumps({"keys": [{"kty": "RSA", "kid": "k1"}]})
            if url.endswith("/oauth/token"):
                payload = json.loads((body or b"{}").decode("utf-8"))
                if payload.get("grant_type") == "authorization_code":
                    return 200, json.dumps({
                        "access_token": "xc_at_py_1",
                        "refresh_token": "xlr_rt_py_1",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": "profile.read kyc.assertion.read",
                        "xid": "XLR-9284-1039",
                    })
                return 200, json.dumps({
                    "access_token": "xc_at_py_2",
                    "refresh_token": "xlr_rt_py_2",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "profile.read kyc.assertion.read",
                })
            if url.endswith("/oauth/userinfo"):
                return 200, json.dumps({"sub": "xapp_py_1", "name": "Adaeze Okafor"})
            if url.endswith("/oauth/introspect"):
                return 200, json.dumps({
                    "active": True,
                    "connected": True,
                    "client_id": "acme-py-app",
                    "sub": "xapp_py_1",
                    "xid": "XLR-9284-1039",
                    "scope": "profile.read kyc.assertion.read",
                    "exp": 1900000000,
                })
            if url.endswith("/api/v1/verify/assertion") and method == "POST":
                return 200, json.dumps({
                    "verification_status": "verified",
                    "verification_type": "government_identity",
                    "verification_reference": "xvr_py_1234",
                    "verified_at": "2026-11-26T00:00:00Z",
                    "credential_category": "bvn",
                })
            if url.endswith("/api/v1/public/verify/qr_py_1"):
                return 200, json.dumps({"valid": True, "xid": "XLR-9284-1039", "verified": True})
            if url.endswith("/api/v1/verify/qr_py_sel"):
                return 200, json.dumps({
                    "valid": True,
                    "xid": "XLR-9284-1039",
                    "sharedFields": ["xid", "verified"],
                })
            if "/api/v1/xid/check?username=adaeze" in url:
                return 200, json.dumps({"available": True})
            if url.endswith("/oauth/revoke"):
                return 200, json.dumps({"revoked": True})
            if url.endswith("/oauth/logout"):
                return 200, json.dumps({"loggedOut": True, "message": "Signed out"})
            return 404, json.dumps({"error": "not_found"})

        client = XelorraClient(
            client_id="acme-py-app",
            redirect_uri="https://acme.example.com/auth/callback",
            http_transport=mock_transport,
        )

        self.assertEqual(client.fetch_discovery()["issuer"], "https://one.xelorra.app")
        self.assertEqual(len(client.fetch_jwks()["keys"]), 1)

        tokens = client.exchange_code("xc_code", "verifier_12345")
        self.assertEqual(tokens["access_token"], "xc_at_py_1")

        user = client.get_userinfo(tokens["access_token"])
        self.assertEqual(user["sub"], "xapp_py_1")

        self.assertTrue(client.is_user_connected(tokens["access_token"]))

        kyc = client.verify_kyc_assertion(tokens["access_token"])
        self.assertEqual(kyc["verification_status"], "verified")
        self.assertEqual(kyc["credential_category"], "bvn")

        rotated = client.refresh_tokens(tokens["refresh_token"])
        self.assertEqual(rotated["access_token"], "xc_at_py_2")

        self.assertTrue(client.verify_passport_token("qr_py_1")["valid"])
        self.assertEqual(
            client.verify_passport_token("qr_py_sel", selective=True)["sharedFields"],
            ["xid", "verified"],
        )
        self.assertTrue(client.check_xid_availability("adaeze")["available"])

        self.assertTrue(client.revoke_token(rotated["access_token"])["revoked"])
        self.assertTrue(client.logout(rotated["access_token"])["loggedOut"])

    def test_revocation_and_insufficient_scope_exceptions(self) -> None:
        def error_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> tuple[int, str]:
            if url.endswith("/oauth/userinfo"):
                return 401, json.dumps({
                    "error": "access_revoked",
                    "error_description": "User disconnected this app.",
                    "reason": "user_disconnected",
                })
            return 403, json.dumps({
                "error": "insufficient_scope",
                "error_description": "Missing kyc.assertion.read scope.",
            })

        client = XelorraClient(client_id="acme-py-app", http_transport=error_transport)

        with self.assertRaises(XelorraAccessRevokedError) as revoked_ctx:
            client.get_userinfo("xc_at_revoked")
        self.assertEqual(revoked_ctx.exception.reason, "user_disconnected")
        self.assertEqual(revoked_ctx.exception.status, 401)

        with self.assertRaises(XelorraInsufficientScopeError) as scope_ctx:
            client.verify_kyc_assertion("xc_at_basic")
        self.assertEqual(scope_ctx.exception.status, 403)

    def test_webhook_signature_verification_and_replay_protection(self) -> None:
        secret = "whsec_py_secret_987654"
        now = 1764150000
        raw_body = json.dumps({
            "id": "evt_py_1",
            "type": "user.access_revoked",
            "created_at": "2026-11-26T12:00:00Z",
            "client_id": "acme-py-app",
            "data": {
                "xid": "XLR-9284-1039",
                "sub": "xapp_py_1",
                "client_id": "acme-py-app",
                "revoked_at": "2026-11-26T12:00:00Z",
                "reason": "user_disconnected",
            },
        })

        expected_hex = hmac.new(
            secret.encode("utf-8"),
            f"{now}.{raw_body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        header = create_webhook_signature_header(raw_body, secret, timestamp_seconds=now)
        self.assertEqual(header, f"t={now},v1={expected_hex}")

        # Valid inside 300s tolerance
        self.assertTrue(
            verify_webhook_signature(raw_body, header, secret, tolerance_seconds=300, now_seconds=now + 100)
        )

        # Tampered payload rejected
        tampered = raw_body.replace("acme-py-app", "evil-app")
        self.assertFalse(verify_webhook_signature(tampered, header, secret, now_seconds=now))

        # Expired timestamp rejected
        self.assertFalse(
            verify_webhook_signature(raw_body, header, secret, tolerance_seconds=300, now_seconds=now + 301)
        )

        # Malformed header rejected
        self.assertFalse(verify_webhook_signature(raw_body, f"sha256={expected_hex}", secret, now_seconds=now))

        # parse_webhook_event succeeds on valid input
        event = parse_webhook_event(raw_body, header, secret, now_seconds=now)
        self.assertEqual(event["type"], "user.access_revoked")
        self.assertEqual(event["data"]["sub"], "xapp_py_1")

        # Expired raises XelorraWebhookSignatureError with expired_timestamp
        with self.assertRaises(XelorraWebhookSignatureError) as exp_ctx:
            parse_webhook_event(raw_body, header, secret, tolerance_seconds=300, now_seconds=now + 400)
        self.assertEqual(exp_ctx.exception.code, "expired_timestamp")


if __name__ == "__main__":
    unittest.main()

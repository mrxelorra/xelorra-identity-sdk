import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import {
  ALL_XELORRA_WEBHOOK_EVENTS,
  XELORRA_SCOPES,
  XELORRA_SCOPE_CATALOG,
  XELORRA_WEBHOOK_EVENTS,
  XelorraAccessRevokedError,
  XelorraAuth,
  XelorraAuthError,
  XelorraClient,
  XelorraError,
  XelorraInsufficientScopeError,
  XelorraWebhookSignatureError,
  buildAuthorizeUrl,
  buildSignInUrl,
  buildSignUpUrl,
  checkXidAvailability,
  computeWebhookSignature,
  createDisconnectGuard,
  createPkcePair,
  exchangeCodeForTokens,
  fetchDiscovery,
  fetchJwks,
  getUserInfo,
  introspectToken,
  isUserConnected,
  logout,
  parseWebhookEvent,
  refreshTokens,
  revokeToken,
  verifyKycAssertion,
  verifyPassportToken,
  verifyWebhookSignature,
} from "./index.js";
import * as reactEntry from "./react.js";
import {
  createExpressAuthMiddleware,
  createExpressCallbackHandler,
  createExpressWebhookHandler,
  type ExpressRequestLike,
  type ExpressResponseLike,
} from "./express.js";
import {
  createNextAuthRedirectHandler,
  createNextCallbackHandler,
  createNextSessionGuard,
  createNextWebhookHandler,
} from "./next.js";

test("scope catalog and webhook event constants match the live Xelorra One contract", () => {
  assert.equal(Object.values(XELORRA_SCOPES).length, 14);
  assert.equal(XELORRA_SCOPE_CATALOG.length, 14);
  assert.equal(ALL_XELORRA_WEBHOOK_EVENTS.length, 11);

  assert.equal(XELORRA_SCOPES.KYC_ASSERTION_READ, "kyc.assertion.read");
  assert.equal(XELORRA_SCOPES.GOV_NIN_VERIFY, "gov.nin.verify");
  assert.equal(XELORRA_SCOPES.GOV_BVN_VERIFY, "gov.bvn.verify");
  assert.equal(XELORRA_WEBHOOK_EVENTS.USER_ACCESS_REVOKED, "user.access_revoked");
  assert.equal(XELORRA_WEBHOOK_EVENTS.USER_ACCOUNT_SUSPENDED, "user.account_suspended");
  assert.equal(XELORRA_WEBHOOK_EVENTS.USER_PERMISSIONS_UPDATED, "user.permissions_updated");
});

test("createPkcePair produces RFC 7636 S256 verifier, unpadded challenge, and state", async () => {
  const pair = await createPkcePair();
  assert.equal(pair.codeChallengeMethod, "S256");
  assert.ok(pair.codeVerifier.length >= 43 && pair.codeVerifier.length <= 128);
  assert.ok(pair.codeChallenge.length >= 43);
  assert.equal(pair.codeVerifier.includes("="), false);
  assert.equal(pair.codeChallenge.includes("="), false);
  assert.notEqual(pair.codeVerifier, pair.codeChallenge);
  assert.ok(pair.state.length >= 16);

  const expectedChallenge = createHash("sha256").update(pair.codeVerifier).digest("base64url");
  assert.equal(pair.codeChallenge, expectedChallenge);
});

test("XelorraClient builds authorize, sign-in, and prompt=create sign-up URLs with issuer or baseUrl", async () => {
  const client = new XelorraClient({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
    scopes: [
      XELORRA_SCOPES.PROFILE_READ,
      XELORRA_SCOPES.EMAIL_READ,
      XELORRA_SCOPES.KYC_ASSERTION_READ,
    ],
  });

  assert.equal(client.issuer, "https://one.xelorra.app");
  assert.equal(client.baseUrl, "https://one.xelorra.app");

  const customClient = new XelorraClient({
    clientId: "staging-app",
    baseUrl: "https://staging.one.xelorra.app/",
    redirectUri: "https://staging.example.com/callback",
  });
  assert.equal(customClient.issuer, "https://staging.one.xelorra.app");

  const { url: signInUrl, pkce } = await client.buildSignInUrl();
  const parsedSignIn = new URL(signInUrl);
  assert.equal(parsedSignIn.origin, "https://one.xelorra.app");
  assert.equal(parsedSignIn.pathname, "/oauth/authorize");
  assert.equal(parsedSignIn.searchParams.get("response_type"), "code");
  assert.equal(parsedSignIn.searchParams.get("client_id"), "acme-app");
  assert.equal(
    parsedSignIn.searchParams.get("redirect_uri"),
    "https://acme.example.com/auth/callback",
  );
  assert.equal(parsedSignIn.searchParams.get("code_challenge"), pkce.codeChallenge);
  assert.equal(parsedSignIn.searchParams.get("code_challenge_method"), "S256");
  assert.equal(
    parsedSignIn.searchParams.get("scope"),
    "profile.read email.read kyc.assertion.read",
  );
  assert.equal(parsedSignIn.searchParams.get("prompt"), null);

  const { url: signUpUrl } = await client.buildSignUpUrl({ loginHint: "adaeze.4821" });
  const parsedSignUp = new URL(signUpUrl);
  assert.equal(parsedSignUp.origin, "https://one.xelorra.app");
  assert.equal(parsedSignUp.pathname, "/oauth/authorize");
  assert.equal(parsedSignUp.searchParams.get("prompt"), "create");
  assert.equal(parsedSignUp.searchParams.get("login_hint"), "adaeze.4821");
  assert.equal(parsedSignUp.searchParams.get("code_challenge_method"), "S256");

  // Standalone functional helpers
  const fnSignUp = await buildSignUpUrl({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
  });
  assert.equal(new URL(fnSignUp.url).searchParams.get("prompt"), "create");

  const fnSignIn = await buildSignInUrl({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
  });
  assert.equal(new URL(fnSignIn.url).searchParams.get("prompt"), null);

  const fnAuth = await buildAuthorizeUrl({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
  });
  assert.equal(new URL(fnAuth.url).searchParams.get("code_challenge_method"), "S256");
});

test("discovery, JWKS, public passport QR verification, selective verify, and XID check", async () => {
  const requests: string[] = [];
  const mockFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    requests.push(`${init?.method || "GET"} ${url}`);

    if (url.endsWith("/.well-known/openid-configuration")) {
      return new Response(
        JSON.stringify({
          issuer: "https://one.xelorra.app",
          authorization_endpoint: "https://one.xelorra.app/oauth/authorize",
          token_endpoint: "https://one.xelorra.app/oauth/token",
          userinfo_endpoint: "https://one.xelorra.app/oauth/userinfo",
          introspection_endpoint: "https://one.xelorra.app/oauth/introspect",
          revocation_endpoint: "https://one.xelorra.app/oauth/revoke",
          end_session_endpoint: "https://one.xelorra.app/oauth/logout",
          jwks_uri: "https://one.xelorra.app/.well-known/jwks.json",
          scopes_supported: Object.values(XELORRA_SCOPES),
          code_challenge_methods_supported: ["S256"],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/.well-known/jwks.json")) {
      return new Response(
        JSON.stringify({
          keys: [{ kty: "RSA", kid: "xlr-key-1", use: "sig", alg: "RS256" }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/api/v1/public/verify/qr_tok_abc")) {
      return new Response(
        JSON.stringify({
          valid: true,
          xid: "XLR-9284-1039",
          name: "Adaeze Okafor",
          tier: "verified",
          status: "active",
          verified: true,
          checkedAt: "2026-11-26T12:00:00.000Z",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/api/v1/verify/qr_tok_sel")) {
      return new Response(
        JSON.stringify({
          valid: true,
          xid: "XLR-9284-1039",
          name: "Adaeze Okafor",
          tier: "verified",
          status: "active",
          verified: true,
          memberSince: "2025-01-15",
          mode: "selective",
          expiresAt: "2026-11-26T12:05:00.000Z",
          checkedAt: "2026-11-26T12:00:00.000Z",
          sharedFields: ["xid", "name", "verified"],
          disclaimer: "Zero PII selective verification.",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.includes("/api/v1/xid/check?username=adaeze")) {
      return new Response(
        JSON.stringify({
          available: false,
          suggestions: ["adaeze.4821", "adaeze.9042"],
          reason: "taken",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    return new Response(null, { status: 404 });
  };

  const discovery = await fetchDiscovery({ fetchImpl: mockFetch });
  assert.equal(discovery.issuer, "https://one.xelorra.app");
  assert.deepEqual(discovery.code_challenge_methods_supported, ["S256"]);

  const jwks = await fetchJwks({ fetchImpl: mockFetch });
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0]?.kid, "xlr-key-1");

  const pubResult = await verifyPassportToken("qr_tok_abc", { fetchImpl: mockFetch });
  assert.equal(pubResult.valid, true);
  assert.equal(pubResult.xid, "XLR-9284-1039");

  const selResult = await verifyPassportToken("qr_tok_sel", {
    endpoint: "selective",
    fetchImpl: mockFetch,
  });
  assert.equal(selResult.valid, true);
  assert.deepEqual(selResult.sharedFields, ["xid", "name", "verified"]);

  const xidCheck = await checkXidAvailability("adaeze", { fetchImpl: mockFetch });
  assert.equal(xidCheck.available, false);
  assert.deepEqual(xidCheck.suggestions, ["adaeze.4821", "adaeze.9042"]);

  const client = new XelorraClient({ clientId: "acme-app", fetchImpl: mockFetch });
  assert.equal((await client.fetchDiscovery()).issuer, "https://one.xelorra.app");
  assert.equal((await client.fetchJwks()).keys.length, 1);
  assert.equal((await client.verifyPassportToken("qr_tok_abc")).valid, true);
  assert.equal((await client.checkXidAvailability("adaeze")).available, false);
  assert.equal(requests.length, 9);
});

test("XelorraClient exchanges code, fetches userinfo, introspects, verifies KYC assertion, refreshes, revokes, and logs out", async () => {
  const calls: string[] = [];
  const mockFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    const method = init?.method || "GET";
    calls.push(`${method} ${url}`);

    if (url.endsWith("/oauth/token")) {
      const body = JSON.parse(String(init?.body)) as Record<string, string>;
      if (body.grant_type === "authorization_code") {
        assert.equal(body.code, "xc_code_test");
        assert.equal(body.code_verifier, "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345");
        assert.equal(body.redirect_uri, "https://acme.example.com/auth/callback");
        return new Response(
          JSON.stringify({
            access_token: "xc_at_live_token",
            refresh_token: "xlr_rt_live_refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "profile.read passport.read kyc.assertion.read",
            xid: "XLR-9284-1039",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (body.grant_type === "refresh_token") {
        assert.equal(body.refresh_token, "xlr_rt_live_refresh");
        return new Response(
          JSON.stringify({
            access_token: "xc_at_rotated_token",
            refresh_token: "xlr_rt_rotated_refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "profile.read passport.read kyc.assertion.read",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
    }

    if (url.endsWith("/oauth/userinfo")) {
      return new Response(
        JSON.stringify({
          sub: "xapp_1234567890abcdef",
          name: "Adaeze Okafor",
          verification_level: "verified",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/oauth/introspect")) {
      return new Response(
        JSON.stringify({
          active: true,
          connected: true,
          client_id: "acme-app",
          sub: "xapp_1234567890abcdef",
          xid: "XLR-9284-1039",
          scope: "profile.read passport.read kyc.assertion.read",
          exp: 1900000000,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/api/v1/verify/assertion")) {
      assert.equal(method, "POST");
      return new Response(
        JSON.stringify({
          verification_status: "verified",
          verification_type: "government_identity",
          verification_reference: "xvr_8492019482",
          verified_at: "2026-11-25T00:00:00.000Z",
          credential_category: "nin",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/oauth/revoke")) {
      const body = JSON.parse(String(init?.body)) as Record<string, string>;
      assert.ok(body.token);
      return new Response(JSON.stringify({ revoked: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (url.endsWith("/oauth/logout")) {
      return new Response(JSON.stringify({ loggedOut: true, message: "Session ended." }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
  };

  const config = {
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
    fetchImpl: mockFetch,
  };
  const client = new XelorraClient(config);

  const tokens = await client.exchangeCodeForTokens({
    code: "xc_code_test",
    codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
  });
  assert.equal(tokens.access_token, "xc_at_live_token");
  assert.equal(tokens.xid, "XLR-9284-1039");

  const user = await client.getUserInfo();
  assert.equal(user.sub, "xapp_1234567890abcdef");
  assert.equal(user.name, "Adaeze Okafor");

  const introspected = await client.introspectToken();
  assert.equal(introspected.active, true);
  assert.equal(introspected.connected, true);
  assert.equal(await client.isUserConnected(), true);

  const assertion = await client.verifyKycAssertion();
  assert.equal(assertion.verification_status, "verified");
  assert.equal(assertion.verification_type, "government_identity");
  assert.equal(assertion.verification_reference, "xvr_8492019482");
  assert.equal(assertion.credential_category, "nin");

  const rotated = await client.refreshTokens({ refreshToken: "xlr_rt_live_refresh" });
  assert.equal(rotated.access_token, "xc_at_rotated_token");

  const logoutRes = await client.logout();
  assert.equal(logoutRes.loggedOut, true);
  assert.equal(client.getAccessToken(), null);
  assert.equal(client.getCachedUser(), null);

  // Verify standalone functional helpers
  const fnTokens = await exchangeCodeForTokens(config, {
    code: "xc_code_test",
    codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
  });
  const fnUser = await getUserInfo(config, fnTokens.access_token);
  assert.equal(fnUser.sub, "xapp_1234567890abcdef");
  const fnIntrospection = await introspectToken(config, fnTokens.access_token);
  assert.equal(fnIntrospection.active, true);
  assert.equal(await isUserConnected(config, fnTokens.access_token), true);
  const fnKyc = await verifyKycAssertion(config, fnTokens.access_token);
  assert.equal(fnKyc.verification_type, "government_identity");
  const fnRefreshed = await refreshTokens(config, { refreshToken: "xlr_rt_live_refresh" });
  assert.equal(fnRefreshed.access_token, "xc_at_rotated_token");
  const fnRevoked = await revokeToken(config, fnRefreshed.access_token);
  assert.equal(fnRevoked.revoked, true);
  const fnLogout = await logout(config, fnRefreshed.access_token);
  assert.equal(fnLogout.loggedOut, true);
  assert.ok(calls.length >= 14);
});

test("getUserInfo throws XelorraAccessRevokedError on 401 access_revoked and verifyKycAssertion throws XelorraInsufficientScopeError on 403", async () => {
  const mockFetch: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/oauth/token")) {
      return new Response(
        JSON.stringify({
          access_token: "xc_at_revoked",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "profile.read",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/oauth/userinfo")) {
      return new Response(
        JSON.stringify({
          error: "access_revoked",
          error_description: "User disconnected this application on Xelorra One.",
          reason: "user_disconnected",
        }),
        { status: 401, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/api/v1/verify/assertion")) {
      return new Response(
        JSON.stringify({
          error: "insufficient_scope",
          error_description: "Token lacks kyc.assertion.read scope.",
        }),
        { status: 403, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(null, { status: 404 });
  };

  const client = new XelorraClient({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
    fetchImpl: mockFetch,
  });

  await client.exchangeCodeForTokens({
    code: "xc_code_test",
    codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
  });

  await assert.rejects(
    () => client.verifyKycAssertion(),
    (err: unknown) =>
      err instanceof XelorraInsufficientScopeError &&
      err instanceof XelorraAuthError &&
      err instanceof XelorraError &&
      err.code === "insufficient_scope" &&
      err.status === 403,
  );

  await assert.rejects(
    () => client.getUserInfo(),
    (err: unknown) =>
      err instanceof XelorraAccessRevokedError &&
      err instanceof XelorraAuthError &&
      err instanceof XelorraError &&
      err.code === "access_revoked" &&
      err.status === 401 &&
      err.reason === "user_disconnected",
  );
  assert.equal(client.getAccessToken(), null);
});

test("webhook signature verification enforces t=<ts>,v1=<hex> over '${t}.${rawBody}' and replay protection", async () => {
  const secret = "whsec_test_xelorra_secret_key_987654321";
  const nowSeconds = 1764150000;
  const payload = JSON.stringify({
    id: "evt_01JXYZ987654",
    type: "user.access_revoked",
    created_at: "2026-11-26T12:00:00.000Z",
    client_id: "acme-app",
    data: {
      xid: "XLR-9284-1039",
      sub: "xapp_1234567890abcdef",
      client_id: "acme-app",
      revoked_at: "2026-11-26T12:00:00.000Z",
      reason: "user_disconnected",
    },
  });

  const expectedHex = createHmac("sha256", secret)
    .update(`${nowSeconds}.${payload}`)
    .digest("hex");
  const validHeader = await computeWebhookSignature(payload, secret, nowSeconds);
  assert.equal(validHeader, `t=${nowSeconds},v1=${expectedHex}`);

  // Valid signature inside tolerance window
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: validHeader,
      signingSecret: secret,
      toleranceSeconds: 300,
      nowSeconds: nowSeconds + 120,
    }),
    true,
  );

  // Tampered payload fails
  const tamperedPayload = payload.replace("acme-app", "evil-app");
  assert.equal(
    await verifyWebhookSignature({
      rawBody: tamperedPayload,
      signatureHeader: validHeader,
      signingSecret: secret,
      nowSeconds,
    }),
    false,
  );

  // Wrong secret fails
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: validHeader,
      signingSecret: "wrong-secret",
      nowSeconds,
    }),
    false,
  );

  // Expired timestamp (older than 300s tolerance) fails
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: validHeader,
      signingSecret: secret,
      toleranceSeconds: 300,
      nowSeconds: nowSeconds + 301,
    }),
    false,
  );

  // Future timestamp beyond tolerance fails
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: validHeader,
      signingSecret: secret,
      toleranceSeconds: 300,
      nowSeconds: nowSeconds - 301,
    }),
    false,
  );

  // Malformed or missing headers fail
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: `sha256=${expectedHex}`,
      signingSecret: secret,
      nowSeconds,
    }),
    false,
  );
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: "t=notanumber,v1=deadbeef",
      signingSecret: secret,
      nowSeconds,
    }),
    false,
  );
  assert.equal(
    await verifyWebhookSignature({
      rawBody: payload,
      signatureHeader: "",
      signingSecret: secret,
      nowSeconds,
    }),
    false,
  );

  // parseWebhookEvent returns typed event
  const event = await parseWebhookEvent({
    rawBody: payload,
    signatureHeader: validHeader,
    signingSecret: secret,
    nowSeconds,
  });
  assert.equal(event.id, "evt_01JXYZ987654");
  assert.equal(event.type, "user.access_revoked");
  assert.equal(event.client_id, "acme-app");
  assert.equal(event.data.sub, "xapp_1234567890abcdef");

  // Typed error codes from parseWebhookEvent
  await assert.rejects(
    () =>
      parseWebhookEvent({
        rawBody: payload,
        signatureHeader: null,
        signingSecret: secret,
        nowSeconds,
      }),
    (err: unknown) =>
      err instanceof XelorraWebhookSignatureError && err.code === "missing_signature",
  );

  await assert.rejects(
    () =>
      parseWebhookEvent({
        rawBody: payload,
        signatureHeader: "malformed_header",
        signingSecret: secret,
        nowSeconds,
      }),
    (err: unknown) =>
      err instanceof XelorraWebhookSignatureError && err.code === "malformed_signature",
  );

  await assert.rejects(
    () =>
      parseWebhookEvent({
        rawBody: payload,
        signatureHeader: validHeader,
        signingSecret: secret,
        toleranceSeconds: 300,
        nowSeconds: nowSeconds + 600,
      }),
    (err: unknown) =>
      err instanceof XelorraWebhookSignatureError && err.code === "expired_timestamp",
  );

  await assert.rejects(
    () =>
      parseWebhookEvent({
        rawBody: tamperedPayload,
        signatureHeader: validHeader,
        signingSecret: secret,
        nowSeconds,
      }),
    (err: unknown) =>
      err instanceof XelorraWebhookSignatureError && err.code === "invalid_signature",
  );
});

test("createDisconnectGuard supports getAccessToken and handles introspection + 401 access_revoked", async () => {
  let isRevoked = false;
  const mockFetch: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/oauth/introspect")) {
      return new Response(
        JSON.stringify(
          isRevoked
            ? {
                active: false,
                connected: false,
                reason: "access_revoked",
              }
            : {
                active: true,
                connected: true,
                client_id: "acme-app",
                sub: "xapp_123",
                xid: "XLR-1111-2222",
                scope: "profile.read",
                exp: 1900000000,
              },
        ),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/oauth/userinfo")) {
      return new Response(
        JSON.stringify({ error: "access_revoked", reason: "user_disconnected" }),
        { status: 401, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(null, { status: 404 });
  };

  const client = new XelorraClient({ clientId: "acme-app", fetchImpl: mockFetch });
  const revokedReasons: string[] = [];

  const guard = createDisconnectGuard<{ userId: string }>({
    client,
    getAccessToken: () => "xc_at_session_token",
    onRevoked: ({ reason }) => {
      revokedReasons.push(reason);
    },
  });

  const activeCheck = await guard.check({ userId: "u_1" });
  assert.equal(activeCheck.active, true);
  assert.equal(revokedReasons.length, 0);

  isRevoked = true;
  const revokedCheck = await guard.check({ userId: "u_1" });
  assert.equal(revokedCheck.active, false);
  assert.deepEqual(revokedReasons, ["access_revoked"]);

  await assert.rejects(
    () => guard.run({ userId: "u_1" }, (token) => client.getUserInfo(token)),
    (err: unknown) => err instanceof XelorraAccessRevokedError,
  );
  assert.deepEqual(revokedReasons, ["access_revoked", "user_disconnected"]);
});

test("Express and Next.js adapters handle redirects, callbacks, session guards, and signed webhooks", async () => {
  const secret = "whsec_adapter_test_secret";
  const mockFetch: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/oauth/token")) {
      return new Response(
        JSON.stringify({
          access_token: "xc_at_adapter",
          refresh_token: "xlr_rt_adapter",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "profile.read",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/oauth/userinfo")) {
      return new Response(
        JSON.stringify({ sub: "xapp_adapter", name: "Chidi Eze" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/oauth/introspect")) {
      return new Response(
        JSON.stringify({ active: false, connected: false, reason: "access_revoked" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(null, { status: 404 });
  };

  const client = new XelorraClient({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/api/auth/xelorra/callback",
    fetchImpl: mockFetch,
  });

  // Express callback
  let expressStatus = 0;
  let expressJson: unknown = null;
  const mockRes: ExpressResponseLike = {
    status(code: number) {
      expressStatus = code;
      return this;
    },
    json(payload: unknown) {
      expressJson = payload;
      return this;
    },
  };

  const expressCallback = createExpressCallbackHandler({
    client,
    resolveCodeVerifier: () => "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
    onSuccess: ({ user }, _req, res) => {
      res.status(200).json({ sub: user.sub });
    },
  });
  await expressCallback(
    { headers: {}, query: { code: "xc_code_1", state: "st_1" } },
    mockRes,
    () => {},
  );
  assert.equal(expressStatus, 200);
  assert.deepEqual(expressJson, { sub: "xapp_adapter" });

  // Express auth middleware with revocation sync
  let revokedInMiddleware = false;
  const expressMiddleware = createExpressAuthMiddleware({
    client,
    onRevoked: () => {
      revokedInMiddleware = true;
    },
  });
  const req: ExpressRequestLike = { headers: { authorization: "Bearer xc_at_adapter" } };
  await expressMiddleware(req, mockRes, () => {});
  assert.equal(revokedInMiddleware, true);
  assert.equal(expressStatus, 401);

  // Express webhook handler
  const webhookBody = JSON.stringify({
    id: "evt_exp_1",
    type: "user.access_revoked",
    created_at: "2026-11-26T12:00:00.000Z",
    client_id: "acme-app",
    data: {
      xid: "XLR-9284-1039",
      sub: "xapp_adapter",
      client_id: "acme-app",
      revoked_at: "2026-11-26T12:00:00.000Z",
      reason: "user_disconnected",
    },
  });
  const signature = await computeWebhookSignature(webhookBody, secret);
  let revokedSub = "";
  const expressWebhook = createExpressWebhookHandler({
    signingSecret: secret,
    onAccessRevoked: (event) => {
      revokedSub = event.data.sub;
    },
  });
  await expressWebhook(
    { headers: { "x-xelorra-signature": signature }, rawBody: webhookBody },
    mockRes,
    () => {},
  );
  assert.equal(expressStatus, 200);
  assert.equal(revokedSub, "xapp_adapter");

  // Next.js App Router auth redirect handler (signup mode sets prompt=create)
  let savedVerifier = "";
  const nextSignUp = createNextAuthRedirectHandler({
    client,
    mode: "signup",
    saveCodeVerifier: (pkce) => {
      savedVerifier = pkce.codeVerifier;
      return { "set-cookie": `xlr_pkce=${pkce.state}; HttpOnly; Path=/` };
    },
  });
  const redirectRes = await nextSignUp(
    new Request("https://acme.example.com/api/auth/xelorra/signup"),
  );
  assert.equal(redirectRes.status, 302);
  const location = new URL(redirectRes.headers.get("location")!);
  assert.equal(location.pathname, "/oauth/authorize");
  assert.equal(location.searchParams.get("prompt"), "create");
  assert.ok(savedVerifier.length >= 43);

  // Next.js App Router callback
  const nextCallback = createNextCallbackHandler({
    client,
    resolveCodeVerifier: () => "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
    onSuccess: ({ user }) => new Response(JSON.stringify({ sub: user.sub }), { status: 200 }),
  });
  const nextCbRes = await nextCallback(
    new Request("https://acme.example.com/api/auth/xelorra/callback?code=xc_1&state=st_1"),
  );
  assert.equal(nextCbRes.status, 200);
  assert.deepEqual(await nextCbRes.json(), { sub: "xapp_adapter" });

  // Next.js revocation-aware session guard
  let nextSessionRevoked = false;
  const sessionGuard = createNextSessionGuard({
    client,
    getAccessToken: (request) => request.headers.get("authorization")?.replace("Bearer ", ""),
    onRevoked: () => {
      nextSessionRevoked = true;
    },
  });
  const protectedRoute = sessionGuard.withSession(
    () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
  );
  const protectedRes = await protectedRoute(
    new Request("https://acme.example.com/api/protected", {
      headers: { authorization: "Bearer xc_at_adapter" },
    }),
  );
  assert.equal(protectedRes.status, 401);
  assert.equal(nextSessionRevoked, true);

  // Next.js webhook handler
  let nextRevokedSub = "";
  const nextWebhook = createNextWebhookHandler({
    signingSecret: secret,
    onAccessRevoked: (event) => {
      nextRevokedSub = event.data.sub;
    },
  });
  const nextWhRes = await nextWebhook(
    new Request("https://acme.example.com/api/webhooks/xelorra", {
      method: "POST",
      headers: { "content-type": "application/json", "x-xelorra-signature": signature },
      body: webhookBody,
    }),
  );
  assert.equal(nextWhRes.status, 200);
  assert.equal(nextRevokedSub, "xapp_adapter");

  const nextBadWhRes = await nextWebhook(
    new Request("https://acme.example.com/api/webhooks/xelorra", {
      method: "POST",
      headers: { "content-type": "application/json", "x-xelorra-signature": "bad" },
      body: webhookBody,
    }),
  );
  assert.equal(nextBadWhRes.status, 401);
});

test("Package entrypoints export core, React, Express, and Next.js APIs cleanly", () => {
  assert.equal(XelorraAuth, XelorraClient);
  assert.equal(typeof XelorraClient, "function");
  assert.equal(typeof createPkcePair, "function");
  assert.equal(typeof XelorraError, "function");
  assert.equal(typeof XelorraAuthError, "function");
  assert.equal(typeof XelorraAccessRevokedError, "function");
  assert.equal(typeof XelorraInsufficientScopeError, "function");
  assert.equal(typeof XelorraWebhookSignatureError, "function");
  assert.equal(typeof verifyWebhookSignature, "function");
  assert.equal(typeof parseWebhookEvent, "function");
  assert.equal(typeof createDisconnectGuard, "function");

  assert.equal(typeof reactEntry.XelorraProvider, "function");
  assert.equal(typeof reactEntry.useXelorraAuth, "function");
  assert.equal(typeof reactEntry.useXelorraCallback, "function");
  assert.equal(typeof reactEntry.XelorraAuthButton, "function");
  assert.equal(typeof reactEntry.XelorraSignInButton, "function");
  assert.equal(typeof reactEntry.XelorraSignUpButton, "function");
});

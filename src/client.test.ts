import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  XelorraAccessRevokedError,
  XelorraAuth,
  XelorraAuthError,
  XelorraClient,
  XelorraWebhookSignatureError,
  buildAuthorizeUrl,
  buildSignUpUrl,
  computeWebhookSignature,
  createDisconnectGuard,
  createPkcePair,
  exchangeCodeForTokens,
  getUserInfo,
  introspectToken,
  parseWebhookEvent,
  refreshTokens,
  revokeToken,
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
import { createNextCallbackHandler, createNextWebhookHandler } from "./next.js";

test("createPkcePair produces RFC 7636 S256 verifier, challenge, and state", async () => {
  const pair = await createPkcePair();
  assert.equal(pair.codeChallengeMethod, "S256");
  assert.ok(pair.codeVerifier.length >= 43 && pair.codeVerifier.length <= 128);
  assert.ok(pair.codeChallenge.length >= 43);
  assert.notEqual(pair.codeVerifier, pair.codeChallenge);
  assert.ok(pair.state.length >= 16);

  const expectedChallenge = createHash("sha256").update(pair.codeVerifier).digest("base64url");
  assert.equal(pair.codeChallenge, expectedChallenge);
});

test("XelorraClient builds standard authorize URL and prompt=create sign-up URL", async () => {
  const client = new XelorraClient({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
    scopes: ["profile.read", "email.read", "kyc.assertion"],
  });

  assert.equal(client.issuer, "https://one.xelorra.app");

  const { url: signInUrl, pkce } = await client.buildAuthorizeUrl();
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
  assert.equal(parsedSignIn.searchParams.get("scope"), "profile.read email.read kyc.assertion");
  assert.equal(parsedSignIn.searchParams.get("prompt"), null);

  const { url: signUpUrl } = await client.buildSignUpUrl({ loginHint: "new@example.com" });
  const parsedSignUp = new URL(signUpUrl);
  assert.equal(parsedSignUp.origin, "https://one.xelorra.app");
  assert.equal(parsedSignUp.pathname, "/oauth/authorize");
  assert.equal(parsedSignUp.searchParams.get("prompt"), "create");
  assert.equal(parsedSignUp.searchParams.get("login_hint"), "new@example.com");
  assert.equal(parsedSignUp.searchParams.get("code_challenge_method"), "S256");

  // Verify functional helpers match class output
  const fnResult = await buildSignUpUrl({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
  });
  assert.equal(new URL(fnResult.url).searchParams.get("prompt"), "create");

  const fnAuthResult = await buildAuthorizeUrl({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
  });
  assert.equal(new URL(fnAuthResult.url).searchParams.get("prompt"), null);
});

test("XelorraClient.signUp sets prompt=create and redirects without persisting tokens", async () => {
  const localStore = new Map<string, string>();
  const sessionStore = new Map<string, string>();
  let assignedUrl = "";

  const previousWindow = (globalThis as Record<string, unknown>).window;
  (globalThis as Record<string, unknown>).window = {
    location: {
      assign: (url: string) => {
        assignedUrl = url;
      },
    },
    localStorage: {
      getItem: (k: string) => localStore.get(k) ?? null,
      setItem: (k: string, v: string) => localStore.set(k, v),
      removeItem: (k: string) => localStore.delete(k),
    },
    sessionStorage: {
      getItem: (k: string) => sessionStore.get(k) ?? null,
      setItem: (k: string, v: string) => sessionStore.set(k, v),
      removeItem: (k: string) => sessionStore.delete(k),
    },
  };

  try {
    const client = new XelorraClient({
      clientId: "acme-app",
      redirectUri: "https://acme.example.com/auth/callback",
    });

    await client.signUp({ scopes: ["profile.read", "email.read"] });
    const parsed = new URL(assignedUrl);
    assert.equal(parsed.pathname, "/oauth/authorize");
    assert.equal(parsed.searchParams.get("prompt"), "create");
    assert.equal(parsed.searchParams.get("code_challenge_method"), "S256");
    assert.equal(localStore.size, 0);
    assert.equal(sessionStore.size, 1);
  } finally {
    if (previousWindow === undefined) {
      delete (globalThis as Record<string, unknown>).window;
    } else {
      (globalThis as Record<string, unknown>).window = previousWindow;
    }
  }
});

test("XelorraClient exchanges code, fetches userinfo, introspects, refreshes, and revokes cleanly", async () => {
  const calls: string[] = [];
  const mockFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    calls.push(`${init?.method || "GET"} ${url}`);

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
            scope: "profile.read kyc.assertion",
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
            scope: "profile.read kyc.assertion",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
    }

    if (url.endsWith("/oauth/userinfo")) {
      return new Response(
        JSON.stringify({
          sub: "xlr_app_1234567890abcdef",
          xid: "XLR-9284-1039",
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
          sub: "xlr_app_1234567890abcdef",
          xid: "XLR-9284-1039",
          scope: "profile.read kyc.assertion",
          exp: 1900000000,
          reason: null,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/api/v1/verify/assertion")) {
      return new Response(
        JSON.stringify({
          assertion: {
            verification_status: "verified",
            verification_level: "government_verified",
            verification_reference: "xvr_8492019482",
            verified_at: "2026-11-25T00:00:00.000Z",
            country: "Nigeria",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.endsWith("/oauth/revoke")) {
      const body = JSON.parse(String(init?.body)) as Record<string, string>;
      assert.equal(body.client_id, "acme-app");
      assert.ok(body.token);
      return new Response(null, { status: 200 });
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

  const user = await client.getUserInfo();
  assert.equal(user.sub, "xlr_app_1234567890abcdef");
  assert.equal(user.name, "Adaeze Okafor");

  const introspected = await client.introspectToken();
  assert.equal(introspected.active, true);
  assert.equal(introspected.connected, true);
  assert.equal(introspected.xid, "XLR-9284-1039");
  assert.equal(introspected.reason, null);

  const assertion = await client.getVerificationAssertion();
  assert.equal(assertion.verification_status, "verified");

  const rotated = await client.refreshTokens({ refreshToken: "xlr_rt_live_refresh" });
  assert.equal(rotated.access_token, "xc_at_rotated_token");

  await client.logout();
  assert.equal(client.getAccessToken(), null);
  assert.equal(client.getCachedUser(), null);

  // Verify standalone functional helpers
  const fnTokens = await exchangeCodeForTokens(config, {
    code: "xc_code_test",
    codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
  });
  assert.equal(fnTokens.access_token, "xc_at_live_token");
  const fnUser = await getUserInfo(config, fnTokens.access_token);
  assert.equal(fnUser.sub, "xlr_app_1234567890abcdef");
  const fnIntrospection = await introspectToken(config, fnTokens.access_token);
  assert.equal(fnIntrospection.active, true);
  const fnRefreshed = await refreshTokens(config, { refreshToken: "xlr_rt_live_refresh" });
  assert.equal(fnRefreshed.access_token, "xc_at_rotated_token");
  await revokeToken(config, fnRefreshed.access_token);
  assert.ok(calls.length >= 11);
});

test("getUserInfo throws XelorraAccessRevokedError on 401 access_revoked and clears session", async () => {
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
  assert.equal(client.getAccessToken(), "xc_at_revoked");

  await assert.rejects(
    () => client.getUserInfo(),
    (err: unknown) =>
      err instanceof XelorraAccessRevokedError &&
      err instanceof XelorraAuthError &&
      err.code === "access_revoked" &&
      err.status === 401 &&
      err.reason === "user_disconnected",
  );
  assert.equal(client.getAccessToken(), null);
});

test("verifyWebhookSignature and parseWebhookEvent validate HMAC-SHA256 signatures strictly", async () => {
  const secret = "whsec_test_xelorra_secret_key_987654321";
  const payload = JSON.stringify({
    id: "evt_01JXYZ987654",
    type: "user.access_revoked",
    created_at: "2026-11-25T12:00:00.000Z",
    data: {
      sub: "xlr_app_1234567890abcdef",
      xid: "XLR-9284-1039",
      client_id: "acme-app",
      revoked_at: "2026-11-25T12:00:00.000Z",
      reason: "user_disconnected",
    },
  });

  const validHex = await computeWebhookSignature(payload, secret);
  assert.equal(await verifyWebhookSignature(payload, validHex, secret), true);
  assert.equal(await verifyWebhookSignature(payload, `sha256=${validHex}`, secret), true);

  // Tampered body fails verification
  const tamperedPayload = payload.replace("acme-app", "evil-app");
  assert.equal(await verifyWebhookSignature(tamperedPayload, validHex, secret), false);

  // Wrong secret or missing header fails verification
  assert.equal(await verifyWebhookSignature(payload, validHex, "wrong-secret"), false);
  assert.equal(await verifyWebhookSignature(payload, undefined, secret), false);
  assert.equal(await verifyWebhookSignature(payload, "", secret), false);
  assert.equal(await verifyWebhookSignature(payload, "not-a-hex-digest", secret), false);

  // parseWebhookEvent returns typed event on valid signature
  const event = await parseWebhookEvent(payload, `sha256=${validHex}`, secret);
  assert.equal(event.type, "user.access_revoked");
  assert.equal(event.data.sub, "xlr_app_1234567890abcdef");
  assert.equal(event.data.client_id, "acme-app");

  // Missing header throws XelorraWebhookSignatureError("missing_signature")
  await assert.rejects(
    () => parseWebhookEvent(payload, null, secret),
    (err: unknown) =>
      err instanceof XelorraWebhookSignatureError && err.code === "missing_signature",
  );

  // Tampered body throws XelorraWebhookSignatureError("invalid_signature")
  await assert.rejects(
    () => parseWebhookEvent(tamperedPayload, validHex, secret),
    (err: unknown) =>
      err instanceof XelorraWebhookSignatureError && err.code === "invalid_signature",
  );
});

test("createDisconnectGuard triggers onRevoked via introspectToken and XelorraAccessRevokedError", async () => {
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
                client_id: "acme-app",
                sub: null,
                xid: null,
                scope: null,
                exp: null,
                reason: "access_revoked",
              }
            : {
                active: true,
                connected: true,
                client_id: "acme-app",
                sub: "xlr_app_123",
                xid: "XLR-1111-2222",
                scope: "profile.read",
                exp: 1900000000,
                reason: null,
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
    getToken: () => "xc_at_session_token",
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

test("Express and Next.js adapters handle callbacks, revocation sync, and signed webhooks", async () => {
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
        JSON.stringify({ sub: "xlr_app_adapter", name: "Chidi Eze" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/oauth/introspect")) {
      return new Response(
        JSON.stringify({ active: false, connected: false, reason: "user_disconnected" }),
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
  assert.deepEqual(expressJson, { sub: "xlr_app_adapter" });

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
    created_at: "2026-11-25T12:00:00.000Z",
    data: { sub: "xlr_app_adapter", client_id: "acme-app", revoked_at: "2026-11-25T12:00:00.000Z" },
  });
  const signature = await computeWebhookSignature(webhookBody, secret);
  let revokedSub = "";
  const expressWebhook = createExpressWebhookHandler({
    webhookSecret: secret,
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
  assert.equal(revokedSub, "xlr_app_adapter");

  // Next.js App Router callback + webhook handlers
  const nextCallback = createNextCallbackHandler({
    client,
    resolveCodeVerifier: () => "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
    onSuccess: ({ user }) => new Response(JSON.stringify({ sub: user.sub }), { status: 200 }),
  });
  const nextCbRes = await nextCallback(
    new Request("https://acme.example.com/api/auth/xelorra/callback?code=xc_1&state=st_1"),
  );
  assert.equal(nextCbRes.status, 200);
  assert.deepEqual(await nextCbRes.json(), { sub: "xlr_app_adapter" });

  let nextRevokedSub = "";
  const nextWebhook = createNextWebhookHandler({
    webhookSecret: secret,
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
  assert.equal(nextRevokedSub, "xlr_app_adapter");

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
  assert.equal(typeof XelorraAuthError, "function");
  assert.equal(typeof XelorraAccessRevokedError, "function");
  assert.equal(typeof XelorraWebhookSignatureError, "function");
  assert.equal(typeof verifyWebhookSignature, "function");
  assert.equal(typeof parseWebhookEvent, "function");
  assert.equal(typeof createDisconnectGuard, "function");

  assert.equal(typeof reactEntry.XelorraProvider, "function");
  assert.equal(typeof reactEntry.useXelorraAuth, "function");
  assert.equal(typeof reactEntry.XelorraAuthButton, "function");
});

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createPkcePair, XelorraAuth, XelorraAuthError } from "./client.js";
import * as rootEntry from "./index.js";
import * as reactEntry from "./react.js";

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

test("XelorraAuth defaults to https://one.xelorra.app and builds standard OAuth 2.0 + PKCE authorize URL", async () => {
  const auth = new XelorraAuth({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
    scopes: ["profile.read", "email.read", "kyc.assertion"],
  });

  assert.equal(auth.issuer, "https://one.xelorra.app");

  const { url, pkce } = await auth.buildAuthorizationUrl();
  const parsed = new URL(url);
  assert.equal(parsed.origin, "https://one.xelorra.app");
  assert.equal(parsed.pathname, "/oauth/authorize");
  assert.equal(parsed.searchParams.get("response_type"), "code");
  assert.equal(parsed.searchParams.get("client_id"), "acme-app");
  assert.equal(parsed.searchParams.get("redirect_uri"), "https://acme.example.com/auth/callback");
  assert.equal(parsed.searchParams.get("code_challenge"), pkce.codeChallenge);
  assert.equal(parsed.searchParams.get("code_challenge_method"), "S256");
  assert.equal(parsed.searchParams.get("scope"), "profile.read email.read kyc.assertion");
});

test("XelorraAuth exchanges authorization code, fetches pairwise userinfo, retrieves KYC assertion, refreshes, and logs out without browser token storage", async () => {
  const calls: string[] = [];
  const mockFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    calls.push(`${init?.method || "GET"} ${url}`);

    if (url.endsWith("/oauth/token")) {
      const body = JSON.parse(String(init?.body)) as Record<string, string>;
      if (body.grant_type === "authorization_code") {
        assert.equal(body.code, "xc_code_test");
        assert.equal(body.code_verifier, "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345");
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
          name: "Adaeze Okafor",
          verification_level: "verified",
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
      return new Response(null, { status: 200 });
    }

    return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
  };

  const localStore = new Map<string, string>();
  const sessionStore = new Map<string, string>();
  const previousWindow = (globalThis as Record<string, unknown>).window;
  (globalThis as Record<string, unknown>).window = {
    localStorage: {
      getItem: (k: string) => localStore.get(k) ?? null,
      setItem: (k: string, v: string) => {
        localStore.set(k, v);
      },
      removeItem: (k: string) => {
        localStore.delete(k);
      },
    },
    sessionStorage: {
      getItem: (k: string) => sessionStore.get(k) ?? null,
      setItem: (k: string, v: string) => {
        sessionStore.set(k, v);
      },
      removeItem: (k: string) => {
        sessionStore.delete(k);
      },
    },
  };

  try {
    const auth = new XelorraAuth({
      clientId: "acme-app",
      redirectUri: "https://acme.example.com/auth/callback",
      fetchImpl: mockFetch,
    });

    const { tokens, user } = await auth.handleCallback({
      url: "https://acme.example.com/auth/callback?code=xc_code_test&state=xyz",
      codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz_0123456789012345",
    });

    assert.equal(tokens.access_token, "xc_at_live_token");
    assert.equal(user.sub, "xlr_app_1234567890abcdef");
    assert.equal(user.name, "Adaeze Okafor");

    const assertion = await auth.getVerificationAssertion();
    assert.equal(assertion.verification_status, "verified");
    assert.equal(assertion.verification_reference, "xvr_8492019482");

    const rotated = await auth.refreshSession();
    assert.equal(rotated.access_token, "xc_at_rotated_token");

    assert.equal(localStore.size, 0);
    assert.equal(sessionStore.size, 0);

    await auth.logout();
    assert.equal(auth.getAccessToken(), null);
    assert.equal(auth.getCachedUser(), null);
    assert.equal(calls.length, 5);
  } finally {
    if (previousWindow === undefined) {
      delete (globalThis as Record<string, unknown>).window;
    } else {
      (globalThis as Record<string, unknown>).window = previousWindow;
    }
  }
});

test("XelorraAuth surfaces OAuth access_denied errors cleanly", async () => {
  const auth = new XelorraAuth({
    clientId: "acme-app",
    redirectUri: "https://acme.example.com/auth/callback",
  });

  await assert.rejects(
    () =>
      auth.handleCallback({
        url: "https://acme.example.com/auth/callback?error=access_denied&error_description=User+cancelled",
      }),
    (err: unknown) => err instanceof XelorraAuthError && err.code === "access_denied",
  );
});

test("Package entrypoints export core and React SDK APIs", () => {
  assert.equal(typeof rootEntry.XelorraAuth, "function");
  assert.equal(typeof rootEntry.XelorraAuth.Button, "function");
  assert.equal(typeof rootEntry.createPkcePair, "function");
  assert.equal(typeof rootEntry.XelorraAuthError, "function");

  assert.equal(typeof reactEntry.XelorraProvider, "function");
  assert.equal(typeof reactEntry.useXelorraAuth, "function");
  assert.equal(typeof reactEntry.XelorraAuthButton, "function");
});

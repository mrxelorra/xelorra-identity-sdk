import {
  DEFAULT_XELORRA_ISSUER,
  DEFAULT_XELORRA_SCOPES,
  KYC_ASSERTION_SCOPES,
} from "./constants.js";
import {
  XelorraAccessRevokedError,
  XelorraAuthError,
  XelorraInsufficientScopeError,
} from "./errors.js";
import { createPkcePair } from "./pkce.js";
import type {
  AuthorizeUrlOptions,
  ExchangeCodeOptions,
  PkcePair,
  RefreshTokensOptions,
  VerifyPassportTokenOptions,
  XelorraClientConfig,
  XelorraDiscoveryDocument,
  XelorraEnvironment,
  XelorraIntrospectionResult,
  XelorraJwksResponse,
  XelorraKycAssertion,
  XelorraLogoutResult,
  XelorraPassportVerificationResult,
  XelorraPublicRequestOptions,
  XelorraRevokeResult,
  XelorraTokenSet,
  XelorraUserClaims,
  XelorraXidAvailabilityResult,
} from "./types.js";

export { DEFAULT_XELORRA_ISSUER, DEFAULT_XELORRA_SCOPES };

const PKCE_STORAGE_PREFIX = "xelorra_pkce_tx_";

interface OAuthErrorPayload {
  error?: string;
  error_description?: string;
  message?: string;
  reason?: string;
  required_scopes?: string[];
  [key: string]: unknown;
}

function normalizeIssuer(issuer?: string, baseUrl?: string): string {
  const raw = (issuer || baseUrl || DEFAULT_XELORRA_ISSUER).trim();
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new XelorraAuthError("invalid_config", "issuer / baseUrl must be a valid http(s) URL.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new XelorraAuthError("invalid_config", "issuer / baseUrl must use https:// or http://.");
  }
  return raw.replace(/\/+$/, "");
}

function resolveFetch(fetchImpl?: typeof fetch): typeof fetch {
  if (fetchImpl) return fetchImpl;
  if (typeof globalThis.fetch === "function") {
    return globalThis.fetch.bind(globalThis);
  }
  throw new XelorraAuthError(
    "fetch_unavailable",
    "A global fetch implementation (Node.js 18+, browser, Bun, Deno, or fetchImpl) is required.",
  );
}

function isAccessRevokedResponse(status: number, body: OAuthErrorPayload): boolean {
  return status === 401 && body.error === "access_revoked";
}

function createResponseError(
  status: number,
  body: OAuthErrorPayload,
  fallbackCode: string,
  fallbackMessage: string,
): XelorraAuthError {
  if (isAccessRevokedResponse(status, body)) {
    return new XelorraAccessRevokedError(
      body.error_description ||
        body.message ||
        "Access to this application has been revoked on Xelorra One.",
      typeof body.reason === "string" ? body.reason : undefined,
      body,
    );
  }
  if (status === 403 && body.error === "insufficient_scope") {
    return new XelorraInsufficientScopeError(
      body.error_description ||
        body.message ||
        "The access token does not include the required scope for this endpoint.",
      Array.isArray(body.required_scopes) ? body.required_scopes : undefined,
      body,
    );
  }
  return new XelorraAuthError(
    body.error || fallbackCode,
    body.error_description || body.message || fallbackMessage,
    status,
    body,
  );
}

/**
 * Production OAuth 2.0 + OIDC + PKCE (`S256`) client for Xelorra Identity (`https://one.xelorra.app`).
 *
 * Keeps access and refresh tokens strictly in memory by default and never writes
 * tokens to `localStorage` or `sessionStorage`.
 */
export class XelorraClient {
  readonly clientId: string;
  readonly redirectUri?: string;
  readonly issuer: string;
  readonly baseUrl: string;
  readonly environment: XelorraEnvironment;
  readonly scopes: string[];
  private readonly clientSecret?: string;
  private readonly fetchImpl: typeof fetch;
  private tokens: XelorraTokenSet | null = null;
  private cachedUser: XelorraUserClaims | null = null;

  constructor(config: XelorraClientConfig) {
    if (!config.clientId || !config.clientId.trim()) {
      throw new XelorraAuthError("invalid_config", "clientId is required.");
    }
    this.clientId = config.clientId.trim();
    this.redirectUri = config.redirectUri?.trim() || undefined;
    this.clientSecret = config.clientSecret?.trim() || undefined;
    this.issuer = normalizeIssuer(config.issuer, config.baseUrl);
    this.baseUrl = this.issuer;
    this.environment = config.environment || "production";
    this.scopes = config.scopes?.length ? [...config.scopes] : [...DEFAULT_XELORRA_SCOPES];
    this.fetchImpl = resolveFetch(config.fetchImpl);
  }

  /** Returns the current in-memory access token, or `null` when signed out. */
  getAccessToken(): string | null {
    return this.tokens?.access_token ?? null;
  }

  /** Returns the full in-memory token set, or `null` when signed out. */
  getTokens(): XelorraTokenSet | null {
    return this.tokens;
  }

  /** Returns the most recently fetched user claims from memory, or `null`. */
  getCachedUser(): XelorraUserClaims | null {
    return this.cachedUser;
  }

  /** Clears in-memory tokens and cached user claims without issuing a network request. */
  clearSession(): void {
    this.tokens = null;
    this.cachedUser = null;
  }

  private resolveRedirectUri(override?: string): string {
    const resolved = (override ?? this.redirectUri ?? "").trim();
    if (!resolved) {
      throw new XelorraAuthError(
        "invalid_config",
        "redirectUri is required for OAuth authorization and code exchange.",
      );
    }
    return resolved;
  }

  /** Fetches the OpenID Connect Discovery document from `GET /.well-known/openid-configuration`. */
  async fetchDiscovery(): Promise<XelorraDiscoveryDocument> {
    return fetchDiscovery({ issuer: this.issuer, fetchImpl: this.fetchImpl });
  }

  /** Fetches the JSON Web Key Set from `GET /.well-known/jwks.json`. */
  async fetchJwks(): Promise<XelorraJwksResponse> {
    return fetchJwks({ issuer: this.issuer, fetchImpl: this.fetchImpl });
  }

  /**
   * Builds an OAuth 2.0 + PKCE `S256` authorization URL targeting `GET /oauth/authorize`.
   *
   * Returns both the ready-to-navigate `url` and the generated `pkce` bundle
   * (containing `codeVerifier`, `codeChallenge`, and `state`).
   */
  async buildAuthorizeUrl(
    options?: AuthorizeUrlOptions,
  ): Promise<{ url: string; pkce: PkcePair }> {
    const redirectUri = this.resolveRedirectUri(options?.redirectUri);
    const pkce = options?.pkce ?? (await createPkcePair());
    const finalState = options?.state ?? pkce.state;
    const scopeString = (options?.scopes?.length ? options.scopes : this.scopes).join(" ");

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: scopeString,
      state: finalState,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: "S256",
    });

    if (options?.prompt) {
      params.set("prompt", options.prompt);
    }
    if (options?.loginHint) {
      params.set("login_hint", options.loginHint);
    }
    if (options?.extraParams) {
      for (const [key, value] of Object.entries(options.extraParams)) {
        params.set(key, value);
      }
    }

    return {
      url: `${this.issuer}/oauth/authorize?${params.toString()}`,
      pkce: { ...pkce, state: finalState },
    };
  }

  /** Alias for `buildAuthorizeUrl` targeting returning users ("Sign in with Xelorra ID"). */
  async buildSignInUrl(
    options?: AuthorizeUrlOptions,
  ): Promise<{ url: string; pkce: PkcePair }> {
    return this.buildAuthorizeUrl(options);
  }

  /** Backwards-compatible alias for `buildAuthorizeUrl`. */
  async buildAuthorizationUrl(
    options?: AuthorizeUrlOptions,
  ): Promise<{ url: string; pkce: PkcePair }> {
    return this.buildAuthorizeUrl(options);
  }

  /**
   * Builds an authorization URL with `prompt=create` so new users go straight
   * to Xelorra ID registration and automatically return to the consent screen.
   */
  async buildSignUpUrl(
    options?: Omit<AuthorizeUrlOptions, "prompt">,
  ): Promise<{ url: string; pkce: PkcePair }> {
    return this.buildAuthorizeUrl({ ...options, prompt: "create" });
  }

  /**
   * Initiates a browser redirect to Xelorra One `/oauth/authorize` using PKCE `S256`.
   *
   * Stores only the ephemeral PKCE `codeVerifier` in `sessionStorage` keyed by `state`
   * for the duration of the redirect and deletes it immediately in `handleCallback`.
   * Access and refresh tokens are never stored in browser storage.
   */
  async loginWithRedirect(options?: AuthorizeUrlOptions): Promise<void> {
    if (typeof window === "undefined") {
      throw new XelorraAuthError(
        "browser_required",
        "loginWithRedirect can only run in a browser environment. Use buildAuthorizeUrl on the server.",
      );
    }
    const { url, pkce } = await this.buildAuthorizeUrl(options);
    // Store only the ephemeral PKCE verifier across the redirect; never persist tokens.
    window.sessionStorage.setItem(
      `${PKCE_STORAGE_PREFIX}${pkce.state}`,
      JSON.stringify({ codeVerifier: pkce.codeVerifier, createdAt: Date.now() }),
    );
    window.location.assign(url);
  }

  /** Convenience alias for `loginWithRedirect`. */
  async signIn(options?: AuthorizeUrlOptions): Promise<void> {
    return this.loginWithRedirect(options);
  }

  /**
   * Redirects a new user directly to Xelorra ID sign-up (`prompt=create`)
   * before automatically returning them to the OAuth consent screen.
   */
  async signUp(options?: Omit<AuthorizeUrlOptions, "prompt">): Promise<void> {
    return this.loginWithRedirect({ ...options, prompt: "create" });
  }

  /**
   * Exchanges an authorization `code` and PKCE `codeVerifier` for tokens via `POST /oauth/token`.
   */
  async exchangeCodeForTokens(options: ExchangeCodeOptions): Promise<XelorraTokenSet> {
    const code = options.code.trim();
    const codeVerifier = options.codeVerifier.trim();
    const redirectUri = this.resolveRedirectUri(options.redirectUri);

    if (!code) {
      throw new XelorraAuthError("missing_code", "Authorization code is required.");
    }
    if (!codeVerifier) {
      throw new XelorraAuthError(
        "missing_pkce_verifier",
        "PKCE codeVerifier is required to exchange an authorization code.",
      );
    }

    const payload: Record<string, string> = {
      grant_type: "authorization_code",
      code,
      client_id: this.clientId,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    };
    if (this.clientSecret) {
      payload.client_secret = this.clientSecret;
    }

    const res = await this.fetchImpl(`${this.issuer}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraTokenSet> &
      OAuthErrorPayload;
    if (!res.ok || !body.access_token) {
      throw createResponseError(
        res.status,
        body,
        "token_exchange_failed",
        "Unable to exchange authorization code for tokens.",
      );
    }

    this.tokens = body as XelorraTokenSet;
    return this.tokens;
  }

  /**
   * Completes the browser or server OAuth callback: extracts `code`/`state`,
   * resolves and deletes the ephemeral PKCE verifier, exchanges the code for tokens,
   * and loads user claims from `GET /oauth/userinfo`.
   */
  async handleCallback(input?: {
    url?: string;
    code?: string;
    state?: string;
    codeVerifier?: string;
    redirectUri?: string;
  }): Promise<{ tokens: XelorraTokenSet; user: XelorraUserClaims }> {
    const urlStr =
      input?.url ?? (typeof window !== "undefined" ? window.location.href : undefined);
    const parsedUrl = urlStr ? new URL(urlStr) : null;

    const oauthError = parsedUrl?.searchParams.get("error");
    if (oauthError) {
      throw new XelorraAuthError(
        oauthError,
        parsedUrl?.searchParams.get("error_description") || "Authorization was denied.",
      );
    }

    const code = input?.code ?? parsedUrl?.searchParams.get("code") ?? "";
    const state = input?.state ?? parsedUrl?.searchParams.get("state") ?? "";
    if (!code) {
      throw new XelorraAuthError("missing_code", "Authorization code is missing from callback.");
    }

    let verifier = input?.codeVerifier ?? "";
    if (!verifier && typeof window !== "undefined" && state) {
      const storageKey = `${PKCE_STORAGE_PREFIX}${state}`;
      const raw = window.sessionStorage.getItem(storageKey);
      window.sessionStorage.removeItem(storageKey);
      if (raw) {
        try {
          const parsed = JSON.parse(raw) as { codeVerifier?: string };
          verifier = parsed.codeVerifier ?? "";
        } catch {
          verifier = "";
        }
      }
    }

    if (!verifier) {
      throw new XelorraAuthError(
        "missing_pkce_verifier",
        "PKCE code_verifier is missing or expired. Restart the sign-in flow.",
      );
    }

    const tokens = await this.exchangeCodeForTokens({
      code,
      codeVerifier: verifier,
      redirectUri: input?.redirectUri,
    });
    const user = await this.getUserInfo(tokens.access_token);
    return { tokens, user };
  }

  /**
   * Exchanges a single-use rotating refresh token for a fresh token set via `POST /oauth/token`.
   * Clears in-memory session state if the refresh token is rejected or revoked.
   */
  async refreshTokens(options?: RefreshTokensOptions): Promise<XelorraTokenSet> {
    const refreshToken = options?.refreshToken ?? this.tokens?.refresh_token;
    if (!refreshToken) {
      throw new XelorraAuthError("missing_refresh_token", "No refresh token available.");
    }

    const payload: Record<string, string> = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.clientId,
    };
    if (this.clientSecret) {
      payload.client_secret = this.clientSecret;
    }
    if (options?.scope) {
      payload.scope = options.scope;
    }

    const res = await this.fetchImpl(`${this.issuer}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraTokenSet> &
      OAuthErrorPayload;
    if (!res.ok || !body.access_token) {
      this.clearSession();
      throw createResponseError(
        res.status,
        body,
        "refresh_failed",
        "Unable to refresh Xelorra session.",
      );
    }

    this.tokens = body as XelorraTokenSet;
    return this.tokens;
  }

  /** Backwards-compatible alias for `refreshTokens`. */
  async refreshSession(refreshToken?: string): Promise<XelorraTokenSet> {
    return this.refreshTokens(refreshToken ? { refreshToken } : undefined);
  }

  /**
   * Fetches scoped identity claims from `GET /oauth/userinfo`.
   *
   * Throws `XelorraAccessRevokedError` whenever Xelorra One returns HTTP `401`
   * with `error: "access_revoked"`.
   */
  async getUserInfo(accessToken?: string): Promise<XelorraUserClaims> {
    const token = accessToken ?? this.tokens?.access_token;
    if (!token) {
      throw new XelorraAuthError("unauthenticated", "No active Xelorra access token.");
    }

    const res = await this.fetchImpl(`${this.issuer}/oauth/userinfo`, {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
    });

    const body = (await res.json().catch(() => ({}))) as XelorraUserClaims & OAuthErrorPayload;
    if (!res.ok) {
      if (isAccessRevokedResponse(res.status, body) && token === this.tokens?.access_token) {
        this.clearSession();
      }
      throw createResponseError(
        res.status,
        body,
        "userinfo_failed",
        "Failed to load user identity claims.",
      );
    }

    if (!accessToken || accessToken === this.tokens?.access_token) {
      this.cachedUser = body;
    }
    return body;
  }

  /** Backwards-compatible alias for `getUserInfo`. */
  async getUser(accessToken?: string): Promise<XelorraUserClaims> {
    return this.getUserInfo(accessToken);
  }

  /**
   * Introspects an access token via `POST /oauth/introspect` to check whether the
   * token is still active and the user's connection on Xelorra One is intact.
   */
  async introspectToken(accessToken?: string): Promise<XelorraIntrospectionResult> {
    const token = accessToken ?? this.tokens?.access_token;
    if (!token) {
      return {
        active: false,
        connected: false,
        client_id: this.clientId,
        sub: null,
        xid: null,
        scope: null,
        exp: null,
        reason: "missing_token",
      };
    }

    const payload: Record<string, string> = {
      token,
      client_id: this.clientId,
    };
    if (this.clientSecret) {
      payload.client_secret = this.clientSecret;
    }

    const res = await this.fetchImpl(`${this.issuer}/oauth/introspect`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraIntrospectionResult> &
      OAuthErrorPayload;
    if (!res.ok) {
      throw createResponseError(
        res.status,
        body,
        "introspection_failed",
        "Failed to introspect Xelorra token.",
      );
    }

    const active = Boolean(body.active);
    const connected = typeof body.connected === "boolean" ? body.connected : active;

    if ((!active || !connected) && token === this.tokens?.access_token) {
      this.clearSession();
    }

    return {
      active,
      connected,
      client_id: typeof body.client_id === "string" ? body.client_id : null,
      sub: typeof body.sub === "string" ? body.sub : null,
      xid: typeof body.xid === "string" ? body.xid : null,
      scope: typeof body.scope === "string" ? body.scope : null,
      exp: typeof body.exp === "number" ? body.exp : null,
      reason: typeof body.reason === "string" ? body.reason : null,
    };
  }

  /**
   * Convenience helper returning `true` only when `introspectToken()` confirms both
   * `active === true` and `connected === true`.
   */
  async isUserConnected(accessToken?: string): Promise<boolean> {
    const result = await this.introspectToken(accessToken);
    return result.active && result.connected;
  }

  /**
   * Retrieves a minimum-disclosure Reusable KYC verification assertion via
   * `POST /api/v1/verify/assertion`.
   *
   * Requires at least one of: `kyc.assertion.read`, `verification.read`,
   * `gov.nin.verify`, or `gov.bvn.verify`.
   * Throws `XelorraInsufficientScopeError` on HTTP 403 `insufficient_scope`.
   */
  async verifyKycAssertion(accessToken?: string): Promise<XelorraKycAssertion> {
    const token = accessToken ?? this.tokens?.access_token;
    if (!token) {
      throw new XelorraAuthError("unauthenticated", "No active Xelorra access token.");
    }

    const res = await this.fetchImpl(`${this.issuer}/api/v1/verify/assertion`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({}),
    });

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraKycAssertion> & {
      assertion?: XelorraKycAssertion;
    } & OAuthErrorPayload;

    if (!res.ok) {
      if (isAccessRevokedResponse(res.status, body) && token === this.tokens?.access_token) {
        this.clearSession();
      }
      if (res.status === 403 && body.error === "insufficient_scope") {
        throw new XelorraInsufficientScopeError(
          body.error_description ||
            body.message ||
            "Access token requires one of: kyc.assertion.read, verification.read, gov.nin.verify, or gov.bvn.verify.",
          Array.isArray(body.required_scopes)
            ? body.required_scopes
            : [...KYC_ASSERTION_SCOPES],
          body,
        );
      }
      throw createResponseError(
        res.status,
        body,
        "assertion_failed",
        "Failed to retrieve Reusable KYC verification assertion.",
      );
    }

    const assertion = body.assertion ?? (body as XelorraKycAssertion);
    if (!assertion || typeof assertion.verification_status !== "string") {
      throw new XelorraAuthError(
        "assertion_failed",
        "Unexpected Reusable KYC assertion payload from Xelorra One.",
        res.status,
        body,
      );
    }

    return assertion;
  }

  /** Backwards-compatible alias for `verifyKycAssertion`. */
  async getVerificationAssertion(accessToken?: string): Promise<XelorraKycAssertion> {
    return this.verifyKycAssertion(accessToken);
  }

  /**
   * Verifies a member's short-lived rotating Digital Passport QR token without authentication.
   * Supports both `GET /api/v1/public/verify/:token` (default) and `GET /api/v1/verify/:token`
   * (when `{ endpoint: "selective" }` is passed).
   */
  async verifyPassportToken(
    token: string,
    options?: { endpoint?: "public" | "selective" },
  ): Promise<XelorraPassportVerificationResult> {
    return verifyPassportToken(token, {
      issuer: this.issuer,
      fetchImpl: this.fetchImpl,
      endpoint: options?.endpoint,
    });
  }

  /**
   * Checks memorable XID availability via `GET /api/v1/xid/check?username=<handle>` (zero auth).
   */
  async checkXidAvailability(username: string): Promise<XelorraXidAvailabilityResult> {
    return checkXidAvailability(username, {
      issuer: this.issuer,
      fetchImpl: this.fetchImpl,
    });
  }

  /**
   * Revokes an access or refresh token via `POST /oauth/revoke` (RFC 7009) so partner apps
   * keep disconnect state synchronized with Xelorra One.
   */
  async revokeToken(tokenToRevoke?: string): Promise<XelorraRevokeResult> {
    const token = tokenToRevoke ?? this.tokens?.refresh_token ?? this.tokens?.access_token;
    if (!token) {
      return { revoked: true };
    }

    const payload: Record<string, string> = {
      token,
      client_id: this.clientId,
    };
    if (this.clientSecret) {
      payload.client_secret = this.clientSecret;
    }

    const res = await this.fetchImpl(`${this.issuer}/oauth/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraRevokeResult> &
      OAuthErrorPayload;

    if (!res.ok) {
      throw createResponseError(
        res.status,
        body,
        "revocation_failed",
        "Failed to revoke Xelorra token.",
      );
    }

    if (
      token === this.tokens?.access_token ||
      token === this.tokens?.refresh_token
    ) {
      this.clearSession();
    }

    return { revoked: body.revoked ?? true };
  }

  /**
   * Revokes the active token (`POST /oauth/revoke`), ends the session via `POST /oauth/logout`,
   * and clears all in-memory tokens and cached user state.
   */
  async logout(accessToken?: string): Promise<XelorraLogoutResult> {
    const activeToken = accessToken ?? this.tokens?.access_token;
    const tokenToRevoke = accessToken ?? this.tokens?.refresh_token ?? this.tokens?.access_token;

    try {
      if (tokenToRevoke) {
        await this.revokeToken(tokenToRevoke);
      }

      const headers: Record<string, string> = { "content-type": "application/json" };
      if (activeToken) {
        headers.authorization = `Bearer ${activeToken}`;
      }

      const res = await this.fetchImpl(`${this.issuer}/oauth/logout`, {
        method: "POST",
        headers,
        body: JSON.stringify({ client_id: this.clientId }),
      });

      const body = (await res.json().catch(() => ({}))) as Partial<XelorraLogoutResult> &
        OAuthErrorPayload;

      if (!res.ok) {
        throw createResponseError(
          res.status,
          body,
          "logout_failed",
          "Failed to complete logout on Xelorra One.",
        );
      }

      return {
        loggedOut: body.loggedOut ?? true,
        message: typeof body.message === "string" ? body.message : undefined,
      };
    } finally {
      this.clearSession();
    }
  }
}

/** Backwards-compatible alias for `XelorraClient`. */
export const XelorraAuth = XelorraClient;
export type XelorraAuth = XelorraClient;

/** Fetches OpenID Connect discovery metadata from `GET /.well-known/openid-configuration`. */
export async function fetchDiscovery(
  options?: XelorraPublicRequestOptions,
): Promise<XelorraDiscoveryDocument> {
  const issuer = normalizeIssuer(options?.issuer, options?.baseUrl);
  const fetchImpl = resolveFetch(options?.fetchImpl);
  const res = await fetchImpl(`${issuer}/.well-known/openid-configuration`, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const body = (await res.json().catch(() => ({}))) as XelorraDiscoveryDocument &
    OAuthErrorPayload;
  if (!res.ok || !body.issuer) {
    throw createResponseError(
      res.status,
      body,
      "discovery_failed",
      "Failed to fetch OpenID Connect discovery document.",
    );
  }
  return body;
}

/** Fetches the public JWKS document from `GET /.well-known/jwks.json`. */
export async function fetchJwks(
  options?: XelorraPublicRequestOptions,
): Promise<XelorraJwksResponse> {
  const issuer = normalizeIssuer(options?.issuer, options?.baseUrl);
  const fetchImpl = resolveFetch(options?.fetchImpl);
  const res = await fetchImpl(`${issuer}/.well-known/jwks.json`, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const body = (await res.json().catch(() => ({}))) as XelorraJwksResponse & OAuthErrorPayload;
  if (!res.ok || !Array.isArray(body.keys)) {
    throw createResponseError(
      res.status,
      body,
      "jwks_failed",
      "Failed to fetch JWKS keys from Xelorra One.",
    );
  }
  return body;
}

/**
 * Verifies a rotating Digital Passport QR token without authentication.
 * Defaults to `GET /api/v1/public/verify/:token`; pass `{ endpoint: "selective" }`
 * to call `GET /api/v1/verify/:token`.
 */
export async function verifyPassportToken(
  token: string,
  options?: VerifyPassportTokenOptions,
): Promise<XelorraPassportVerificationResult> {
  const trimmed = token.trim();
  if (!trimmed) {
    throw new XelorraAuthError("invalid_token", "Passport QR token is required.");
  }

  const issuer = normalizeIssuer(options?.issuer, options?.baseUrl);
  const fetchImpl = resolveFetch(options?.fetchImpl);
  const path =
    options?.endpoint === "selective"
      ? `/api/v1/verify/${encodeURIComponent(trimmed)}`
      : `/api/v1/public/verify/${encodeURIComponent(trimmed)}`;

  const res = await fetchImpl(`${issuer}${path}`, {
    method: "GET",
    headers: { accept: "application/json" },
  });

  const body = (await res.json().catch(() => ({}))) as XelorraPassportVerificationResult &
    OAuthErrorPayload;

  if (!res.ok && typeof body.valid !== "boolean") {
    throw createResponseError(
      res.status,
      body,
      "passport_verification_failed",
      "Failed to verify Digital Passport token.",
    );
  }

  return body;
}

/**
 * Checks memorable XID handle availability via `GET /api/v1/xid/check?username=<handle>`.
 */
export async function checkXidAvailability(
  username: string,
  options?: XelorraPublicRequestOptions,
): Promise<XelorraXidAvailabilityResult> {
  const trimmed = username.trim();
  if (!trimmed) {
    throw new XelorraAuthError("invalid_request", "username is required.");
  }

  const issuer = normalizeIssuer(options?.issuer, options?.baseUrl);
  const fetchImpl = resolveFetch(options?.fetchImpl);
  const query = new URLSearchParams({ username: trimmed });

  const res = await fetchImpl(`${issuer}/api/v1/xid/check?${query.toString()}`, {
    method: "GET",
    headers: { accept: "application/json" },
  });

  const body = (await res.json().catch(() => ({}))) as XelorraXidAvailabilityResult &
    OAuthErrorPayload;

  if (!res.ok) {
    throw createResponseError(
      res.status,
      body,
      "xid_check_failed",
      "Failed to check memorable XID availability.",
    );
  }

  return body;
}

/** Functional helper that builds an OAuth 2.0 + PKCE `S256` authorization URL. */
export async function buildAuthorizeUrl(
  config: XelorraClientConfig,
  options?: AuthorizeUrlOptions,
): Promise<{ url: string; pkce: PkcePair }> {
  return new XelorraClient(config).buildAuthorizeUrl(options);
}

/** Functional helper that builds a sign-in authorization URL. */
export async function buildSignInUrl(
  config: XelorraClientConfig,
  options?: AuthorizeUrlOptions,
): Promise<{ url: string; pkce: PkcePair }> {
  return new XelorraClient(config).buildSignInUrl(options);
}

/** Functional helper that builds a sign-up authorization URL with `prompt=create`. */
export async function buildSignUpUrl(
  config: XelorraClientConfig,
  options?: Omit<AuthorizeUrlOptions, "prompt">,
): Promise<{ url: string; pkce: PkcePair }> {
  return new XelorraClient(config).buildSignUpUrl(options);
}

/** Functional helper that exchanges an authorization code and PKCE verifier via `POST /oauth/token`. */
export async function exchangeCodeForTokens(
  config: XelorraClientConfig,
  options: ExchangeCodeOptions,
): Promise<XelorraTokenSet> {
  return new XelorraClient(config).exchangeCodeForTokens(options);
}

/** Functional helper that refreshes an access token via `POST /oauth/token`. */
export async function refreshTokens(
  config: XelorraClientConfig,
  options: RefreshTokensOptions,
): Promise<XelorraTokenSet> {
  return new XelorraClient(config).refreshTokens(options);
}

/** Functional helper that loads user claims from `GET /oauth/userinfo`. */
export async function getUserInfo(
  config: XelorraClientConfig,
  accessToken: string,
): Promise<XelorraUserClaims> {
  return new XelorraClient(config).getUserInfo(accessToken);
}

/** Functional helper that introspects an access token via `POST /oauth/introspect`. */
export async function introspectToken(
  config: XelorraClientConfig,
  accessToken: string,
): Promise<XelorraIntrospectionResult> {
  return new XelorraClient(config).introspectToken(accessToken);
}

/** Functional helper returning `true` only if the user's connection is active and connected. */
export async function isUserConnected(
  config: XelorraClientConfig,
  accessToken: string,
): Promise<boolean> {
  return new XelorraClient(config).isUserConnected(accessToken);
}

/** Functional helper that retrieves a Reusable KYC assertion via `POST /api/v1/verify/assertion`. */
export async function verifyKycAssertion(
  config: XelorraClientConfig,
  accessToken: string,
): Promise<XelorraKycAssertion> {
  return new XelorraClient(config).verifyKycAssertion(accessToken);
}

/** Functional helper that revokes a token on Xelorra One via `POST /oauth/revoke`. */
export async function revokeToken(
  config: XelorraClientConfig,
  token: string,
): Promise<XelorraRevokeResult> {
  return new XelorraClient(config).revokeToken(token);
}

/** Functional helper that revokes a token and calls `POST /oauth/logout`. */
export async function logout(
  config: XelorraClientConfig,
  accessToken?: string,
): Promise<XelorraLogoutResult> {
  return new XelorraClient(config).logout(accessToken);
}

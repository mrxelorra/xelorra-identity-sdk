import { XelorraAccessRevokedError, XelorraAuthError } from "./errors.js";
import { createPkcePair } from "./pkce.js";
import type {
  AuthorizeUrlOptions,
  ExchangeCodeOptions,
  PkcePair,
  RefreshTokensOptions,
  XelorraClientConfig,
  XelorraEnvironment,
  XelorraIntrospectionResult,
  XelorraKycAssertion,
  XelorraTokenSet,
  XelorraUserClaims,
} from "./types.js";

export const DEFAULT_XELORRA_ISSUER = "https://one.xelorra.app";
export const DEFAULT_XELORRA_SCOPES = ["profile.read", "passport.read", "email.read"] as const;

const PKCE_STORAGE_PREFIX = "xelorra_pkce_tx_";

interface OAuthErrorPayload {
  error?: string;
  error_description?: string;
  reason?: string;
  [key: string]: unknown;
}

function normalizeIssuer(issuer?: string): string {
  const raw = (issuer || DEFAULT_XELORRA_ISSUER).trim();
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new XelorraAuthError("invalid_config", "issuer must be a valid http(s) URL.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new XelorraAuthError("invalid_config", "issuer must use https:// or http://.");
  }
  return raw.replace(/\/+$/, "");
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
      body.error_description || "Access to this application has been revoked on Xelorra One.",
      typeof body.reason === "string" ? body.reason : undefined,
      body,
    );
  }
  return new XelorraAuthError(
    body.error || fallbackCode,
    body.error_description || fallbackMessage,
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
    this.issuer = normalizeIssuer(config.issuer);
    this.environment = config.environment || "production";
    this.scopes = config.scopes?.length ? [...config.scopes] : [...DEFAULT_XELORRA_SCOPES];
    this.fetchImpl = config.fetchImpl || globalThis.fetch.bind(globalThis);
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

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraTokenSet> & OAuthErrorPayload;
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
    const urlStr = input?.url ?? (typeof window !== "undefined" ? window.location.href : undefined);
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
   * Exchanges a refresh token for a rotated token set via `POST /oauth/token`.
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

    const body = (await res.json().catch(() => ({}))) as Partial<XelorraTokenSet> & OAuthErrorPayload;
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
    const connected =
      typeof body.connected === "boolean" ? body.connected : active;

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
   * Retrieves a minimum-disclosure Reusable KYC verification assertion via
   * `GET /api/v1/verify/assertion`.
   */
  async getVerificationAssertion(accessToken?: string): Promise<XelorraKycAssertion> {
    const token = accessToken ?? this.tokens?.access_token;
    if (!token) {
      throw new XelorraAuthError("unauthenticated", "No active Xelorra access token.");
    }

    const res = await this.fetchImpl(`${this.issuer}/api/v1/verify/assertion`, {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
    });

    const body = (await res.json().catch(() => ({}))) as {
      assertion?: XelorraKycAssertion;
    } & OAuthErrorPayload;

    if (!res.ok || !body.assertion) {
      if (isAccessRevokedResponse(res.status, body) && token === this.tokens?.access_token) {
        this.clearSession();
      }
      throw createResponseError(
        res.status,
        body,
        "assertion_failed",
        "Failed to retrieve Reusable KYC verification assertion.",
      );
    }

    return body.assertion;
  }

  /**
   * Revokes an access or refresh token via `POST /oauth/revoke` so partner apps
   * can cleanly disconnect a user back on Xelorra One.
   */
  async revokeToken(tokenToRevoke?: string): Promise<void> {
    const token = tokenToRevoke ?? this.tokens?.refresh_token ?? this.tokens?.access_token;
    if (!token) return;

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

    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as OAuthErrorPayload;
      throw createResponseError(
        res.status,
        body,
        "revocation_failed",
        "Failed to revoke Xelorra token.",
      );
    }
  }

  /**
   * Revokes the active session on Xelorra One and clears in-memory tokens and user state.
   */
  async logout(): Promise<void> {
    try {
      await this.revokeToken();
    } finally {
      this.clearSession();
    }
  }
}

/** Backwards-compatible alias for `XelorraClient`. */
export const XelorraAuth = XelorraClient;
export type XelorraAuth = XelorraClient;

/** Functional helper that builds an OAuth 2.0 + PKCE `S256` authorization URL. */
export async function buildAuthorizeUrl(
  config: XelorraClientConfig,
  options?: AuthorizeUrlOptions,
): Promise<{ url: string; pkce: PkcePair }> {
  return new XelorraClient(config).buildAuthorizeUrl(options);
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

/** Functional helper that revokes a token on Xelorra One via `POST /oauth/revoke`. */
export async function revokeToken(
  config: XelorraClientConfig,
  token: string,
): Promise<void> {
  return new XelorraClient(config).revokeToken(token);
}

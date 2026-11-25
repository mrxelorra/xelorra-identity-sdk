export type XelorraEnvironment = "development" | "staging" | "production";

export interface XelorraAuthConfig {
  clientId: string;
  redirectUri: string;
  issuer?: string;
  environment?: XelorraEnvironment;
  scopes?: string[];
  fetchImpl?: typeof fetch;
}

export interface XelorraTokenSet {
  access_token: string;
  refresh_token?: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  xid?: string | null;
}

export interface XelorraKycAssertion {
  verification_status: "verified" | "pending" | "unverified";
  verification_level: "none" | "basic" | "verified" | "government_verified";
  verification_reference: string | null;
  verified_at: string | null;
  country: string | null;
}

export interface XelorraUserClaims {
  sub: string;
  xid?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  country?: string;
  verification_level?: string;
  membership_status?: string;
  tier?: string;
  kyc_assertion?: XelorraKycAssertion;
  [key: string]: unknown;
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  state: string;
}

export class XelorraAuthError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = "XelorraAuthError";
    this.code = code;
    this.status = status;
  }
}

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function bytesToBase64Url(bytes: Uint8Array): string {
  let output = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const hasB1 = i + 1 < bytes.length;
    const hasB2 = i + 2 < bytes.length;
    const b1 = hasB1 ? bytes[i + 1]! : 0;
    const b2 = hasB2 ? bytes[i + 2]! : 0;

    output += BASE64URL_ALPHABET[b0 >> 2]!;
    output += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    if (hasB1) {
      output += BASE64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]!;
    }
    if (hasB2) {
      output += BASE64URL_ALPHABET[b2 & 0x3f]!;
    }
  }
  return output;
}

function getCryptoSubtle(): Crypto {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  throw new XelorraAuthError(
    "crypto_unavailable",
    "WebCrypto API (crypto.subtle) is required for PKCE S256 authentication.",
  );
}

export async function createPkcePair(): Promise<PkcePair> {
  const cryptoApi = getCryptoSubtle();
  const verifierBytes = new Uint8Array(48);
  cryptoApi.getRandomValues(verifierBytes);
  const codeVerifier = bytesToBase64Url(verifierBytes);

  const digest = await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const codeChallenge = bytesToBase64Url(new Uint8Array(digest));

  const stateBytes = new Uint8Array(18);
  cryptoApi.getRandomValues(stateBytes);
  const state = bytesToBase64Url(stateBytes);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
    state,
  };
}

const PKCE_STORAGE_PREFIX = "xelorra_pkce_tx_";

export class XelorraAuth {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly issuer: string;
  readonly environment: XelorraEnvironment;
  readonly scopes: string[];
  private readonly fetchImpl: typeof fetch;
  private tokens: XelorraTokenSet | null = null;
  private cachedUser: XelorraUserClaims | null = null;

  constructor(config: XelorraAuthConfig) {
    if (!config.clientId.trim()) {
      throw new XelorraAuthError("invalid_config", "clientId is required.");
    }
    if (!config.redirectUri.trim()) {
      throw new XelorraAuthError("invalid_config", "redirectUri is required.");
    }
    this.clientId = config.clientId.trim();
    this.redirectUri = config.redirectUri.trim();
    this.issuer = (config.issuer || "https://one.xelorra.app").replace(/\/+$/, "");
    this.environment = config.environment || "production";
    this.scopes = config.scopes?.length
      ? config.scopes
      : ["profile.read", "passport.read", "email.read"];
    this.fetchImpl = config.fetchImpl || globalThis.fetch.bind(globalThis);
  }

  getAccessToken(): string | null {
    return this.tokens?.access_token ?? null;
  }

  getTokens(): XelorraTokenSet | null {
    return this.tokens;
  }

  async buildAuthorizationUrl(options?: {
    scopes?: string[];
    state?: string;
    pkce?: PkcePair;
  }): Promise<{ url: string; pkce: PkcePair }> {
    const pkce = options?.pkce ?? (await createPkcePair());
    const finalState = options?.state ?? pkce.state;
    const scopeString = (options?.scopes ?? this.scopes).join(" ");

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: scopeString,
      state: finalState,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: "S256",
    });

    return {
      url: `${this.issuer}/oauth/authorize?${params.toString()}`,
      pkce: { ...pkce, state: finalState },
    };
  }

  async loginWithRedirect(options?: { scopes?: string[]; state?: string }): Promise<void> {
    if (typeof window === "undefined") {
      throw new XelorraAuthError(
        "browser_required",
        "loginWithRedirect can only run in a browser environment. Use buildAuthorizationUrl on the server.",
      );
    }
    const { url, pkce } = await this.buildAuthorizationUrl(options);
    // Ephemeral PKCE transaction verifier only (removed immediately on callback; never stores tokens).
    window.sessionStorage.setItem(
      `${PKCE_STORAGE_PREFIX}${pkce.state}`,
      JSON.stringify({ codeVerifier: pkce.codeVerifier, createdAt: Date.now() }),
    );
    window.location.assign(url);
  }

  async handleCallback(input?: {
    url?: string;
    code?: string;
    state?: string;
    codeVerifier?: string;
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

    const tokenRes = await this.fetchImpl(`${this.issuer}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        code_verifier: verifier,
      }),
    });

    const tokenBody = (await tokenRes.json().catch(() => ({}))) as Partial<XelorraTokenSet> & {
      error?: string;
      error_description?: string;
    };
    if (!tokenRes.ok || !tokenBody.access_token) {
      throw new XelorraAuthError(
        tokenBody.error || "token_exchange_failed",
        tokenBody.error_description || "Unable to exchange authorization code.",
        tokenRes.status,
      );
    }

    this.tokens = tokenBody as XelorraTokenSet;
    const user = await this.getUser(this.tokens.access_token);
    return { tokens: this.tokens, user };
  }

  async refreshSession(refreshToken?: string): Promise<XelorraTokenSet> {
    const rt = refreshToken ?? this.tokens?.refresh_token;
    if (!rt) {
      throw new XelorraAuthError("missing_refresh_token", "No refresh token available.");
    }
    const res = await this.fetchImpl(`${this.issuer}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: rt,
        client_id: this.clientId,
      }),
    });
    const body = (await res.json().catch(() => ({}))) as Partial<XelorraTokenSet> & {
      error?: string;
      error_description?: string;
    };
    if (!res.ok || !body.access_token) {
      this.tokens = null;
      this.cachedUser = null;
      throw new XelorraAuthError(
        body.error || "refresh_failed",
        body.error_description || "Unable to refresh session.",
        res.status,
      );
    }
    this.tokens = body as XelorraTokenSet;
    return this.tokens;
  }

  async getUser(accessToken?: string): Promise<XelorraUserClaims> {
    const token = accessToken ?? this.tokens?.access_token;
    if (!token) {
      throw new XelorraAuthError("unauthenticated", "No active Xelorra access token.");
    }
    const res = await this.fetchImpl(`${this.issuer}/oauth/userinfo`, {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
    });
    const body = (await res.json().catch(() => ({}))) as XelorraUserClaims & {
      error?: string;
      error_description?: string;
    };
    if (!res.ok) {
      throw new XelorraAuthError(
        body.error || "userinfo_failed",
        body.error_description || "Failed to load user identity claims.",
        res.status,
      );
    }
    this.cachedUser = body;
    return body;
  }

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
      error?: string;
      error_description?: string;
    };
    if (!res.ok || !body.assertion) {
      throw new XelorraAuthError(
        body.error || "assertion_failed",
        body.error_description || "Failed to retrieve Reusable KYC verification assertion.",
        res.status,
      );
    }
    return body.assertion;
  }

  async revokeToken(tokenToRevoke?: string): Promise<void> {
    const token = tokenToRevoke ?? this.tokens?.refresh_token ?? this.tokens?.access_token;
    if (!token) return;
    await this.fetchImpl(`${this.issuer}/oauth/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
  }

  async logout(): Promise<void> {
    try {
      await this.revokeToken();
    } finally {
      this.tokens = null;
      this.cachedUser = null;
    }
  }

  getCachedUser(): XelorraUserClaims | null {
    return this.cachedUser;
  }
}

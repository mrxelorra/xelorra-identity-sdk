export type XelorraEnvironment = "development" | "staging" | "production";

/**
 * Standard OIDC `prompt` parameter values supported by Xelorra One.
 * Use `"create"` (or `buildSignUpUrl` / `signUp`) to send new users straight
 * to Xelorra ID registration before returning to the OAuth consent screen.
 */
export type XelorraPrompt = "login" | "consent" | "create" | "none";

/**
 * Configuration options for initializing `XelorraClient` or calling
 * standalone functional helpers.
 */
export interface XelorraClientConfig {
  /** Public OAuth 2.0 client identifier registered on Xelorra One. */
  clientId: string;
  /**
   * Default callback URL registered for this client.
   * Optional for backend-only clients that only call `introspectToken` or `revokeToken`.
   */
  redirectUri?: string;
  /**
   * Optional confidential client secret for server-side token exchange,
   * refresh, introspection, or revocation calls. Never expose in browser bundles.
   */
  clientSecret?: string;
  /** Base URL of the Xelorra Identity issuer. Defaults to `"https://one.xelorra.app"`. */
  issuer?: string;
  /** Target deployment environment label. Defaults to `"production"`. */
  environment?: XelorraEnvironment;
  /** Default OAuth scopes requested during authorization. */
  scopes?: string[];
  /** Optional custom `fetch` implementation for tests or custom HTTP agents. */
  fetchImpl?: typeof fetch;
}

/** Backwards-compatible alias for `XelorraClientConfig`. */
export type XelorraAuthConfig = XelorraClientConfig;

/** RFC 7636 PKCE S256 verifier, challenge, and CSRF state bundle. */
export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  state: string;
}

/** Options accepted by `buildAuthorizeUrl` and `loginWithRedirect`. */
export interface AuthorizeUrlOptions {
  /** Override default scopes for this authorization request. */
  scopes?: string[];
  /** Custom CSRF state string. Generated automatically when omitted. */
  state?: string;
  /** Pre-generated PKCE pair. Generated automatically when omitted. */
  pkce?: PkcePair;
  /** Override the client's default `redirectUri` for this request. */
  redirectUri?: string;
  /** Optional OIDC `prompt` directive (`"create"`, `"login"`, `"consent"`, or `"none"`). */
  prompt?: XelorraPrompt;
  /** Optional email or Xelorra ID hint to pre-fill on the sign-in screen. */
  loginHint?: string;
  /** Additional custom query parameters appended to `/oauth/authorize`. */
  extraParams?: Record<string, string>;
}

/** Options accepted by `exchangeCodeForTokens`. */
export interface ExchangeCodeOptions {
  /** Authorization code returned on the redirect callback. */
  code: string;
  /** PKCE `code_verifier` matching the `code_challenge` sent to `/oauth/authorize`. */
  codeVerifier: string;
  /** Redirect URI used in the initial authorize request. Falls back to `config.redirectUri`. */
  redirectUri?: string;
}

/** Options accepted by `refreshTokens`. */
export interface RefreshTokensOptions {
  /** Active refresh token issued by Xelorra One. */
  refreshToken: string;
  /** Optional narrowed scope list for the refreshed token. */
  scope?: string;
}

/** OAuth 2.0 token response returned by `POST /oauth/token`. */
export interface XelorraTokenSet {
  access_token: string;
  refresh_token?: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  xid?: string | null;
}

/** Minimum-disclosure Reusable KYC verification assertion. */
export interface XelorraKycAssertion {
  verification_status: "verified" | "pending" | "unverified";
  verification_level: "none" | "basic" | "verified" | "government_verified";
  verification_reference: string | null;
  verified_at: string | null;
  country: string | null;
}

/** User identity claims returned by `GET /oauth/userinfo`. */
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

/** Typed token introspection payload returned by `POST /oauth/introspect`. */
export interface XelorraIntrospectionResult {
  active: boolean;
  connected: boolean;
  client_id: string | null;
  sub: string | null;
  xid: string | null;
  scope: string | null;
  exp: number | null;
  reason: string | null;
}

/** Payload delivered with a `user.access_revoked` webhook event. */
export interface XelorraAccessRevokedEventData {
  sub: string;
  xid?: string | null;
  client_id: string;
  revoked_at: string;
  reason?: string | null;
  [key: string]: unknown;
}

/** Payload delivered with a `user.connected` webhook event. */
export interface XelorraUserConnectedEventData {
  sub: string;
  xid?: string | null;
  client_id: string;
  scopes?: string[];
  connected_at: string;
  [key: string]: unknown;
}

/** Payload delivered with a `user.verification_updated` webhook event. */
export interface XelorraVerificationUpdatedEventData {
  sub: string;
  xid?: string | null;
  client_id?: string;
  verification_status: XelorraKycAssertion["verification_status"];
  verification_level: XelorraKycAssertion["verification_level"];
  updated_at: string;
  [key: string]: unknown;
}

/** Generic signed webhook envelope sent by Xelorra One. */
export interface XelorraWebhookEnvelope<
  TType extends string = string,
  TData extends Record<string, unknown> = Record<string, unknown>,
> {
  id: string;
  type: TType;
  created_at: string;
  data: TData;
}

export type XelorraAccessRevokedWebhookEvent = XelorraWebhookEnvelope<
  "user.access_revoked",
  XelorraAccessRevokedEventData
>;

export type XelorraUserConnectedWebhookEvent = XelorraWebhookEnvelope<
  "user.connected",
  XelorraUserConnectedEventData
>;

export type XelorraVerificationUpdatedWebhookEvent = XelorraWebhookEnvelope<
  "user.verification_updated",
  XelorraVerificationUpdatedEventData
>;

export type XelorraWebhookEvent =
  | XelorraAccessRevokedWebhookEvent
  | XelorraUserConnectedWebhookEvent
  | XelorraVerificationUpdatedWebhookEvent
  | XelorraWebhookEnvelope<string, Record<string, unknown>>;

import type { XelorraScope, XelorraWebhookEventType } from "./constants.js";

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
  /** Alias for `issuer`. Takes effect when `issuer` is omitted. */
  baseUrl?: string;
  /** Target deployment environment label. Defaults to `"production"`. */
  environment?: XelorraEnvironment;
  /** Default OAuth scopes requested during authorization. */
  scopes?: (XelorraScope | (string & {}))[];
  /** Optional custom `fetch` implementation for tests or custom HTTP agents. */
  fetchImpl?: typeof fetch;
}

/** Backwards-compatible alias for `XelorraClientConfig`. */
export type XelorraAuthConfig = XelorraClientConfig;

/** Options for public zero-auth helper calls (discovery, JWKS, passport QR verify, XID check). */
export interface XelorraPublicRequestOptions {
  /** Base URL of the Xelorra Identity issuer. Defaults to `"https://one.xelorra.app"`. */
  issuer?: string;
  /** Alias for `issuer`. */
  baseUrl?: string;
  /** Optional custom `fetch` implementation. */
  fetchImpl?: typeof fetch;
}

/** RFC 7636 PKCE S256 verifier, challenge, and CSRF state bundle. */
export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  state: string;
}

/** OpenID Connect Discovery document from `GET /.well-known/openid-configuration`. */
export interface XelorraDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  introspection_endpoint: string;
  revocation_endpoint: string;
  end_session_endpoint: string;
  jwks_uri: string;
  scopes_supported: string[];
  code_challenge_methods_supported: string[];
  [key: string]: unknown;
}

/** Single JSON Web Key from `GET /.well-known/jwks.json`. */
export interface XelorraJwk {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  [key: string]: unknown;
}

/** JSON Web Key Set from `GET /.well-known/jwks.json`. */
export interface XelorraJwksResponse {
  keys: XelorraJwk[];
}

/** Options accepted by `buildAuthorizeUrl`, `buildSignInUrl`, and `loginWithRedirect`. */
export interface AuthorizeUrlOptions {
  /** Override default scopes for this authorization request. */
  scopes?: (XelorraScope | (string & {}))[];
  /** Custom CSRF state string. Generated automatically when omitted. */
  state?: string;
  /** Pre-generated PKCE pair. Generated automatically when omitted. */
  pkce?: PkcePair;
  /** Override the client's default `redirectUri` for this request. */
  redirectUri?: string;
  /** Optional OIDC `prompt` directive (`"create"`, `"login"`, `"consent"`, or `"none"`). */
  prompt?: XelorraPrompt;
  /** Optional email, `XLR-XXXX-XXXX`, or memorable XID (`username.4821`) hint. */
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
  /** Active single-use rotating refresh token issued by Xelorra One. */
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

/** Minimum-disclosure Reusable KYC verification assertion from `POST /api/v1/verify/assertion`. */
export interface XelorraKycAssertion {
  verification_status: "verified" | "pending" | "unverified";
  verification_type: "government_identity" | "ecosystem_identity";
  verification_reference: string | null;
  verified_at: string | null;
  credential_category?: "nin" | "bvn" | "national_id";
  /** Optional compatibility field when returned by legacy or extended verifiers. */
  verification_level?: string;
  country?: string | null;
  [key: string]: unknown;
}

/** User identity claims returned by `GET /oauth/userinfo`. */
export interface XelorraUserClaims {
  /** Pairwise tenant-isolated subject (`xapp_...`) for third-party apps, or `xid` for first-party apps. */
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
  address?: Record<string, unknown> | string;
  country?: string;
  verification_level?: string;
  verification_status?: string;
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
  reason: "access_revoked" | "account_suspended" | "missing_token" | (string & {}) | null;
}

/** Response returned by `POST /oauth/revoke`. */
export interface XelorraRevokeResult {
  revoked: boolean;
}

/** Response returned by `POST /oauth/logout`. */
export interface XelorraLogoutResult {
  loggedOut: boolean;
  message?: string;
}

/** Options for `verifyPassportToken`. */
export interface VerifyPassportTokenOptions extends XelorraPublicRequestOptions {
  /**
   * Choose `"public"` (`GET /api/v1/public/verify/:token`, logs scan to member's
   * "Who checked my passport" history) or `"selective"` (`GET /api/v1/verify/:token`).
   * Defaults to `"public"`.
   */
  endpoint?: "public" | "selective";
}

/** Response returned by `GET /api/v1/public/verify/:token` or `GET /api/v1/verify/:token`. */
export interface XelorraPassportVerificationResult {
  valid: boolean;
  reason?: string;
  xid?: string;
  name?: string;
  tier?: string;
  status?: string;
  verified?: boolean;
  memberSince?: string;
  mode?: string;
  expiresAt?: string;
  checkedAt?: string;
  sharedFields?: string[];
  disclaimer?: string;
  [key: string]: unknown;
}

/** Response returned by `GET /api/v1/xid/check?username=<handle>`. */
export interface XelorraXidAvailabilityResult {
  available: boolean;
  suggestions?: string[];
  reason?: string;
  [key: string]: unknown;
}

/** Payload delivered with a `user.access_revoked` webhook event. */
export interface XelorraAccessRevokedEventData {
  xid: string | null;
  sub: string;
  client_id: string;
  revoked_at: string;
  reason: "user_disconnected" | (string & {});
  [key: string]: unknown;
}

/** Payload delivered with `user.permissions_updated` webhook events. */
export interface XelorraPermissionsUpdatedEventData {
  xid?: string | null;
  sub: string;
  client_id: string;
  scopes?: string[];
  updated_at?: string;
  [key: string]: unknown;
}

/** Payload delivered with `user.account_suspended` webhook events. */
export interface XelorraAccountSuspendedEventData {
  xid?: string | null;
  sub: string;
  client_id?: string;
  suspended_at?: string;
  reason?: string;
  [key: string]: unknown;
}

/** Payload delivered with verification webhook events (`user.email_verified`, `user.phone_verified`, `user.identity_verified`). */
export interface XelorraVerificationEventData {
  xid?: string | null;
  sub: string;
  client_id?: string;
  verification_status?: XelorraKycAssertion["verification_status"];
  verification_type?: XelorraKycAssertion["verification_type"];
  verified_at?: string;
  [key: string]: unknown;
}

/** Generic signed webhook envelope sent by Xelorra One. */
export interface XelorraWebhookEnvelope<
  TType extends string = XelorraWebhookEventType,
  TData extends Record<string, unknown> = Record<string, unknown>,
> {
  id: string;
  type: TType;
  created_at: string;
  client_id: string;
  data: TData;
}

export type XelorraAccessRevokedWebhookEvent = XelorraWebhookEnvelope<
  "user.access_revoked",
  XelorraAccessRevokedEventData
>;

export type XelorraPermissionsUpdatedWebhookEvent = XelorraWebhookEnvelope<
  "user.permissions_updated",
  XelorraPermissionsUpdatedEventData
>;

export type XelorraAccountSuspendedWebhookEvent = XelorraWebhookEnvelope<
  "user.account_suspended",
  XelorraAccountSuspendedEventData
>;

export type XelorraIdentityVerifiedWebhookEvent = XelorraWebhookEnvelope<
  "user.identity_verified",
  XelorraVerificationEventData
>;

export type XelorraWebhookEvent =
  | XelorraAccessRevokedWebhookEvent
  | XelorraPermissionsUpdatedWebhookEvent
  | XelorraAccountSuspendedWebhookEvent
  | XelorraIdentityVerifiedWebhookEvent
  | XelorraWebhookEnvelope<XelorraWebhookEventType, Record<string, unknown>>
  | XelorraWebhookEnvelope<string, Record<string, unknown>>;

/** Options object for `verifyWebhookSignature` and `parseWebhookEvent`. */
export interface VerifyWebhookOptions {
  /** Exact raw request payload string or bytes before JSON parsing. */
  rawBody: string | Uint8Array;
  /** Value of the `X-Xelorra-Signature` header (`t=<unix_seconds>,v1=<hmac_sha256_hex>`). */
  signatureHeader: string | null | undefined;
  /** Signing secret configured for this webhook endpoint in Xelorra Developer Console. */
  signingSecret: string;
  /** Maximum allowed timestamp skew in seconds to prevent replay attacks. Defaults to `300`. */
  toleranceSeconds?: number;
  /** Optional current Unix timestamp in seconds (primarily for deterministic unit testing). */
  nowSeconds?: number;
}

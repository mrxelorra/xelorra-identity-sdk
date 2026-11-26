export {
  ALL_XELORRA_WEBHOOK_EVENTS,
  DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
  DEFAULT_XELORRA_ISSUER,
  DEFAULT_XELORRA_SCOPES,
  KYC_ASSERTION_SCOPES,
  XELORRA_EVENT_HEADER,
  XELORRA_EVENT_ID_HEADER,
  XELORRA_SCOPES,
  XELORRA_SCOPE_CATALOG,
  XELORRA_SIGNATURE_HEADER,
  XELORRA_WEBHOOK_EVENTS,
  type XelorraScope,
  type XelorraScopeMetadata,
  type XelorraWebhookEventType,
} from "./constants.js";

export {
  XelorraAuth,
  XelorraClient,
  buildAuthorizeUrl,
  buildSignInUrl,
  buildSignUpUrl,
  checkXidAvailability,
  exchangeCodeForTokens,
  fetchDiscovery,
  fetchJwks,
  getUserInfo,
  introspectToken,
  isUserConnected,
  logout,
  refreshTokens,
  revokeToken,
  verifyKycAssertion,
  verifyPassportToken,
} from "./client.js";

export {
  XelorraAccessRevokedError,
  XelorraAuthError,
  XelorraError,
  XelorraInsufficientScopeError,
  XelorraWebhookSignatureError,
  type XelorraWebhookSignatureErrorCode,
} from "./errors.js";

export { bytesToBase64Url, createPkcePair } from "./pkce.js";

export {
  computeWebhookSignature,
  parseSignatureHeader,
  parseWebhookEvent,
  verifyWebhookSignature,
} from "./webhooks.js";

export {
  createDisconnectGuard,
  type DisconnectGuard,
  type DisconnectGuardCheckResult,
  type DisconnectGuardOptions,
  type DisconnectGuardRevokedInfo,
} from "./sync.js";

export type {
  AuthorizeUrlOptions,
  ExchangeCodeOptions,
  PkcePair,
  RefreshTokensOptions,
  VerifyPassportTokenOptions,
  VerifyWebhookOptions,
  XelorraAccessRevokedEventData,
  XelorraAccessRevokedWebhookEvent,
  XelorraAccountSuspendedEventData,
  XelorraAccountSuspendedWebhookEvent,
  XelorraAuthConfig,
  XelorraClientConfig,
  XelorraDiscoveryDocument,
  XelorraEnvironment,
  XelorraIdentityVerifiedWebhookEvent,
  XelorraIntrospectionResult,
  XelorraJwk,
  XelorraJwksResponse,
  XelorraKycAssertion,
  XelorraLogoutResult,
  XelorraPassportVerificationResult,
  XelorraPermissionsUpdatedEventData,
  XelorraPermissionsUpdatedWebhookEvent,
  XelorraPrompt,
  XelorraPublicRequestOptions,
  XelorraRevokeResult,
  XelorraTokenSet,
  XelorraUserClaims,
  XelorraVerificationEventData,
  XelorraWebhookEnvelope,
  XelorraWebhookEvent,
  XelorraXidAvailabilityResult,
} from "./types.js";

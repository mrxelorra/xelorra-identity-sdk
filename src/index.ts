export {
  DEFAULT_XELORRA_ISSUER,
  DEFAULT_XELORRA_SCOPES,
  XelorraAuth,
  XelorraClient,
  buildAuthorizeUrl,
  buildSignUpUrl,
  exchangeCodeForTokens,
  getUserInfo,
  introspectToken,
  refreshTokens,
  revokeToken,
} from "./client.js";

export {
  XelorraAccessRevokedError,
  XelorraAuthError,
  XelorraWebhookSignatureError,
  type XelorraWebhookSignatureErrorCode,
} from "./errors.js";

export { bytesToBase64Url, createPkcePair } from "./pkce.js";

export {
  XELORRA_SIGNATURE_HEADER,
  computeWebhookSignature,
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
  XelorraAccessRevokedEventData,
  XelorraAccessRevokedWebhookEvent,
  XelorraAuthConfig,
  XelorraClientConfig,
  XelorraEnvironment,
  XelorraIntrospectionResult,
  XelorraKycAssertion,
  XelorraPrompt,
  XelorraTokenSet,
  XelorraUserClaims,
  XelorraUserConnectedEventData,
  XelorraUserConnectedWebhookEvent,
  XelorraVerificationUpdatedEventData,
  XelorraVerificationUpdatedWebhookEvent,
  XelorraWebhookEnvelope,
  XelorraWebhookEvent,
} from "./types.js";

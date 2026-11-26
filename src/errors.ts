/**
 * Base error thrown by `@xelorra/identity` for configuration, network,
 * OAuth 2.0, OIDC, KYC, passport verification, or webhook failures.
 */
export class XelorraError extends Error {
  /** Machine-readable error code (for example `"access_denied"` or `"insufficient_scope"`). */
  readonly code: string;
  /** HTTP status code returned by Xelorra One when available. */
  readonly status?: number;
  /** Optional structured error metadata returned by the server. */
  readonly details?: Record<string, unknown>;

  constructor(
    code: string,
    message: string,
    status?: number,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "XelorraError";
    this.code = code;
    this.status = status;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error thrown when an OAuth 2.0, OIDC, or authenticated API request fails.
 */
export class XelorraAuthError extends XelorraError {
  constructor(
    code: string,
    message: string,
    status?: number,
    details?: Record<string, unknown>,
  ) {
    super(code, message, status, details);
    this.name = "XelorraAuthError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when Xelorra One responds with HTTP 401 and `error: "access_revoked"`.
 * Partner applications should catch this error to clear the user's local session
 * and prompt them to reconnect if needed.
 */
export class XelorraAccessRevokedError extends XelorraAuthError {
  /** Optional server-provided revocation reason (for example `"user_disconnected"`). */
  readonly reason?: string;

  constructor(
    message = "The user has revoked this application's access on Xelorra One.",
    reason?: string,
    details?: Record<string, unknown>,
  ) {
    super("access_revoked", message, 401, details);
    this.name = "XelorraAccessRevokedError";
    this.reason = reason;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when Xelorra One responds with HTTP 403 and `error: "insufficient_scope"`.
 */
export class XelorraInsufficientScopeError extends XelorraAuthError {
  /** Optional list of scopes required for the attempted operation. */
  readonly requiredScopes?: string[];

  constructor(
    message = "The access token does not include the required scope for this endpoint.",
    requiredScopes?: string[],
    details?: Record<string, unknown>,
  ) {
    super("insufficient_scope", message, 403, details);
    this.name = "XelorraInsufficientScopeError";
    this.requiredScopes = requiredScopes;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type XelorraWebhookSignatureErrorCode =
  | "missing_webhook_secret"
  | "missing_signature"
  | "malformed_signature"
  | "expired_timestamp"
  | "invalid_signature"
  | "invalid_payload";

/**
 * Thrown when an incoming Xelorra webhook cannot be authenticated or parsed.
 */
export class XelorraWebhookSignatureError extends XelorraError {
  declare readonly code: XelorraWebhookSignatureErrorCode;

  constructor(code: XelorraWebhookSignatureErrorCode, message: string) {
    super(code, message, 401);
    this.name = "XelorraWebhookSignatureError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

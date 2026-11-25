/**
 * Base error thrown by `@xelorra/identity` when an OAuth 2.0, OIDC,
 * configuration, or API request fails.
 */
export class XelorraAuthError extends Error {
  /** Machine-readable OAuth or SDK error code (for example `"access_denied"`). */
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
    this.name = "XelorraAuthError";
    this.code = code;
    this.status = status;
    this.details = details;
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

export type XelorraWebhookSignatureErrorCode =
  | "missing_webhook_secret"
  | "missing_signature"
  | "invalid_signature"
  | "invalid_payload";

/**
 * Thrown when an incoming Xelorra webhook cannot be authenticated or parsed.
 */
export class XelorraWebhookSignatureError extends XelorraAuthError {
  declare readonly code: XelorraWebhookSignatureErrorCode;

  constructor(code: XelorraWebhookSignatureErrorCode, message: string) {
    super(code, message, 401);
    this.name = "XelorraWebhookSignatureError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

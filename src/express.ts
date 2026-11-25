import type { XelorraClient } from "./client.js";
import { XelorraAuthError, XelorraWebhookSignatureError } from "./errors.js";
import { createDisconnectGuard } from "./sync.js";
import type {
  XelorraAccessRevokedWebhookEvent,
  XelorraIntrospectionResult,
  XelorraTokenSet,
  XelorraUserClaims,
  XelorraWebhookEvent,
} from "./types.js";
import { parseWebhookEvent, XELORRA_SIGNATURE_HEADER } from "./webhooks.js";

/** Minimal Express-compatible request interface (zero runtime Express dependency). */
export interface ExpressRequestLike {
  headers: Record<string, string | string[] | undefined>;
  query?: Record<string, unknown>;
  body?: unknown;
  rawBody?: string | Uint8Array;
  xelorra?: {
    token: string;
    introspection: XelorraIntrospectionResult;
  };
}

/** Minimal Express-compatible response interface. */
export interface ExpressResponseLike {
  status: (code: number) => ExpressResponseLike;
  json: (payload: unknown) => unknown;
}

export type ExpressNextFunction = (err?: unknown) => void;

export type ExpressHandler<TReq extends ExpressRequestLike = ExpressRequestLike> = (
  req: TReq,
  res: ExpressResponseLike,
  next: ExpressNextFunction,
) => void | Promise<void>;

function readHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const lower = name.toLowerCase();
  const value = headers[lower] ?? headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function readQueryParam(query: Record<string, unknown> | undefined, key: string): string {
  const value = query?.[key];
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return "";
}

export interface ExpressCallbackHandlerOptions<TReq extends ExpressRequestLike = ExpressRequestLike> {
  client: XelorraClient;
  /** Resolve the PKCE `codeVerifier` stored in your session/cookie for the given `state`. */
  resolveCodeVerifier: (
    state: string,
    req: TReq,
  ) => string | null | undefined | Promise<string | null | undefined>;
  /** Called once tokens and user claims are loaded. Create your session or redirect here. */
  onSuccess: (
    result: { tokens: XelorraTokenSet; user: XelorraUserClaims; state: string },
    req: TReq,
    res: ExpressResponseLike,
  ) => void | Promise<void>;
  /** Optional custom error handler. Defaults to responding with HTTP 400/401 JSON. */
  onError?: (err: unknown, req: TReq, res: ExpressResponseLike) => void | Promise<void>;
}

/**
 * Creates an Express route handler for your OAuth 2.0 + PKCE callback route
 * (for example `GET /auth/xelorra/callback`).
 */
export function createExpressCallbackHandler<
  TReq extends ExpressRequestLike = ExpressRequestLike,
>(options: ExpressCallbackHandlerOptions<TReq>): ExpressHandler<TReq> {
  return async (req, res) => {
    try {
      const oauthError = readQueryParam(req.query, "error");
      if (oauthError) {
        throw new XelorraAuthError(
          oauthError,
          readQueryParam(req.query, "error_description") || "Authorization was denied.",
          400,
        );
      }

      const code = readQueryParam(req.query, "code");
      const state = readQueryParam(req.query, "state");
      if (!code) {
        throw new XelorraAuthError("missing_code", "Authorization code is missing.", 400);
      }

      const codeVerifier = (await options.resolveCodeVerifier(state, req)) ?? "";
      if (!codeVerifier) {
        throw new XelorraAuthError(
          "missing_pkce_verifier",
          "PKCE code_verifier is missing or expired.",
          400,
        );
      }

      const tokens = await options.client.exchangeCodeForTokens({ code, codeVerifier });
      const user = await options.client.getUserInfo(tokens.access_token);
      await options.onSuccess({ tokens, user, state }, req, res);
    } catch (err) {
      if (options.onError) {
        await options.onError(err, req, res);
        return;
      }
      const status = err instanceof XelorraAuthError && err.status ? err.status : 400;
      const code = err instanceof XelorraAuthError ? err.code : "callback_failed";
      const message = err instanceof Error ? err.message : "OAuth callback failed.";
      res.status(status).json({ error: code, error_description: message });
    }
  };
}

export interface ExpressAuthMiddlewareOptions<TReq extends ExpressRequestLike = ExpressRequestLike> {
  client: XelorraClient;
  /**
   * Resolves the user's Xelorra access token from the request.
   * Defaults to parsing `Authorization: Bearer <token>`.
   */
  getToken?: (req: TReq) => string | null | undefined | Promise<string | null | undefined>;
  /** Called automatically when Xelorra One reports the connection has been revoked. */
  onRevoked?: (info: {
    reason: string;
    introspection?: XelorraIntrospectionResult;
    req: TReq;
  }) => void | Promise<void>;
  /** Optional introspection cache TTL in ms. Defaults to `0` (always introspect live). */
  cacheTtlMs?: number;
}

/**
 * Creates an Express authentication middleware backed by `createDisconnectGuard`
 * and `POST /oauth/introspect`. Rejects revoked or inactive tokens with HTTP 401
 * and invokes `onRevoked` so local sessions stay synchronized with Xelorra One.
 */
export function createExpressAuthMiddleware<
  TReq extends ExpressRequestLike = ExpressRequestLike,
>(options: ExpressAuthMiddlewareOptions<TReq>): ExpressHandler<TReq> {
  const resolveToken =
    options.getToken ??
    ((req: TReq) => {
      const header = readHeader(req.headers, "authorization");
      if (!header || !header.startsWith("Bearer ")) return null;
      return header.slice(7).trim() || null;
    });

  const guard = createDisconnectGuard<TReq>({
    client: options.client,
    getToken: resolveToken,
    cacheTtlMs: options.cacheTtlMs,
    onRevoked: async ({ reason, introspection, context }) => {
      await options.onRevoked?.({ reason, introspection, req: context });
    },
  });

  return async (req, res, next) => {
    try {
      const result = await guard.check(req);
      if (!result.active || !result.token || !result.introspection) {
        const reason = result.introspection?.reason || "unauthenticated";
        res.status(401).json({
          error: result.token ? "access_revoked" : "unauthenticated",
          reason,
        });
        return;
      }
      req.xelorra = { token: result.token, introspection: result.introspection };
      next();
    } catch (err) {
      next(err);
    }
  };
}

export interface ExpressWebhookHandlerOptions<TReq extends ExpressRequestLike = ExpressRequestLike> {
  webhookSecret: string;
  /** Called for `user.access_revoked` events after signature verification succeeds. */
  onAccessRevoked?: (
    event: XelorraAccessRevokedWebhookEvent,
    req: TReq,
  ) => void | Promise<void>;
  /** Called for every verified webhook event. */
  onEvent?: (event: XelorraWebhookEvent, req: TReq) => void | Promise<void>;
  /** Optional custom error handler for signature or processing failures. */
  onError?: (err: unknown, req: TReq, res: ExpressResponseLike) => void | Promise<void>;
}

/**
 * Creates an Express webhook handler for `POST /webhooks/xelorra`.
 *
 * Mount this route with `express.raw({ type: "application/json" })` (or expose
 * `req.rawBody`) so HMAC-SHA256 verification runs against the exact raw request bytes.
 */
export function createExpressWebhookHandler<
  TReq extends ExpressRequestLike = ExpressRequestLike,
>(options: ExpressWebhookHandlerOptions<TReq>): ExpressHandler<TReq> {
  return async (req, res) => {
    try {
      const rawBody =
        req.rawBody !== undefined
          ? req.rawBody
          : typeof req.body === "string" || req.body instanceof Uint8Array
            ? req.body
            : null;

      if (rawBody === null) {
        throw new XelorraWebhookSignatureError(
          "invalid_payload",
          "Raw request body is required. Mount express.raw({ type: 'application/json' }) before this handler.",
        );
      }

      const signature = readHeader(req.headers, XELORRA_SIGNATURE_HEADER);
      const event = await parseWebhookEvent(rawBody, signature, options.webhookSecret);

      if (event.type === "user.access_revoked" && options.onAccessRevoked) {
        await options.onAccessRevoked(event as XelorraAccessRevokedWebhookEvent, req);
      }
      if (options.onEvent) {
        await options.onEvent(event, req);
      }

      res.status(200).json({ received: true, event_type: event.type });
    } catch (err) {
      if (options.onError) {
        await options.onError(err, req, res);
        return;
      }
      const status = err instanceof XelorraWebhookSignatureError ? 401 : 500;
      const code = err instanceof XelorraWebhookSignatureError ? err.code : "webhook_error";
      const message = err instanceof Error ? err.message : "Webhook verification failed.";
      res.status(status).json({ error: code, error_description: message });
    }
  };
}

import type { XelorraClient } from "./client.js";
import { XelorraAuthError, XelorraWebhookSignatureError } from "./errors.js";
import { createDisconnectGuard } from "./sync.js";
import type {
  AuthorizeUrlOptions,
  PkcePair,
  XelorraAccessRevokedWebhookEvent,
  XelorraIntrospectionResult,
  XelorraTokenSet,
  XelorraUserClaims,
  XelorraWebhookEvent,
} from "./types.js";
import { parseWebhookEvent, XELORRA_SIGNATURE_HEADER } from "./webhooks.js";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export interface NextAuthRedirectHandlerOptions {
  client: XelorraClient;
  /** Choose `"signin"` (default) or `"signup"` (automatically adds `prompt=create`). */
  mode?: "signin" | "signup";
  /** Optional default scopes override. */
  scopes?: AuthorizeUrlOptions["scopes"];
  /**
   * Persist the generated PKCE `codeVerifier` keyed by `state` (for example in an
   * HttpOnly cookie or server-side store). Optionally return extra headers such as
   * `Set-Cookie` to attach to the 302 redirect response.
   */
  saveCodeVerifier: (
    pkce: PkcePair,
    request: Request,
  ) => void | HeadersInit | Promise<void | HeadersInit>;
}

/**
 * Creates a Next.js App Router `GET` route handler that generates a PKCE `S256` pair,
 * persists the `codeVerifier`, and redirects to Xelorra One (`/oauth/authorize` or
 * `/oauth/authorize?prompt=create` when `mode: "signup"`).
 */
export function createNextAuthRedirectHandler(
  options: NextAuthRedirectHandlerOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const reqUrl = new URL(request.url);
    const queryPrompt = reqUrl.searchParams.get("prompt");
    const loginHint = reqUrl.searchParams.get("login_hint") ?? undefined;
    const isSignUp = options.mode === "signup" || queryPrompt === "create";

    const { url, pkce } = isSignUp
      ? await options.client.buildSignUpUrl({ scopes: options.scopes, loginHint })
      : await options.client.buildSignInUrl({ scopes: options.scopes, loginHint });

    const extraHeaders = await options.saveCodeVerifier(pkce, request);
    const headers = new Headers(extraHeaders || undefined);
    headers.set("location", url);
    headers.set("cache-control", "no-store");

    return new Response(null, { status: 302, headers });
  };
}

export interface NextCallbackHandlerOptions {
  client: XelorraClient;
  /** Resolve the PKCE `codeVerifier` from your encrypted cookie or session store. */
  resolveCodeVerifier: (
    state: string,
    request: Request,
  ) => string | null | undefined | Promise<string | null | undefined>;
  /** Called once the authorization code is exchanged and user claims are fetched. */
  onSuccess: (
    result: { tokens: XelorraTokenSet; user: XelorraUserClaims; state: string },
    request: Request,
  ) => Response | Promise<Response>;
  /** Optional error response builder. Defaults to JSON error responses. */
  onError?: (error: unknown, request: Request) => Response | Promise<Response>;
}

/**
 * Creates a Next.js App Router `GET` route handler for OAuth 2.0 + PKCE callbacks
 * (for example `app/api/auth/xelorra/callback/route.ts`).
 */
export function createNextCallbackHandler(
  options: NextCallbackHandlerOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    try {
      const url = new URL(request.url);
      const oauthError = url.searchParams.get("error");
      if (oauthError) {
        throw new XelorraAuthError(
          oauthError,
          url.searchParams.get("error_description") || "Authorization was denied.",
          400,
        );
      }

      const code = url.searchParams.get("code") || "";
      const state = url.searchParams.get("state") || "";
      if (!code) {
        throw new XelorraAuthError("missing_code", "Authorization code is missing.", 400);
      }

      const codeVerifier = (await options.resolveCodeVerifier(state, request)) ?? "";
      if (!codeVerifier) {
        throw new XelorraAuthError(
          "missing_pkce_verifier",
          "PKCE code_verifier is missing or expired.",
          400,
        );
      }

      const tokens = await options.client.exchangeCodeForTokens({ code, codeVerifier });
      const user = await options.client.getUserInfo(tokens.access_token);
      return await options.onSuccess({ tokens, user, state }, request);
    } catch (err) {
      if (options.onError) {
        return await options.onError(err, request);
      }
      const status = err instanceof XelorraAuthError && err.status ? err.status : 400;
      const code = err instanceof XelorraAuthError ? err.code : "callback_failed";
      const message = err instanceof Error ? err.message : "OAuth callback failed.";
      return jsonResponse({ error: code, error_description: message }, status);
    }
  };
}

export interface NextSessionGuardOptions {
  client: XelorraClient;
  /** Resolve the user's Xelorra access token from the request, cookie, or session store. */
  getAccessToken: (
    request: Request,
  ) => string | null | undefined | Promise<string | null | undefined>;
  /** Invoked automatically when Xelorra One reports the session is revoked or suspended. */
  onRevoked: (info: {
    reason: string;
    introspection?: XelorraIntrospectionResult;
    request: Request;
  }) => void | Promise<void>;
  /** Optional introspection cache TTL in milliseconds. Defaults to `0`. */
  cacheTtlMs?: number;
}

/**
 * Creates a revocation-aware Next.js App Router session helper backed by
 * `POST /oauth/introspect` and `createDisconnectGuard`.
 */
export function createNextSessionGuard(options: NextSessionGuardOptions) {
  const guard = createDisconnectGuard<Request>({
    client: options.client,
    getAccessToken: options.getAccessToken,
    cacheTtlMs: options.cacheTtlMs,
    onRevoked: async ({ reason, introspection, context }) => {
      await options.onRevoked({ reason, introspection, request: context });
    },
  });

  return {
    /** Verifies whether the incoming request still has an active Xelorra connection. */
    verifySession: (request: Request) => guard.check(request),
    /** Wraps an App Router handler and rejects revoked or missing sessions with HTTP 401. */
    withSession:
      (
        handler: (
          request: Request,
          session: { token: string; introspection: XelorraIntrospectionResult },
        ) => Response | Promise<Response>,
      ) =>
      async (request: Request): Promise<Response> => {
        const result = await guard.check(request);
        if (!result.active || !result.token || !result.introspection) {
          return jsonResponse(
            {
              error: result.token ? "access_revoked" : "unauthenticated",
              reason: result.introspection?.reason || "unauthenticated",
            },
            401,
          );
        }
        return handler(request, {
          token: result.token,
          introspection: result.introspection,
        });
      },
    invalidate: guard.invalidate,
  };
}

export interface NextWebhookHandlerOptions {
  /** Signing secret from Xelorra Developer Console. */
  signingSecret?: string;
  /** Backwards-compatible alias for `signingSecret`. */
  webhookSecret?: string;
  /** Maximum timestamp skew in seconds (defaults to `300`). */
  toleranceSeconds?: number;
  /** Called for verified `user.access_revoked` events. */
  onAccessRevoked?: (
    event: XelorraAccessRevokedWebhookEvent,
    request: Request,
  ) => void | Promise<void>;
  /** Called for all verified webhook events. */
  onEvent?: (event: XelorraWebhookEvent, request: Request) => void | Promise<void>;
  /** Optional custom error response builder. */
  onError?: (error: unknown, request: Request) => Response | Promise<Response>;
}

/**
 * Creates a Next.js App Router `POST` route handler for `/api/webhooks/xelorra`.
 * Reads the exact raw request text, verifies `X-Xelorra-Signature` (`t=<ts>,v1=<hex>`),
 * and dispatches typed webhook events.
 */
export function createNextWebhookHandler(
  options: NextWebhookHandlerOptions,
): (request: Request) => Promise<Response> {
  const secret = options.signingSecret ?? options.webhookSecret ?? "";

  return async (request: Request): Promise<Response> => {
    try {
      const rawBody = await request.text();
      const signature = request.headers.get(XELORRA_SIGNATURE_HEADER);
      const event = await parseWebhookEvent({
        rawBody,
        signatureHeader: signature,
        signingSecret: secret,
        toleranceSeconds: options.toleranceSeconds,
      });

      if (event.type === "user.access_revoked" && options.onAccessRevoked) {
        await options.onAccessRevoked(event as XelorraAccessRevokedWebhookEvent, request);
      }
      if (options.onEvent) {
        await options.onEvent(event, request);
      }

      return jsonResponse({ received: true, event_type: event.type }, 200);
    } catch (err) {
      if (options.onError) {
        return await options.onError(err, request);
      }
      const status = err instanceof XelorraWebhookSignatureError ? 401 : 500;
      const code = err instanceof XelorraWebhookSignatureError ? err.code : "webhook_error";
      const message = err instanceof Error ? err.message : "Webhook verification failed.";
      return jsonResponse({ error: code, error_description: message }, status);
    }
  };
}

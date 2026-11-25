import type { XelorraClient } from "./client.js";
import { XelorraAuthError, XelorraWebhookSignatureError } from "./errors.js";
import type {
  XelorraAccessRevokedWebhookEvent,
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

export interface NextWebhookHandlerOptions {
  webhookSecret: string;
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
 * Reads the exact raw request text, verifies `X-Xelorra-Signature`, and dispatches
 * typed webhook events.
 */
export function createNextWebhookHandler(
  options: NextWebhookHandlerOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    try {
      const rawBody = await request.text();
      const signature = request.headers.get(XELORRA_SIGNATURE_HEADER);
      const event = await parseWebhookEvent(rawBody, signature, options.webhookSecret);

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

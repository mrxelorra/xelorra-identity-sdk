import type { XelorraClient } from "./client.js";
import { XelorraAccessRevokedError } from "./errors.js";
import type { XelorraIntrospectionResult } from "./types.js";

export interface DisconnectGuardRevokedInfo<TContext = void> {
  reason: string;
  introspection?: XelorraIntrospectionResult;
  error?: XelorraAccessRevokedError;
  context: TContext;
}

export interface DisconnectGuardOptions<TContext = void> {
  /** Configured `XelorraClient` used to call `POST /oauth/introspect`. */
  client: XelorraClient;
  /** Resolves the user's current Xelorra access token for the given request or app context. */
  getToken: (
    context: TContext,
  ) => string | null | undefined | Promise<string | null | undefined>;
  /**
   * Callback invoked automatically whenever introspection shows the token is inactive
   * or disconnected, or whenever a guarded call throws `XelorraAccessRevokedError`.
   */
  onRevoked: (info: DisconnectGuardRevokedInfo<TContext>) => void | Promise<void>;
  /**
   * Optional TTL in milliseconds to cache active introspection responses in memory.
   * Defaults to `0` (always introspect live).
   */
  cacheTtlMs?: number;
}

export interface DisconnectGuardCheckResult {
  active: boolean;
  token: string | null;
  introspection: XelorraIntrospectionResult | null;
}

export interface DisconnectGuard<TContext = void> {
  /**
   * Introspects the current token via `client.introspectToken()`.
   * Automatically invokes `onRevoked()` if the token is inactive or disconnected.
   */
  check: (context: TContext) => Promise<DisconnectGuardCheckResult>;
  /**
   * Runs an async operation using the resolved token and automatically invokes
   * `onRevoked()` if the operation throws `XelorraAccessRevokedError`.
   */
  run: <TResult>(
    context: TContext,
    operation: (token: string) => Promise<TResult>,
  ) => Promise<TResult>;
  /** Evicts one token (or all cached tokens) from the optional introspection cache. */
  invalidate: (token?: string) => void;
}

/**
 * Creates a two-way disconnect synchronization guard that keeps partner app
 * sessions synchronized with Xelorra One via `introspectToken()` and
 * `XelorraAccessRevokedError` handling.
 */
export function createDisconnectGuard<TContext = void>(
  options: DisconnectGuardOptions<TContext>,
): DisconnectGuard<TContext> {
  const { client, getToken, onRevoked, cacheTtlMs = 0 } = options;
  const cache = new Map<string, { result: XelorraIntrospectionResult; expiresAt: number }>();

  function invalidate(token?: string): void {
    if (token) {
      cache.delete(token);
    } else {
      cache.clear();
    }
  }

  async function check(context: TContext): Promise<DisconnectGuardCheckResult> {
    const token = (await getToken(context)) ?? null;
    if (!token) {
      return { active: false, token: null, introspection: null };
    }

    const now = Date.now();
    if (cacheTtlMs > 0) {
      const cached = cache.get(token);
      if (cached && cached.expiresAt > now) {
        return { active: true, token, introspection: cached.result };
      }
      cache.delete(token);
    }

    const introspection = await client.introspectToken(token);
    if (!introspection.active || !introspection.connected) {
      cache.delete(token);
      await onRevoked({
        reason: introspection.reason || "access_revoked",
        introspection,
        context,
      });
      return { active: false, token, introspection };
    }

    if (cacheTtlMs > 0) {
      cache.set(token, { result: introspection, expiresAt: now + cacheTtlMs });
    }

    return { active: true, token, introspection };
  }

  async function run<TResult>(
    context: TContext,
    operation: (token: string) => Promise<TResult>,
  ): Promise<TResult> {
    const token = (await getToken(context)) ?? "";
    try {
      return await operation(token);
    } catch (err) {
      if (err instanceof XelorraAccessRevokedError) {
        if (token) {
          cache.delete(token);
        }
        await onRevoked({
          reason: err.reason || err.code,
          error: err,
          context,
        });
      }
      throw err;
    }
  }

  return { check, run, invalidate };
}

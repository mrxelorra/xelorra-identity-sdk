import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import type { XelorraClient } from "./client.js";
import { XelorraAccessRevokedError } from "./errors.js";
import type {
  AuthorizeUrlOptions,
  XelorraIntrospectionResult,
  XelorraKycAssertion,
  XelorraTokenSet,
  XelorraUserClaims,
} from "./types.js";

/** React context value exposed by `useXelorraAuth()`. */
export interface XelorraContextValue {
  client: XelorraClient;
  user: XelorraUserClaims | null;
  tokens: XelorraTokenSet | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | null;
  loginWithRedirect: (options?: AuthorizeUrlOptions) => Promise<void>;
  signUp: (options?: Omit<AuthorizeUrlOptions, "prompt">) => Promise<void>;
  handleCallback: (url?: string) => Promise<XelorraUserClaims>;
  refreshSession: () => Promise<XelorraTokenSet>;
  introspectSession: () => Promise<XelorraIntrospectionResult>;
  getVerificationAssertion: () => Promise<XelorraKycAssertion>;
  logout: () => Promise<void>;
}

export interface XelorraProviderProps {
  client: XelorraClient;
  /** Optional callback triggered automatically whenever Xelorra One revokes access. */
  onAccessRevoked?: (error: XelorraAccessRevokedError) => void;
  children: ReactNode;
}

const XelorraAuthContext = createContext<XelorraContextValue | null>(null);

/**
 * Provides Xelorra Identity authentication state and actions to React components.
 * Keeps tokens strictly in memory and synchronizes local state if access is revoked.
 */
export function XelorraProvider({
  client,
  onAccessRevoked,
  children,
}: XelorraProviderProps) {
  const [user, setUser] = useState<XelorraUserClaims | null>(() => client.getCachedUser());
  const [tokens, setTokens] = useState<XelorraTokenSet | null>(() => client.getTokens());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const handlePotentialRevocation = useCallback(
    (err: unknown) => {
      if (err instanceof XelorraAccessRevokedError) {
        setTokens(null);
        setUser(null);
        onAccessRevoked?.(err);
      }
    },
    [onAccessRevoked],
  );

  const loginWithRedirect = useCallback(
    async (options?: AuthorizeUrlOptions) => {
      setError(null);
      setIsLoading(true);
      try {
        await client.loginWithRedirect(options);
      } catch (err) {
        const normalized = err instanceof Error ? err : new Error("Failed to start Xelorra login.");
        setError(normalized);
        setIsLoading(false);
        throw normalized;
      }
    },
    [client],
  );

  const signUp = useCallback(
    async (options?: Omit<AuthorizeUrlOptions, "prompt">) => {
      return loginWithRedirect({ ...options, prompt: "create" });
    },
    [loginWithRedirect],
  );

  const handleCallback = useCallback(
    async (url?: string) => {
      setError(null);
      setIsLoading(true);
      try {
        const result = await client.handleCallback({ url });
        setTokens(result.tokens);
        setUser(result.user);
        return result.user;
      } catch (err) {
        handlePotentialRevocation(err);
        const normalized = err instanceof Error ? err : new Error("Xelorra callback failed.");
        setError(normalized);
        throw normalized;
      } finally {
        setIsLoading(false);
      }
    },
    [client, handlePotentialRevocation],
  );

  const refreshSession = useCallback(async () => {
    setError(null);
    try {
      const nextTokens = await client.refreshTokens();
      setTokens(nextTokens);
      return nextTokens;
    } catch (err) {
      handlePotentialRevocation(err);
      const normalized = err instanceof Error ? err : new Error("Unable to refresh session.");
      setError(normalized);
      throw normalized;
    }
  }, [client, handlePotentialRevocation]);

  const introspectSession = useCallback(async () => {
    const result = await client.introspectToken();
    if (!result.active || !result.connected) {
      setTokens(null);
      setUser(null);
      onAccessRevoked?.(
        new XelorraAccessRevokedError(
          "Session is no longer active on Xelorra One.",
          result.reason || undefined,
        ),
      );
    }
    return result;
  }, [client, onAccessRevoked]);

  const getVerificationAssertion = useCallback(async () => {
    try {
      return await client.getVerificationAssertion();
    } catch (err) {
      handlePotentialRevocation(err);
      throw err;
    }
  }, [client, handlePotentialRevocation]);

  const logout = useCallback(async () => {
    setIsLoading(true);
    try {
      await client.logout();
      setTokens(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const value = useMemo<XelorraContextValue>(
    () => ({
      client,
      user,
      tokens,
      isAuthenticated: Boolean(user && tokens?.access_token),
      isLoading,
      error,
      loginWithRedirect,
      signUp,
      handleCallback,
      refreshSession,
      introspectSession,
      getVerificationAssertion,
      logout,
    }),
    [
      client,
      user,
      tokens,
      isLoading,
      error,
      loginWithRedirect,
      signUp,
      handleCallback,
      refreshSession,
      introspectSession,
      getVerificationAssertion,
      logout,
    ],
  );

  return <XelorraAuthContext.Provider value={value}>{children}</XelorraAuthContext.Provider>;
}

/**
 * Accesses the nearest `<XelorraProvider>` authentication state and actions.
 */
export function useXelorraAuth(): XelorraContextValue {
  const ctx = useContext(XelorraAuthContext);
  if (!ctx) {
    throw new Error("useXelorraAuth must be used inside <XelorraProvider>.");
  }
  return ctx;
}

export interface XelorraAuthButtonProps {
  client?: XelorraClient;
  /** Choose `"signin"` (default) or `"signup"` (sets `prompt=create` for new Xelorra IDs). */
  mode?: "signin" | "signup";
  label?: string;
  theme?: "light" | "dark";
  variant?: "solid" | "outline";
  showLogo?: boolean;
  scopes?: string[];
  className?: string;
  disabled?: boolean;
  onError?: (error: Error) => void;
}

/**
 * Branded sign-in or sign-up button that starts the PKCE `S256` redirect flow.
 * Set `mode="signup"` to send new users directly to Xelorra ID registration (`prompt=create`).
 */
export function XelorraAuthButton({
  client: explicitClient,
  mode = "signin",
  label,
  theme = "dark",
  variant = "solid",
  showLogo = true,
  scopes,
  className,
  disabled = false,
  onError,
}: XelorraAuthButtonProps) {
  const ctx = useContext(XelorraAuthContext);
  const [busy, setBusy] = useState(false);

  const resolvedLabel =
    label ?? (mode === "signup" ? "Sign up with Xelorra" : "Continue with Xelorra");
  const isDark = theme === "dark";
  const isSolid = variant === "solid";

  const style: CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "10px",
    minHeight: "44px",
    padding: "0 18px",
    borderRadius: "10px",
    fontSize: "14px",
    fontWeight: 600,
    cursor: disabled || busy ? "not-allowed" : "pointer",
    opacity: disabled || busy ? 0.65 : 1,
    transition: "opacity 140ms ease, background-color 140ms ease",
    backgroundColor: isSolid ? (isDark ? "#2563EB" : "#0F172A") : "transparent",
    color: isSolid ? "#FFFFFF" : isDark ? "#F8FAFC" : "#0F172A",
    border: isSolid
      ? "1px solid transparent"
      : isDark
        ? "1px solid rgba(148, 163, 184, 0.35)"
        : "1px solid rgba(15, 23, 42, 0.22)",
  };

  const handleClick = async () => {
    const activeClient = explicitClient ?? ctx?.client;
    if (!activeClient) {
      const err = new Error(
        "XelorraAuthButton requires either a <XelorraProvider> ancestor or a `client` prop.",
      );
      onError?.(err);
      return;
    }
    setBusy(true);
    try {
      if (mode === "signup") {
        await activeClient.signUp({ scopes });
      } else {
        await activeClient.loginWithRedirect({ scopes });
      }
    } catch (err) {
      const normalized = err instanceof Error ? err : new Error("Unable to start Xelorra sign-in.");
      onError?.(normalized);
      setBusy(false);
    }
  };

  return (
    <button
      type="button"
      className={className}
      style={className ? undefined : style}
      disabled={disabled || busy}
      onClick={() => void handleClick()}
    >
      {showLogo && (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M4 4L10.5 12L4 20H7.8L12.4 14.1L17 20H20.8L14.3 12L20.8 4H17L12.4 9.9L7.8 4H4Z"
            fill="currentColor"
          />
        </svg>
      )}
      <span>{busy ? "Redirecting to Xelorra..." : resolvedLabel}</span>
    </button>
  );
}

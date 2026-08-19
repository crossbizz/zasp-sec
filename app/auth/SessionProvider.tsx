"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import type { Principal, SessionBootstrap } from "../../apps/web/api/generated";
import { useAPI } from "../api/APIProvider";

type AuthenticatedSession = {
  status: "authenticated";
  principal: Principal;
  organizationID: string;
  workspaceID: string;
  environmentID: string;
  permissions: readonly string[];
  capabilities: readonly string[];
};

type SessionState = AuthenticatedSession | {
  status: "loading" | "unauthenticated" | "forbidden" | "error";
  error?: unknown;
};

export type SessionContextValue = SessionState & {
  hasCapability(capability: string): boolean;
  signIn(returnTo?: string): void;
  signOut(): Promise<void>;
  retry(): Promise<void>;
};

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const { client, setCSRFToken, clearQueryCache, sessionExpiry } = useAPI();
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const [stateSessionExpiry, setStateSessionExpiry] = useState(sessionExpiry);
  const sessionCSRF = useRef<string | null>(null);
  const loadSession = useCallback(async (expiryVersion: number) => {
    try {
      const result = await client.GET("/api/v1/session/bootstrap");
      if (!result.data) {
        sessionCSRF.current = null;
        setCSRFToken(null);
        setState({ status: result.response.status === 401 ? "unauthenticated" : result.response.status === 403 ? "forbidden" : "error", error: result.error });
        return;
      }
      const bootstrapValue = result.data as unknown as SessionBootstrap;
      sessionCSRF.current = bootstrapValue.csrf_token;
      setCSRFToken(bootstrapValue.csrf_token);
      setStateSessionExpiry(expiryVersion);
      setState(authenticatedState(bootstrapValue));
    } catch (error) {
      setCSRFToken(null);
      setState({ status: "error", error });
    }
  }, [client, setCSRFToken]);
  const retry = useCallback(async () => {
    setState({ status: "loading" });
    await loadSession(sessionExpiry);
  }, [loadSession, sessionExpiry]);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void loadSession(0); });
    return () => { active = false; };
  }, [loadSession]);
  const signOut = useCallback(async () => {
    if (!sessionCSRF.current) throw new Error("Session CSRF token is unavailable");
    const result = await client.POST("/api/v1/session/sign-out", { params: { header: { "X-CSRF-Token": sessionCSRF.current } } });
    if (result.error) throw result.error;
    sessionCSRF.current = null;
    setCSRFToken(null);
    clearQueryCache();
    setState({ status: "unauthenticated" });
  }, [client, clearQueryCache, setCSRFToken]);
  const signIn = useCallback((returnTo?: string) => {
    window.location.assign(buildSignInURL(returnTo ?? `${window.location.pathname}${window.location.search}`));
  }, []);
	const value = useMemo<SessionContextValue>(() => {
		const visibleState: SessionState = sessionExpiry === stateSessionExpiry ? state : { status: "unauthenticated" };
		const capabilities = visibleState.status === "authenticated" ? new Set(visibleState.capabilities) : new Set<string>();
		return {
			...visibleState,
			hasCapability: (capability: string) => capabilities.has(capability),
			signIn,
			signOut,
			retry,
		};
	}, [sessionExpiry, stateSessionExpiry, state, signIn, signOut, retry]);
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}

export function buildSignInURL(returnTo: string): string {
  try {
    if (!returnTo.startsWith("/") || returnTo.startsWith("//") || returnTo.includes("\\")) throw new Error("invalid return path");
    const origin = "https://same-origin.invalid";
    const parsed = new URL(returnTo, origin);
    if (parsed.origin !== origin) throw new Error("foreign return path");
    return `/sign-in?return_to=${encodeURIComponent(`${parsed.pathname}${parsed.search}`)}`;
  } catch {
    return "/sign-in?return_to=%2F";
  }
}

function authenticatedState(value: SessionBootstrap): AuthenticatedSession {
  return {
    status: "authenticated",
    principal: value.principal,
    organizationID: value.organization_id,
    workspaceID: value.workspace_id,
    environmentID: value.environment_id,
    permissions: value.permissions,
    capabilities: value.capabilities,
  };
}

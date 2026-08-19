"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import type { Principal, SessionBootstrap, SessionScope } from "../../apps/web/api/generated";
import { requireAPIData } from "../../apps/web/api/client";
import { decodeSessionBootstrap, decodeSessionScopePage } from "../../apps/web/api/decoders";
import { useAPI } from "../api/APIProvider";

type AuthenticatedSession = {
  status: "authenticated";
  principal: Principal;
  organizationID: string;
  workspaceID: string;
  environmentID: string;
  permissions: readonly string[];
  capabilities: readonly string[];
	 scopes: readonly SessionScope[];
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
	 switchScope(workspaceID: string, environmentID: string): Promise<void>;
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
	  const bootstrapValue = requireAPIData(result, decodeSessionBootstrap);
	  let scopes: readonly SessionScope[] = [];
	  if (bootstrapValue.capabilities.includes("scope.switch")) {
		const scopeResult = await client.GET("/api/v1/session/scopes");
		scopes = requireAPIData(scopeResult, decodeSessionScopePage).items;
	  }
      sessionCSRF.current = bootstrapValue.csrf_token;
      setCSRFToken(bootstrapValue.csrf_token);
      setStateSessionExpiry(expiryVersion);
	  setState(authenticatedState(bootstrapValue, scopes));
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
	const switchScope = useCallback(async (workspaceID: string, environmentID: string) => {
		if (state.status !== "authenticated" || !sessionCSRF.current || !state.scopes.some((scope) => scope.workspace_id === workspaceID && scope.environment_id === environmentID)) throw new Error("Scope is not authorized");
		const result = await client.PUT("/api/v1/session/scope", { params: { header: { "X-CSRF-Token": sessionCSRF.current } }, body: { workspace_id: workspaceID, environment_id: environmentID } });
		if (result.error || result.response.status !== 204) requireAPIData<never>(result);
		clearQueryCache();
		await loadSession(sessionExpiry + 1);
	}, [client, clearQueryCache, loadSession, sessionExpiry, state]);
	const value = useMemo<SessionContextValue>(() => {
		const visibleState: SessionState = sessionExpiry === stateSessionExpiry ? state : { status: "unauthenticated" };
		const capabilities = visibleState.status === "authenticated" ? new Set(visibleState.capabilities) : new Set<string>();
		return {
			...visibleState,
			hasCapability: (capability: string) => capabilities.has(capability),
			signIn,
			signOut,
			switchScope,
			retry,
		};
	}, [sessionExpiry, stateSessionExpiry, state, signIn, signOut, switchScope, retry]);
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

function authenticatedState(value: SessionBootstrap, scopes: readonly SessionScope[]): AuthenticatedSession {
  return {
    status: "authenticated",
    principal: value.principal,
    organizationID: value.organization_id,
    workspaceID: value.workspace_id,
    environmentID: value.environment_id,
    permissions: value.permissions,
    capabilities: value.capabilities,
	 scopes,
  };
}

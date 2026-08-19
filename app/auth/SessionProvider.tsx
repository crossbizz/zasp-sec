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

type ActiveScope = {
  organizationID: string;
  workspaceID: string;
  environmentID: string;
};

export type ScopeSwitchFailure = {
  code: "scope_reconciliation_failed" | "scope_not_applied";
  message: string;
  target: ActiveScope;
  active?: ActiveScope;
  cause?: unknown;
};

type ScopeSwitchState = {
  status: "idle" | "pending" | "error";
  error?: ScopeSwitchFailure;
};

type ScopeAttempt = {
  target: ActiveScope;
  next: "reconcile" | "mutate";
};

export type SessionContextValue = SessionState & {
  hasCapability(capability: string): boolean;
  signIn(returnTo?: string): void;
  signOut(): Promise<void>;
  retry(): Promise<void>;
	 switchScope(workspaceID: string, environmentID: string): Promise<void>;
	 scopeSwitch: {
		 status: "idle" | "pending" | "error";
		 error?: ScopeSwitchFailure;
		 retry(): Promise<void>;
	 };
};

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const { client, setCSRFToken, setQueryScope, suspendQueryCache, sessionExpiry } = useAPI();
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const [stateSessionExpiry, setStateSessionExpiry] = useState(sessionExpiry);
  const [scopeSwitch, setScopeSwitch] = useState<ScopeSwitchState>({ status: "idle" });
  const scopeAttempt = useRef<ScopeAttempt | null>(null);
  const sessionCSRF = useRef<string | null>(null);
  const loadSession = useCallback(async (expiryVersion: number): Promise<ActiveScope | null> => {
    try {
      const result = await client.GET("/api/v1/session/bootstrap");
      if (!result.data) {
        sessionCSRF.current = null;
        setCSRFToken(null);
        suspendQueryCache();
		  setStateSessionExpiry(expiryVersion);
        setState({ status: result.response.status === 401 ? "unauthenticated" : result.response.status === 403 ? "forbidden" : "error", error: result.error });
		  return null;
      }
      const bootstrapValue = requireAPIData(result, decodeSessionBootstrap);
      let scopes: readonly SessionScope[] = [];
      if (bootstrapValue.capabilities.includes("scope.switch")) {
        const scopeResult = await client.GET("/api/v1/session/scopes");
        scopes = requireAPIData(scopeResult, decodeSessionScopePage).items;
        if (!scopes.some((scope) => scope.organization_id === bootstrapValue.organization_id && scope.workspace_id === bootstrapValue.workspace_id && scope.environment_id === bootstrapValue.environment_id)) throw new Error("Active scope is not authorized");
      }
      const activeScope = scopeFromBootstrap(bootstrapValue);
      sessionCSRF.current = bootstrapValue.csrf_token;
      setCSRFToken(bootstrapValue.csrf_token);
      setStateSessionExpiry(expiryVersion);
      setQueryScope(scopeCacheKey(activeScope));
      setState(authenticatedState(bootstrapValue, scopes));
      return activeScope;
    } catch (error) {
      sessionCSRF.current = null;
      setCSRFToken(null);
      suspendQueryCache();
      setStateSessionExpiry(expiryVersion);
      setState({ status: "error", error });
      return null;
    }
  }, [client, setCSRFToken, setQueryScope, suspendQueryCache]);
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
    suspendQueryCache();
    setState({ status: "unauthenticated" });
  }, [client, setCSRFToken, suspendQueryCache]);
  const signIn = useCallback((returnTo?: string) => {
    window.location.assign(buildSignInURL(returnTo ?? `${window.location.pathname}${window.location.search}`));
  }, []);
  const reconcileScope = useCallback(async (attempt: ScopeAttempt, cause?: unknown) => {
    attempt.next = "reconcile";
    const active = await loadSession(sessionExpiry);
    if (!active) {
      setScopeSwitch({
        status: "error",
        error: {
          code: "scope_reconciliation_failed",
          message: "The active scope could not be confirmed. Retry reconciliation before resending the switch.",
          target: attempt.target,
          cause,
        },
      });
      return;
    }
    if (sameScope(active, attempt.target)) {
      scopeAttempt.current = null;
      setScopeSwitch({ status: "idle" });
      return;
    }
    attempt.next = "mutate";
    setScopeSwitch({
      status: "error",
      error: {
        code: "scope_not_applied",
        message: "The server confirmed a different active scope. Retry to submit a new switch from that authoritative scope.",
        target: attempt.target,
        active,
        cause,
      },
    });
  }, [loadSession, sessionExpiry]);
  const submitScopeSwitch = useCallback(async (attempt: ScopeAttempt) => {
    if (!sessionCSRF.current) throw new Error("Session CSRF token is unavailable");
    setScopeSwitch({ status: "pending" });
    let mutationError: unknown;
    try {
      const result = await client.PUT("/api/v1/session/scope", {
        params: { header: { "X-CSRF-Token": sessionCSRF.current } },
        body: { workspace_id: attempt.target.workspaceID, environment_id: attempt.target.environmentID },
      });
      if (result.error || result.response.status !== 204) requireAPIData<never>(result);
    } catch (error) {
      mutationError = error;
    }
    attempt.next = "reconcile";
    sessionCSRF.current = null;
    setCSRFToken(null);
    suspendQueryCache();
    await reconcileScope(attempt, mutationError);
  }, [client, reconcileScope, setCSRFToken, suspendQueryCache]);
  const switchScope = useCallback(async (workspaceID: string, environmentID: string) => {
    if (state.status !== "authenticated") throw new Error("An authenticated session is required");
    const selected = state.scopes.find((scope) => scope.workspace_id === workspaceID && scope.environment_id === environmentID);
    if (!selected) throw new Error("Scope is not authorized");
    const attempt: ScopeAttempt = {
      target: {
        organizationID: selected.organization_id,
        workspaceID: selected.workspace_id,
        environmentID: selected.environment_id,
      },
      next: "mutate",
    };
    scopeAttempt.current = attempt;
    await submitScopeSwitch(attempt);
  }, [state, submitScopeSwitch]);
  const retryScopeSwitch = useCallback(async () => {
    const attempt = scopeAttempt.current;
    if (!attempt) throw new Error("Scope retry is unavailable");
    setScopeSwitch({ status: "pending" });
    if (attempt.next === "reconcile") {
      await reconcileScope(attempt);
      return;
    }
    await submitScopeSwitch(attempt);
  }, [reconcileScope, submitScopeSwitch]);
	const value = useMemo<SessionContextValue>(() => {
		const visibleState: SessionState = sessionExpiry === stateSessionExpiry ? state : { status: "unauthenticated" };
		const capabilities = visibleState.status === "authenticated" ? new Set(visibleState.capabilities) : new Set<string>();
		return {
			...visibleState,
			hasCapability: (capability: string) => capabilities.has(capability),
			signIn,
			signOut,
			switchScope,
			scopeSwitch: { ...scopeSwitch, retry: retryScopeSwitch },
			retry,
		};
	}, [sessionExpiry, stateSessionExpiry, state, signIn, signOut, switchScope, scopeSwitch, retryScopeSwitch, retry]);
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

function scopeFromBootstrap(value: SessionBootstrap): ActiveScope {
  return {
    organizationID: value.organization_id,
    workspaceID: value.workspace_id,
    environmentID: value.environment_id,
  };
}

function scopeCacheKey(scope: ActiveScope): string {
  return `${scope.organizationID}/${scope.workspaceID}/${scope.environmentID}`;
}

function sameScope(left: ActiveScope, right: ActiveScope): boolean {
  return left.organizationID === right.organizationID
    && left.workspaceID === right.workspaceID
    && left.environmentID === right.environmentID;
}

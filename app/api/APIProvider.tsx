"use client";

import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from "react";

import { createAPIClient, type APIClient } from "../../apps/web/api/client";

type APIContextValue = {
  client: APIClient;
  revisions: ReadonlyMap<string, number>;
  queryScopeKey: string | null;
  queryGeneration: number;
  sessionExpiry: number;
	scopeStale: number;
	getScopeStaleGeneration(): number;
  invalidate(keys: readonly string[]): void;
  setCSRFToken(value: string | null): void;
	setRequestScope(value: string | null): void;
  setQueryScope(scopeKey: string): void;
  suspendQueryCache(): void;
  clearQueryCache(): void;
};

const APIContext = createContext<APIContextValue | null>(null);

class CSRFVault {
  #value: string | null = null;
  get() { return this.#value; }
  set(value: string | null) { this.#value = value; }
}

class ScopeVault {
	#value: string | null = null;
	get() { return this.#value; }
	set(value: string | null) { this.#value = value; }
}

class GenerationVault {
	#value = 0;
	get() { return this.#value; }
	advance() {
		this.#value += 1;
		return this.#value;
	}
}

export function APIProvider({ children, client: suppliedClient }: { children: ReactNode; client?: APIClient }) {
  const [csrfToken] = useState(() => new CSRFVault());
	const [requestScope] = useState(() => new ScopeVault());
  const [revisions, setRevisions] = useState<ReadonlyMap<string, number>>(() => new Map());
  const [queryEpoch, setQueryEpoch] = useState({ scopeKey: "__unscoped__" as string | null, generation: 0 });
  const [sessionExpiry, setSessionExpiry] = useState(0);
	const [scopeStale, setScopeStale] = useState(0);
	const [scopeStaleGeneration] = useState(() => new GenerationVault());
  const [client] = useState(() => suppliedClient ?? createAPIClient({
    getCSRFToken: () => csrfToken.get() ?? undefined,
	getExpectedScope: () => requestScope.get() ?? undefined,
    onSessionExpired: () => {
      csrfToken.set(null);
      setRevisions(new Map());
      setQueryEpoch((current) => ({ scopeKey: null, generation: current.generation + 1 }));
      setSessionExpiry((value) => value + 1);
    },
	onScopeStale: () => {
		csrfToken.set(null);
		requestScope.set(null);
		setRevisions(new Map());
		setQueryEpoch((current) => ({ scopeKey: null, generation: current.generation + 1 }));
		setScopeStale(scopeStaleGeneration.advance());
	},
  }));
  const invalidate = useCallback((keys: readonly string[]) => {
    setRevisions((current) => {
      const next = new Map(current);
      for (const key of new Set(keys)) next.set(key, (next.get(key) ?? 0) + 1);
      return next;
    });
  }, []);
  const setCSRFToken = useCallback((value: string | null) => { csrfToken.set(value); }, [csrfToken]);
	const setRequestScope = useCallback((value: string | null) => { requestScope.set(value); }, [requestScope]);
  const setQueryScope = useCallback((scopeKey: string) => {
    if (!scopeKey) throw new Error("Query scope key is required");
    setRevisions(new Map());
    setQueryEpoch((current) => current.scopeKey === scopeKey
      ? current
      : { scopeKey, generation: current.generation + 1 });
  }, []);
  const suspendQueryCache = useCallback(() => {
    setRevisions(new Map());
    setQueryEpoch((current) => ({ scopeKey: null, generation: current.generation + 1 }));
  }, []);
  const clearQueryCache = useCallback(() => {
    setRevisions(new Map());
    setQueryEpoch((current) => ({ ...current, generation: current.generation + 1 }));
  }, []);
	const getScopeStaleGeneration = useCallback(() => scopeStaleGeneration.get(), [scopeStaleGeneration]);
  const value = useMemo<APIContextValue>(() => ({
    client,
    revisions,
    queryScopeKey: queryEpoch.scopeKey,
    queryGeneration: queryEpoch.generation,
    sessionExpiry,
	scopeStale,
	getScopeStaleGeneration,
    invalidate,
    setCSRFToken,
	setRequestScope,
    setQueryScope,
    suspendQueryCache,
    clearQueryCache,
  }), [client, revisions, queryEpoch, sessionExpiry, scopeStale, getScopeStaleGeneration, invalidate, setCSRFToken, setRequestScope, setQueryScope, suspendQueryCache, clearQueryCache]);
  return <APIContext.Provider value={value}>{children}</APIContext.Provider>;
}

export function useAPI(): APIContextValue {
  const value = useContext(APIContext);
  if (!value) throw new Error("useAPI must be used inside APIProvider");
  return value;
}

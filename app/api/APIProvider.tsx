"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { createAPIClient, type APIClient, type APIClientOptions } from "../../apps/web/api/client";
import { createAuditExportsAPI, type AuditExportsAPI } from "../../apps/web/api/audit-exports";

type APIContextValue = {
  client: APIClient;
  auditExports: AuditExportsAPI;
  revisions: ReadonlyMap<string, number>;
  queryScopeKey: string | null;
  queryGeneration: number;
  sessionExpiry: number;
	getSessionInvalidationGeneration(): number;
  scopeStale: number;
  getScopeStaleGeneration(): number;
	freshAuthRequired: number;
	markFreshAuthenticated(): void;
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

class ExportRequestBoundary {
  #generation = 0;
  #controller = new AbortController();
  #scopeKey: string | null = "__unscoped__";
  generation() { return this.#generation; }
  signal() { return this.#controller.signal; }
  select(scopeKey: string) {
    if (this.#scopeKey !== scopeKey) { this.advance(); this.#scopeKey = scopeKey; }
  }
  suspend() { this.advance(); this.#scopeKey = null; }
  advance() {
    this.#generation++;
    this.#controller.abort(new DOMException("Audit export session or scope changed", "AbortError"));
    this.#controller = new AbortController();
  }
}

export function APIProvider({ children, client: suppliedClient }: { children: ReactNode; client?: APIClient }) {
  const [csrfToken] = useState(() => new CSRFVault());
	const [requestScope] = useState(() => new ScopeVault());
  const [revisions, setRevisions] = useState<ReadonlyMap<string, number>>(() => new Map());
  const [queryEpoch, setQueryEpoch] = useState({ scopeKey: "__unscoped__" as string | null, generation: 0 });
  const [sessionExpiry, setSessionExpiry] = useState(0);
	const [sessionInvalidationGeneration] = useState(() => new GenerationVault());
	const [scopeStale, setScopeStale] = useState(0);
	const [scopeStaleGeneration] = useState(() => new GenerationVault());
	const [freshAuthRequired, setFreshAuthRequired] = useState(0);
  const [exportBoundary] = useState(() => new ExportRequestBoundary());
  const [{ client, auditExports }] = useState(() => {
    const options: APIClientOptions = {
    getCSRFToken: () => csrfToken.get() ?? undefined,
	getExpectedScope: () => requestScope.get() ?? undefined,
    onSessionExpired: () => {
      exportBoundary.advance();
      csrfToken.set(null);
	  requestScope.set(null);
      setRevisions(new Map());
      setQueryEpoch((current) => ({ scopeKey: null, generation: current.generation + 1 }));
	  setSessionExpiry(sessionInvalidationGeneration.advance());
    },
	onScopeStale: () => {
		exportBoundary.advance();
		csrfToken.set(null);
		requestScope.set(null);
		setRevisions(new Map());
		setQueryEpoch((current) => ({ scopeKey: null, generation: current.generation + 1 }));
		setScopeStale(scopeStaleGeneration.advance());
	},
	onFreshAuthRequired: () => {
		exportBoundary.advance();
		csrfToken.set(null);
		setRevisions(new Map());
		setQueryEpoch((current) => ({ ...current, generation: current.generation + 1 }));
		setFreshAuthRequired((current) => current + 1);
	},
    };
    const client = suppliedClient ?? createAPIClient(options);
    // Supplied clients remain caller-owned, including their transport bounds.
    // Production exposes only two operations from its private finite client.
    const exportClient = suppliedClient ?? createAPIClient({ ...options, maximumResponseBytes: 1064960 });
    const auditExports = createAuditExportsAPI(exportClient, () => ({ generation: exportBoundary.generation(), signal: exportBoundary.signal(), scope: requestScope.get(), csrf: csrfToken.get() }));
    return { client, auditExports };
  });
  useEffect(() => () => exportBoundary.advance(), [exportBoundary]);
  const invalidate = useCallback((keys: readonly string[]) => {
    setRevisions((current) => {
      const next = new Map(current);
      for (const key of new Set(keys)) next.set(key, (next.get(key) ?? 0) + 1);
      return next;
    });
  }, []);
  const setCSRFToken = useCallback((value: string | null) => { csrfToken.set(value); }, [csrfToken]);
	const setRequestScope = useCallback((value: string | null) => { if (requestScope.get() !== value) exportBoundary.advance(); requestScope.set(value); }, [requestScope, exportBoundary]);
  const setQueryScope = useCallback((scopeKey: string) => {
    if (!scopeKey) throw new Error("Query scope key is required");
    exportBoundary.select(scopeKey);
    setRevisions(new Map());
    setQueryEpoch((current) => current.scopeKey === scopeKey
      ? current
      : { scopeKey, generation: current.generation + 1 });
  }, [exportBoundary]);
  const suspendQueryCache = useCallback(() => {
    exportBoundary.suspend();
    setRevisions(new Map());
    setQueryEpoch((current) => ({ scopeKey: null, generation: current.generation + 1 }));
  }, [exportBoundary]);
  const clearQueryCache = useCallback(() => {
    exportBoundary.advance();
    setRevisions(new Map());
    setQueryEpoch((current) => ({ ...current, generation: current.generation + 1 }));
  }, [exportBoundary]);
	const getScopeStaleGeneration = useCallback(() => scopeStaleGeneration.get(), [scopeStaleGeneration]);
	const getSessionInvalidationGeneration = useCallback(() => sessionInvalidationGeneration.get(), [sessionInvalidationGeneration]);
	const markFreshAuthenticated = useCallback(() => setFreshAuthRequired(0), []);
  const value = useMemo<APIContextValue>(() => ({
    client,
    auditExports,
    revisions,
    queryScopeKey: queryEpoch.scopeKey,
    queryGeneration: queryEpoch.generation,
    sessionExpiry,
	getSessionInvalidationGeneration,
	scopeStale,
	getScopeStaleGeneration,
	freshAuthRequired,
	markFreshAuthenticated,
    invalidate,
    setCSRFToken,
	setRequestScope,
    setQueryScope,
    suspendQueryCache,
    clearQueryCache,
	  }), [client, auditExports, revisions, queryEpoch, sessionExpiry, getSessionInvalidationGeneration, scopeStale, getScopeStaleGeneration, freshAuthRequired, markFreshAuthenticated, invalidate, setCSRFToken, setRequestScope, setQueryScope, suspendQueryCache, clearQueryCache]);
  return <APIContext.Provider value={value}>{children}</APIContext.Provider>;
}

export function useAPI(): APIContextValue {
  const value = useContext(APIContext);
  if (!value) throw new Error("useAPI must be used inside APIProvider");
  return value;
}

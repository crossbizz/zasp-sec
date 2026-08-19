"use client";

import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from "react";

import { createAPIClient, type APIClient } from "../../apps/web/api/client";

type APIContextValue = {
  client: APIClient;
  revisions: ReadonlyMap<string, number>;
  queryGeneration: number;
  sessionExpiry: number;
  invalidate(keys: readonly string[]): void;
  setCSRFToken(value: string | null): void;
  clearQueryCache(): void;
};

const APIContext = createContext<APIContextValue | null>(null);

class CSRFVault {
  #value: string | null = null;
  get() { return this.#value; }
  set(value: string | null) { this.#value = value; }
}

export function APIProvider({ children, client: suppliedClient }: { children: ReactNode; client?: APIClient }) {
  const [csrfToken] = useState(() => new CSRFVault());
  const [revisions, setRevisions] = useState<ReadonlyMap<string, number>>(() => new Map());
	const [queryGeneration, setQueryGeneration] = useState(0);
  const [sessionExpiry, setSessionExpiry] = useState(0);
  const [client] = useState(() => suppliedClient ?? createAPIClient({
    getCSRFToken: () => csrfToken.get() ?? undefined,
    onSessionExpired: () => {
      csrfToken.set(null);
      setRevisions(new Map());
	  setQueryGeneration((value) => value + 1);
      setSessionExpiry((value) => value + 1);
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
  const clearQueryCache = useCallback(() => {
    setRevisions(new Map());
	setQueryGeneration((value) => value + 1);
  }, []);
  const value = useMemo<APIContextValue>(() => ({
	client, revisions, queryGeneration, sessionExpiry, invalidate, setCSRFToken, clearQueryCache,
	}), [client, revisions, queryGeneration, sessionExpiry, invalidate, setCSRFToken, clearQueryCache]);
  return <APIContext.Provider value={value}>{children}</APIContext.Provider>;
}

export function useAPI(): APIContextValue {
  const value = useContext(APIContext);
  if (!value) throw new Error("useAPI must be used inside APIProvider");
  return value;
}

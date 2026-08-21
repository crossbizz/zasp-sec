"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";

import type { APIClient } from "../../apps/web/api/client";
import { requireAPIData } from "../../apps/web/api/client";
import { decodeGlobalSearchPage } from "../../apps/web/api/decoders";
import type { SearchResult } from "../../apps/web/api/generated";
import { SearchBox } from "./ui";

const safeQuery = /^[A-Za-z0-9.:_/-](?:[A-Za-z0-9 .:_/-]{0,126}[A-Za-z0-9.:_/-])?$/;

export function ProductionGlobalSearch({ client, onNavigate }: { client: APIClient; onNavigate(path: string): void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<readonly SearchResult[]>([]);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const request = useRef<AbortController | null>(null);

  useEffect(() => () => request.current?.abort(), []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!safeQuery.test(query)) { setResults([]); setState("error"); return; }
    request.current?.abort(); const controller = new AbortController(); request.current = controller; setState("loading");
    try {
      const page = requireAPIData(await client.GET("/api/v1/search", { params: { query: { q: query, limit: 20 } }, signal: controller.signal }), decodeGlobalSearchPage);
      if (controller.signal.aborted || request.current !== controller) return;
      setResults(page.items); setState("ready");
    } catch {
      if (!controller.signal.aborted && request.current === controller) { setResults([]); setState("error"); }
    }
  };
  const open = (result: SearchResult) => {
    const path = searchResultPath(result.type);
    request.current?.abort(); request.current = null; setQuery(""); setResults([]); setState("idle"); onNavigate(path);
  };
  return <form role="search" className="global-search production-global-search" onSubmit={(event) => void submit(event)}>
    <SearchBox aria-label="Search product entities" value={query} maxLength={128} placeholder="Search agents, tools, identities, runtimes, and findings" onChange={(event) => { setQuery(event.target.value); if (state !== "idle") { setResults([]); setState("idle"); } }} />
    <button type="submit" className="global-search-submit" disabled={state === "loading"}>Search</button>
    {state !== "idle" && <div className="global-results" aria-live="polite">
      {state === "loading" && <span>Searching authorized scope</span>}
      {state === "error" && <span role="alert">Enter 2-128 safe search characters and retry.</span>}
      {state === "ready" && results.length === 0 && <span>No matching product entities</span>}
      {state === "ready" && results.map((result) => <button type="button" key={`${result.type}/${result.id}`} aria-label={`Open ${result.name}`} onClick={() => open(result)}><span>{result.name}<small>{result.type} · {result.id}</small></span></button>)}
    </div>}
  </form>;
}

function searchResultPath(type: SearchResult["type"]): string {
  switch (type) {
  case "agent": return "/discovery/assets";
  case "tool": return "/inventory/tools";
  case "identity": return "/identities";
  case "runtime": return "/inventory/runtimes";
  case "finding": return "/violations";
  default: return "/discovery/assets";
  }
}

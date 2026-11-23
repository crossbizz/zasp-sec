"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { requireAPIData, type APIClient } from "../../apps/web/api/client";
import { decodeGlobalSearchPage } from "../../apps/web/api/decoders";
import type { SearchResult } from "../../apps/web/api/generated";
import { activityLink, type ActivityScope } from "../domain/activity-links";
import { Button, Card, SearchBox } from "./ui";

const safeQuery = /^[A-Za-z0-9.:_/-][A-Za-z0-9 .:_/-]{0,126}[A-Za-z0-9.:_/-]$/;
const resultRoute = { agent: "/discovery/assets", tool: "/inventory/tools", identity: "/identities", runtime: "/inventory/runtimes", finding: "/violations" } as const;

type Props = { client: APIClient; resultsHost: HTMLElement | null; routes: readonly { path: string }[]; scope: ActivityScope; onNavigate(path: string): void };
export function ProductionGlobalSearch({ client, resultsHost, routes, scope, onNavigate }: Props) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<readonly SearchResult[]>([]);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "invalid" | "error">("idle");
  const request = useRef<AbortController | null>(null);
  const input = useRef<HTMLFormElement>(null);
  useEffect(() => () => request.current?.abort(), []);
  function clear() { request.current?.abort(); request.current = null; setResults([]); setState("idle"); }

  const submit = async (event: FormEvent) => {
    event.preventDefault(); clear();
    if (!safeQuery.test(query)) { setState("invalid"); return; }
    const controller = new AbortController(); request.current = controller; setState("loading");
    try {
      const page = requireAPIData(await client.GET("/api/v1/search", { params: { query: { q: query, limit: 20 } }, signal: controller.signal }), decodeGlobalSearchPage);
      if (controller.signal.aborted || request.current !== controller) return;
      setResults(page.items); setState("ready");
    } catch { if (!controller.signal.aborted) setState("error"); }
  };
  function resultLink(result: SearchResult) {
    if (result.type === "asset") return null;
    const path = resultRoute[result.type];
    if (!routes.some(route => route.path === path)) return null;
    return result.type === "finding" ? activityLink({ kind: "finding", id: result.id }, scope) : `${path}?inventory=${result.id}`;
  }
  return <form ref={input} role="search" className="global-search production-global-search" onSubmit={event => void submit(event)}>
    <SearchBox aria-label="Search product entities" aria-controls="product-search-results" value={query} maxLength={128} placeholder="Search agents, tools, identities, runtimes, and findings" onChange={event => { clear(); setQuery(event.target.value); }} />
    <button type="submit" className="global-search-submit" disabled={state === "loading"}>Search</button>
    {resultsHost && state !== "idle" && createPortal(<Card className="search-results-inline" title={<h2>Search results</h2>} action={<Button onClick={() => { clear(); input.current?.querySelector("input")?.focus(); }}>Dismiss results</Button>}>
      <div aria-live="polite">{state === "loading" && "Searching authorized scope…"}
        {state === "invalid" && <p role="alert">Enter 2–128 letters, numbers, spaces, or identifier characters.</p>}
        {state === "error" && <p role="alert">Search is unavailable. Submit the search again to retry.</p>}
        {state === "ready" && (results.length === 0 ? <p>No matching product entities.</p> : <ul>{results.map(result => {
          const href = resultLink(result);
          return <li key={result.type + result.id}>{href ? <a href={href} aria-label={`Open ${result.name}`} onClick={event => { event.preventDefault(); clear(); onNavigate(href); }}>{result.name}</a> : <strong>{result.name}</strong>}<small>{result.type} · {result.id}</small></li>;
        })}</ul>)}</div>
    </Card>, resultsHost)}
  </form>;
}

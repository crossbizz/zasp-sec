"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { createPortal } from "react-dom";

import { APITransportError, requireAPIData, type APIClient } from "../../apps/web/api/client";
import { decodeGlobalSearchPage, decodeInventoryDetail } from "../../apps/web/api/decoders";
import type { SearchResult } from "../../apps/web/api/generated";
import { useAPIQuery } from "../api/query";
import { activityLink, type ActivityScope } from "../domain/activity-links";
import { Button, Card, SearchBox } from "./ui";
import "./production-global-search.css";

const safeQuery = /^[A-Za-z0-9.:_/-][A-Za-z0-9 .:_/-]{0,126}[A-Za-z0-9.:_/-]$/;
const resultRoutes = { asset: "/discovery/assets", agent: "/discovery/assets", tool: "/inventory/tools", identity: "/identities", runtime: "/inventory/runtimes", finding: "/violations" } as const;

type Props = {
  client: APIClient;
  scope: ActivityScope;
  resultsHost: HTMLElement | null;
  routes: readonly { path: string }[];
  onNavigate(path: string): void;
};

export function ProductionGlobalSearch({ client, scope, resultsHost, routes, onNavigate }: Props) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<readonly SearchResult[]>([]);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "invalid" | "error">("idle");
  const [asset, setAsset] = useState<SearchResult | null>(null);
  const request = useRef<AbortController | null>(null);
  const form = useRef<HTMLFormElement>(null);
  const dismiss = useCallback(() => {
    request.current?.abort();
    request.current = null;
    setResults([]);
    setState("idle");
    setAsset(null);
  }, []);
  const closeAndFocus = useCallback(() => {
    dismiss();
    form.current?.querySelector("input")?.focus();
  }, [dismiss]);

  useEffect(() => () => request.current?.abort(), []);
  useEffect(() => {
    if (state === "idle" && !asset) return;
    const outside = (event: Event) => {
      if (event.target instanceof Node && !form.current?.contains(event.target) && !resultsHost?.contains(event.target)) dismiss();
    };
    function navigateResults(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeAndFocus();
      } else if (event.key === "Tab" && event.shiftKey && event.target === resultsHost?.querySelector("button, a[href]")) {
        event.preventDefault();
        form.current?.querySelector<HTMLButtonElement>("button[type=submit]")?.focus();
      }
    }
    resultsHost?.addEventListener("keydown", navigateResults);
    document.addEventListener("pointerdown", outside);
    document.addEventListener("focusin", outside);
    return () => {
      resultsHost?.removeEventListener("keydown", navigateResults);
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("focusin", outside);
    };
  }, [asset, closeAndFocus, dismiss, resultsHost, state]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    dismiss();
    if (!safeQuery.test(query)) { setState("invalid"); return; }
    const controller = new AbortController();
    request.current = controller;
    setState("loading");
    try {
      const page = requireAPIData(await client.GET("/api/v1/search", { params: { query: { q: query, limit: 20 } }, signal: controller.signal }), decodeGlobalSearchPage);
      if (controller.signal.aborted || request.current !== controller) return;
      setResults(page.items);
      setState("ready");
    } catch {
      if (!controller.signal.aborted) setState("error");
    }
  }

  function dismissOnEscape(event: ReactKeyboardEvent) {
    if (event.key !== "Escape" || state === "idle" && !asset) return;
    event.preventDefault();
    event.stopPropagation();
    closeAndFocus();
  }
  function submitKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    dismissOnEscape(event);
    if (event.key !== "Tab" || event.shiftKey) return;
    const first = resultsHost?.querySelector<HTMLElement>("button, a[href]");
    if (first) { event.preventDefault(); first.focus(); }
  }

  function resultControl(result: SearchResult) {
    const path = resultRoutes[result.type];
    if (!routes.some(route => route.path === path)) return <strong>{result.name}</strong>;
    if (result.type === "asset") return <Button aria-label={`Open ${result.name}`} onClick={() => { dismiss(); setAsset(result); }}>{result.name}</Button>;
    const href = result.type === "finding" ? activityLink({ kind: "finding", id: result.id }, scope) : `${path}?inventory=${result.id}`;
    return <a href={href} aria-label={`Open ${result.name}`} onClick={event => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
      event.preventDefault();
      closeAndFocus();
      setQuery("");
      onNavigate(href);
    }}>{result.name}</a>;
  }

  return <>
    <form ref={form} role="search" className="global-search production-global-search" onSubmit={event => void submit(event)}>
      <SearchBox aria-label="Search product entities" aria-controls="product-search-results" value={query} maxLength={128} placeholder="Search agents, tools, identities, runtimes, and findings" onKeyDown={dismissOnEscape} onChange={event => { dismiss(); setQuery(event.target.value); }} />
      <button type="submit" className="global-search-submit" disabled={state === "loading"} onKeyDown={submitKeyDown}>Search</button>
    </form>
    {resultsHost && (asset || state !== "idle") && createPortal(<>
      {asset ? <AssetSearchDetail key={asset.id} asset={asset} client={client} onClose={closeAndFocus} /> :
        <Card className="search-results-inline" title={<h2>Search results</h2>} action={<Button onClick={closeAndFocus}>Dismiss results</Button>}>
          <div aria-live="polite">
            {state === "loading" && "Searching authorized scope…"}
            {state === "invalid" && <p role="alert">Enter 2–128 letters, numbers, spaces, or identifier characters.</p>}
            {state === "error" && <p role="alert">Search is unavailable. Submit the search again to retry.</p>}
            {state === "ready" && (results.length === 0 ? <p>No matching product entities.</p> : <ul>{results.map(result => <li key={`${result.type}/${result.id}`}>
              {resultControl(result)}<small>{result.type} · {result.id}</small>
            </li>)}</ul>)}
          </div>
        </Card>}
    </>, resultsHost)}
  </>;
}

function AssetSearchDetail({ asset, client, onClose }: { asset: SearchResult; client: APIClient; onClose(): void }) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  const read = useCallback(async (signal?: AbortSignal) => {
    const detail = requireAPIData(await client.GET("/api/v1/assets/{id}", { params: { path: { id: asset.id } }, signal }), decodeInventoryDetail);
    if (detail.summary.kind !== "asset" || detail.summary.id !== asset.id) throw new APITransportError("invalid_response", "Unexpected asset");
    return detail;
  }, [asset.id, client]);
  const detail = useAPIQuery(`search-asset:${asset.id}`, read);
  return <Card className="search-results-inline" title={<h2 ref={heading} tabIndex={-1}>{asset.name}</h2>} action={<Button onClick={onClose}>Close asset details</Button>}>
    {detail.status === "loading" && <p role="status">Loading asset details…</p>}
    {["error", "forbidden", "stale"].includes(detail.status) && <p role="alert">Asset details could not be refreshed. <Button onClick={() => void detail.retry()}>Retry</Button></p>}
    {detail.data && <dl className="search-asset-detail">
      <dt>Asset ID</dt><dd><code>{detail.data.summary.id}</code></dd>
      <dt>Owner</dt><dd>{detail.data.summary.owner || "Unassigned"}</dd>
      <dt>Team</dt><dd>{detail.data.summary.team || "Unassigned"}</dd>
      <dt>Source observations</dt><dd>{detail.data.sources.length}</dd>
    </dl>}
  </Card>;
}

"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { APITransportError, requireAPIData, type APIClient } from "../../apps/web/api/client";
import { decodeGlobalSearchPage, decodeInventoryDetail } from "../../apps/web/api/decoders";
import type { SearchResult } from "../../apps/web/api/generated";
import { useAPIQuery } from "../api/query";
import { activityLink, type ActivityScope } from "../domain/activity-links";
import { Button, Drawer, SearchBox } from "./ui";
import "./production-global-search.css";

const safeQuery = /^[A-Za-z0-9.:_/-][A-Za-z0-9 .:_/-]{0,126}[A-Za-z0-9.:_/-]$/;
const inventoryRoutes = { agent: "/discovery/assets", tool: "/inventory/tools", identity: "/identities", runtime: "/inventory/runtimes" } as const;

export function ProductionGlobalSearch({ client, scope, onNavigate }: { client: APIClient; scope: ActivityScope; onNavigate(path: string): void }) {
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
  }, []);

  useEffect(() => () => request.current?.abort(), []);
  useEffect(() => {
    if (state === "idle") return;
    const outside = (event: Event) => {
      if (event.target instanceof Node && !form.current?.contains(event.target)) dismiss();
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("focusin", outside);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("focusin", outside);
    };
  }, [state, dismiss]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    dismiss();
    if (!safeQuery.test(query)) { setState("invalid"); return; }
    const controller = new AbortController();
    request.current = controller;
    setState("loading");
    try {
      const page = requireAPIData(await client.GET("/api/v1/search", { params: { query: { q: query, limit: 20 } }, signal: controller.signal }), decodeGlobalSearchPage);
      if (!controller.signal.aborted) { setResults(page.items); setState("ready"); }
    } catch {
      if (!controller.signal.aborted) setState("error");
    }
  };
  const open = (result: SearchResult) => {
    dismiss();
    form.current?.querySelector("input")?.focus();
    if (result.type === "asset") { setAsset(result); return; }
    setQuery("");
    const path = result.type === "finding" ? activityLink({ kind: "finding", id: result.id }, scope) : `${inventoryRoutes[result.type]}?inventory=${result.id}`;
    onNavigate(path);
  };
  return <>
    <form ref={form} role="search" className="global-search production-global-search" onSubmit={(event) => void submit(event)}
      onKeyDown={event => {
        if (event.key !== "Escape" || state === "idle") return;
        event.preventDefault(); event.stopPropagation();
        dismiss(); form.current?.querySelector("input")?.focus();
      }}>
      <SearchBox aria-label="Search product entities" value={query} maxLength={128} placeholder="Search agents, tools, identities, runtimes, and findings" onChange={(event) => { dismiss(); setQuery(event.target.value); }} />
      <button type="submit" className="global-search-submit" disabled={state === "loading"}>Search</button>
      {state !== "idle" && <div className="global-results" aria-live="polite">
        {state === "loading" && <span>Searching authorized scope</span>}
        {state === "invalid" && <span role="alert">Enter 2–128 valid search characters.</span>}
        {state === "error" && <span role="alert">Search could not be completed. Retry your search.</span>}
        {state === "ready" && results.length === 0 && <span>No matching product entities</span>}
        {state === "ready" && results.map((result) => <button type="button" key={`${result.type}/${result.id}`} aria-label={`Open ${result.name}`} onClick={() => open(result)}><span>{result.name}<small>{result.type} · {result.id}</small></span></button>)}
      </div>}
    </form>
    {asset && <AssetSearchDetail key={asset.id} asset={asset} client={client} onClose={() => setAsset(null)} />}
  </>;
}

function AssetSearchDetail({ asset, client, onClose }: { asset: SearchResult; client: APIClient; onClose(): void }) {
  const read = useCallback(async (signal?: AbortSignal) => {
    const detail = requireAPIData(await client.GET("/api/v1/assets/{id}", { params: { path: { id: asset.id } }, signal }), decodeInventoryDetail);
    if (detail.summary.kind !== "asset" || detail.summary.id !== asset.id) throw new APITransportError("invalid_response", "Unexpected asset");
    return detail;
  }, [asset.id, client]);
  const detail = useAPIQuery(`search-asset:${asset.id}`, read);
  return <Drawer open title={asset.name} width="medium" onClose={onClose}>
    {detail.status === "loading" && <p role="status">Loading asset details…</p>}
    {["error", "forbidden", "stale"].includes(detail.status) && <p role="alert">Asset details could not be refreshed. <Button onClick={() => void detail.retry()}>Retry</Button></p>}
    {detail.data && <dl className="search-asset-detail">
      <dt>Asset ID</dt><dd><code>{detail.data.summary.id}</code></dd>
      <dt>Owner</dt><dd>{detail.data.summary.owner || "Unassigned"}</dd>
      <dt>Team</dt><dd>{detail.data.summary.team || "Unassigned"}</dd>
      <dt>Source observations</dt><dd>{detail.data.sources.length}</dd>
    </dl>}
  </Drawer>;
}

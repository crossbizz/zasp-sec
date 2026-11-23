"use client";

import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import type { AnalystThread, AnalystThreadSummary } from "../../../apps/web/api/generated";
import { requireAPIData } from "../../../apps/web/api/client";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card } from "../../components/ui";
import { Time } from "../../components/time";
import { workflowIdempotencyKey } from "../workflows/api";

const Conversation = lazy(() => import("./AnalystConversation"));
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function decodeSummary(value: unknown, sessionID: string): AnalystThreadSummary {
  if (!value || typeof value !== "object" || !("id" in value) || typeof value.id !== "string" || !productID.test(value.id)
    || !("session_id" in value) || value.session_id !== sessionID || !("created_at" in value) || !Number.isFinite(Date.parse(String(value.created_at)))) throw Error("Invalid thread");
  return value as AnalystThreadSummary;
}
function decodeHistory(value: unknown, sessionID: string, id: string): AnalystThread {
  const summary = decodeSummary(value, sessionID);
  if (summary.id !== id || !("messages" in summary) || !Array.isArray(summary.messages) || summary.messages.length > 48 ||
    summary.messages.some(m => !m || !productID.test(m.id) || !["user", "assistant"].includes(m.role) || typeof m.text !== "string" || !Array.isArray(m.evidence_ids) || !m.evidence_ids.every((e: string) => productID.test(e)))) throw Error("Invalid thread history");
  return value as AnalystThread;
}
export type StudioBinding = { id: string; revision: number };
export function SessionInvestigation({ sessionID, studio }: { sessionID: string; studio?: StudioBinding }) {
  const [open, setOpen] = useState(false);
  const { queryScopeKey, queryGeneration } = useAPI();
  return <Card title="Session investigation">
    {open ? <><Button onClick={() => setOpen(false)}>Close investigation</Button>
      <InvestigationThreads key={[queryScopeKey, queryGeneration, sessionID, studio?.id, studio?.revision].join("/")} sessionID={sessionID} studio={studio} /></>
      : <Button onClick={() => setOpen(true)}>Investigate session</Button>}
  </Card>;
}
function InvestigationThreads({ sessionID, studio }: { sessionID: string; studio?: StudioBinding }) {
  const { client } = useAPI();
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const pendingKey = useRef("");
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);
  const list = useAPIQuery("investigations:"+sessionID, useCallback(async (signal?: AbortSignal) => {
    const result = await client.GET("/api/v1/security-agents/chat/threads", { params: { query: { session_id: sessionID } }, signal });
    return requireAPIData(result, data => {
      if (!data || typeof data !== "object" || !("items" in data) || !Array.isArray(data.items) || data.items.length > 100) throw Error("Invalid investigations");
      return data.items.map(v => decodeSummary(v, sessionID));
    });
  }, [client, sessionID]));
  const history = useAPIQuery("investigation:"+sessionID+"/"+selected, useCallback(async (signal?: AbortSignal) =>
    requireAPIData(await client.GET("/api/v1/security-agents/chat/threads/{id}", { params: { path: { id: selected }, query: { session_id: sessionID } }, signal }), data => decodeHistory(data, sessionID, selected)), [client, selected, sessionID]), !!selected);
  async function create() {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    pendingKey.current ||= workflowIdempotencyKey();
    setBusy(true); setError("");
    try {
      const result = await client.POST("/api/v1/security-agents/chat/threads", { params: { query: { session_id: sessionID }, header: { "X-CSRF-Token": "", "Idempotency-Key": pendingKey.current } },
        body: { session_id: sessionID, ...(studio ? { studio_id: studio.id, studio_revision: studio.revision } : {}) }, signal: controller.signal });
      const summary = requireAPIData(result, v => decodeSummary(v, sessionID));
      if (controller.signal.aborted) return;
      pendingKey.current = ""; setSelected(summary.id); void list.retry();
    } catch { if (!controller.signal.aborted) setError("Could not start an investigation. Check this environment’s analyst policy and qualified model."); }
    finally { pending.current = null; if (!controller.signal.aborted) setBusy(false); }
  }
  return <div className="analyst-threads">
    <p>The analyst examines recorded action outcomes and evidence references. Questions and event contents stay in this workspace.</p>
    {list.data ? <><div className="row-actions"><Button variant="primary" disabled={busy} onClick={() => void create()}>Start investigation</Button></div>
      {list.data.length > 0 && <details open={!selected}><summary>Saved investigations ({list.data.length})</summary><ul>
        {list.data.map(t => <li key={t.id}><button type="button" className="row-title" onClick={() => setSelected(t.id)}>Investigation from <Time value={t.created_at} /></button></li>)}</ul></details>}</>
      : list.status === "loading" || list.status === "idle" ? <p role="status">Loading investigations…</p> : <p role="status">Investigations are unavailable in this scope. <Button onClick={() => void list.retry()}>Retry</Button></p>}
    {error && <p role="alert">{error}</p>}
    {selected && (history.data ? <Suspense fallback={<p>Loading conversation…</p>}><Conversation key={selected} thread={history.data} /></Suspense>
      : <p role="status">{history.status === "error" || history.status === "forbidden" ? "Investigation history is unavailable." : "Loading investigation history…"}</p>)}
  </div>;
}

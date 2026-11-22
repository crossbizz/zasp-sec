"use client";

import { useCallback, useState } from "react";
import { requireAPIData } from "../../../apps/web/api/client";
import { decodeAgentSuggestions } from "../../../apps/web/api/decoders";
import type { AgentSuggestion, AgentSuggestionPage, InventorySummary, Policy } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Field } from "../../components/ui";

export function SuggestedTools({ agent, revision, tools, onCreate, disabled, canManage }: { canManage:boolean; agent: string; revision: number; tools: readonly InventorySummary[]; disabled: boolean; onCreate(policy: Policy): void }) {
  const { client } = useAPI();
  const [after, setAfter] = useState("");
  const [from, setFrom] = useState(() => new Date(Date.now() - 86400000).toISOString().slice(0, 16));
  const [to, setTo] = useState(() => new Date().toISOString().slice(0, 16));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [review, setReview] = useState("");
  const [saved, setSaved] = useState<AgentSuggestionPage>();
  const getPage = useCallback(async (signal?: AbortSignal) => requireAPIData(await client.GET("/api/v1/agents/{id}/suggestions", { params: { path: { id: agent }, query: after ? { after_tool_id: after } : {} }, signal }), value => decodeAgentSuggestions(value, agent)), [client, agent, after]);
  const result = useAPIQuery(`purpose:suggestions:${agent}:${revision}:${after}`, getPage);
  const page = saved ?? result.data;
  const available = page?.purpose_revision === revision && ["success", "empty"].includes(result.status);
  const label = (tool: string) => tools.find(value => value.id === tool)?.name ?? tool;
  const refresh = async () => {
    const start = Date.parse(from + "Z"), end = Date.parse(to + "Z");
    if (!canManage || busy || disabled) return;
    if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end || end > Date.now() || end - start > 30*86400000) { setError("Select a past UTC interval of up to 30 days."); return; }
    setBusy(true); setError("");
    try {
      const response = await client.POST("/api/v1/agents/{id}/suggestions/refresh", { params: { path: { id: agent } }, body: { purpose_revision: revision, from: new Date(start).toISOString(), to: new Date(end).toISOString() } });
      const current = requireAPIData(response, value => decodeAgentSuggestions(value, agent));
      if (current.purpose_revision !== revision) throw new Error();
      setAfter(""); setSaved(current); setReview("");
    } catch { setError("Runtime observation review unavailable. Refresh the saved declaration and try again."); }
    finally { setBusy(false); }
  };
  const decide = async (item: AgentSuggestion, decision: "request_draft" | "dismiss") => {
    if (!canManage || !available || disabled || busy) return;
    setBusy(true); setError("");
    try {
      const response = await client.PUT("/api/v1/agents/{id}/suggestions/{toolId}/decision", { params: { path: { id: agent, toolId: item.tool_id } }, body: { purpose_revision: revision, decision } });
      const updated = requireAPIData(response, value => decodeAgentSuggestions(value, agent));
      const reviewedPage = after ? await getPage() : updated;
      const receipt = reviewedPage.items.find(row => row.tool_id === item.tool_id);
      if (reviewedPage.purpose_revision !== revision || receipt?.policy_id !== item.policy_id ||
        (decision === "dismiss" ? receipt.state !== "dismissed" : receipt.state !== "draft_requested" && receipt.state !== "draft_linked")) throw new Error();
      setSaved(reviewedPage); setReview("");
      if (decision === "request_draft" && receipt.state === "draft_requested") {
        onCreate({
          id: item.policy_id,
          name: `Restrict ${label(item.tool_id)} (purpose r${revision})`.slice(0, 128),
          scope: "environment",
          trigger: "tool",
          conditions: [
            { field: "agent_id", operator: "equals", value: agent },
            { field: "resource", operator: "equals", value: item.tool_id },
          ],
          action: "block",
          rollout: "draft",
          failure_mode: "open",
        });
      }
    } catch { setError("The review decision is unconfirmed. Reload saved reviews before retrying."); }
    finally { setBusy(false); }
  };
  const reload = async () => { setSaved(undefined); setReview(""); await result.retry(); };
  return <fieldset disabled={disabled || busy}><legend>Observed tool deviations</legend>
    {canManage && <><Field type="datetime-local" label="Observation window from (UTC)" value={from} onChange={e=>setFrom(e.target.value)} />
    <Field type="datetime-local" label="Observation window to (UTC, exclusive)" value={to} onChange={e=>setTo(e.target.value)} />
    <Button onClick={() => void refresh()}>Check runtime observations</Button></>} <Button onClick={() => void reload()}>Reload saved reviews</Button>
    {!available && result.status !== "loading" && <p>Saved reviews are unavailable for this purpose revision.</p>}
    {error && <p role="alert">{error}</p>}
    {available && page && <>
      {page.last_scan ? <p>From {page.last_scan.from} to {page.last_scan.to}, {page.last_scan.eligible} of {page.last_scan.examined} indexed events had an exact agent, session and inventory tool match. {page.last_scan.truncated && "More than 100 events matched. Narrow the window to review older activity."} Unreported activity and adapter coverage are unknown.</p> : <p>No runtime observation window has been reviewed.</p>}
      {page.last_scan && page.items.length === 0 && <p>No saved deviations on this page.</p>}
      <ul>{page.items.map(item => <li key={item.tool_id}><strong>{label(item.tool_id)}</strong> · {item.state.replaceAll("_", " ")}
        <Button onClick={() => setReview(item.tool_id)}>{item.state === "suggested" ? "Review" : "View evidence for"} {label(item.tool_id)}</Button>
        {canManage && item.state === "draft_requested" && <Button onClick={() => void decide(item, "request_draft")}>Resume inactive draft</Button>}
        {item.state === "draft_linked" && <p>Linked policy <code>{item.policy_id}</code> · Creation audit <code>{item.draft_audit_id}</code></p>}
        {review === item.tool_id && <div><p>Block calls by agent <code>{agent}</code> to tool <code>{item.tool_id}</code> outside purpose revision {revision}.</p><p>Evidence recorded between {item.from} and {item.to}</p>
          <ul>{item.evidence_ids.map(id=><li key={id}><code>{id}</code></li>)}</ul>
          {canManage && item.state === "suggested" && <><Button variant="primary" onClick={() => void decide(item, "request_draft")}>Save as inactive draft</Button> <Button onClick={() => void decide(item, "dismiss")}>Dismiss suggestion</Button></>}</div>}
      </li>)}</ul>
      {page.more && page.items.length > 0 && <Button onClick={() => {setSaved(undefined); setReview(""); setAfter(page.items[page.items.length-1].tool_id);}}>Next suggestions</Button>}
      {after && <Button onClick={() => {setSaved(undefined); setReview(""); setAfter("");}}>First suggestions</Button>}
    </>}
  </fieldset>;
}

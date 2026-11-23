"use client";

import { useCallback, useState } from "react";
import type { APIClient } from "../../../apps/web/api/client";
import type { WorkloadDelegationReceipt } from "../../../apps/web/api/generated";
import { readDelegations } from "../../../apps/web/api/workload-delegations";
import { useAPIQuery } from "../../api/query";
import { EvidenceGraph, type EvidenceEdge } from "../../components/EvidenceGraph";
import { Time } from "../../components/time";
import { Button } from "../../components/ui";

type Props = { client: APIClient; credential: string; agent: string };
const states = { issued: "Grant issued", verified: "Scope verified", denied: "Delegation denied", delegation_unverified: "Unverified delegation" };

function GrantEvidence({ receipt }: { receipt: WorkloadDelegationReceipt }) {
  const [selected, select] = useState(receipt.grants.length - 1);
  if (receipt.grants.length === 0) return <p>{receipt.status === "delegation_unverified"
    ? "The workload presented no verifiable grant." : receipt.status === "denied"
    ? "The action failed the delegation check." : "The issuance record for this grant is unavailable."}</p>;
  const hop = receipt.grants[selected];
  const first = receipt.grants[0];
  const nodes = [{ id: "parent", label: first.depth === 1 ? "Task owner" : "Earlier agent" },
    ...receipt.grants.map(g => ({ id: String(g.depth), label: `Delegated agent · hop ${g.depth}` }))];
  const edges: EvidenceEdge[] = receipt.grants.map((g, index) => ({ source: index === 0 ? "parent" : String(receipt.grants[index - 1].depth), target: String(g.depth), kind: "observed" }));
  return <>
    {first.depth > 1 && <p>Earlier hops have no matching issuance receipt.</p>}
    <EvidenceGraph label="Signed delegation chain" nodes={nodes} edges={edges} selectedID={hop ? String(hop.depth) : "parent"}
      onSelect={id => select(receipt.grants.findIndex(g => String(g.depth) === id))} />
    {hop ? <dl><dt>Delegated agent</dt><dd><code>{hop.child_agent_id}</code></dd>
      <dt>Allowed operations</dt><dd>{hop.allowed_operations.join(", ")}</dd>
      <dt>Allowed resources</dt><dd>{hop.allowed_resources.join(", ")}</dd>
      <dt>Depth limit</dt><dd>{hop.depth} of {hop.max_depth} hops</dd>
      <dt>Grant expiry</dt><dd><Time value={new Date(hop.expires_at * 1000).toISOString()} /></dd></dl>
    : <p>Parent agent <code>{first.parent_agent_id}</code></p>}
  </>;
}

function Receipts({ client, credential, agent }: Props) {
  const load = useCallback((signal?: AbortSignal) => readDelegations(client, credential, agent, signal), [client, credential, agent]);
  const q = useAPIQuery(`workload-delegations:${credential}:${agent}`, load);
  const [id, setID] = useState("");
  if (q.status === "forbidden") return <p role="status">Access to these delegation receipts is restricted.</p>;
  if (q.status === "error" || q.status === "stale") return <p role="alert">Delegation receipts could not be verified. <Button onClick={() => void q.retry()}>Retry receipts</Button></p>;
  if (!q.data) return <p role="status">Loading delegation receipts…</p>;
  if (!q.data.items.length) return <p>No delegation receipts recorded for this workload.</p>;
  const selected = q.data.items.find(r => r.id === id) ?? q.data.items[0];
  return <>
    <label>Receipt <select value={selected.id} onChange={e => setID(e.target.value)}>{q.data.items.map(r =>
      <option key={r.id} value={r.id}>{states[r.status]} · {r.parent_task_id || "Unknown task"} · #{r.id}</option>)}</select></label>
    <p><strong>{states[selected.status]}</strong> · <Time value={selected.observed_at} /></p>
    <GrantEvidence key={selected.id} receipt={selected} />
    {q.data.truncated && <p>Showing the 25 most recent receipts.</p>}
  </>;
}

export function WorkloadDelegations(props: Props) {
  const [open, setOpen] = useState(false);
  return <details onToggle={e => setOpen(e.currentTarget.open)}>
    <summary>Task delegation receipts</summary>
    {open && <Receipts {...props} />}
  </details>;
}

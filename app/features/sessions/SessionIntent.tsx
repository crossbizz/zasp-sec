"use client";

import { useEffect, useState } from "react";
import type { SessionIntent, SessionIntentAction } from "../../../apps/web/api/generated";
import { Badge, Button, Card } from "../../components/ui";
import { EvidenceGraph } from "../../components/EvidenceGraph";
import { Time } from "../../components/time";

export const outcomeLabel = { prevented: "Prevented", completed: "Completed", outcome_unknown: "Outcome unknown" } as const;
const sourceLabel = { authenticated_workload: "Authenticated workload", gateway: "Hosted gateway", tetragon: "Kernel sensor", otlp: "OTLP sensor" };
type Reader = (id: string, signal: AbortSignal) => Promise<SessionIntent>;

export function OutcomeBadge({ outcome }: { outcome: SessionIntentAction["outcome"] }) {
  return <Badge tone={outcome === "completed" ? "info" : "warning"}>{outcomeLabel[outcome]}</Badge>;
}

export function SessionIntentPanel({ id, read }: { id: string; read: Reader }) {
  const [opened, setOpened] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<SessionIntent | "error" | null>(null);
  const [selected, setSelected] = useState<string>();
  useEffect(() => {
    if (!opened) return;
    const controller = new AbortController();
    void read(id, controller.signal).then(value => {
      if (!controller.signal.aborted) setResult(value);
    }).catch(() => { if (!controller.signal.aborted) setResult("error"); });
    return () => controller.abort();
  }, [id, read, opened, attempt]);
  const refresh = () => { setResult(null); setAttempt(attempt + 1); };
  const value = result && result !== "error" && result.session_id === id ? result : null;
  const selectedAction = value?.actions.find(action => action.decision_id === selected) ?? value?.actions[0];
  return <Card title="Action outcomes" action={<Button aria-expanded={opened} onClick={() => setOpened(!opened)}>{opened ? "Hide outcomes" : "View outcomes"}</Button>}>
    {opened && <>
      {result === "error" && <p role="alert">Action receipts could not be loaded. <Button onClick={refresh}>Retry receipts</Button></p>}
      {!result && <p role="status">Loading action receipts…</p>}
      {value && <>
        <p>Outcomes apply at the reporting boundary. An operation returning to a workload leaves downstream effects unconfirmed.</p>
        {value.actions.length === 0 ? <p>No linked receipts yet.</p> : <>
          <label className="field"><span>Inspect an action</span><select value={selectedAction?.decision_id} onChange={event => setSelected(event.target.value)}>
            {value.actions.map(action => <option key={action.decision_id} value={action.decision_id}>{action.operation} · {outcomeLabel[action.outcome]} · {action.decision_id.slice(-8)}</option>)}
          </select></label>
          {selectedAction && <ActionEvidence action={selectedAction} />}
        </>}
        {value.truncated && <p>Showing the 100 most recent actions.</p>}
        <Button onClick={refresh}>Refresh outcomes</Button>
      </>}
    </>}
  </Card>;
}

function ActionEvidence({ action }: { action: SessionIntentAction }) {
  const evidence = action.evidence_ids.map((id, index) => ({ id: "receipt/" + id, label: index === 1 ? "Outcome receipt" : "Source receipt", detail: id }));
  const [detail, setDetail] = useState<string>();
  const nodes = [{ id: action.decision_id, label: action.operation, detail: action.decision_id }, ...evidence];
  const current = nodes.find(node => node.id === detail) ?? nodes[0];
  return <section aria-label="Selected action evidence">
    <p><OutcomeBadge outcome={action.outcome} /> · {sourceLabel[action.source]} · <Time value={action.observed_at} /></p>
    {action.attention && <p>{action.outcome === "outcome_unknown" ? "Open evidence gap. A matching outcome receipt is missing or inconclusive." : "Review this blocked attempt and its receipts."}</p>}
    <EvidenceGraph label="Action and linked receipts" nodes={nodes} selectedID={current.id} onSelect={setDetail}
      edges={evidence.map(node => ({ source: action.decision_id, target: node.id, kind: "observed" as const }))} />
    <p>{current.label} · <code>{current.detail}</code></p>
  </section>;
}

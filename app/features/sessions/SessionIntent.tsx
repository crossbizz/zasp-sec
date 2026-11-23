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
          {value.links.length > 0 && <SessionSequence intent={value} onSelect={setSelected} />}
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

function SessionSequence({ intent, onSelect }: { intent: SessionIntent; onSelect(id: string): void }) {
  const [end, setEnd] = useState<string>();
  const byID = new Map(intent.actions.map(a => [a.decision_id, a]));
  const incoming = new Map(intent.links.map(link => [link.target, link]));
  const latest = [...intent.links].reverse();
  const target = end && incoming.has(end) ? end : latest[0].target;
  const edges = [], nodes = [byID.get(target)!];
  let next = incoming.get(target);
  while (next && edges.length < 2) {
    edges.unshift({ source: next.source, target: next.target, kind: "inferred" as const });
    nodes.unshift(byID.get(next.source)!);
    next = incoming.get(next.source);
  }
  return <section aria-label="Possible session sequences">
    <label className="field"><span>Possible follow-up</span><select value={target} onChange={e => { setEnd(e.target.value); onSelect(e.target.value); }}>
      {latest.map(link => <option key={link.target} value={link.target}>{byID.get(link.target)?.operation} · {link.target.slice(-8)}</option>)}
    </select></label>
    <p>Dashed links connect observations from the same agent within two minutes. Their order suggests a possible sequence. Confirm each action using its receipts.</p>
    <EvidenceGraph label="Possible session sequence" nodes={nodes.map(n => ({ id:n.decision_id, label:n.operation, detail:outcomeLabel[n.outcome] }))}
      edges={edges} onSelect={onSelect} />
  </section>;
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

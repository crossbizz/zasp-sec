"use client";

import { useState } from "react";
import type { Policy, PolicyReplayInput, PolicySimulation } from "../../../apps/web/api/generated";
import { Button, Field } from "../../components/ui";

export function ScopedReplay({ policy, version, disabled, runReplay }: { policy: Policy; version: string; disabled: boolean; runReplay(input: PolicyReplayInput): Promise<PolicySimulation> }) {
  const [agent, setAgent] = useState(policy.conditions.find(condition => condition.field === "agent_id" && condition.operator === "equals")?.value ?? "");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<PolicySimulation | null>(null);
  const [error, setError] = useState("");
  const reset = () => { setData(null); setError(""); };
  const submit = async (continuation?: { to: string; before_event_id: string }) => {
    if (busy || disabled) return;
    reset();
    const start = Date.parse(`${from}Z`), end = continuation ? Date.parse(continuation.to) : Date.parse(`${to}Z`);
    const revision = /^"([1-9]\d*)"$/.exec(version)?.[1];
    if (!revision || !/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(agent) || !Number.isFinite(start) || !Number.isFinite(end) || (start > end || start === end && !continuation) || end > Date.now() || end - start > 30*86400000) {
      setError("Choose a valid agent ID and a past UTC interval of up to 30 days."); return;
    }
    setBusy(true);
    try {
      setData(await runReplay({ schema_version: 2, policy_revision: Number(revision), agent_id: agent, from: new Date(start).toISOString(), to: new Date(end).toISOString(), ...(continuation ? { before_event_id: continuation.before_event_id } : {}) }));
    } catch { setError("Replay unavailable. Refresh the policy revision and check access to runtime history."); }
    finally { setBusy(false); }
  };
  const replay = data?.replay;
  const continuation = replay?.next_window_to && replay.next_before_event_id ? { to: replay.next_window_to, before_event_id: replay.next_before_event_id } : undefined;
  return <fieldset disabled={disabled || busy}><legend>Replay a policy revision</legend>
    <Field label="Replay agent ID" value={agent} onChange={event => { reset(); setAgent(event.target.value); }} />
    <Field type="datetime-local" label="Replay from (UTC)" value={from} onChange={event => { reset(); setFrom(event.target.value); }} />
    <Field type="datetime-local" label="Replay to (UTC, exclusive)" value={to} onChange={event => { reset(); setTo(event.target.value); }} />
    <Button onClick={() => void submit()} disabled={!agent || !from || !to}>Replay revision {version.replaceAll('"', '')}</Button>
    {busy && <p role="status">Replaying scoped runtime history…</p>}
    {error && <p role="alert">{error}</p>}
    {data?.replay && <div role="status"><p>{data.matches} matched and {data.would_block} would block across {data.replay.evaluated} indexed actions.</p>
      <p>Coverage includes indexed {policy.trigger} events attributed to this agent during the selected interval. Unreported activity and adapter availability are unknown.</p>
      {data.replay.evaluated === 0 && <p>Insufficient activity in this window.</p>}
      {data.replay.would_block_rate && Object.entries(data.replay.would_block_rate).map(([surface, rate]) => <p key={surface}>Would block {(rate * 100).toFixed(1)}% of eligible {surface} actions.</p>)}
      {data.replay.truncated && <p>Additional indexed actions matched this window. {continuation ?
        <Button onClick={() => void submit(continuation)}>Replay remaining actions</Button> :
        "Narrow the window to review older activity."}</p>}
      {data.example_session_ids.length > 0 && <p>Example sessions: {[...new Set(data.example_session_ids)].join(", ")}</p>}
    </div>}
  </fieldset>;
}

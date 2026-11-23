"use client";

import { useState } from "react";
import type { Policy, PolicyReplayInput, PolicySimulation } from "../../../apps/web/api/generated";
import { Button, Field } from "../../components/ui";
import { activityLink, type ActivityScope } from "../../domain/activity-links";

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;

type Cursor = { to: string; before_event_id: string };
type Page = { number: number; result: PolicySimulation };

export function PolicyExampleSessions({ ids, scope }: { ids: readonly string[]; scope?: ActivityScope }) {
  if (ids.length === 0) return null;
  return <div><h4>Example sessions</h4><ul>
    {[...new Set(ids)].map(id => <li key={id}>
      {scope && productID.test(id) ? <a href={activityLink({ kind: "session", id }, scope)}>{id}</a> : <code>{id}</code>}
    </li>)}
  </ul></div>;
}

export function ScopedReplay({ policy, version, disabled, sessionScope, runReplay }: {
  policy: Policy; version: string; disabled: boolean; sessionScope?: ActivityScope;
  runReplay(input: PolicyReplayInput): Promise<PolicySimulation>;
}) {
  const [agent, setAgent] = useState(policy.conditions.find(condition => condition.field === "agent_id" && condition.operator === "equals")?.value ?? "");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState("");
  const reset = () => { setPage(null); setError(""); };

  async function submit(continuation?: Cursor) {
    if (busy || disabled) return;
    const start = Date.parse(`${from}Z`);
    const end = Date.parse(continuation?.to ?? `${to}Z`);
    const revision = /^"([1-9]\d*)"$/.exec(version)?.[1];
    if (!revision || !productID.test(agent) || !Number.isFinite(start) || !Number.isFinite(end) || start > end || (start === end && !continuation) || end > Date.now() || end - start > 30 * 86400000) {
      setError("Choose a valid agent ID and a past UTC interval of up to 30 days.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      // The service cursor may contain sub-millisecond precision. Preserve both
      // fields verbatim so tied and adjacent events remain reachable.
      const result = await runReplay({ schema_version: 2, policy_revision: Number(revision), agent_id: agent, from: new Date(start).toISOString(),
        to: continuation?.to ?? new Date(end).toISOString(), ...(continuation ? { before_event_id: continuation.before_event_id } : {}) });
      setPage({ number: continuation && page ? page.number + 1 : 1, result });
    } catch {
      setError("Replay unavailable. Refresh the policy revision and check access to runtime history.");
    } finally { setBusy(false); }
  }
  const replay = page?.result.replay;
  const continuation = replay?.next_window_to && replay.next_before_event_id ? { to: replay.next_window_to, before_event_id: replay.next_before_event_id } : undefined;
  return <fieldset disabled={disabled || busy}><legend>Replay a policy revision</legend>
    <Field label="Replay agent ID" value={agent} onChange={event => { reset(); setAgent(event.target.value); }} />
    <Field type="datetime-local" label="Replay from (UTC)" value={from} onChange={event => { reset(); setFrom(event.target.value); }} />
    <Field type="datetime-local" label="Replay to (UTC, exclusive)" value={to} onChange={event => { reset(); setTo(event.target.value); }} />
    <Button onClick={() => void submit()} disabled={!agent || !from || !to}>Replay revision {version.replaceAll('"', '')}</Button>
    {busy && <p role="status">Replaying scoped runtime history…</p>}
    {error && <p role="alert">{error}</p>}
    {replay && page && <div role="status">
      <p><strong>Page {page.number}.</strong> {page.result.matches} matched and {page.result.would_block} would block across {replay.evaluated} indexed actions.</p>
      <p>Coverage includes indexed {policy.trigger} events attributed to this agent during the selected interval. Unreported activity and adapter availability are unknown.</p>
      {replay.evaluated === 0 && <p>Insufficient activity on this page.</p>}
      {replay.would_block_rate && Object.entries(replay.would_block_rate).map(([surface, rate]) => <p key={surface}>Would block {(rate * 100).toFixed(1)}% of eligible {surface} actions on this page.</p>)}
      {replay.truncated && <p>Additional indexed actions matched this window. {continuation ?
        <Button onClick={() => void submit(continuation)}>Replay remaining actions</Button> :
        "Narrow the window to review older activity."}</p>}
      <PolicyExampleSessions ids={page.result.example_session_ids} scope={sessionScope} />
    </div>}
  </fieldset>;
}

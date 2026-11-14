"use client";

import { useState } from "react";

import type { SecurityAgentRunCloseReason, SecurityAgentRunClosure, SecurityAgentRunDetail } from "../../../apps/web/api/generated";
import { Badge, Button, Select } from "../../components/ui";

// Plain-language text for the stop codes the product records on a run. The API
// returns a code, never provider text; an unknown code is shown as recorded.
const stopReasonText: Readonly<Record<string, string>> = {
  planner_provider_rejected: "The AI provider refused the planning request before it generated anything. Nothing was charged and no action ran. Typical causes are a provider account without credits, a credential the provider does not accept, or a rate limit.",
  planner_not_sent: "No planning request left the product. Nothing was sent to the AI provider, nothing was charged and no action ran.",
  budget_usage_unknown: "A planning request was sent to the AI provider, but its outcome and usage could not be verified. The usage stays recorded as unknown, never as zero. Until someone closes this run it keeps holding its agent's capacity.",
  planner_rejected: "The product did not accept the result of the planning step, so no plan was stored.",
};

export const closeReasonText: Readonly<Record<SecurityAgentRunCloseReason, string>> = {
  no_action_required: "No action required",
  resolved_outside_product: "Resolved outside the product",
  usage_unknown_accepted: "Accept that the AI usage stays unknown",
};

export function describeStopReason(code: string): string {
  return stopReasonText[code] ?? `The run stopped with the recorded code ${code}.`;
}

// A run whose planner request has an unknown outcome can be closed only with
// usage_unknown_accepted; every other run only with one of the other reasons.
export function hasUnknownPlannerUsage(value: Pick<SecurityAgentRunDetail, "stop_reason" | "budget_stop_reason">): boolean {
  return value.stop_reason === "budget_usage_unknown" || value.budget_stop_reason === "budget_usage_unknown";
}

export function closeReasonsFor(value: Pick<SecurityAgentRunDetail, "stop_reason" | "budget_stop_reason">): readonly SecurityAgentRunCloseReason[] {
  return hasUnknownPlannerUsage(value) ? ["usage_unknown_accepted"] : ["no_action_required", "resolved_outside_product"];
}

export function RunStateBadge({ state, closed }: { state: SecurityAgentRunDetail["run"]["state"]; closed: boolean }) {
  return <>
    <Badge tone={state === "contained" || state === "remediated" ? "success" : state === "failed" ? "critical" : state === "needs_human" && !closed ? "warning" : "info"}>{state}</Badge>
    {closed && <> <Badge tone="neutral">closed</Badge></>}
  </>;
}

export function RunStopReason({ code }: { code: string }) {
  return <section className="security-agent-run-stop" aria-label="Stop reason">
    <h3>Why this run stopped</h3>
    <p>{describeStopReason(code)}</p>
    <p><small>Recorded code: <code>{code}</code></small></p>
  </section>;
}

export function RunClosure({ value }: { value: SecurityAgentRunClosure }) {
  return <section className="security-agent-run-closure" aria-label="Closure">
    <h3>Closed by a person</h3>
    <p>This run was reviewed and closed. It keeps the state needs_human and its recorded stop reason; it no longer holds its agent&apos;s capacity.</p>
    <dl>
      <div><dt>Reason</dt><dd>{closeReasonText[value.reason]}</dd></div>
      <div><dt>Closed at</dt><dd><time dateTime={value.closed_at}>{value.closed_at}</time></dd></div>
      <div><dt>Closed by</dt><dd><code>{value.closed_by}</code></dd></div>
      {value.note && <div><dt>Note</dt><dd>{value.note}</dd></div>}
    </dl>
  </section>;
}

export type RunCloseInput = { reason: SecurityAgentRunCloseReason; note?: string };

export function CloseRunForm({ value, disabled, retrying, failure, onClose }: { value: SecurityAgentRunDetail; disabled: boolean; retrying: boolean; failure: "none" | "lost" | "rejected"; onClose(input: RunCloseInput): void }) {
  const expected = closeReasonsFor(value);
  // After the server refused a reason, offer every reason of the contract so a
  // run whose usage was settled meanwhile can still be closed.
  const reasons: readonly SecurityAgentRunCloseReason[] = failure === "rejected" ? ["no_action_required", "resolved_outside_product", "usage_unknown_accepted"] : expected;
  const [chosen, setChosen] = useState<SecurityAgentRunCloseReason>(expected[0]);
  const [note, setNote] = useState("");
  const reason = reasons.includes(chosen) ? chosen : reasons[0];
  const trimmed = note.trim();
  const noteInvalid = trimmed.length > 500;
  return <section className="security-agent-run-close" aria-label="Close run">
    <h3>Close this run</h3>
    <p>Closing records that a person reviewed this run. The run keeps its state and stop reason, and the closure is written to the audit log. It cannot be undone.</p>
    {hasUnknownPlannerUsage(value) && <p>The AI usage of this run is unknown. Closing it accepts that the usage stays recorded as unknown and frees the agent&apos;s capacity.</p>}
    <Select label="Reason" value={reason} disabled={disabled || retrying} onChange={(event) => setChosen(event.target.value as SecurityAgentRunCloseReason)}>
      {reasons.map((item) => <option key={item} value={item}>{closeReasonText[item]}</option>)}
    </Select>
    <label className="field"><span>Note (optional, one line, up to 500 characters)</span><input type="text" value={note} maxLength={500} disabled={disabled || retrying} onChange={(event) => setNote(event.target.value.replace(/[\r\n]+/g, " "))} /></label>
    <Button variant="danger" disabled={disabled || noteInvalid} onClick={() => onClose(trimmed ? { reason, note: trimmed } : { reason })}>{retrying ? "Retry retained run closure" : "Close run"}</Button>
    {failure === "lost" && <p role="alert">The closure response was lost. Retry reuses the exact run, version, reason and idempotency key.</p>}
    {failure === "rejected" && <p role="alert">The run could not be closed. The server accepts &quot;{closeReasonText.usage_unknown_accepted}&quot; only for a run with unknown AI usage, and only that reason for such a run. Choose the other kind of reason, or reopen the run to load its current state.</p>}
  </section>;
}

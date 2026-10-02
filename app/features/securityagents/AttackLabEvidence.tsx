import type { SecurityAgentAttackLabDetail } from "../../../apps/web/api/generated";
import { activityLink, type ActivityScope } from "../../domain/activity-links";

const reasons = {
  attack_lab_unsafe_condition_reproduced: "Unsafe condition reproduced.",
  attack_lab_not_reproduced_in_bounded_run: "Not reproduced in this bounded run.",
  attack_lab_evidence_unavailable: "Immutable evidence could not be verified.",
  attack_lab_outcome_unknown: "Execution outcome is uncertain.",
  attack_lab_pre_execution_denied: "Execution was refused before any sandbox action.",
  attack_lab_cancelled: "Cancellation and sandbox cleanup confirmed.",
};
export function AttackLabEvidence({ value, activityScope, canReadTests, onNavigate }: { value: SecurityAgentAttackLabDetail; activityScope?: ActivityScope; canReadTests?: boolean; onNavigate?: (path: string) => void }) {
  const href = activityScope && canReadTests && onNavigate ? activityLink({ kind: "test_run", id: value.source_run_id }, activityScope) : null;
  const executionHref = activityScope && canReadTests && onNavigate ? activityLink({ kind: "attack_lab_run", id: value.execution_id }, activityScope) : null;
  return <section aria-label="Recorded Attack Lab evidence" style={{ overflowWrap: "anywhere" }}>
    <h4>Recorded Attack Lab evidence</h4>
    <p>Test definition: {value.definition_id} · version {value.definition_version}</p>
    <p>Source run: {value.source_run_id} · attempt {value.source_attempt}</p>
    {href && <a href={href} onClick={event => { event.preventDefault(); onNavigate?.(href); }}>Open approved source run</a>}
    <p>Execution run: {value.execution_id} · attempt {value.attempt}</p>
    {executionHref && <a href={executionHref} onClick={event => { event.preventDefault(); onNavigate?.(executionHref); }}>Open linked Attack Lab execution</a>}
    <p>Sandbox state: {value.state}</p>
    {value.cancel_requested && !value.cleanup_complete && <p>Cancellation requested; execution may already have occurred.</p>}
    <p>{value.cleanup_complete ? "Sandbox cleanup confirmed." : "Sandbox cleanup pending. This obligation remains after the Security Agent stops."}</p>
    <p>Cleanup checkpoint: {value.cleanup_state}</p>
    {value.settlement ? <>
      <p>Attack Lab outcome: {{ needs_human: "Needs human", inconclusive: "Inconclusive", failed: "Failed", cancelled: "Cancelled" }[value.settlement.outcome]}</p>
      <p>{reasons[value.settlement.reason]}</p>
      <p>Settlement digest: {value.settlement.proof_digest}</p>
    </> : <p>Attack Lab verification pending.</p>}
    <p>This bounded reproduction does not resolve a finding or establish that the target is safe.</p>
    {value.evidence && <section aria-label="Immutable Attack Lab evidence">
      <p>Evidence version: {value.evidence.version_id}</p><p>Evidence SHA-256: {value.evidence.sha256}</p>
      <p>Reference digest: {value.evidence.reference_digest}</p><p>Evidence size: {value.evidence.size_bytes} bytes</p>
    </section>}
  </section>;
}

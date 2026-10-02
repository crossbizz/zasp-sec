import type { SecurityAgentActionDetail } from "../../../apps/web/api/generated";
import { ExistingTestEvidence } from "./ExistingTestEvidence";
import { AttackLabEvidence } from "./AttackLabEvidence";
import type { ActivityScope } from "../../domain/activity-links";

export function ActionDetails({ value, stepID, activityScope, canReadTests = false, onNavigate }: { value?: SecurityAgentActionDetail; stepID: string; activityScope?: ActivityScope; canReadTests?: boolean; onNavigate?: (path: string) => void }) {
  if (!value) return <p>Action details unavailable from this server.</p>;
  const args = value.arguments;
  return <section aria-label={`Action details ${stepID}`}>
    <h4>Persisted action details</h4>
    {args ? <div>
      <p>Target: {args.target_id}</p>
      {"evidence_ids" in args && <div>
        <p>Selected export evidence</p>
        <ul aria-label="Selected export evidence">
          {args.evidence_ids.map(source => <li key={`${source.source_kind}/${source.source_id}`}>
            {source.source_kind}: {source.source_id} · version {source.source_version}
          </li>)}
        </ul>
      </div>}
      {"expected_version" in args && <p>Expected version: {args.expected_version}</p>}
      {"target_status" in args && <p>Target status: {args.target_status}</p>}
      {"assignee_id" in args && <p>Assignee: {args.assignee_id}</p>}
      {"response_status" in args && <p>Response status: {args.response_status}</p>}
      {"note" in args && <p>Response note: {args.note}</p>}
      {"mode" in args && <p>Mode: {args.mode}</p>}
      {"scope" in args && <p>Environment: {args.scope}</p>}
      {"session_id" in args && <><p>Session: {args.session_id}</p><p>Device: {args.device_id}</p></>}
      {"integration_id" in args && <p>Integration: {args.integration_id}</p>}
    </div> : <p>Redacted arguments unavailable.</p>}
    {value.result ? <div>
      <p>Effect state: {value.result.state}</p>
      {value.result.outcome_id && <p>Recorded outcome: {value.result.outcome_id}</p>}
      {value.result.result_digest && <p>Result digest: {value.result.result_digest}</p>}
    </div> : <p>No effect result recorded.</p>}
    <p>{value.ttl_seconds === null ? "TTL unavailable or not applicable." : `TTL: ${value.ttl_seconds} seconds`}</p>
    <p>{value.control_expires_at === null ? "Control expiry unavailable." : `Control expires: ${value.control_expires_at}`}</p>
    <p>{{ automatic: "Automatic cleanup", manual: "Manual restoration only", not_supported: "No rollback support" }[value.rollback.support]}</p>
    <p>Rollback: {value.rollback.state}</p>
    <p>Cleanup verification {value.rollback.verification.state}</p>
    <p>Application verification {value.verification.state}</p>
    <p>{{ none: "No verification evidence", effect_record: "Recorded action result", policy_targets: "Recorded policy target verification" }[value.verification.source]}</p>
    <p>Recorded evidence, not a new live provider check.</p>
    {value.existing_test && <ExistingTestEvidence value={value.existing_test} activityScope={activityScope} canReadTests={canReadTests} onNavigate={onNavigate} />}
    {value.attack_lab && <AttackLabEvidence value={value.attack_lab} activityScope={activityScope} canReadTests={canReadTests} onNavigate={onNavigate} />}
  </section>;
}

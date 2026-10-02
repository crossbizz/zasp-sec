import type { SecurityAgentExistingTestDetail, SecurityAgentTestArtifactIdentity, SecurityAgentTestAttemptProof, SecurityAgentTestCheckChange, SecurityAgentTestVerification } from "../../../apps/web/api/generated";
import { activityLink, type ActivityScope } from "../../domain/activity-links";

type TestHistoryProps = { activityScope?: ActivityScope; canReadTests?: boolean; onNavigate?: (path: string) => void };
function TestHistoryLink({ id, label, activityScope, canReadTests, onNavigate }: TestHistoryProps & { id: string; label: string }) {
  if (!activityScope || !canReadTests || !onNavigate) return null;
  const href = activityLink({ kind: "test_run", id }, activityScope);
  return <a href={href} onClick={event => { event.preventDefault(); onNavigate(href); }}>{label}</a>;
}

const outcomeLabels: Record<SecurityAgentTestVerification["outcome"], string> = {
  remediated: "Remediated",
  needs_human: "Needs human review",
  inconclusive: "Inconclusive",
  failed: "Failed",
  cancelled: "Cancelled",
};
const reasonLabels: Record<SecurityAgentTestVerification["reason"], string> = {
  test_condition_changed: "Test condition changed.",
  test_baseline_unavailable: "Test baseline unavailable.",
  test_condition_persists: "Test condition persists.",
  test_outcome_unknown: "Test outcome unknown.",
  test_evidence_unavailable: "Test evidence unavailable.",
  test_evaluation_inconclusive: "Test evaluation inconclusive.",
  test_run_failed: "Test run failed.",
  test_run_cancelled: "Test run cancelled.",
};
const cancellationLabels: Record<NonNullable<SecurityAgentExistingTestDetail["cancellation_outcome"]>, string> = {
  cancelled_before_execution: "Cancellation confirmed before execution.",
  cancelled_after_partial_execution: "Cancellation confirmed after partial execution. Prior work was not undone.",
  outcome_unknown: "Execution is unconfirmed. Cancellation was requested but its outcome is unknown.",
};
const categoryLabels: Record<SecurityAgentTestCheckChange["category"], string> = {
  prompt_injection: "Prompt injection",
  tool_abuse: "Tool abuse",
  data_leakage: "Data leakage",
  authorization_bypass: "Authorization bypass",
  excessive_agency: "Excessive agency",
  sensitive_information: "Sensitive information",
};

function ArtifactIdentity({ label, value }: { label: string; value: SecurityAgentTestArtifactIdentity }) {
  return <section aria-label={label}>
    <h6>{label}</h6>
    <p>Reference digest: {value.reference_digest}</p>
    <p>Version ID: {value.version_id}</p>
    <p>SHA-256: {value.sha256}</p>
    <p>Size: {value.size_bytes} bytes</p>
  </section>;
}

function TestAttempt({ label, value, historyLabel, ...history }: TestHistoryProps & { label: string; historyLabel: string; value: SecurityAgentTestAttemptProof | null }) {
  if (!value) return <p>{label}: No recorded evidence.</p>;
  return <section aria-label={label}>
    <h5>{label}</h5>
    <p>Run: {value.run_id}</p>
    <TestHistoryLink id={value.run_id} label={historyLabel} {...history} />
    <p>Attempt: {value.attempt}</p>
    <p>Input digest: {value.input_digest}</p>
    <ArtifactIdentity label="Input artifact" value={value.input_artifact} />
    <ArtifactIdentity label="Output artifact" value={value.output_artifact} />
  </section>;
}

export function ExistingTestEvidence({ value, ...history }: TestHistoryProps & { value: SecurityAgentExistingTestDetail }) {
  const verification = value.verification;
  return <section aria-label="Recorded test evidence" style={{ overflowWrap: "anywhere" }}>
    <h4>Recorded test evidence</h4>
    <p>Recorded evidence, not current provider health or a fresh test. The test outcome is separate from the Security Agent run status.</p>
    <p>Test definition: {value.definition_id}</p>
    <p>Test definition version: {value.definition_version}</p>
    <p>Linked test run: {value.test_run_id}</p>
    <TestHistoryLink id={value.test_run_id} label="Open linked test run" {...history} />
    <p>{value.state === "pending" ? "Test verification pending." : "Test verification settled."}</p>
    {value.cancellation_outcome && <p>{cancellationLabels[value.cancellation_outcome]}</p>}
    {verification && <>
      <p>Test outcome: {outcomeLabels[verification.outcome]}</p>
      <p>Reason: {reasonLabels[verification.reason]}</p>
      <p>Proof digest: {verification.proof_digest}</p>
      <TestAttempt label="Before test attempt" historyLabel="Open before test run" value={verification.before} {...history} />
      <TestAttempt label="After test attempt" historyLabel="Open after test run" value={verification.after} {...history} />
      {verification.checks.length > 0 ? <div style={{ overflowX: "auto" }}>
        <table>
          <caption>Recorded check comparison</caption>
          <thead><tr>
            <th scope="col">Category</th><th scope="col">Check ID</th>
            <th scope="col">Before protected</th><th scope="col">After protected</th>
            <th scope="col">Before HTTP status</th><th scope="col">After HTTP status</th>
            <th scope="col">Prompt digest</th><th scope="col">Assertion digest</th>
          </tr></thead>
          <tbody>{verification.checks.map(check => <tr key={check.check_id}>
            <td>{categoryLabels[check.category]}</td><td>{check.check_id}</td>
            <td>{check.before_protected ? "Yes" : "No"}</td><td>{check.after_protected ? "Yes" : "No"}</td>
            <td>{check.before_http_status}</td><td>{check.after_http_status}</td>
            <td>{check.prompt_digest}</td><td>{check.assertion_digest}</td>
          </tr>)}</tbody>
        </table>
      </div> : <p>No recorded check comparison.</p>}
    </>}
  </section>;
}

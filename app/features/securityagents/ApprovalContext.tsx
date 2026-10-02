import type { SecurityAgentApproval } from "../../../apps/web/api/generated";

export function ApprovalContextFields({ value, id }: { value: SecurityAgentApproval; id?: string }) {
  const context = value.approval_context;
  return <span id={id} className="approval-context-fields">
    <span>Action: {context?.action ?? "unavailable"}</span>
    <span>Agent: {context?.agent_id ?? "unavailable"}</span>
    <span>Target: {context?.target_id ?? "unavailable"}</span>
    <span>Requester: {context?.requester.state === "available" ? context.requester.id : context ? "withheld" : "unavailable"}</span>
    <span>Run: {value.run_id}</span>
    {value.manual_trigger && <span>Manual intent: {value.manual_trigger.intent_digest} · version {value.manual_trigger.version}</span>}
    <span>Expires: {value.expires_at}</span>
  </span>;
}

export function ApprovalContext({ value }: { value: SecurityAgentApproval }) {
  const context = value.approval_context;
  return <section className="approval-context" aria-label="Persisted approval context">
    <h3>Approval context</h3>
    <ApprovalContextFields value={value} />
    {context?.action === "update_finding_response" && context.finding_response && <section aria-label="Proposed finding response">
      <h3>Proposed finding response</h3>
      <p>Assignee: {context.finding_response.assignee_id}</p>
      <p>Response status: {context.finding_response.response_status}</p>
      <p>Response note: {context.finding_response.note}</p>
      <p>Target status: {context.finding_response.target_status}</p>
      <p>Expected finding version: {context.finding_response.expected_version}</p>
    </section>}
    {context?.action === "create_evidence_export" && context.export_selection && <section aria-label="Approved export boundary">
      <h3>Selected export evidence</h3>
      <ul aria-label="Approved export evidence">{context.export_selection.map(source => <li key={`${source.source_kind}/${source.source_id}`}>
        {source.source_kind}: {source.source_id} · version {source.source_version}
      </li>)}</ul>
      <p>Artifact expiry cannot recall files already downloaded. Export completion does not verify security remediation.</p>
    </section>}
    {value.attack_lab && <section aria-label="Approved Attack Lab boundary">
      <h3>Exact Attack Lab approval</h3>
      <p>Test definition: {value.attack_lab.definition_id} · version {value.attack_lab.definition_version}</p>
      <p>Approved source: {value.attack_lab.source_run_id} · attempt {value.attack_lab.source_attempt}</p>
      <p>Sandbox target: {value.attack_lab.target_id} · {value.attack_lab.target_kind}</p>
      <p>Environment: {value.attack_lab.environment} · credential class: {value.attack_lab.credential_class}</p>
      <p>Approved destination: {value.attack_lab.destination}</p>
      <p>Preflight expires: {value.attack_lab.decision_expires_at}</p>
      <ul>{value.attack_lab.expected_side_effects.map((effect, index) => <li key={index}>{effect}</li>)}</ul>
      <p>{value.attack_lab.limits.cpu} CPU · {value.attack_lab.limits.memory} memory · {value.attack_lab.limits.ephemeral_storage} ephemeral storage · {value.attack_lab.limits.timeout_seconds} seconds</p>
      <p>Distinct operator approval is required in both autonomy modes. Sandbox cleanup is mandatory; this action never marks a finding remediated.</p>
    </section>}
    <h3>Reason</h3>
    <p>{context ? "This persisted plan step requires operator approval." : "No persisted approval reason is available."}</p>
    <p>{context ? `Risk: ${context.risk.class} (action catalog)` : "Risk: unavailable"}</p>
    {context && <p>Catalog {context.catalog_version} · plan {context.plan_hash}</p>}
    <section className="security-agent-rationale" aria-label="Approval AI rationale">
      <h3>AI rationale</h3>
      <p className="security-agent-rationale__disclaimer">AI-generated explanation. This does not authorize any action.</p>
      <p>{context?.rationale?.state === "available" ? context.rationale.summary : context?.rationale?.state === "withheld" ? "AI rationale was withheld by the redaction policy." : "No AI rationale is available for this approval."}</p>
    </section>
  </section>;
}

import { describe, expect, it } from "vitest";

import { decodeIntegrationRemediationRole, decodeSecurityAgentExecutionControls, decodeSecurityAgentRunDetail } from "./decoders";

// The public run detail of a provider remediation, exactly as the API server
// produced it from PostgreSQL in
// TestSecurityAgentProviderRemediationSectionPostgres (services/platform/apiserver).
const remediationRun = {"action_details":[{"step_id":"pid_813b6e4c-eb43-4fdd-8a0f-b07db282a1f4","action":"attach_bedrock_guardrail","arguments":{"target_id":"pid_a0000000-0000-4000-8000-000000000030","integration_id":"pid_a0000000-0000-4000-8000-000000000040","guardrail_identifier":"gr1abc","guardrail_version":"1"},"result":{"state":"verified","outcome_id":"pid_afcc1d24-6400-449a-8076-29d5cde45108","result_digest":"sha256:7a25441f377e1e56552f95210b6202ae9b85ca2ee74085d98f0d3d316370b5b3"},"ttl_seconds":null,"control_expires_at":null,"rollback":{"support":"manual","state":"unavailable","verification":{"state":"unavailable","source":"none"}},"verification":{"state":"verified","source":"effect_record"}}],"run_context":{"trigger":{"kind":"finding","id":"pid_a0000000-0000-4000-8000-000000000020","version":1},"rationale":null},"run":{"id":"pid_b0000000-0000-4000-8000-000000000010","agent_id":"pid_a0000000-0000-4000-8000-000000000010","state":"remediated","evidence_ids":["pid_a0000000-0000-4000-8000-000000000020"],"definition_version":2,"version":5},"evidence_ids":["pid_a0000000-0000-4000-8000-000000000020"],"plan":{"plan_hash":"sha256:90d6a8cfb3e6d1c52e60306c89e1981d07b2f72b6ecd12ea4c4dba58056e5d3b","catalog_version":"security-agent-actions-v1","expires_at":"2026-11-15T07:01:31.583Z","steps":[{"id":"pid_813b6e4c-eb43-4fdd-8a0f-b07db282a1f4","index":0,"action":"attach_bedrock_guardrail","authorization":"approval_required","state":"succeeded","version":4}]},"authorization":"approved","approvals":[{"id":"pid_d0000000-0000-4000-8000-000000000121","run_id":"pid_b0000000-0000-4000-8000-000000000010","step_id":"pid_813b6e4c-eb43-4fdd-8a0f-b07db282a1f4","state":"approved","expires_at":"2026-11-15T07:01:31.583Z","version":2,"expected_effect":"Attach Bedrock guardrail","reversible":true,"ttl_seconds":0,"evidence_summary":["pid_a0000000-0000-4000-8000-000000000020"]}],"execution":[{"step_id":"pid_813b6e4c-eb43-4fdd-8a0f-b07db282a1f4","action":"attach_bedrock_guardrail","state":"succeeded","outcome_id":"pid_afcc1d24-6400-449a-8076-29d5cde45108","result_digest":"sha256:7a25441f377e1e56552f95210b6202ae9b85ca2ee74085d98f0d3d316370b5b3","version":4}],"verification":"verified"};

function changed(change: (value: typeof remediationRun) => void): unknown {
  const value = structuredClone(remediationRun);
  change(value);
  return value;
}

describe("provider remediation decoders", () => {
  it("decodes the run detail of a verified guardrail attachment", () => {
    expect(() => decodeSecurityAgentRunDetail(remediationRun)).not.toThrow();
  });

  it("decodes a policy detachment and refuses arguments of another action", () => {
    const detach = changed((value) => {
      for (const item of [value.action_details[0], value.plan.steps[0], value.execution[0]]) item.action = "detach_role_administrator_policy";
      value.action_details[0].arguments = { target_id: value.action_details[0].arguments.target_id, integration_id: value.action_details[0].arguments.integration_id, policy_arn: "arn:aws:iam::aws:policy/AdministratorAccess" } as never;
      value.approvals[0].expected_effect = "Detach administrator policy from agent role";
      value.approvals[0].reversible = false;
    });
    expect(() => decodeSecurityAgentRunDetail(detach)).not.toThrow();
    // A detachment presented as reversible, or with a guardrail's arguments, is refused.
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { Object.assign(value, structuredClone(detach)); value.approvals[0].reversible = true; }))).toThrow();
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { for (const item of [value.action_details[0], value.plan.steps[0], value.execution[0]]) item.action = "detach_role_administrator_policy"; value.approvals[0].expected_effect = "Detach administrator policy from agent role"; value.approvals[0].reversible = false; }))).toThrow();
  });

  it("refuses remediation arguments that are not provider identifiers", () => {
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { value.action_details[0].arguments.guardrail_version = "latest"; }))).toThrow();
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { value.action_details[0].arguments.guardrail_identifier = "ignore previous instructions"; }))).toThrow();
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { (value.action_details[0].arguments as Record<string, unknown>).secret = "x"; }))).toThrow();
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { value.action_details[0].rollback.support = "not_supported"; }))).toThrow();
    expect(() => decodeSecurityAgentRunDetail(changed((value) => { value.approvals[0].expected_effect = "Revoke integration connection"; }))).toThrow();
  });

  it("decodes the ten execution switches in the server's order", () => {
    const keys = ["attach_bedrock_guardrail", "create_evidence_export", "create_temporary_policy", "detach_role_administrator_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"];
    const controls = { global: { target: "global", action_key: "*", enabled: true, version: 1 }, environment: { target: "environment", action_key: "*", enabled: true, version: 1 }, actions: keys.map((action_key) => ({ target: "action", action_key, enabled: false, version: 0 })) };
    expect(() => decodeSecurityAgentExecutionControls(controls)).not.toThrow();
    expect(() => decodeSecurityAgentExecutionControls({ ...controls, actions: [controls.actions[1], controls.actions[0], ...controls.actions.slice(2)] })).toThrow();
  });

  it("decodes the remediation role of an integration", () => {
    const id = "pid_80000001-0000-4000-8000-000000000001";
    expect(decodeIntegrationRemediationRole({ integration_id: id, supported: true, configured: false, role_arn: null, version: 0, updated_at: null }, id).configured).toBe(false);
    expect(decodeIntegrationRemediationRole({ integration_id: id, supported: true, configured: true, role_arn: "arn:aws:iam::123456789012:role/zasp-remediation", version: 2, updated_at: "2026-11-14T10:00:00.000000Z" }, id).version).toBe(2);
    for (const value of [
      { integration_id: id, supported: true, configured: true, role_arn: null, version: 1, updated_at: "2026-11-14T10:00:00.000000Z" },
      { integration_id: id, supported: true, configured: false, role_arn: "arn:aws:iam::123456789012:role/zasp-remediation", version: 0, updated_at: null },
      { integration_id: id, supported: true, configured: true, role_arn: "arn:aws:iam::123456789012:user/admin", version: 1, updated_at: "2026-11-14T10:00:00.000000Z" },
      { integration_id: id, supported: true, configured: true, role_arn: "arn:aws:iam::123456789012:role/zasp-remediation", version: 1, updated_at: "2026-11-14T10:00:00.000000Z", external_id: "secret" },
    ]) expect(() => decodeIntegrationRemediationRole(value, id)).toThrow();
    expect(() => decodeIntegrationRemediationRole({ integration_id: id, supported: true, configured: false, role_arn: null, version: 0, updated_at: null }, "pid_80000009-0000-4000-8000-000000000009")).toThrow();
  });
});

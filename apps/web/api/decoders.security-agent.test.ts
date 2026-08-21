import { describe, expect, it } from "vitest";
import { decodeSecurityAgentApproval, decodeSecurityAgentRunDetail } from "./decoders";

const runID = "pid_78000006-0000-4000-8000-000000000006";
const definitionID = "pid_78000001-0000-4000-8000-000000000001";
const evidenceID = "pid_78000005-0000-4000-8000-000000000005";
const stepID = "pid_78000008-0000-4000-8000-000000000008";

function autonomousDetail(authorization = "autonomous") {
  return {
    run: { id: runID, agent_id: definitionID, state: "remediated", evidence_ids: [evidenceID], definition_version: 3, version: 4 },
    evidence_ids: [evidenceID],
    plan: { plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: "2026-08-21T12:15:00Z", steps: [{ id: stepID, index: 0, action: "update_finding_response", authorization, state: "succeeded", version: 2 }] },
    authorization: "authorized",
    approvals: [],
    execution: [{ step_id: stepID, action: "update_finding_response", state: "succeeded", outcome_id: "pid_78000009-0000-4000-8000-000000000009", result_digest: `sha256:${"b".repeat(64)}`, version: 2 }],
    verification: "verified",
  };
}

describe("security agent autonomous run detail", () => {
  it("accepts exact autonomous authorization without an approval", () => {
    expect(decodeSecurityAgentRunDetail(autonomousDetail()).plan?.steps[0]?.authorization).toBe("autonomous");
  });

  it("rejects an unrecognized autonomous authorization label", () => {
    expect(() => decodeSecurityAgentRunDetail(autonomousDetail("automatic"))).toThrow("schema mismatch");
  });
});

describe("security agent approval effects", () => {
  const approval = {
    id: "pid_78000007-0000-4000-8000-000000000007",
    run_id: runID,
    step_id: stepID,
    state: "pending",
    expires_at: "2026-08-21T12:15:00Z",
    version: 1,
    expected_effect: "Apply temporary containment policy",
    reversible: true,
    ttl_seconds: 300,
    evidence_summary: [evidenceID],
  };

  it("accepts exact temporary containment metadata", () => {
    expect(decodeSecurityAgentApproval(approval).ttl_seconds).toBe(300);
  });

  it.each([
    { expected_effect: "Move finding to under review", ttl_seconds: 300 },
    { expected_effect: "Apply temporary containment policy", ttl_seconds: 0 },
    { expected_effect: "Apply temporary containment policy", ttl_seconds: 3601 },
  ])("rejects mismatched effect and TTL metadata %#", (change) => {
    expect(() => decodeSecurityAgentApproval({ ...approval, ...change })).toThrow("schema mismatch");
  });

  it("binds approval metadata to the planned action", () => {
    const detail = {
      ...autonomousDetail("approval_required"),
      run: { ...autonomousDetail().run, state: "waiting_approval" },
      plan: { ...autonomousDetail().plan, steps: [{ id: stepID, index: 0, action: "create_temporary_policy", authorization: "approval_required", state: "waiting_approval", version: 1 }] },
      authorization: "approval_required",
      approvals: [approval],
      execution: [{ step_id: stepID, action: "create_temporary_policy", state: "waiting_approval", version: 1 }],
      verification: "not_started",
    };
    expect(decodeSecurityAgentRunDetail(detail).approvals[0]?.expected_effect).toBe("Apply temporary containment policy");
    expect(() => decodeSecurityAgentRunDetail({ ...detail, approvals: [{ ...approval, expected_effect: "Move finding to under review", ttl_seconds: 0 }] })).toThrow("schema mismatch");
  });
});

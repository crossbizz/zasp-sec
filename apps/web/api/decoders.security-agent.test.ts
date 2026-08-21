import { describe, expect, it } from "vitest";
import { decodeSecurityAgentRunDetail } from "./decoders";

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

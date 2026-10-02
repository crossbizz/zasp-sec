import { describe, expect, it } from "vitest";
import { decodeSecurityAgentApproval, decodeSecurityAgentRun, decodeSecurityAgentRunDetail } from "./decoders";

const runID = "pid_78000006-0000-4000-8000-000000000006";
const agentID = "pid_78000001-0000-4000-8000-000000000001";
const stepID = "pid_78000008-0000-4000-8000-000000000008";
const digest = "a".repeat(64);
const provenance = { kind: "manual", intent_digest: `sha256:${digest}`, version: 1 };
const run = { id: runID, agent_id: agentID, state: "waiting_approval", evidence_ids: [], definition_version: 1, version: 2, manual_trigger: provenance };
const approval = { id: agentID, run_id: runID, step_id: stepID, state: "pending", expires_at: "2026-09-19T12:15:00Z", version: 1, expected_effect: "Create run-scoped evidence export", reversible: true, ttl_seconds: 0, evidence_summary: [], manual_trigger: provenance };
function detail() {
  return { run: structuredClone(run), evidence_ids: [], plan: { plan_hash: `sha256:${"b".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: approval.expires_at, steps: [{ id: stepID, index: 0, action: "create_evidence_export", authorization: "approval_required", state: "waiting_approval", version: 1 }] }, authorization: "approval_required", approvals: [structuredClone(approval)], execution: [{ step_id: stepID, action: "create_evidence_export", state: "waiting_approval", version: 1 }], verification: "not_started", run_context: { trigger: { kind: "manual", id: digest, version: 1 }, rationale: null } };
}

describe("manual agent provenance", () => {
  it("retains typed intent in run, approval and parent detail", () => {
    expect(decodeSecurityAgentRun(run)).toEqual(run);
    expect(decodeSecurityAgentApproval(approval)).toEqual(approval);
    expect(decodeSecurityAgentRunDetail(detail())).toEqual(detail());
  });
  it.each([null, undefined, {}, { ...provenance, private: true }, { ...provenance, kind: "finding" }, { ...provenance, version: 0 }, { ...provenance, version: 1.5 }, { ...provenance, version: Number.MAX_SAFE_INTEGER + 1 }, { ...provenance, intent_digest: `sha256:${"A".repeat(64)}` }])("rejects malformed provenance %j", manual_trigger => {
    expect(() => decodeSecurityAgentRun({ ...run, manual_trigger })).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentApproval({ ...approval, manual_trigger })).toThrow("schema mismatch");
  });
  it.each([null, [agentID], [digest]])("rejects mixed or null evidence %j", evidence => {
    expect(() => decodeSecurityAgentRun({ ...run, evidence_ids: evidence })).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentApproval({ ...approval, evidence_summary: evidence })).toThrow("schema mismatch");
  });
  it.each(["trigger digest", "trigger kind", "trigger version", "approval digest", "approval version"])("rejects parent binding drift: %s", field => {
    const value = detail();
    if (field === "trigger digest") value.run_context.trigger.id = "b".repeat(64);
    if (field === "trigger kind") value.run_context.trigger.kind = "finding";
    if (field === "trigger version") value.run_context.trigger.version = 2;
    if (field === "approval digest") value.approvals[0].manual_trigger.intent_digest = `sha256:${"b".repeat(64)}`;
    if (field === "approval version") value.approvals[0].manual_trigger.version = 2;
    expect(() => decodeSecurityAgentRunDetail(value)).toThrow("schema mismatch");
  });
  it("retains a maximum safe provenance version", () => {
    expect(decodeSecurityAgentRun({ ...run, manual_trigger: { ...provenance, version: Number.MAX_SAFE_INTEGER } })).toEqual({ ...run, manual_trigger: { ...provenance, version: Number.MAX_SAFE_INTEGER } });
  });
});

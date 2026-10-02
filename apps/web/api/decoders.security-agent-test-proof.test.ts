import { describe, expect, it } from "vitest";
import { decodeSecurityAgentRunDetail } from "./decoders";

const id = "pid_78000001-0000-4000-8000-000000000001";
const testRun = "pid_78000002-0000-4000-8000-000000000002";
const priorRun = "pid_78000003-0000-4000-8000-000000000003";
const digest = "a".repeat(64);
const artifact = { reference_digest: digest, version_id: "version-1", sha256: digest, size_bytes: 100 };
const attempt = (run_id: string) => ({ run_id, attempt: 1, input_digest: digest, input_artifact: { ...artifact }, output_artifact: { ...artifact } });
const check = { category: "prompt_injection", check_id: "zasp.curated.prompt_injection.v1", prompt_digest: digest, assertion_digest: digest, before_protected: false, after_protected: true, before_http_status: 200, after_http_status: 200 };
const proof = () => ({ outcome: "remediated", reason: "test_condition_changed", proof_digest: `sha256:${digest}`, before: attempt(priorRun), after: attempt(testRun), checks: [{ ...check }] });

export function testProofDetail(verification: unknown = null) {
  return {
    run: { id, agent_id: id, state: "running", evidence_ids: [id], definition_version: 1, version: 1 }, evidence_ids: [id],
    plan: { plan_hash: `sha256:${digest}`, catalog_version: "security-agent-actions-v1", expires_at: "2030-01-01T00:00:00Z", steps: [{ id, index: 0, action: "run_test", authorization: "autonomous", state: "executing", version: 1 }] },
    authorization: "authorized", approvals: [], execution: [{ step_id: id, action: "run_test", state: "executing", version: 1, outcome_id: id, result_digest: `sha256:${digest}` }], verification: "not_started",
    action_details: [{ step_id: id, action: "run_test", arguments: { target_id: id, expected_version: 1 }, result: { state: "pending", outcome_id: id, result_digest: `sha256:${digest}` }, ttl_seconds: null, control_expires_at: null,
      rollback: { support: "not_supported", state: "unavailable", verification: { state: "unavailable", source: "none" } }, verification: { state: "pending", source: "effect_record" },
      existing_test: { definition_id: id, definition_version: 1, test_run_id: testRun, state: verification === null ? "pending" : "settled", cancellation_outcome: null, verification } }],
  };
}

describe("stored linked-test public proof", () => {
  it("accepts pending association without confusing effect ID and test-run ID", () => {
    const value = testProofDetail(); expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
  });
  it("accepts recorded comparison separately from a stopped or running parent's state", () => {
    const value = testProofDetail(proof()); expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
  });
  it.each([
    ["needs_human", "test_baseline_unavailable"], ["needs_human", "test_condition_persists"],
    ["inconclusive", "test_evidence_unavailable"], ["inconclusive", "test_evaluation_inconclusive"], ["inconclusive", "test_outcome_unknown"],
    ["failed", "test_run_failed"], ["cancelled", "test_run_cancelled"],
  ])("accepts bounded %s/%s without invented comparison", (outcome, reason) => {
    const value = testProofDetail({ ...proof(), outcome, reason, before: null, checks: [] }); expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
  });
  it.each([
    { outcome: "needs_human" }, { reason: "raw provider secret" }, { proof_digest: `sha256:${"b".repeat(64)}` },
    { before: null }, { after: null }, { before: attempt(testRun) }, { after: attempt(priorRun) }, { checks: [] },
    { checks: [{ ...check, after_protected: false }] }, { checks: [{ ...check, before_protected: true }] },
    { checks: [{ ...check, before_http_status: 503 }] }, { checks: [{ ...check, check_id: "other" }] },
    { checks: [check, check] }, { proof_hex: "private" },
    { after: { ...attempt(testRun), input_artifact: { ...artifact, reference: "s3://private/key" } } },
    { after: { ...attempt(testRun), output_artifact: { ...artifact, size_bytes: 16777217 } } },
    { after: { ...attempt(testRun), input_artifact: { ...artifact, version_id: "bad\nversion" } } },
  ])("rejects invalid comparison %#", (mutation) => {
    expect(() => decodeSecurityAgentRunDetail(testProofDetail({ ...proof(), ...mutation }))).toThrow("schema mismatch");
  });
  it.each([{ definition_id: priorRun }, { definition_version: 2 }, { state: "settled" }, { cancellation_outcome: "cancelled" }, { token_digest: digest }])("rejects malformed association %#", (mutation) => {
    const value = testProofDetail(); Object.assign(value.action_details[0].existing_test, mutation);
    expect(() => decodeSecurityAgentRunDetail(value)).toThrow("schema mismatch");
  });
  it("does not turn unknown cancellation into remediation", () => {
    const value = testProofDetail(proof()); Object.assign(value.action_details[0].existing_test, { cancellation_outcome: "outcome_unknown" });
    expect(() => decodeSecurityAgentRunDetail(value)).toThrow("schema mismatch");
  });
});

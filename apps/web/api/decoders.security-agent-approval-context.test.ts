import { describe, expect, it } from "vitest";
import { decodeSecurityAgentApproval } from "./decoders";

const id = "pid_78000001-0000-4000-8000-000000000001";
const cases = [
  ["update_finding_response", "low", "Move finding to under review", true, 0],
  ["create_temporary_policy", "containment", "Apply temporary containment policy", true, 120],
  ["isolate_session", "containment", "Isolate runtime session", true, 120],
  ["revoke_integration_connection", "destructive", "Revoke integration connection", false, 0],
  ["run_test", "low", "Run existing test", false, 0],
  ["rerun_test", "low", "Rerun existing test", false, 0],
] as const;

function fixture(index = 0) {
  const [action, risk, expected_effect, reversible, ttl_seconds] = cases[index];
  return { id, run_id: id, step_id: id, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1, expected_effect, reversible, ttl_seconds, evidence_summary: [id],
    approval_context: { agent_id: id, action, target_id: id as string | null, plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1",
      requester: { state: "available", id: id as string | null }, reason: { code: "operator_approval_required", source: "persisted_step" }, risk: { class: risk, source: "action_catalog" }, rationale: null as unknown } };
}

describe("persisted approval context contract", () => {
  it.each([4, 5])("rejects swapped test approval semantics for action %i", (index) => {
    const value = fixture(index);
    expect(() => decodeSecurityAgentApproval({ ...value, expected_effect: index === 4 ? "Rerun existing test" : "Run existing test" })).toThrow("schema mismatch");
    for (const risk of ["containment", "destructive"]) {
      expect(() => decodeSecurityAgentApproval({ ...value, approval_context: { ...value.approval_context, risk: { class: risk, source: "action_catalog" } } })).toThrow("schema mismatch");
    }
  });
  it.each([0, 1, 2, 3, 4, 5])("accepts action %i and legacy omission", (index) => {
    const value = fixture(index);
    expect(decodeSecurityAgentApproval(value)).toEqual(value);
    const { approval_context: context, ...legacy } = value;
    expect(decodeSecurityAgentApproval(legacy)).toEqual(legacy);
    context.target_id = null; context.requester = { state: "withheld", id: null };
    context.rationale = { state: "withheld", summary: "" };
    expect(decodeSecurityAgentApproval(value)).toEqual(value);
    context.rationale = { state: "available", summary: "Review the persisted evidence." };
    expect(decodeSecurityAgentApproval(value)).toEqual(value);
  });
  it.each([
    ["agent_id", "private-sentinel"], ["target_id", "private-sentinel"], ["plan_hash", "bad"], ["catalog_version", "v2"], ["action", "unknown"],
    ["requester", { state: "withheld", id }], ["requester", { state: "available", id: null }], ["requester", { state: "available", id: "private-sentinel" }],
    ["reason", { code: "operator_approval_required", source: "model" }], ["risk", { class: "destructive", source: "action_catalog" }],
    ["rationale", { state: "withheld", summary: "private-sentinel" }], ["rationale", { state: "available", summary: "x".repeat(501) }],
    ["rationale", { state: "available", summary: "hidden\u200btext" }], ["unexpected", "private-sentinel"],
  ])("rejects malformed %s", (key, value) => {
    const approval = fixture();
    Object.assign(approval.approval_context, { [key as string]: value });
    expect(() => decodeSecurityAgentApproval(approval)).toThrow("schema mismatch");
  });
  it("rejects null context, missing keys and a valid but contradictory action", () => {
    expect(() => decodeSecurityAgentApproval({ ...fixture(), approval_context: null })).toThrow("schema mismatch");
    const value = fixture();
    Reflect.deleteProperty(value.approval_context, "requester");
    expect(() => decodeSecurityAgentApproval(value)).toThrow("schema mismatch");
    const other = fixture();
    Object.assign(other.approval_context, { action: "isolate_session", risk: { class: "containment", source: "action_catalog" } });
    expect(() => decodeSecurityAgentApproval(other)).toThrow("schema mismatch");
  });
});

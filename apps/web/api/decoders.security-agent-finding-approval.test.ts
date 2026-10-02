import { describe, expect, it } from "vitest";
import { decodeSecurityAgentApproval, decodeSecurityAgentRunDetail } from "./decoders";

const id = "pid_78000001-0000-4000-8000-000000000001";
const assignee = "pid_78000002-0000-4000-8000-000000000002";
const effect = "Assign investigator and update finding response";
function approval(response_status = "investigating", note = "Review recorded evidence") {
  return { id, run_id: id, step_id: id, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1,
    expected_effect: effect, reversible: true, ttl_seconds: 0, evidence_summary: [id],
    approval_context: { agent_id: id, action: "update_finding_response", target_id: id, plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1",
      requester: { state: "available", id }, reason: { code: "operator_approval_required", source: "persisted_step" }, risk: { class: "low", source: "action_catalog" }, rationale: null,
      finding_response: { target_id: id, expected_version: Number.MAX_SAFE_INTEGER, target_status: response_status === "open" ? "open" : "under_review", assignee_id: assignee, response_status, note } } };
}

describe("exact finding response approval", () => {
  it.each(["open", "investigating"])("rejects explicit boundary spaces without normalizing %s proposals", status => {
    for (const note of ["a\u00a0b\u3000c\ufeffd", "é".repeat(256)]) expect(decodeSecurityAgentApproval(approval(status, note))).toEqual(approval(status, note));
    const edges = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
    for (const edge of edges) for (const note of [edge + "Investigate", "Investigate" + edge]) expect(() => decodeSecurityAgentApproval(approval(status, note))).toThrow("schema mismatch");
    for (const note of ["", "é".repeat(256) + "x", "a\u0000b", "a\u001fb", "a\u007fb", "a\u0080b", "a\u009fb"]) expect(() => decodeSecurityAgentApproval(approval(status, note))).toThrow("schema mismatch");
  });
  it.each([["open", "a"], ["investigating", "é".repeat(256)], ["open", "😀".repeat(128)]])("accepts exact %s metadata", (status, note) => {
    const value = approval(status, note);
    expect(decodeSecurityAgentApproval(value)).toEqual(value);
  });
  it("retains legacy approvals only without enriched context", () => {
    const value = approval();
    const context = { ...value.approval_context };
    Reflect.deleteProperty(context, "finding_response");
    const legacy = { ...value, expected_effect: "Move finding to under review", approval_context: context };
    expect(decodeSecurityAgentApproval(legacy)).toEqual(legacy);
    const old = { ...legacy };
    Reflect.deleteProperty(old, "approval_context");
    expect(decodeSecurityAgentApproval(old)).toEqual(old);
    expect(() => decodeSecurityAgentApproval({ ...value, expected_effect: legacy.expected_effect })).toThrow("schema mismatch");
  });
  it("requires the complete exact new context and target binding", () => {
    const value = approval();
    for (const context of [undefined, null, { ...value.approval_context, finding_response: undefined }, { ...value.approval_context, finding_response: null }, { ...value.approval_context, target_id: assignee }, { ...value.approval_context, target_id: null }]) {
      expect(() => decodeSecurityAgentApproval({ ...value, approval_context: context })).toThrow("schema mismatch");
    }
    for (const key of Object.keys(value.approval_context.finding_response)) {
      const partial = { ...value.approval_context.finding_response };
      Reflect.deleteProperty(partial, key);
      expect(() => decodeSecurityAgentApproval({ ...value, approval_context: { ...value.approval_context, finding_response: partial } })).toThrow("schema mismatch");
    }
    for (const delta of [{ expected_effect: "Run existing test", reversible: false }, { ttl_seconds: 60 }, { reversible: false }]) expect(() => decodeSecurityAgentApproval({ ...value, ...delta })).toThrow("schema mismatch");
  });
  it("rejects unsafe arguments and other-action metadata", () => {
    const value = approval();
    for (const delta of [
      { target_id: assignee }, { target_id: id.toUpperCase() }, { assignee_id: "external-user" }, { assignee_id: null },
      { expected_version: 0 }, { expected_version: 1.5 }, { expected_version: Number.MAX_SAFE_INTEGER + 1 }, { expected_version: "1" },
      { target_status: "open" }, { target_status: "closed" }, { response_status: "open" }, { response_status: "resolved" }, { response_status: "safe" }, { response_status: "closed" },
      { note: "" }, { note: " leading" }, { note: "trailing " }, { note: "line\nfeed" }, { note: "control\u0085here" }, { note: "é".repeat(257) }, { note: "😀".repeat(129) }, { note: null }, { extra: true },
    ]) expect(() => decodeSecurityAgentApproval({ ...value, approval_context: { ...value.approval_context, finding_response: { ...value.approval_context.finding_response, ...delta } } })).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentApproval({ ...value, expected_effect: "Run existing test", reversible: false, approval_context: { ...value.approval_context, action: "run_test" } })).toThrow("schema mismatch");
  });
  it("accepts the new approval inside the matching persisted run only", () => {
    const item = approval();
    const value = { run: { id, agent_id: assignee, state: "waiting_approval", evidence_ids: [id], definition_version: 1, version: 1 },
      evidence_ids: [id], authorization: "approval_required", verification: "not_started", approvals: [item],
      plan: { plan_hash: item.approval_context.plan_hash, catalog_version: "security-agent-actions-v1", expires_at: item.expires_at,
        steps: [{ id, index: 0, action: "update_finding_response", authorization: "approval_required", state: "waiting_approval", version: 1 }] },
      execution: [{ step_id: id, action: "update_finding_response", state: "waiting_approval", version: 1 }] };
    expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
    expect(() => decodeSecurityAgentRunDetail({ ...value, plan: { ...value.plan, steps: [{ ...value.plan.steps[0], action: "run_test" }] }, execution: [{ ...value.execution[0], action: "run_test" }] })).toThrow("schema mismatch");
  });
});

import { describe, expect, it } from "vitest";
import { decodeSecurityAgentRunDetail } from "./decoders";

const id = "pid_78000005-0000-4000-8000-000000000005";
const device = "pid_78000009-0000-4000-8000-000000000009";
const unavailable = { state: "unavailable", source: "none" };

function detail(action: string, args: unknown = null) {
  const policy = action === "create_temporary_policy" || action === "isolate_session";
  return {
    run: { id, agent_id: device, state: "running", evidence_ids: [id], definition_version: 1, version: 1 },
    evidence_ids: [id], plan: { plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: "2026-09-16T12:00:00Z", steps: [{ id, index: 0, action, authorization: "allow", state: "authorized", version: 1 }] },
    authorization: "authorized", approvals: [], execution: [{ step_id: id, action, state: "authorized", version: 1 }], verification: "not_started",
    action_details: [{ step_id: id, action, arguments: args, result: null, ttl_seconds: policy && args !== null ? 120 : null, control_expires_at: null,
      rollback: { support: policy ? "automatic" : action === "update_finding_response" ? "manual" : "not_supported", state: policy ? "not_started" : "unavailable", verification: policy ? { state: "unavailable", source: "policy_targets" } : unavailable },
      verification: policy ? { state: "unavailable", source: "policy_targets" } : unavailable }],
  };
}

describe("persisted security action details", () => {
  it.each(["open", "investigating"])("keeps the explicit Unicode note domain for %s", response_status => {
    const value = (note: string) => detail("update_finding_response", { target_id: id, expected_version: 1, target_status: response_status === "open" ? "open" : "under_review", assignee_id: device, response_status, note });
    for (const note of ["a\u00a0b\u3000c\ufeffd", "é".repeat(256)]) expect(decodeSecurityAgentRunDetail(value(note))).toEqual(value(note));
    const edges = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
    for (const edge of edges) for (const note of [edge + "Investigate", "Investigate" + edge]) expect(() => decodeSecurityAgentRunDetail(value(note))).toThrow("schema mismatch");
    for (const note of ["", "é".repeat(256) + "x", "a\u0000b", "a\u001fb", "a\u007fb", "a\u0080b", "a\u009fb"]) expect(() => decodeSecurityAgentRunDetail(value(note))).toThrow("schema mismatch");
  });
  // These fail if enrichment is dropped, made partial, or measured in UTF-16
  // characters instead of the persisted action's UTF-8 byte contract.
  it.each([
    ["open", "open", "Review API evidence"],
    ["investigating", "under_review", "<img src=x onerror=alert(1)>"],
    ["open", "open", "é".repeat(256)],
    ["investigating", "under_review", "😀".repeat(128)],
  ])("preserves complete finding metadata %s", (response_status, target_status, note) => {
    const value = detail("update_finding_response", { target_id: id, expected_version: 2, target_status, assignee_id: device, response_status, note });
    expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
  });

  it("rejects partial, mismatched and unsafe enriched finding arguments", () => {
    const args = { target_id: id, expected_version: 2, target_status: "under_review", assignee_id: device, response_status: "investigating", note: "Persisted investigation note" };
    const keys = ["assignee_id", "response_status", "note"] as const;
    for (let mask = 1; mask < 7; mask++) {
      const partial: Record<string, unknown> = { target_id: id, expected_version: 2, target_status: "under_review" };
      keys.forEach((key, index) => { if (mask & (1 << index)) partial[key] = args[key]; });
      expect(() => decodeSecurityAgentRunDetail(detail("update_finding_response", partial))).toThrow("schema mismatch");
    }
    for (const invalid of [
      { assignee_id: "external-user" }, { assignee_id: device.toUpperCase() }, { assignee_id: null },
      { response_status: "resolved" }, { response_status: "safe" }, { response_status: "closed" },
      { response_status: "open" }, { target_status: "open" }, { target_status: "resolved" },
      { note: "" }, { note: " " }, { note: " leading" }, { note: "trailing " },
      { note: "line\nfeed" }, { note: "tab\there" }, { note: "nul\u0000here" }, { note: "del\u007fhere" }, { note: "control\u0085here" },
      { note: "é".repeat(257) }, { note: "😀".repeat(129) }, { note: "a".repeat(513) }, { note: null },
      { password: "not-public" },
    ]) expect(() => decodeSecurityAgentRunDetail(detail("update_finding_response", { ...args, ...invalid }))).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentRunDetail(detail("update_finding_response", { target_id: id, expected_version: 2, target_status: "open" }))).toThrow("schema mismatch");
  });

  it.each([
    ["pending", "pending"], ["succeeded", "pending"],
    ["known_failure", "failed"], ["cleanup_pending", "inconclusive"],
  ])("preserves export %s without inventing security verification or rollback", (state, verification) => {
    const value = detail("create_evidence_export", { target_id: id, evidence_ids: [{ source_kind: "finding", source_id: device, source_version: 7, association_digest: `sha256:${"a".repeat(64)}` }] });
    const result = { state, outcome_id: device, result_digest: `sha256:${"b".repeat(64)}` };
    const projected = { ...value, execution: [{ ...value.execution[0], outcome_id: result.outcome_id, result_digest: result.result_digest }], action_details: [{ ...value.action_details[0], result, verification: { state: verification, source: "effect_record" } }] };
    expect(decodeSecurityAgentRunDetail(projected)).toEqual(projected);
    for (const invalidState of ["verified", "cleaned", "cleanup_failed", "leased", "unknown_outcome"]) {
      expect(() => decodeSecurityAgentRunDetail({ ...projected, action_details: [{ ...projected.action_details[0], result: { ...result, state: invalidState }, verification: { state: invalidState === "verified" ? "verified" : invalidState === "unknown_outcome" ? "inconclusive" : "pending", source: "effect_record" } }] })).toThrow();
    }
  });
  it("binds export selections to the original parent without inventing rollback", () => {
    const selection = [{ source_kind: "finding", source_id: device, source_version: 7, association_digest: `sha256:${"a".repeat(64)}` }];
    const value = detail("create_evidence_export", { target_id: id, evidence_ids: selection });
    expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
    for (const args of [null, { target_id: device, evidence_ids: selection }, { target_id: id, evidence_ids: [] }, { target_id: id, evidence_ids: [selection[0], selection[0]] }, { target_id: id, evidence_ids: [{ ...selection[0], key: "private" }] }]) {
      expect(() => decodeSecurityAgentRunDetail(detail("create_evidence_export", args))).toThrow();
    }
  });
  it.each(["run_test", "rerun_test"])("binds %s approval to its action and rejects test overrides", (action) => {
    const value = detail(action, { target_id: id, expected_version: 1 });
    value.plan.steps[0].authorization = "approval_required";
    value.authorization = "approval_required";
    const approval = { id, run_id: id, step_id: id, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1,
      expected_effect: action === "run_test" ? "Run existing test" : "Rerun existing test", reversible: false, ttl_seconds: 0, evidence_summary: [id] };
    expect(decodeSecurityAgentRunDetail({ ...value, approvals: [approval] })).toEqual({ ...value, approvals: [approval] });
    for (const invalid of [{ expected_effect: "Revoke integration connection" }, { expected_effect: action === "run_test" ? "Rerun existing test" : "Run existing test" }, { reversible: true }, { ttl_seconds: 60 }]) {
      expect(() => decodeSecurityAgentRunDetail({ ...value, approvals: [{ ...approval, ...invalid }] })).toThrow("schema mismatch");
    }
    for (const expected_version of [0, 1000001, 1.5, "1", null]) {
      expect(() => decodeSecurityAgentRunDetail(detail(action, { target_id: id, expected_version }))).toThrow("schema mismatch");
    }
    for (const key of ["prompt", "url", "credential_reference", "categories", "target_status"]) {
      expect(() => decodeSecurityAgentRunDetail(detail(action, { target_id: id, expected_version: 1, [key]: "override" }))).toThrow("schema mismatch");
    }
  });
  it.each([
    ["update_finding_response", { target_id: id, expected_version: 2, target_status: "under_review" }],
    ["create_temporary_policy", { target_id: id, scope: id, mode: "block", ttl_seconds: 120 }],
    ["isolate_session", { target_id: id, session_id: id, device_id: device, scope: id, ttl_seconds: 120 }],
    ["revoke_integration_connection", { target_id: id, integration_id: device }],
    ["run_test", { target_id: id, expected_version: 1 }],
    ["rerun_test", { target_id: id, expected_version: 1000000 }],
  ])("accepts only the typed persisted arguments for %s", (action, args) => {
    const value = detail(action as string, args);
    expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
    expect(decodeSecurityAgentRunDetail(detail(action as string))).toEqual(detail(action as string));
    expect(() => decodeSecurityAgentRunDetail(detail(action as string, { ...args as object, password: "protected-action-sentinel" }))).toThrow("schema mismatch");
  });

  it.each([
    { target_id: "protected-action-sentinel", expected_version: 1, target_status: "under_review" },
    { target_id: id, expected_version: 0, target_status: "under_review" },
    { target_id: id, expected_version: 2, target_status: "resolved" },
    { target_id: id, expected_version: null, target_status: "under_review" },
  ])("rejects unsafe or malformed finding arguments", (args) => {
    expect(() => decodeSecurityAgentRunDetail(detail("update_finding_response", args))).toThrow("schema mismatch");
  });

  it("rejects duplicate, unbound, or incomplete details", () => {
    const value = detail("update_finding_response");
    expect(() => decodeSecurityAgentRunDetail({ ...value, action_details: [] })).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentRunDetail({ ...value, action_details: [value.action_details[0], value.action_details[0]] })).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentRunDetail({ ...value, action_details: [{ ...value.action_details[0], step_id: device }] })).toThrow("schema mismatch");
  });

  it("rejects verification without effect evidence and invented rollback", () => {
    const value = detail("update_finding_response");
    expect(() => decodeSecurityAgentRunDetail({ ...value, action_details: [{ ...value.action_details[0], verification: { state: "verified", source: "effect_record" } }] })).toThrow("schema mismatch");
    expect(() => decodeSecurityAgentRunDetail({ ...value, action_details: [{ ...value.action_details[0], rollback: { ...value.action_details[0].rollback, state: "completed" } }] })).toThrow("schema mismatch");
  });

  // Removing any public enum/field guard must reject at the decoder boundary,
  // before a malformed persisted value can reach the mounted action component.
  it.each([
    { action: "unrecognized_action" },
    { result: { state: "unrecognized_effect" } },
    { verification: { state: "unrecognized_verification", source: "none" } },
    { verification: { state: "unavailable", source: "unrecognized_source" } },
    { rollback: { support: "unrecognized_support", state: "unavailable", verification: unavailable } },
    { rollback: { support: "manual", state: "unrecognized_rollback", verification: unavailable } },
    { rollback: { support: "manual", state: "unavailable", verification: { state: "unrecognized_cleanup", source: "none" } } },
    { rollback: { support: "manual", state: "unavailable", verification: { state: "unavailable", source: "unrecognized_source" } } },
    { result: { state: "pending", password: "protected-action-sentinel" } },
    { verification: { ...unavailable, password: "protected-action-sentinel" } },
    { rollback: { support: "manual", state: "unavailable", verification: unavailable, password: "protected-action-sentinel" } },
    { control_expires_at: "protected-action-sentinel" },
    { password: "protected-action-sentinel" },
  ])("refuses malformed public evidence %#", (invalid) => {
    const value = detail("update_finding_response");
    expect(() => decodeSecurityAgentRunDetail({ ...value, action_details: [{ ...value.action_details[0], ...invalid }] })).toThrow("schema mismatch");
  });

  it.each([59, 3601, 1.5, "120", null])("refuses invalid persisted policy TTL %s", (ttl_seconds) => {
    const value = detail("create_temporary_policy", { target_id: id, scope: id, mode: "block", ttl_seconds });
    expect(() => decodeSecurityAgentRunDetail(value)).toThrow("schema mismatch");
  });

  it("preserves old-server omission without fabricating action evidence", () => {
    const value = detail("update_finding_response");
    const { action_details: omitted, ...legacy } = value;
    expect(omitted).toHaveLength(1);
    const decoded = decodeSecurityAgentRunDetail(legacy);
    expect(decoded).toEqual(legacy);
    expect(decoded.action_details).toBeUndefined();
  });

  it("keeps recorded cleanup separate from missing application verification", () => {
    const value = detail("isolate_session");
    const outcome_id = device, result_digest = `sha256:${"b".repeat(64)}`;
    const complete = { ...value, execution: [{ ...value.execution[0], outcome_id, result_digest }], action_details: [{ ...value.action_details[0], result: { state: "cleaned", outcome_id, result_digest }, rollback: { ...value.action_details[0].rollback, state: "completed" } }] };
    expect(decodeSecurityAgentRunDetail(complete)).toEqual(complete);
  });

  it.each(["cleanup_pending", "leased"])("preserves stopped partial cleanup %s without an application outcome", (state) => {
    const value = detail("isolate_session");
    const evidence = { state: "pending", source: "policy_targets" };
    const pending = { ...value, action_details: [{ ...value.action_details[0], result: { state }, verification: evidence, rollback: { support: "automatic", state: "pending", verification: evidence } }] };
    expect(decodeSecurityAgentRunDetail(pending)).toEqual(pending);
  });
});

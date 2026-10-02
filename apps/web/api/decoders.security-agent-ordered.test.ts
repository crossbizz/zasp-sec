import { describe, expect, expectTypeOf, it } from "vitest";
import * as decoders from "./decoders";
import { createAPIClient } from "./client";
import type { SecurityAgentCancellation, SecurityAgentManualRunInput, SecurityAgentOrderedDetail, SecurityAgentRun, operations } from "./generated";

const id = (n: number) => `pid_78000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const digest = `sha256:${"a".repeat(64)}`;
const expiry = "2026-09-22T12:15:00Z";
type ObjectValue = { [key: string]: unknown };
function change(value: unknown, path: string, replacement: unknown): void {
  const keys = path.split(".");
  let target = value as ObjectValue;
  for (const key of keys.slice(0, -1)) target = target[key] as ObjectValue;
  if (replacement === undefined) delete target[keys.at(-1)!];
  else target[keys.at(-1)!] = replacement;
}
function fixture(stage = "waiting") {
  const applied = ["successor", "contained", "remediated", "needs_human"].includes(stage);
  const settled = ["contained", "remediated", "needs_human"].includes(stage);
  const terminal = settled || stage === "cancelled" || stage === "rejected" || stage === "partial";
  const state = stage === "partial" || stage === "rejected" ? "needs_human" : terminal ? stage : "waiting_approval";
  const steps = [0, 1].map((index) => ({
    step_id: id(index + 4), index, action: index === 0 ? "create_temporary_policy" : "run_test",
    state: index === 0 ? applied ? "succeeded" : terminal ? "cancelled" : "waiting_approval" : settled ? "succeeded" : applied ? "waiting_approval" : terminal ? "cancelled" : "blocked",
    version: applied ? 4 : terminal ? 2 : 1,
    authorization: "approval_required",
    dependency: { predecessor_step_id: index === 0 ? null : id(4), required_receipt_kind: index === 0 ? null : "temporary_policy_applied.v1", satisfied: index === 0 || applied, blocked: index === 1 && !applied && !terminal, ready: !terminal && (index === 0 ? !applied : applied) },
    approval: index === 1 && !applied ? { state: "absent", version: 0, approval_id: null } : { state: stage === "rejected" ? "rejected" : terminal || index === 0 && applied ? "approved" : "pending", version: terminal || index === 0 && applied ? 2 : 1, approval_id: id(index + 6) },
    receipt: index === 0 && applied || index === 1 && settled ? { kind: index === 0 ? "temporary_policy_applied.v1" : "existing_test_settled.v1", version: 1, digest, reference: id(index + 8) } : null,
    settlement: index === 0 ? "not_applicable" : settled ? stage === "needs_human" ? "unknown" : "not_reproduced" : "pending",
    cleanup: { state: index === 1 ? "not_applicable" : stage === "remediated" ? "cleaned" : stage === "partial" ? "leased" : applied ? "pending" : "not_started", version: index === 0 && stage === "remediated" ? 3 : index === 0 && stage === "partial" ? 1 : 0, attempt: index === 0 && ["remediated", "partial"].includes(stage) ? 1 : 0, partial: index === 0 && stage === "partial", cleaned: index === 0 && stage === "remediated" },
  }));
  return {
    run: { id: id(1), agent_id: id(2), state, evidence_ids: [id(3)], definition_version: 1, version: 10 },
    evidence_ids: [id(3)], authorization: stage === "cancelled" ? "cancelled" : "approval_required", verification: ["contained", "remediated"].includes(stage) ? "verified" : terminal ? "inconclusive" : "pending",
    plan: { plan_hash: digest, catalog_version: "security-agent-actions-v1", expires_at: expiry, steps: steps.map((s) => ({ id: s.step_id, index: s.index, action: s.action, state: s.state === "blocked" ? "queued" : s.state, version: s.version, authorization: s.authorization })) },
    execution: steps.map((s) => ({ step_id: s.step_id, action: s.action, state: s.state === "blocked" ? "queued" : s.state, version: s.version, ...(s.receipt ? { result_digest: digest } : {}) })),
    approvals: steps.filter((s) => s.approval.approval_id !== null).map((s) => ({ id: s.approval.approval_id!, run_id: id(1), step_id: s.step_id, state: s.approval.state, version: s.approval.version, expires_at: expiry, expected_effect: s.index === 0 ? "Apply temporary containment policy" : "Run existing test", reversible: s.index === 0, ttl_seconds: s.index === 0 ? 300 : 0, evidence_summary: [id(3)] })),
    ordered: { contract_version: 62, steps },
  };
}

describe("ordered HTTP detail boundary", () => {
  it("publishes operation-specific immutable types", () => {
    expectTypeOf<operations["cancelSecurityAgentRun"]["responses"][200]["content"]["application/json"]>().toEqualTypeOf<SecurityAgentCancellation>();
    expectTypeOf<operations["runSecurityAgent"]["requestBody"]["content"]["application/json"]>().toEqualTypeOf<SecurityAgentManualRunInput>();
    expectTypeOf<SecurityAgentRun>().not.toHaveProperty("ordered");
    expectTypeOf<SecurityAgentOrderedDetail["contract_version"]>().toEqualTypeOf<62>();
  });
  it.each(["waiting", "successor", "contained", "remediated", "needs_human", "cancelled", "rejected", "partial"])("preserves exact %s wire bytes", (stage) => {
    const value = fixture(stage);
    const wire = JSON.stringify(value);
    expect(decoders.decodeSecurityAgentRunDetail(value)).toBe(value);
    expect(JSON.stringify(value)).toBe(wire);
  });
  it.each(["queued", "planning", "failed", "cancelled", "needs_human", "inconclusive"])("accepts unadmitted %s without inventing steps", (state) => {
    const value = { ...fixture(), run: { ...fixture().run, state, version: state === "queued" ? 1 : 2 }, plan: null, execution: [], approvals: [], authorization: "not_planned", verification: state === "queued" || state === "planning" ? "not_started" : state === "failed" ? "failed" : "inconclusive", ordered: { contract_version: 62, steps: [] } };
    expect(decoders.decodeSecurityAgentRunDetail(value)).toBe(value);
  });
  it.each([
    ["ordered.contract_version", 61], ["ordered.steps", []], ["ordered.steps.0.step_id", "PID_bad"], ["ordered.steps.1.step_id", id(4)],
    ["ordered.steps.0.index", 1], ["ordered.steps.0.action", "run_test"], ["ordered.steps.0.state", "queued"], ["ordered.steps.0.version", 0], ["ordered.steps.0.version", 11],
    ["ordered.steps.0.authorization", "autonomous"], ["ordered.steps.0.dependency.predecessor_step_id", id(5)], ["ordered.steps.0.dependency.required_receipt_kind", "temporary_policy_applied.v1"],
    ["ordered.steps.0.dependency.satisfied", false], ["ordered.steps.0.dependency.blocked", true], ["ordered.steps.1.dependency.predecessor_step_id", id(9)], ["ordered.steps.1.dependency.satisfied", true], ["ordered.steps.1.dependency.blocked", false], ["ordered.steps.1.dependency.ready", true],
    ["ordered.steps.0.approval.state", "cancelled"], ["ordered.steps.0.approval.version", 2], ["ordered.steps.0.approval.approval_id", null], ["ordered.steps.1.approval.version", 1],
    ["ordered.steps.0.receipt", { kind: "temporary_policy_applied.v1", version: 1, digest, reference: id(9) }], ["ordered.steps.0.settlement", "pending"], ["ordered.steps.1.settlement", "unknown"],
    ["ordered.steps.0.cleanup.state", "pending"], ["ordered.steps.0.cleanup.partial", true], ["ordered.steps.1.cleanup.state", "pending"], ["ordered.steps.1.cleanup.version", 1],
    ["authorization", "approved"], ["verification", "not_started"], ["run.state", "running"], ["run.version", 1000001], ["run.evidence_ids", [id(3), id(9)]],
    ["plan.plan_hash", digest.toUpperCase()], ["plan.expires_at", "2026-02-30T12:15:00Z"], ["plan.expires_at", "2026-09-22T12:15:00+00:00"], ["plan.steps.0.state", "authorized"], ["plan.steps.0.version", 2],
    ["execution.0.outcome_id", id(9)], ["execution.0.result_digest", digest], ["execution.0.version", 2], ["execution.0.state", "succeeded"],
    ["approvals.0.id", id(9)], ["approvals.0.run_id", id(9)], ["approvals.0.step_id", id(9)], ["approvals.0.state", "approved"], ["approvals.0.version", 2], ["approvals.0.expected_effect", "Run existing test"], ["approvals.0.expires_at", "2026-09-22T12:16:00Z"], ["approvals.0.evidence_summary", []], ["approvals.0.ttl_seconds", 59],
  ])("rejects contradiction %s = %j", (path, replacement) => {
    const value = fixture(); change(value, path as string, replacement);
    expect(() => decoders.decodeSecurityAgentRunDetail(value)).toThrow("schema mismatch");
  });
  it("rejects every missing, unknown, null and wrongly typed nested field", () => {
    const value = fixture("remediated");
    const visit = (node: unknown, path = "") => {
      if (!node || typeof node !== "object") return;
      if (!Array.isArray(node)) {
        const extra = structuredClone(value); change(extra, `${path ? `${path}.` : ""}provider_payload`, "private");
        expect(() => decoders.decodeSecurityAgentRunDetail(extra), path).toThrow("schema mismatch");
      }
      for (const [key, field] of Object.entries(node)) {
        const next = path ? `${path}.${key}` : key;
        if (!Array.isArray(node)) for (const wrong of [undefined, null, typeof field === "string" ? 7 : "wrong"]) {
          if (field === null && wrong === null || next === "ordered" && wrong === undefined) continue;
          const bad = structuredClone(value); change(bad, next, wrong);
          expect(() => decoders.decodeSecurityAgentRunDetail(bad), `${next}: ${String(wrong)}`).toThrow("schema mismatch");
        }
        visit(field, next);
      }
    };
    visit(value);
  });
  it.each([
    ["ordered.steps.0.receipt.digest", digest.toUpperCase()], ["ordered.steps.0.receipt.kind", "existing_test_settled.v1"], ["ordered.steps.0.receipt.version", 2], ["ordered.steps.0.receipt.reference", "secret"],
    ["execution.0.result_digest", `sha256:${"b".repeat(64)}`], ["ordered.steps.1.dependency.satisfied", false], ["ordered.steps.1.dependency.ready", true], ["ordered.steps.1.settlement", "reproduced"],
    ["ordered.steps.0.cleanup.version", 2], ["ordered.steps.0.cleanup.attempt", 101], ["ordered.steps.0.cleanup.partial", true], ["ordered.steps.0.cleanup.cleaned", false],
  ])("rejects terminal contradiction %s", (path, replacement) => {
    const value = fixture("remediated"); change(value, path as string, replacement);
    expect(() => decoders.decodeSecurityAgentRunDetail(value)).toThrow("schema mismatch");
  });
  it("does not advertise ordered wire on list items or ordinary runs", () => {
    for (const ordered of [fixture().ordered, { cleanup_required: false }]) {
      expect(() => decoders.decodeSecurityAgentRun({ ...fixture().run, ordered })).toThrow();
      expect(() => decoders.decodeSecurityAgentRunPage({ items: [{ ...fixture().run, ordered }] })).toThrow();
    }
  });
  it.each(["authorized", "executing", "verifying"])("accepts admitted %s without false readiness", (state) => {
    const value = fixture(); value.run.state = state === "verifying" ? "verifying" : "running";
    value.ordered.steps[0].state = state; value.ordered.steps[0].version = 3; value.ordered.steps[0].approval.state = "approved"; value.ordered.steps[0].approval.version = 2; value.ordered.steps[0].dependency.ready = false;
    value.plan.steps[0].state = state; value.plan.steps[0].version = 3; value.execution[0].state = state; value.execution[0].version = 3; value.approvals[0].state = "approved"; value.approvals[0].version = 2;
    expect(decoders.decodeSecurityAgentRunDetail(value)).toBe(value);
    if (state !== "authorized") { value.ordered.steps[0].dependency.ready = true; expect(() => decoders.decodeSecurityAgentRunDetail(value)).toThrow(); }
  });
  it.each(["leased", "retryable", "cleaned"])("checks recovery cleanup version floors for %s", (state) => {
    const value = fixture("needs_human"); const c = value.ordered.steps[0].cleanup;
    c.state = state; c.attempt = 2; c.version = state === "cleaned" ? 5 : state === "retryable" ? 4 : 3; c.cleaned = state === "cleaned"; c.partial = true;
    expect(decoders.decodeSecurityAgentRunDetail(value)).toBe(value);
    c.version--; expect(() => decoders.decodeSecurityAgentRunDetail(value)).toThrow();
  });
  it("accepts expired approvals and rejects approval cancellation", () => {
    const value = fixture("rejected"); value.approvals[0].state = "expired"; value.ordered.steps[0].approval.state = "expired";
    expect(decoders.decodeSecurityAgentRunDetail(value)).toBe(value);
    value.approvals[0].state = "cancelled"; value.ordered.steps[0].approval.state = "cancelled";
    expect(() => decoders.decodeSecurityAgentRunDetail(value)).toThrow();
  });
  it("accepts the new standalone test approval without widening legacy effects", () => {
    const a = fixture("successor").approvals[1];
    expect(decoders.decodeOrderedSecurityAgentApproval(a)).toBe(a);
    expect(() => decoders.decodeOrderedSecurityAgentApproval({ ...a, state: "cancelled" })).toThrow();
    expect(() => decoders.decodeOrderedSecurityAgentApproval({ ...a, reversible: true })).toThrow();
    expect(() => decoders.decodeOrderedSecurityAgentApproval({ ...a, ttl_seconds: 1 })).toThrow();
  });
  it("rejects duplicate summaries, oversized arrays and extra fractional timestamp precision", () => {
    for (const [path, bad] of [["ordered.steps", Array(3).fill(fixture().ordered.steps[0])], ["approvals", Array(3).fill(fixture().approvals[0])], ["execution", []], ["plan.expires_at", "2026-09-22T12:15:00.1234567890Z"], ["plan.expires_at", "1999-09-22T12:15:00Z"]]) {
      const value = fixture(); change(value, path as string, bad); expect(() => decoders.decodeSecurityAgentRunDetail(value)).toThrow();
    }
    const duplicate = fixture("remediated"); duplicate.ordered.steps[1].receipt!.reference = duplicate.ordered.steps[0].receipt!.reference;
    expect(() => decoders.decodeSecurityAgentRunDetail(duplicate)).toThrow();
  });
});

describe("ordered trigger and cancellation", () => {
  it("exports strict typed decoders", () => {
    expect(decoders).toHaveProperty("decodeSecurityAgentManualRunInput", expect.any(Function));
    expect(decoders).toHaveProperty("decodeSecurityAgentCancellation", expect.any(Function));
  });
  it("retains the legacy trigger and requires both ordered fields", () => {
    const legacy = { environment_id: id(2), trigger_kind: "finding", trigger_id: id(3) };
    const decode = (decoders as unknown as Record<string, (v: unknown) => unknown>).decodeSecurityAgentManualRunInput;
    expect(decode(legacy)).toBe(legacy);
    const ordered = { ...legacy, trigger_version: 1, trigger_source: "credential" };
    expect(decode(ordered)).toBe(ordered);
    for (const bad of [{ ...legacy, trigger_version: 1 }, { ...legacy, trigger_source: "credential" }, { ...ordered, trigger_kind: "session" }, { ...ordered, trigger_version: 1000001 }, { ...ordered, trigger_source: "a".repeat(129) }, { ...ordered, trigger_source: " x " }, { ...ordered, trigger_source: "a\nb" }, { ...ordered, tenant_id: id(9) }]) expect(() => decode(bad)).toThrow();
    const unicode = { ...ordered, trigger_source: "\uFEFFcredential" };
    expect(decode(unicode)).toBe(unicode);
    expect(() => decode({ ...ordered, trigger_source: "\u0085credential" })).toThrow();
    expect(() => decode({ ...ordered, trigger_source: "é".repeat(65) })).toThrow();
  });
  it("accepts cancellation cleanup without fabricating a successful outcome", () => {
    const decode = (decoders as unknown as Record<string, (v: unknown) => unknown>).decodeSecurityAgentCancellation;
    const legacy = { ...fixture().run, state: "cancelled" };
    expect(decode(legacy)).toBe(legacy);
    for (const [state, cleanup_required] of [["cancelled", true], ["cancelled", false], ["needs_human", false]]) {
      const value = { ...legacy, state, ordered: { cleanup_required } };
      expect(decode(value)).toBe(value);
    }
    expect(() => decode({ ...legacy, state: "needs_human", ordered: { cleanup_required: true } })).toThrow();
    for (const bad of [{ ...legacy, ordered: {} }, { ...legacy, ordered: null }, { ...legacy, ordered: { cleanup_required: 1 } }, { ...legacy, ordered: { cleanup_required: false, secret: "private" } }, { ...legacy, state: "remediated", ordered: { cleanup_required: false } }]) expect(() => decode(bad)).toThrow();
  });
  it("rejects duplicate ordered JSON keys before JSON.parse discards them", async () => {
    const wire = JSON.stringify(fixture()).replace('"contract_version":62', '"contract_version":61,"contract_version":62');
    const client = createAPIClient({ fetch: async () => new Response(wire, { headers: { "Content-Type": "application/json" } }) });
    await expect(client.GET("/api/v1/security-agent-runs/{id}", { params: { path: { id: id(1) } } })).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it.each([
    (wire: string) => wire.replace('"contract_version":62', '"contract_version":61,"contract_\\u0076ersion":62'),
    (wire: string) => wire.replace('"satisfied":true', '"satisfied":false,"satisfied":true'),
    (wire: string) => " ".repeat(16384) + wire,
  ])("rejects hostile original ordered bytes %#", async (mutate) => {
    const client = createAPIClient({ fetch: async () => new Response(mutate(JSON.stringify(fixture())), { headers: { "Content-Type": "application/json" } }) });
    await expect(client.GET("/api/v1/security-agent-runs/{id}", { params: { path: { id: id(1) } } })).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it("does not apply ordered byte validation to unrelated API payloads", async () => {
    const wire = '{"ordered":{"a":1,"a":2}}';
    const client = createAPIClient({ fetch: async () => new Response(wire, { headers: { "Content-Type": "application/json" } }) });
    const result = await client.GET("/api/v1/security-agents");
    expect(result.data).toEqual({ ordered: { a: 2 } });
  });
});

import { describe, expect, it } from "vitest";

import { decodeAttackPathPage, decodeBreakOptionPage, decodeFinding, decodeFindingPage, decodeGlobalSearchPage, decodeWorkflowMutationReceipt } from "./decoders";

const finding = {
  id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", title: "Public tool access", severity: "high", status: "open",
  evidence_ids: ["pid_20000002-0000-4000-8000-000000000002"], risk_factors: [{ name: "Public input", evidence_id: "pid_20000002-0000-4000-8000-000000000002" }],
  version: 2, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z",
} as const;
const path = {
  id: "pid_30000001-0000-4000-8000-000000000001", entry_id: "pid_30000002-0000-4000-8000-000000000002", sink_id: "pid_30000003-0000-4000-8000-000000000003",
  node_ids: ["pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"], state: "verified",
  evidence_ids: ["pid_20000002-0000-4000-8000-000000000002"], blocked_edge: -1, version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z",
} as const;

describe("strict risk decoders", () => {
  it("accepts exact bounded finding, path, and break-option pages", () => {
    expect(decodeFindingPage({ items: [finding], page_info: { next_cursor: null, has_more: false } }).items[0]?.id).toBe(finding.id);
    expect(decodeAttackPathPage({ items: [path], page_info: { next_cursor: null, has_more: false } }).items[0]?.id).toBe(path.id);
    expect(decodeBreakOptionPage({ items: [{ path_id: path.id, target_id: path.entry_id, evidence_id: finding.evidence_ids[0], kind: "remove_node", rank: 1 }] }, path).items).toHaveLength(1);
  });

  it.each([
    ["extra key", { ...finding, extra: true }],
    ["duplicate evidence", { ...finding, evidence_ids: [finding.evidence_ids[0], finding.evidence_ids[0]] }],
    ["accepted without reason", { ...finding, status: "accepted" }],
    ["invalid timestamp order", { ...finding, updated_at: "2026-08-18T00:00:00Z" }],
    ["invalid enum", { ...finding, severity: "urgent" }],
  ])("rejects finding %s", (_name, value) => expect(() => decodeFinding(value)).toThrow("schema mismatch"));

  it("rejects oversized pages, malformed path edges, and noncontiguous break ranks", () => {
    expect(() => decodeFindingPage({ items: Array.from({ length: 101 }, () => finding), page_info: { next_cursor: null, has_more: false } })).toThrow("schema mismatch");
    expect(() => decodeAttackPathPage({ items: [{ ...path, blocked_edge: 0 }], page_info: { next_cursor: null, has_more: false } })).toThrow("schema mismatch");
    expect(() => decodeBreakOptionPage({ items: [{ path_id: path.id, target_id: path.entry_id, evidence_id: finding.evidence_ids[0], kind: "remove_node", rank: 2 }] }, path)).toThrow("schema mismatch");
  });

  it("rejects evidence references outside their parent finding or attack path", () => {
    const foreignEvidence = "pid_90000001-0000-4000-8000-000000000001";
    expect(() => decodeFinding({ ...finding, risk_factors: [{ name: "Foreign evidence", evidence_id: foreignEvidence }] })).toThrow("schema mismatch");
    expect(() => decodeBreakOptionPage({ items: [{ path_id: path.id, target_id: path.entry_id, evidence_id: foreignEvidence, kind: "remove_node", rank: 1 }] }, path)).toThrow("schema mismatch");
  });

  it("decodes exact ordered product search results and rejects raw-query shapes", () => {
    const agent = { id: "pid_10000001-0000-4000-8000-000000000001", type: "agent", name: "Production agent" };
    const findingResult = { id: finding.id, type: "finding", name: finding.title };
    expect(decodeGlobalSearchPage({ items: [agent, findingResult] }).items).toEqual([agent, findingResult]);
    expect(() => decodeGlobalSearchPage({ items: [{ ...agent, type: "graph_query" }] })).toThrow("schema mismatch");
    expect(() => decodeGlobalSearchPage({ items: [{ ...agent, query: "MATCH (n)" }] })).toThrow("schema mismatch");
    expect(() => decodeGlobalSearchPage({ items: [findingResult, agent] })).toThrow("schema mismatch");
    expect(() => decodeGlobalSearchPage({ items: [agent, agent] })).toThrow("schema mismatch");
  });

  it.each(["updateFinding", "acceptFindingRisk"])("discriminates exact %s receipts", (operation) => {
    const accepted = { ...finding, status: "accepted", acceptance_reason: "Approved exception", version: 3 };
    const result = operation === "updateFinding" ? { ...finding, status: "under_review", version: 3 } : accepted;
    const body = operation === "updateFinding" ? { status: "under_review" } : { reason: "Approved exception" };
    const value = {
      id: "pid_11111111-1111-4111-8111-111111111111", operation, idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
      intent: { body, expected_version: 2, resource_id: finding.id }, result, resource_kind: "finding", resource_id: finding.id, resource_version: 3,
      audit_id: "pid_33333333-3333-4333-8333-333333333333", correlation_id: "pid_44444444-4444-4444-8444-444444444444",
      created_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-25T00:00:00Z",
    };
    expect(decodeWorkflowMutationReceipt(value).operation).toBe(operation);
    expect(() => decodeWorkflowMutationReceipt({ ...value, resource_kind: "policy" })).toThrow("schema mismatch");
    expect(() => decodeWorkflowMutationReceipt({ ...value, operation: "unknownFindingMutation" })).toThrow("schema mismatch");
  });
});

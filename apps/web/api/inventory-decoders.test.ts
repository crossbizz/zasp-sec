import { describe, expect, it } from "vitest";

import {
  decodeAgentSessionPage,
  decodeAgentMutation,
  decodeCapabilityPage,
  decodeInventoryDetail,
  decodeInventoryPage,
  decodeRelationshipPage,
} from "./decoders";

const ids = {
  entity: "pid_10000001-0000-4000-8000-000000000001",
  other: "pid_10000002-0000-4000-8000-000000000002",
  evidence: "pid_20000001-0000-4000-8000-000000000001",
  integration: "pid_30000001-0000-4000-8000-000000000001",
  snapshot: "pid_40000001-0000-4000-8000-000000000001",
};

const summary = {
  id: ids.entity,
  name: "Production agent",
  kind: "agent",
  owner: "security",
  team: "platform",
  tags: ["production"],
  evidence_id: ids.evidence,
  confidence_basis_points: 9500,
  first_seen: "2026-08-19T00:00:00Z",
  last_seen: "2026-08-19T01:00:00Z",
  observed_at: "2026-08-19T01:00:00Z",
  fresh_until: "2026-08-19T01:15:00Z",
  freshness_state: "fresh",
  version: 1,
} as const;

const pageInfo = { next_cursor: null, has_more: false } as const;

describe("typed inventory decoders", () => {
  it("accepts exact cursor pages and source-bound detail authority", () => {
    expect(decodeInventoryPage({ items: [summary], page_info: pageInfo }).items[0]).toEqual(summary);
    expect(decodeInventoryDetail({
      summary,
      sources: [{
        integration_id: ids.integration,
        provider: "kubernetes",
        source: "kubernetes",
        source_identifier: `sha256:${"b".repeat(64)}`,
        snapshot_id: ids.snapshot,
        generation: 1,
        evidence_id: ids.evidence,
        confidence_basis_points: 9500,
        observed_at: summary.observed_at,
        fresh_until: summary.fresh_until,
        projection_version: 1,
        winning: true,
      }],
      evidence: [{ id: ids.evidence, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: summary.observed_at, size_bytes: 128 }],
    }).summary.id).toBe(ids.entity);
  });

  it("rejects missing pagination, secret fields, and unbound winning evidence", () => {
    expect(() => decodeInventoryPage({ items: [summary] })).toThrow();
    expect(() => decodeInventoryPage({ items: [{ ...summary, credential_reference: "ref:secret/value" }], page_info: pageInfo })).toThrow();
    expect(() => decodeInventoryDetail({
      summary,
      sources: [{ integration_id: ids.integration, provider: "kubernetes", source: "kubernetes", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: ids.snapshot, generation: 1, evidence_id: ids.other, confidence_basis_points: 9500, observed_at: summary.observed_at, fresh_until: summary.fresh_until, projection_version: 1, winning: true }],
      evidence: [{ id: ids.evidence, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: summary.observed_at, size_bytes: 128 }],
    })).toThrow();
  });

  it("strictly decodes bounded agent subresource pages", () => {
    expect(decodeCapabilityPage({ items: [], page_info: pageInfo }).items).toEqual([]);
    expect(decodeRelationshipPage({ items: [{ id: ids.snapshot, from_id: ids.entity, to_id: ids.other, type: "uses", evidence_id: ids.evidence }], page_info: pageInfo }).items).toHaveLength(1);
    expect(decodeAgentSessionPage({ items: [{ id: ids.snapshot, agent_id: ids.entity, started_at: summary.observed_at }], page_info: pageInfo }).items).toHaveLength(1);
    expect(() => decodeRelationshipPage({ items: [{ from_id: ids.entity, to_id: ids.other, type: "uses", evidence_id: ids.evidence }], page_info: pageInfo })).toThrow();
  });

  it("strictly decodes ownership mutation evidence", () => {
    const auditID = "pid_50000001-0000-4000-8000-000000000001";
    expect(decodeAgentMutation({ agent: { ...summary, version: 2 }, audit_id: auditID })).toEqual({ agent: { ...summary, version: 2 }, audit_id: auditID });
    expect(() => decodeAgentMutation({ agent: { ...summary, kind: "tool", version: 2 }, audit_id: auditID })).toThrow();
    expect(() => decodeAgentMutation({ agent: { ...summary, version: 2 }, audit_id: auditID, receipt_id: ids.other })).toThrow();
  });
});

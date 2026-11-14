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
  provider: "kubernetes",
  source_kind: "kubernetes_agent",
  discovery: { method: "declared", platform: "kubernetes_agent", signals: [] },
  management_state: "managed",
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

  it("binds how an object was found to its kind and owner", () => {
    const page = (item: unknown) => decodeInventoryPage({ items: [item], page_info: pageInfo });
    const found = { ...summary, owner: "", team: "", provider: "aws", source_kind: "aws_bedrock_agent", discovery: { method: "provider_api", platform: "bedrock_agent", signals: [] }, management_state: "unmanaged" } as const;
    const inferred = { ...found, provider: "okta", source_kind: "okta_ai_application", discovery: { method: "inferred", platform: "saas_assistant", signals: ["app:chatgpt"] } } as const;
    const identity = { ...summary, kind: "identity", provider: "aws", source_kind: "aws_role", discovery: { method: "provider_api", platform: "aws_role", signals: [] }, management_state: "not_applicable" } as const;
    for (const accepted of [found, inferred, { ...found, owner: "security", management_state: "managed" }, identity]) expect(page(accepted).items).toHaveLength(1);
    for (const refused of [
      { ...found, management_state: "managed" },
      { ...found, owner: "security" },
      { ...found, management_state: "not_applicable" },
      { ...summary, management_state: "unmanaged" },
      { ...inferred, discovery: { ...inferred.discovery, signals: [] } },
      { ...inferred, discovery: { ...inferred.discovery, signals: ["env:OPENAI_API_KEY=sk-live"] } },
      { ...inferred, discovery: { ...inferred.discovery, signals: ["package:langgraph", "env:openai"] } },
      { ...inferred, discovery: { ...inferred.discovery, value: "x" } },
      { ...found, provider: "azure" },
      { ...found, discovery: { ...found.discovery, method: "guessed" } },
      { ...identity, management_state: "unmanaged" },
      { ...identity, discovery: { method: "inferred", platform: "aws_role", signals: ["env:openai"] } },
      (({ discovery: _discovery, ...rest }) => rest)(found),
    ]) expect(() => page(refused)).toThrow();
  });

  it("calls an agent dismissed exactly when it was found without a declaration and carries the reserved tag", () => {
    const page = (item: unknown) => decodeInventoryPage({ items: [item], page_info: pageInfo });
    const found = { ...summary, owner: "", team: "", tags: [], provider: "aws", source_kind: "aws_bedrock_agent", discovery: { method: "provider_api", platform: "bedrock_agent", signals: [] }, management_state: "unmanaged" } as const;
    const inferred = { ...found, provider: "okta", source_kind: "okta_ai_application", discovery: { method: "inferred", platform: "saas_assistant", signals: ["app:chatgpt"] } } as const;
    const tags = ["critical", "not-an-agent"];
    for (const accepted of [
      { ...found, tags, management_state: "dismissed" },
      { ...found, owner: "security", team: "platform", tags, management_state: "dismissed" },
      { ...inferred, tags, management_state: "dismissed" },
      // The owner of a declared agent labelled it: the tag means nothing there.
      { ...summary, tags, management_state: "managed" },
    ]) expect(page(accepted).items).toHaveLength(1);
    for (const refused of [
      { ...found, tags },
      { ...found, owner: "security", team: "platform", tags, management_state: "managed" },
      { ...inferred, tags },
      { ...found, management_state: "dismissed" },
      { ...found, owner: "security", management_state: "dismissed" },
      { ...found, tags: ["not-an-agent-2"], management_state: "dismissed" },
      { ...summary, tags, management_state: "dismissed" },
      { ...summary, kind: "identity", tags, provider: "aws", source_kind: "aws_role", discovery: { method: "provider_api", platform: "aws_role", signals: [] }, management_state: "dismissed" },
    ]) expect(() => page(refused)).toThrow();
  });

  it("accepts objects found by Microsoft and Salesforce and refuses an unknown provider", () => {
    const page = (item: unknown) => decodeInventoryPage({ items: [item], page_info: pageInfo });
    const unowned = { ...summary, owner: "", team: "", management_state: "unmanaged" } as const;
    const accepted = [
      { ...unowned, provider: "microsoft", source_kind: "microsoft_agent_identity", discovery: { method: "provider_api", platform: "entra_agent_identity", signals: [] } },
      { ...unowned, provider: "microsoft", source_kind: "microsoft_copilot_agent", discovery: { method: "provider_api", platform: "copilot_studio", signals: [] } },
      { ...unowned, provider: "microsoft", source_kind: "microsoft_ai_application", confidence_basis_points: 7000, discovery: { method: "inferred", platform: "saas_assistant", signals: ["app:chatgpt"] } },
      { ...unowned, provider: "salesforce", source_kind: "salesforce_agent", discovery: { method: "provider_api", platform: "agentforce", signals: [] } },
      { ...summary, kind: "asset", provider: "microsoft", source_kind: "microsoft_tenant", discovery: { method: "provider_api", platform: "microsoft_tenant", signals: [] }, management_state: "not_applicable" },
      { ...summary, kind: "asset", provider: "salesforce", source_kind: "salesforce_org", discovery: { method: "provider_api", platform: "salesforce_org", signals: [] }, management_state: "not_applicable" },
    ];
    for (const item of accepted) expect(page(item).items[0]).toEqual(item);
    for (const provider of ["azure", "entra", "microsoft-entra", "Microsoft", "salesforce ", "servicenow", ""]) {
      expect(() => page({ ...accepted[0], provider })).toThrow();
    }
    // A source observation names its provider from the same list.
    const source = { integration_id: ids.integration, provider: "salesforce", source: "salesforce", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: ids.snapshot, generation: 1, evidence_id: ids.evidence, confidence_basis_points: 9500, observed_at: summary.observed_at, fresh_until: summary.fresh_until, projection_version: 1, winning: true };
    const evidence = [{ id: ids.evidence, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: summary.observed_at, size_bytes: 128 }];
    const agentforce = accepted[3];
    expect(decodeInventoryDetail({ summary: agentforce, sources: [source], evidence }).sources[0]?.provider).toBe("salesforce");
    expect(decodeInventoryDetail({ summary: accepted[0], sources: [{ ...source, provider: "microsoft", source: "microsoft" }], evidence }).sources[0]?.provider).toBe("microsoft");
    expect(() => decodeInventoryDetail({ summary: agentforce, sources: [{ ...source, provider: "servicenow" }], evidence })).toThrow();
  });
});

import { describe, expect, it } from "vitest";

import { decodeConnectorManifest, decodeConnectorManifestPage, decodeIntegration, decodeIntegrationSetupStatus, decodeInventoryDetail, decodeInventoryPage } from "./decoders";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const ids = { entity: "pid_10000001-0000-4000-8000-000000000001", evidence: "pid_20000001-0000-4000-8000-000000000001", integration: "pid_30000001-0000-4000-8000-000000000001", snapshot: "pid_40000001-0000-4000-8000-000000000001" };

const manifest = {
  key: "saas-databricks", platform: "databricks", provider: "Databricks", category: "saas",
  description: "Inventory the model serving endpoints and served agents of one Databricks workspace through a Nango connection.",
  data_types: ["agent", "application"], actions: ["inventory_read"], auth_mode: "nango_connection",
  setup_schema: [
    { key: "tenant_id", label: "Workspace ID", type: "string", required: true, description: "The numeric workspace ID." },
    { key: "connection_reference", label: "Nango connection", type: "connection_reference", required: true, description: "Opaque reference to the Nango connection." },
  ],
  access_guidance: "Create the Nango connection as a principal that can view the serving endpoints.",
  test_semantics: "Ask the platform which tenant the connection reaches.",
} as const;

const setupStatus = {
  integration_id: integrationID, connector_key: "saas",
  authorization: { state: "verified", scope_kind: "saas_tenant", scope_label: "databricks/1234567890123456", repository_selection: null, permissions: [] },
  runtime_coverage: { state: "not_applicable", reason: "not_applicable", sensor_count: 0, healthy_sensor_count: 0 },
  updated_at: "2026-08-31T19:00:00Z",
} as const;

const summary = {
  id: ids.entity, name: "support-agent", kind: "agent", owner: "", team: "", tags: [], evidence_id: ids.evidence, confidence_basis_points: 9500,
  first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-20T01:00:00Z", freshness_state: "fresh", version: 1,
  provider: "saas", source_kind: "saas_agent", discovery: { method: "provider_api", platform: "databricks", signals: [] }, management_state: "unmanaged",
  activity_state: "unknown", last_activity_at: null,
} as const;

describe("generic saas provider decoders", () => {
  it("accepts a catalog entry of a SaaS platform and binds its key to its platform", () => {
    expect(decodeConnectorManifest(manifest)).toEqual(manifest);
    // Any platform the API registers is accepted: the list is the API's.
    const other = { ...manifest, key: "saas-acme_ai", platform: "acme_ai", provider: "Acme AI" };
    expect(decodeConnectorManifestPage({ items: [manifest, other] }).items).toHaveLength(2);
    // An entry of another connector has no platform.
    const { platform: _platform, ...firstParty } = { ...manifest, key: "aws" };
    expect(decodeConnectorManifest(firstParty)).toEqual(firstParty);
    for (const refused of [
      { ...manifest, key: "databricks" },
      { ...manifest, key: "saas-slack" },
      { ...manifest, platform: "Databricks" },
      { ...manifest, platform: "" },
      { ...manifest, platform: null },
      { ...manifest, platform: "data/bricks", key: "saas-data/bricks" },
      { ...manifest, platforms: ["databricks"] },
    ]) expect(() => decodeConnectorManifest(refused)).toThrow("schema mismatch");
  });

  it("accepts a saas integration that waits for its sign-in and one that names its connection", () => {
    const integration = { id: integrationID, connector_key: "saas", name: "ServiceNow", status: "pending_authorization", created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z" };
    const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111";
    // Before the sign-in the configuration names the platform and the tenant only.
    expect(decodeIntegration({ ...integration, configuration: { platform: "servicenow", tenant_id: "acme" } }).configuration).toEqual({ platform: "servicenow", tenant_id: "acme" });
    expect(decodeIntegration({ ...integration, configuration: { platform: "servicenow", tenant_id: "acme", connection_reference: reference } }).configuration.connection_reference).toBe(reference);
    for (const configuration of [
      { platform: "servicenow" }, { tenant_id: "acme" }, { platform: "ServiceNow", tenant_id: "acme" }, { platform: "servicenow", tenant_id: "a..b" },
      { platform: "servicenow", tenant_id: "acme", connection_reference: "ref:nango/service-key-0001" }, { platform: "servicenow", tenant_id: "acme", connection_reference: "" },
      { platform: "servicenow", tenant_id: "acme", subdomain: "acme" },
    ]) {
      expect(() => decodeIntegration({ ...integration, configuration })).toThrow();
    }
  });

  it("accepts the bound tenant of a saas integration", () => {
    expect(decodeIntegrationSetupStatus(setupStatus, integrationID)).toEqual(setupStatus);
    const pending = { ...setupStatus, authorization: { state: "pending", scope_kind: "none", scope_label: null, repository_selection: null, permissions: [] } };
    expect(decodeIntegrationSetupStatus(pending, integrationID)).toEqual(pending);
    const slack = { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "slack/T024BE7LD" } };
    expect(decodeIntegrationSetupStatus(slack, integrationID)).toEqual(slack);
    for (const refused of [
      { ...setupStatus, connector_key: "databricks" },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_kind: "salesforce_org" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "1234567890123456" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "Databricks/1234567890123456" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "databricks/a/b" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "databricks/a..b" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: null } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, permissions: ["all-apis"] } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, repository_selection: "all" } },
      { ...setupStatus, connector_key: "salesforce" },
      { ...setupStatus, runtime_coverage: { state: "not_enrolled", reason: "not_enrolled", sensor_count: 0, healthy_sensor_count: 0 } },
    ]) expect(() => decodeIntegrationSetupStatus(refused, integrationID)).toThrow("schema mismatch");
  });

  it("accepts inventory the saas provider reports and names it as a source", () => {
    const page = (item: unknown) => decodeInventoryPage({ items: [item], page_info: { next_cursor: null, has_more: false } });
    const application = { ...summary, name: "gpt-4o-proxy", source_kind: "saas_ai_application", confidence_basis_points: 7000, discovery: { method: "inferred", platform: "databricks", signals: ["model:openai", "surface:model_serving"] } };
    const tenant = { ...summary, name: "Databricks workspace", kind: "asset", source_kind: "saas_tenant", discovery: { method: "provider_api", platform: "saas_tenant", signals: [] }, management_state: "not_applicable", activity_state: "not_applicable" };
    for (const item of [summary, application, tenant]) expect(page(item).items[0]).toEqual(item);
    // The platform is not a provider.
    for (const provider of ["databricks", "slack", "SaaS", "nango"]) expect(() => page({ ...summary, provider })).toThrow();
    const source = { integration_id: ids.integration, provider: "saas", source: "saas", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: ids.snapshot, generation: 1, evidence_id: ids.evidence, confidence_basis_points: 9500, observed_at: summary.observed_at, fresh_until: summary.fresh_until, projection_version: 1, winning: true };
    const evidence = [{ id: ids.evidence, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: summary.observed_at, size_bytes: 128 }];
    expect(decodeInventoryDetail({ summary, sources: [source], evidence }).sources[0]?.provider).toBe("saas");
    expect(() => decodeInventoryDetail({ summary, sources: [{ ...source, provider: "databricks" }], evidence })).toThrow();
  });
});

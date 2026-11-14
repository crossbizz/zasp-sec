import { describe, expect, it } from "vitest";

import { decodeConnectorManifest, decodeIntegration, decodeIntegrationFreshness, decodeIntegrationSetupStatus, decodeInventoryPage } from "./decoders";
import { decodeMCPServer } from "./mcp-decoders";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const ids = { entity: "pid_10000001-0000-4000-8000-000000000001", evidence: "pid_20000001-0000-4000-8000-000000000001" };
const audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws";
const federation = "ref:gcp/workload-identity/acme-security/zasp-reader";
const key = "ref:gcp/service-account-key/customer-0001";

const manifest = {
  key: "gcp", provider: "Google Cloud", category: "cloud",
  description: "Inventory Vertex AI agents, model endpoints, Cloud Run services and functions that call a model, and their service accounts.",
  data_types: ["agent", "identity", "resource"], actions: ["inventory_read", "posture_read"], auth_mode: "gcp_service_account",
  setup_schema: [
    { key: "scope", label: "Organization, folder or project", type: "string", required: true, description: "What to read." },
    { key: "identity_reference", label: "Service account", type: "secret_reference", required: true, description: "How the service account is reached." },
    { key: "audience", label: "Workload identity provider", type: "string", required: false, description: "Required with workload identity federation." },
  ],
  access_guidance: "Create a read-only service account.",
  test_semantics: "Obtain a token and read the named scope.",
} as const;

const setupStatus = {
  integration_id: integrationID, connector_key: "gcp",
  authorization: { state: "verified", scope_kind: "gcp_scope", scope_label: "organizations/123456789012", repository_selection: null, permissions: [] },
  runtime_coverage: { state: "not_applicable", reason: "not_applicable", sensor_count: 0, healthy_sensor_count: 0 },
  updated_at: "2026-11-14T10:00:00Z",
} as const;

const summary = {
  id: ids.entity, name: "Refund agent", kind: "agent", owner: "", team: "", tags: [], evidence_id: ids.evidence, confidence_basis_points: 9500,
  first_seen: "2026-11-13T00:00:00Z", last_seen: "2026-11-14T01:00:00Z", observed_at: "2026-11-14T01:00:00Z", fresh_until: "2026-11-15T01:00:00Z", freshness_state: "fresh", version: 1,
  provider: "gcp", source_kind: "gcp_agent_engine", discovery: { method: "provider_api", platform: "vertex_ai_agent_engine", signals: [] }, management_state: "unmanaged",
  activity_state: "unknown", last_activity_at: null,
} as const;

describe("Google Cloud provider decoders", () => {
  it("accepts the Google Cloud catalog entry with its optional audience field", () => {
    expect(decodeConnectorManifest(manifest)).toEqual(manifest);
  });

  it("accepts the two configuration shapes and nothing that carries key material", () => {
    const integration = { id: integrationID, connector_key: "gcp", name: "Google Cloud", status: "active", created_at: "2026-11-14T00:00:00Z", updated_at: "2026-11-14T00:01:00Z" };
    const federated = { audience, identity_reference: federation, scope: "organizations/123456789012" };
    const keyed = { identity_reference: key, scope: "projects/alpha-prod" };
    expect(decodeIntegration({ ...integration, configuration: federated }).configuration).toEqual(federated);
    expect(decodeIntegration({ ...integration, configuration: keyed }).configuration).toEqual(keyed);
    for (const configuration of [
      { identity_reference: federation, scope: "folders/42" },
      { audience, identity_reference: key, scope: "folders/42" },
      { audience: "https:" + audience, identity_reference: federation, scope: "folders/42" },
      { identity_reference: key, scope: "projects/Alpha" },
      { identity_reference: key, scope: "42" },
      { identity_reference: key },
      { identity_reference: "ref:aws/external-id/customer-0001", scope: "folders/42" },
      { identity_reference: key, scope: "folders/42", private_key: "key material" },
      { identity_reference: key, scope: "folders/42", region: "us-central1" },
      { identity_reference: "zasp-reader@acme-security.iam.gserviceaccount.com", scope: "folders/42" },
    ]) {
      expect(() => decodeIntegration({ ...integration, configuration })).toThrow();
    }
  });

  it("accepts the bound scope of a Google Cloud integration", () => {
    expect(decodeIntegrationSetupStatus(setupStatus, integrationID)).toEqual(setupStatus);
    for (const label of ["folders/42", "projects/alpha-prod"]) {
      const scoped = { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: label } };
      expect(decodeIntegrationSetupStatus(scoped, integrationID)).toEqual(scoped);
    }
    const pending = { ...setupStatus, authorization: { state: "pending", scope_kind: "none", scope_label: null, repository_selection: null, permissions: [] } };
    expect(decodeIntegrationSetupStatus(pending, integrationID)).toEqual(pending);
    for (const refused of [
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_kind: "aws_account" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "123456789012" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: "projects/123" } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, scope_label: null } },
      { ...setupStatus, authorization: { ...setupStatus.authorization, permissions: ["roles/viewer"] } },
      { ...setupStatus, connector_key: "aws", authorization: { ...setupStatus.authorization } },
      { ...setupStatus, connector_key: "azure" },
    ]) expect(() => decodeIntegrationSetupStatus(refused, integrationID)).toThrow("schema mismatch");
  });

  it("accepts inventory Google Cloud reports and names it as a source", () => {
    const page = (item: unknown) => decodeInventoryPage({ items: [item], page_info: { next_cursor: null, has_more: false } });
    const inferred = { ...summary, name: "support-bot", source_kind: "gcp_inferred_agent", confidence_basis_points: 7000, discovery: { method: "inferred", platform: "cloud_run_service", signals: ["env:anthropic", "iam:vertex_ai_user", "invoke:vertex_ai_model"] } };
    const project = { ...summary, name: "Alpha production", kind: "asset", source_kind: "gcp_project", discovery: { method: "provider_api", platform: "gcp_project", signals: [] }, management_state: "not_applicable", activity_state: "not_applicable" };
    for (const item of [summary, inferred, project]) expect(page(item).items[0]).toEqual(item);
    for (const provider of ["google", "azure", "GCP", "vertex"]) expect(() => page({ ...summary, provider })).toThrow();
  });

  it("accepts a Cloud Run MCP server in the MCP inventory", () => {
    const server = {
      id: ids.entity, name: "docs-mcp", provider: "gcp", source_kind: "gcp_mcp_server", source: "workload", transport: "http", endpoint_host: "docs-mcp-abc123-uc.a.run.app", command: null, package: null, package_pinned: null, plain_http: false,
      auth: "none", identity: "host:docs-mcp-abc123-uc.a.run.app", approval: "unapproved", tools: [], tool_count: 0, agents: [], agent_count: 0, first_seen_at: "2026-11-14T01:00:00Z", last_seen_at: "2026-11-14T02:00:00Z",
    };
    expect(decodeMCPServer(server)).toEqual(server);
    expect(() => decodeMCPServer({ ...server, provider: "azure" })).toThrow();
    expect(() => decodeMCPServer({ ...server, source_kind: "gcp_agent_tool" })).toThrow();
  });

  it("accepts the Google APIs a collection could not read as coverage gaps", () => {
    const projection = { state: "current", snapshot_id: "pid_40000001-0000-4000-8000-000000000001", completed_at: "2026-11-14T09:59:00Z", last_error_code: null };
    const freshness = {
      integration_id: integrationID, version: 3, last_good: null, latest_sync: null,
      projections: { risk: projection, graph: projection, search: projection },
      updated_at: "2026-11-14T10:00:00Z",
      coverage_gaps: [{ service: "cloud-functions", name: "Cloud Functions", status: "access_denied" }, { service: "cloud-run", name: "Cloud Run", status: "unavailable" }],
    };
    expect(decodeIntegrationFreshness(freshness).coverage_gaps).toEqual(freshness.coverage_gaps);
    // Gaps are ordered by service, and a status is one of the two.
    expect(() => decodeIntegrationFreshness({ ...freshness, coverage_gaps: [...freshness.coverage_gaps].reverse() })).toThrow();
    expect(() => decodeIntegrationFreshness({ ...freshness, coverage_gaps: [{ service: "cloud-run", name: "Cloud Run", status: "disabled" }] })).toThrow();
  });
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import { load, JSON_SCHEMA } from "js-yaml";

const require = createRequire(import.meta.url);
const fromGenerator = createRequire(require.resolve("openapi-typescript"));
const fromValidator = createRequire(fromGenerator.resolve("@redocly/openapi-core"));
const Ajv2020 = fromValidator("@redocly/ajv/dist/2020.js").default;
// Formats is supplied by the RSC webpack peer's schema validator, not Redocly.
const fromRSC = createRequire(require.resolve("react-server-dom-webpack/package.json"));
const fromWebpack = createRequire(fromRSC.resolve("webpack"));
const fromSchema = createRequire(fromWebpack.resolve("schema-utils"));
const formats = fromSchema("ajv-formats");

const root = resolve(import.meta.dirname, "..");

test("export execution controls retain the closed public mutation contract", async () => {
  const keys = ["create_evidence_export", "create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"];
  const validate = await auditExportValidator("SecurityAgentExecutionControls");
  const value = { global: { target: "global", action_key: "*", enabled: true, version: 1 }, environment: { target: "environment", action_key: "*", enabled: false, version: 0 }, actions: keys.map(action_key => ({ target: "action", action_key, enabled: false, version: 0 })) };
  assert.equal(validate(value), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...value, actions: [...value.actions, value.actions[0]] }), false);
  const input = await auditExportValidator("SecurityAgentExecutionControlInput");
  assert.equal(input({ target: "action", action_key: "create_evidence_export", enabled: true }), true, JSON.stringify(input.errors));
  assert.equal(input({ target: "global", action_key: "create_evidence_export", enabled: true }), false);
  const result = await auditExportValidator("SecurityAgentExecutionControlResult");
  const receipt = { target: "action", action_key: "create_evidence_export", enabled: true, version: 1, audit_id: auditExportID(1), correlation_id: auditExportID(2), receipt_id: auditExportID(3), replayed: false };
  assert.equal(result(receipt), true, JSON.stringify(result.errors));
  assert.equal(result({ ...receipt, setup: true }), false);
});

test("export approval context carries closed selected evidence", async () => {
  const validate = await auditExportValidator("SecurityAgentApprovalContext");
  const context = { agent_id: auditExportID(1), action: "create_evidence_export", target_id: auditExportID(2),
    plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1",
    requester: { state: "withheld", id: null }, reason: { code: "operator_approval_required", source: "persisted_step" },
    risk: { class: "low", source: "action_catalog" }, rationale: null,
    export_selection: [{ source_kind: "finding", source_id: auditExportID(3), source_version: 7, association_digest: `sha256:${"b".repeat(64)}` }] };
  assert.equal(validate(context), true, JSON.stringify(validate.errors));
  for (const invalid of [{ ...context, export_selection: [] }, { ...context, export_selection: undefined }, { ...context, target_id: null }, { ...context, action: "update_finding_response" }, { ...context, export_selection: [{ ...context.export_selection[0], key: "private" }] }]) assert.equal(validate(invalid), false, JSON.stringify(invalid));
});

test("agent export contract validates public status and body-only download grants", async () => {
  const document = load(await readFile(resolve(root, "openapi/openapi.yaml"), "utf8"), { schema: JSON_SCHEMA });
  const base = "/api/v1/security-agent-runs/{id}/steps/{stepId}/export";
  for (const [suffix, method, operationID] of [["", "get", "getSecurityAgentExport"], ["/download-grants", "post", "createSecurityAgentExportDownloadGrant"], ["/download", "post", "downloadSecurityAgentExport"]]) {
    const path = document.paths[base + suffix];
    assert.ok(path, `missing ${base + suffix}`);
    assert.equal(path[method].operationId, operationID);
    assert.deepEqual(path[method].security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
    assert.deepEqual(path.parameters.map(p => p.name).sort(), ["id", "stepId"]);
  }
  const validate = await auditExportValidator("SecurityAgentExportStatus");
  const status = { export_id: auditExportID(4), state: "pending", phase: "queued", failure_code: null, created_at: "2026-09-19T00:00:00Z", retrieval_expires_at: "2026-09-20T00:00:00Z", mapping_revision: "security-agent-run-evidence-v1", snapshot_at: null, cleanup_state: "retained", selection: [{ source_kind: "finding", source_id: auditExportID(5), source_version: 7, association_digest: `sha256:${"a".repeat(64)}` }], artifact: null };
  assert.equal(validate(status), true, JSON.stringify(validate.errors));
  for (const invalid of [{ ...status, key: "private" }, { ...status, selection: [] }, { ...status, state: "ready" }, { ...status, artifact: { sha256: "a".repeat(64), size: 0 } }, { ...status, selection: [{ ...status.selection[0], source_version: 0 }] }]) assert.equal(validate(invalid), false, JSON.stringify(invalid));
  const ajv = new Ajv2020({ strict: false });
  const body = document.paths[base + "/download"].post.requestBody.content["application/json"].schema;
  const download = ajv.compile({ ...body, components: document.components });
  assert.equal(download({ format: "human", token: "a".repeat(64) }), true);
  for (const input of [{ format: "human" }, { format: "pdf", token: "a".repeat(64) }, { format: "json", token: "bad" }, { format: "csv", token: "a".repeat(64), key: "private" }]) assert.equal(download(input), false);
});

test("audit page filters validate exact values without changing browser authority", async () => {
  const document = load(await readFile(resolve(root, "openapi/openapi.yaml"), "utf8"), { schema: JSON_SCHEMA });
  const operation = document.paths["/api/v1/audit-events"].get;
  const names = ["actor_id", "action", "outcome", "from", "to"];
  const properties = {};
  for (const name of names) {
    const parameter = operation.parameters.find((value) => value.name === name);
    assert.ok(parameter, `missing supported query ${name}`);
    assert.equal(parameter.in, "query");
    assert.equal(parameter.required, false);
    properties[name] = parameter.schema;
  }
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  ajv.addFormat("date-time", formats.get("date-time"));
  const validate = ajv.compile({ type: "object", additionalProperties: false, properties, components: document.components });
  const valid = { actor_id: "pid_10000004-0000-4000-8000-000000000004", action: "identity_provider.createSSOConnection", outcome: "denied", from: "2026-01-01T00:00:00Z", to: "2026-01-02T00:00:00.123456Z" };
  for (const value of [{}, valid, { action: "identity_provider.createssoconnection" }, { outcome: "failed" }, { from: "0001-01-01T00:00:00.1Z" }]) assert.equal(validate(value), true, JSON.stringify(value));
  for (const value of [{ actor_id: "foreign" }, { action: "Policy.update" }, { action: "policy.update\n" }, { action: "a".repeat(128) }, { outcome: "rejected" }, { from: "2026-01-01T00:00:00+00:00" }, { from: "2026-01-01T00:00:00.1234567Z" }, { from: "2026-02-30T00:00:00Z" }, { to: "" }, { source: "admin" }]) assert.equal(validate(value), false, JSON.stringify(value));
  assert.deepEqual(operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
  for (const from of ["0000-01-01T00:00:00Z", "2026-01-01T23:59:60Z"]) assert.equal(validate({ from }), false, from);
  assert.equal(operation.responses["200"].content["application/json"].schema.$ref, "#/components/schemas/AuditEventPage");
});

async function auditExportValidator(name) {
  const document = load(await readFile(resolve(root, "openapi/openapi.yaml"), "utf8"), { schema: JSON_SCHEMA });
  assert.ok(document.components.schemas[name], `${name} contract is missing`);
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  ajv.addFormat("date-time", formats.get("date-time"));
  return ajv.compile({ $ref: `#/components/schemas/${name}`, components: document.components });
}

const auditExportID = (n) => `pid_${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000001`;
const auditExportScope = { organization_id: auditExportID(1), workspace_id: auditExportID(2), environment_id: auditExportID(3) };
const auditExportPending = { id: auditExportID(4), ...auditExportScope, status: "queued", event_count: null, created_at: "2026-09-12T08:00:00.000000Z", audit_correlation_id: auditExportID(6) };
const auditExportReady = { ...auditExportPending, status: "ready", captured_at: "2026-09-12T08:00:01.000000Z", event_count: 1, chunk_count: 1, chunk_bytes: 1024, manifest_sha256: "a".repeat(64) };
const auditExportEvent = { ordinal: 1, id: auditExportID(7), ...auditExportScope, actor_id: auditExportID(8), action: "policy.update", target_id: "policy:reference", outcome: "succeeded", metadata: { source: "identity_admin" }, occurred_at: "2026-09-12T07:00:00.123456Z" };
const auditExportBinding = { ...auditExportScope, export_id: auditExportID(4), capture_id: auditExportID(5) };
const auditExportChunk = { schema: "audit-export-chunk-v1", binding: auditExportBinding, ordinal: 1, first_event: 1, event_count: 1, previous_digest: "0".repeat(64), events: [auditExportEvent] };
const auditExportManifest = { schema: "audit-export-manifest-v1", binding: auditExportBinding, event_count: 1, chunk_count: 1, chunk_bytes: 1024, chain_root: "b".repeat(64) };
const auditExportReadReady = { export: auditExportReady, contents: { manifest: auditExportManifest, chunk: auditExportChunk, chunk_sha256: "b".repeat(64), page_info: { next_cursor: null, has_more: false } } };

test("retained identity actions preserve their exact public and export schema values", async () => {
  const validators = await Promise.all(["AuditEvent", "AuditExportEvent", "AuditExportChunk"].map(auditExportValidator));
  const check = (action, expected) => {
    const event = { ...auditExportEvent, action };
    const publicEvent = { ...event }; delete publicEvent.ordinal; delete publicEvent.organization_id;
    for (const [index, value] of [publicEvent, event, { ...auditExportChunk, events: [event] }].entries()) {
      assert.equal(validators[index](value), expected, `${index}: ${JSON.stringify(action)}`);
      assert.equal((index === 2 ? value.events[0] : value).action, action);
    }
  };
  for (const action of ["identity_provider.createSSOConnection", "identity_provider.deleteSSOConnection", "identity_provider.testSSOConnection", "identity_provider.createSCIMConnection", "identity_provider.deleteSCIMConnection", "policy.update", "identity_provider.createssoconnection", "a".repeat(127)]) check(action, true);
  for (const action of ["Identity_provider.createSSOConnection", "identity_provider.CreateSSOConnection", "identity_provider.createSsoConnection", "identity_provider.createSSOConnectionX", "identity_provider.unknownOperation", "identity_provider.createSSOConnection.", "identity_provider.createSSOConnection ", "identity_provider.createSSOConnection\n", "identity_provider.createSSOConnection\0", "identity_provider.créateSSOConnection", "identity_provider..createSSOConnection", "a".repeat(128)]) check(action, false);
});

test("audit export descriptors model durable async state without partial ready metadata", async () => {
  const validate = await auditExportValidator("AuditExport");
  for (const value of [auditExportPending, { ...auditExportPending, status: "processing" }, auditExportReady,
    { ...auditExportPending, status: "failed", failure_code: "capacity_exceeded" },
    { ...auditExportPending, status: "failed", failure_code: "invalid_source" },
    { ...auditExportPending, status: "failed", failure_code: "execution_failed" }]) {
    assert.equal(validate(value), true, `${value.status} descriptor rejected`);
  }
  for (const value of [
    { ...auditExportPending, status: "unknown" }, { ...auditExportPending, event_count: 0 },
    { ...auditExportPending, manifest_sha256: "a".repeat(64) },
    { ...auditExportPending, status: "failed" }, { ...auditExportPending, status: "failed", failure_code: "s3_secret_failure" },
    { ...auditExportReady, captured_at: null }, { ...auditExportReady, manifest_sha256: null },
    { ...auditExportReady, event_count: 0 }, { ...auditExportReady, chunk_count: 0 },
    { ...auditExportReady, event_count: Number.MAX_SAFE_INTEGER + 1 },
    { ...auditExportReady, organization_id: "foreign-string" }, { ...auditExportReady, requested_at: auditExportReady.created_at },
  ]) assert.equal(validate(value), false, "accepted inconsistent descriptor");
  for (const field of ["id", "organization_id", "workspace_id", "environment_id", "created_at", "audit_correlation_id"]) {
    const value = structuredClone(auditExportPending); delete value[field];
    assert.equal(validate(value), false, `accepted missing ${field}`);
  }
});

test("audit export reads separate pending, failed, ready-empty and immutable chunk contents", async () => {
  const validate = await auditExportValidator("AuditExportRead");
  const empty = { export: { ...auditExportReady, event_count: 0, chunk_count: 0, chunk_bytes: 0 }, contents: {
    manifest: { ...auditExportManifest, event_count: 0, chunk_count: 0, chunk_bytes: 0, chain_root: "0".repeat(64) },
    chunk: null, chunk_sha256: null, page_info: { next_cursor: null, has_more: false },
  } };
  const pending = { export: auditExportPending, contents: null };
  const failed = { export: { ...auditExportPending, status: "failed", failure_code: "execution_failed" }, contents: null };
  const continued = structuredClone(auditExportReadReady);
  continued.contents.page_info = { next_cursor: "YWJj", has_more: true };
  for (const value of [pending, failed, empty, auditExportReadReady, continued]) assert.equal(validate(value), true, "valid read rejected");
  const cases = [
    { ...pending, contents: auditExportReadReady.contents }, { ...failed, contents: auditExportReadReady.contents },
    { export: auditExportReady, contents: null }, { ...empty, contents: auditExportReadReady.contents },
    { ...auditExportReadReady, contents: empty.contents },
  ];
  for (const mutate of [
    (v) => { v.contents.chunk = null; }, (v) => { v.contents.chunk_sha256 = null; },
    (v) => { v.contents.manifest.chain_root = "0".repeat(64); },
    (v) => { v.contents.page_info = { next_cursor: null, has_more: true }; },
    (v) => { v.contents.chunk.schema = "audit-export-chunk-v2"; },
    (v) => { v.contents.manifest.schema = "audit-export-manifest-v2"; },
    (v) => { v.contents.chunk.events = []; }, (v) => { v.contents.chunk.events = Array(1001).fill(auditExportEvent); },
    (v) => { v.contents.chunk.events[0].occurred_at = "2026-09-12T07:00:00Z"; },
    (v) => { v.contents.chunk.events[0].occurred_at = "2026-02-30T07:00:00.123456Z"; },
    (v) => { v.contents.chunk.events[0].metadata = null; },
    (v) => { v.contents.chunk.previous_digest = "a".repeat(64); },
  ]) { const value = structuredClone(auditExportReadReady); mutate(value); cases.push(value); }
  for (const value of cases) assert.equal(validate(value), false, "accepted partial or inconsistent contents");
  // The schema closes every public object against credentials and provider locators.
  for (const field of ["raw_token", "authorization", "bucket", "object_key", "version_id", "download_url"]) {
    for (const pick of [v => v, v => v.export, v => v.contents, v => v.contents.manifest,
      v => v.contents.manifest.binding, v => v.contents.chunk, v => v.contents.chunk.events[0]]) {
      const value = structuredClone(auditExportReadReady); pick(value)[field] = "private-fixture";
      assert.equal(validate(value), false, `accepted unmodeled ${field}`);
    }
  }
});

test("runtime session search publishes closed selectors and checkpoint freshness", async () => {
  const document = load(await readFile(resolve(root, "openapi/openapi.yaml"), "utf8"), { schema: JSON_SCHEMA });
  const parameters = document.paths["/api/v1/sessions"].get.parameters;
  assert.deepEqual(parameters.filter(value => value.name).map(value => value.name).sort(), ["agent_id", "credential_id", "decision", "domain", "file", "from", "kind", "principal_id", "process", "resource", "to", "tool"]);
  const schemas = document.components.schemas;
  assert.equal(schemas.RuntimeSessionPage.properties.search.$ref, "#/components/schemas/RuntimeSessionSearchStatus");
  const status = schemas.RuntimeSessionSearchStatus;
  assert.equal(status.additionalProperties, false);
  assert.deepEqual(status.properties.state.enum, ["empty", "catching_up", "blocked", "current"]);
  assert.deepEqual(status.properties.selector_coverage.enum, ["observed_only"]);
  assert.equal(status.properties.pending_batches.maximum, 1000);
  assert.equal(status.properties.quarantined_batches.maximum, 1000);
  assert.equal(status.required.length, 9);
});

test("runtime session reads preserve operation IDs and console-only revocation", async () => {
  const document = load(await readFile(resolve(root, "openapi/openapi.yaml"), "utf8"), { schema: JSON_SCHEMA });
  const paths = document.paths, schemas = document.components.schemas;
  assert.equal(paths["/api/v1/sessions"].get.operationId, "listSessions");
  assert.deepEqual(paths["/api/v1/sessions"].get.parameters.find((value) => value.name === "kind")?.schema.enum, ["console", "runtime"]);
  assert.equal(paths["/api/v1/sessions/{id}"].parameters[0].schema.$ref, "#/components/schemas/SessionInvestigationID");
  assert.equal(paths["/api/v1/sessions/{id}"].delete.parameters.find((value) => value.name === "id")?.schema.$ref, "#/components/schemas/SessionID");
  assert.equal(paths["/api/v1/sessions/{id}/events"].parameters[0].schema.$ref, "#/components/schemas/SessionInvestigationID");
  assert.deepEqual(schemas.RuntimeSession.properties.kind.enum, ["runtime", "unattributed"]);
  assert.deepEqual(schemas.RuntimeSession.properties.agent_id.type, ['string', 'null']);
  assert.deepEqual(schemas.RuntimeSessionEvent.properties.session_id.type, ['string', 'null']);
  assert.deepEqual(schemas.RuntimeSessionEvent.properties.agent_id.type, ['string', 'null']);
  assert.equal(schemas.RuntimeSession.properties.events, undefined);
  assert.equal(schemas.RuntimeSession.properties.expires_at, undefined);
  assert.equal(schemas.RuntimeSession.properties.state, undefined);
  assert.deepEqual(schemas.SessionPage.anyOf.map((value) => value.$ref), ["#/components/schemas/ConsoleSessionPage", "#/components/schemas/RuntimeSessionPage"]);
});

const expectedOperations = new Map([
  ["getOrganization", ["/api/v1/organization", "get"]],
  ["listWorkspaces", ["/api/v1/workspaces", "get"]],
  ["createWorkspace", ["/api/v1/workspaces", "post"]],
  ["getWorkspace", ["/api/v1/workspaces/{id}", "get"]],
  ["updateWorkspace", ["/api/v1/workspaces/{id}", "patch"]],
  ["listEnvironments", ["/api/v1/environments", "get"]],
  ["createEnvironment", ["/api/v1/environments", "post"]],
  ["getEnvironment", ["/api/v1/environments/{id}", "get"]],
  ["updateEnvironment", ["/api/v1/environments/{id}", "patch"]],
  ["getCurrentPrincipal", ["/api/v1/me", "get"]],
  ["listMembers", ["/api/v1/admin/members", "get"]],
  ["updateMemberRole", ["/api/v1/admin/members/{id}", "patch"]],
  ["listBuiltInRoles", ["/api/v1/admin/roles", "get"]],
  ["listGroupMappings", ["/api/v1/admin/group-mappings", "get"]],
  ["updateGroupMappings", ["/api/v1/admin/group-mappings", "patch"]],
  ["listAPITokens", ["/api/v1/admin/api-tokens", "get"]],
  ["createAPIToken", ["/api/v1/admin/api-tokens", "post"]],
  ["listAPITokenRevealGrants", ["/api/v1/admin/api-token-reveal-grants", "get"]],
  ["revealAPIToken", ["/api/v1/admin/api-token-reveal-grants/{id}/reveal", "post"]],
  ["acknowledgeAPITokenRevealGrant", ["/api/v1/admin/api-token-reveal-grants/{id}", "delete"]],
  ["rotateAPIToken", ["/api/v1/admin/api-tokens/{id}/rotate", "post"]],
  ["revokeAPIToken", ["/api/v1/admin/api-tokens/{id}", "delete"]],
  ["listAuditEvents", ["/api/v1/audit-events", "get"]],
  ["listSSOConnections", ["/api/v1/admin/sso-connections", "get"]],
  ["createSSOConnection", ["/api/v1/admin/sso-connections", "post"]],
  ["deleteSSOConnection", ["/api/v1/admin/sso-connections/{id}", "delete"]],
  ["testSSOConnection", ["/api/v1/admin/sso-connections/{id}/test", "post"]],
  ["listSCIMConnections", ["/api/v1/admin/scim-connections", "get"]],
  ["createSCIMConnection", ["/api/v1/admin/scim-connections", "post"]],
  ["deleteSCIMConnection", ["/api/v1/admin/scim-connections/{id}", "delete"]],
]);

expectedOperations.set("createAuditExport", ["/api/v1/audit-exports", "post"]);
expectedOperations.set("getAuditExport", ["/api/v1/audit-exports/{id}", "get"]);

const identityUIOperations = new Set([
  "getOrganization", "listWorkspaces", "createWorkspace", "updateWorkspace", "listEnvironments", "createEnvironment", "updateEnvironment",
  "listMembers", "updateMemberRole", "listBuiltInRoles",
  "listGroupMappings", "updateGroupMappings",
  "listSSOConnections", "createSSOConnection", "deleteSSOConnection", "testSSOConnection",
  "listSCIMConnections", "createSCIMConnection", "deleteSCIMConnection",
  "listAPITokens", "createAPIToken", "listAPITokenRevealGrants", "revealAPIToken", "acknowledgeAPITokenRevealGrant", "rotateAPIToken", "revokeAPIToken", "listAuditEvents",
]);

test("publishes the identity administration operations at their honest UI lifecycle", async () => {
  const [source, mapSource] = await Promise.all([
    readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
    readFile(resolve(root, "docs/product/ui-api-map.yaml"), "utf8"),
  ]);
  const document = load(source, { schema: JSON_SCHEMA, json: false });
  const map = load(mapSource, { schema: JSON_SCHEMA, json: false });
  const mapped = new Map(map.screens.flatMap((screen) => screen.actions.map((action) => [action.operation_id, action.availability])));

  for (const [operationID, [path, method]] of expectedOperations) {
    assert.equal(document.paths?.[path]?.[method]?.operationId, operationID);
    assert.equal(mapped.get(operationID), identityUIOperations.has(operationID) ? "available" : "api_available");
  }
  const create = document.paths["/api/v1/audit-exports"].post;
  const read = document.paths["/api/v1/audit-exports/{id}"].get;
  assert.deepEqual(create.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
  assert.deepEqual(read.security, create.security);
  assert.equal(create.requestBody.content["application/json"].schema.$ref, "#/components/schemas/AuditExportInput");
  assert.equal(create.responses[201].content["application/json"].schema.$ref, "#/components/schemas/AuditExport");
  assert.equal(read.responses[200].content["application/json"].schema.$ref, "#/components/schemas/AuditExportRead");
  assert.deepEqual(read.parameters.map((parameter) => parameter.name), ["cursor"]);
  assert.equal(read.parameters[0].schema.maxLength, 1024);
  for (const operation of [create, read]) for (const status of [400, 401, 403, 404, 409, 503]) {
    assert.equal(operation.responses[status].$ref, "#/components/responses/ProductErrorResponse");
  }
  assert.equal([...mapped].filter(([operationID, value]) => identityUIOperations.has(operationID) && value === "available").length, identityUIOperations.size);
});

test("uses strict product schemas and the shared stable error response", async () => {
  const source = await readFile(resolve(root, "openapi/openapi.yaml"), "utf8");
  const document = load(source, { schema: JSON_SCHEMA, json: false });
  for (const schema of ["Organization", "Workspace", "Environment", "Principal", "BuiltInRole", "APIToken", "APITokenRevealGrant", "APITokenRevealGrantSummary", "APITokenRevealGrantPage", "APITokenRevealedCredential", "AuditEvent"]) {
    assert.equal(document.components?.schemas?.[schema]?.additionalProperties, false);
  }
  for (const [, [path, method]] of expectedOperations) {
    assert.equal(document.paths[path][method].responses?.["default"]?.$ref, "#/components/responses/ProductErrorResponse");
  }
  assert.equal(document.paths["/api/v1/admin/api-tokens"].post.responses["201"].content["application/json"].schema.$ref,
    "#/components/schemas/APITokenRevealGrant");
  assert.equal(document.components.schemas.APIToken.properties.raw_token, undefined);
  assert.deepEqual(document.components.schemas.APITokenRevealedCredential.required.includes("raw_token"), true);
  assert.equal(document.components.schemas.APITokenRevealedCredential.properties.raw_token.readOnly, true);
  assert.equal(document.components.schemas.APITokenRevealGrant.properties.raw_token, undefined);
  assert.equal(document.components.schemas.APITokenPage.properties.items.items.$ref, "#/components/schemas/APIToken");
  assert.equal(Object.hasOwn(document.paths["/api/v1/admin/api-tokens/{id}"].delete, "requestBody"), false);
  assert.equal(Object.hasOwn(document.paths["/api/v1/sessions/{id}"].delete, "requestBody"), false);
  assert.equal(document.components.schemas.ComplianceControl.properties.evidence_ids.minItems, 0);
  assert.equal(document.components.schemas.ComplianceControl.properties.evidence_ids.maxItems, 100);
  assert.equal(document.components.schemas.ComplianceEvidence.properties.evidence.minItems, 1);
  assert.equal(document.components.schemas.ComplianceEvidence.properties.evidence.maxItems, 1);
  assert.equal(document.components.schemas.WorkspaceMutation.properties.initial_environment_id.$ref, "#/components/schemas/ProductID");
  assert.equal(document.components.schemas.GroupMappingInput.properties.group_reference.pattern,
    "^scim-group-(test|live)-[A-Za-z0-9_-]+$");
  assert.equal(document.components.schemas.GroupMapping.properties.group_reference.pattern,
    "^scim-group-(test|live)-[A-Za-z0-9_-]+$");
  const environmentList = document.paths["/api/v1/environments"].get;
  assert.deepEqual(environmentList.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
  assert.equal(environmentList.parameters.find((parameter) => parameter.name === "workspace_id")?.required, true);
  assert.match(environmentList.summary, /authorized/i);
});

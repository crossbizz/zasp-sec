import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { describe, it } from "node:test";
import { load, JSON_SCHEMA } from "js-yaml";

const require = createRequire(import.meta.url);
const generator = createRequire(require.resolve("openapi-typescript"));
const validator = createRequire(generator.resolve("@redocly/openapi-core"));
const Ajv2020 = validator("@redocly/ajv/dist/2020.js").default;
const document = load(await readFile(new URL("./openapi.yaml", import.meta.url), "utf8"), { schema: JSON_SCHEMA });
const schemas = document.components.schemas;
const ajv = new Ajv2020({ strict: false, allErrors: true });
for (const [name, schema] of Object.entries(schemas)) ajv.addSchema(schema, `#/components/schemas/${name}`);
const compile = (name) => ajv.compile({ $ref: `#/components/schemas/${name}` });

const agent = "pid_10000001-0000-4000-8000-000000000001";
const role = "pid_10000002-0000-4000-8000-000000000002";
const evidence = "pid_20000001-0000-4000-8000-000000000001";
const summary = { id: agent, name: "Support agent", kind: "agent", owner: "", team: "", tags: [], evidence_id: evidence, confidence_basis_points: 9000, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-20T01:00:00Z", freshness_state: "fresh", version: 1, provider: "aws", source_kind: "aws_bedrock_agent", discovery: { method: "provider_api", platform: "bedrock_agent", signals: [] }, management_state: "unmanaged", last_activity_at: null, activity_state: "unknown" };

describe("AI frameworks on the compliance contract", () => {
  const frameworks = ["soc2_security", "hipaa", "owasp_agentic_top10_2026", "owasp_llm_top10_2025", "mitre_atlas", "nist_ai_rmf_1_0", "iso_iec_42001_2023", "eu_ai_act"];
  it("names the two product frameworks and the six AI frameworks", () => {
    assert.deepEqual(schemas.ComplianceFrameworkID.enum, frameworks);
    for (const parameter of ["ComplianceFramework", "ComplianceControlFilter"]) assert.match(document.components.parameters[parameter].schema.$ref, /Compliance(FrameworkID|ControlID)$/);
    assert.deepEqual(schemas.ComplianceExportInput.properties.framework, { $ref: "#/components/schemas/ComplianceFrameworkID" });
    assert.deepEqual(schemas.ComplianceExportInput.properties.control_id, { $ref: "#/components/schemas/ComplianceControlID" });
  });
  it("accepts product controls and the frameworks' own control identifiers", () => {
    const control = compile("ComplianceControlID");
    for (const id of ["soc2_security-audit", "hipaa-configuration", "ASI03", "LLM01", "AML.T0051", "GOVERN 1.6", "MEASURE 2.7", "MANAGE 2.4", "A.3.2", "A.6.2.6", "Article 9", "Article 15"]) assert.equal(control(id), true, id);
    for (const id of ["", "hipaa-unknown", "owasp_agentic_top10_2026-ASI03", "ASI3", "LLM001", "AML.T51", "GOVERN-1.6", "govern 1.6", "A.6", "Article", "Article 15 "]) assert.equal(control(id), false, id);
  });
  it("carries a finding count on a control", () => {
    const control = compile("ComplianceControl");
    const base = { id: "ASI03", framework: "owasp_agentic_top10_2026", name: "Identity and Privilege Abuse", evidence_ids: [evidence], fresh_until: "2026-11-15T00:00:00Z", freshness: "fresh" };
    assert.equal(control({ ...base, finding_count: 1 }), true, JSON.stringify(control.errors));
    assert.equal(control(base), true);
    for (const finding_count of [-1, 1.5, "1", null]) assert.equal(control({ ...base, finding_count }), false);
    assert.equal(control({ ...base, findings: 1 }), false);
  });
});

describe("agent activity on the inventory summary", () => {
  const validate = compile("InventorySummary");
  it("requires both members and accepts a null time", () => {
    assert.equal(validate(summary), true, JSON.stringify(validate.errors));
    assert.equal(validate({ ...summary, last_activity_at: "2026-11-01T10:00:00Z", activity_state: "active" }), true);
    assert.equal(validate({ ...summary, activity_state: "inactive" }), true);
    assert.deepEqual(schemas.InventoryActivityState.enum, ["active", "inactive", "unknown", "not_applicable"]);
    for (const key of ["last_activity_at", "activity_state"]) {
      const { [key]: _removed, ...rest } = summary;
      assert.equal(validate(rest), false, key);
    }
    assert.equal(validate({ ...summary, activity_state: "zombie" }), false);
    assert.equal(validate({ ...summary, last_activity_at: 0 }), false);
  });
});

describe("named relationship ends", () => {
  const validate = compile("Relationship");
  const relationship = { id: "pid_50000001-0000-4000-8000-000000000001", from_id: agent, to_id: role, type: "uses_identity", evidence_id: evidence };
  const end = { name: "support-agent-role", kind: "identity", provider: "aws", source_kind: "aws_role" };
  it("keeps the identifiers required and the names optional", () => {
    assert.equal(validate(relationship), true, JSON.stringify(validate.errors));
    assert.equal(validate({ ...relationship, to: end }), true, JSON.stringify(validate.errors));
    assert.equal(validate({ ...relationship, from: { ...end, kind: "agent", source_kind: "aws_bedrock_agent" }, to: end }), true);
    for (const to of [{ ...end, name: "" }, { ...end, kind: "credential" }, { ...end, provider: "gcp" }, { ...end, source_kind: "AWS Role" }, { ...end, arn: "arn:aws:iam::123456789012:role/x" }, { name: "x" }]) assert.equal(validate({ ...relationship, to }), false, JSON.stringify(to));
  });
});

describe("agent evidence pack", () => {
  const operation = document.paths["/api/v1/agents/{id}/evidence-pack"].get;
  it("is one read operation with a JSON document and a Markdown rendering", () => {
    assert.equal(operation.operationId, "getAgentEvidencePack");
    assert.deepEqual(Object.keys(document.paths["/api/v1/agents/{id}/evidence-pack"]), ["parameters", "get"]);
    assert.deepEqual(operation.parameters.map((parameter) => [parameter.name, parameter.in, parameter.schema.enum]), [["format", "query", ["json", "markdown"]]]);
    assert.deepEqual(Object.keys(operation.responses["200"].content), ["application/json", "text/markdown"]);
    assert.equal(operation.responses["200"].content["application/json"].schema.$ref, "#/components/schemas/AgentEvidencePackResponse");
    for (const status of ["400", "401", "403", "404"]) assert.ok(operation.responses[status], status);
    // It follows the default security of the agent reads: no own override.
    assert.equal(operation.security, undefined);
  });
  it("bounds every section and names why a section is empty", () => {
    const pack = schemas.AgentEvidencePack;
    assert.deepEqual(pack.required, ["schema_version", "generated_at", "organization_id", "workspace_id", "environment_id", "agent", "findings", "security_agent_runs", "red_team_tests", "red_team_runs"]);
    assert.equal(pack.additionalProperties, false);
    for (const [section, maximum] of [["findings", 200], ["security_agent_runs", 50], ["red_team_tests", 200], ["red_team_runs", 200]]) {
      assert.deepEqual(pack.properties[section].required, ["status", "items"], section);
      assert.equal(pack.properties[section].properties.items.maxItems, maximum, section);
      assert.equal(pack.properties[section].properties.status.$ref, "#/components/schemas/AgentEvidencePackStatus", section);
    }
    assert.deepEqual(schemas.AgentEvidencePackStatus.enum, ["complete", "truncated", "not_permitted", "browser_session_required", "unavailable"]);
    assert.equal(pack.properties.agent.$ref, "#/components/schemas/InventoryDetail");
    assert.equal(pack.properties.findings.properties.items.items.$ref, "#/components/schemas/Finding");
    assert.equal(pack.properties.red_team_tests.properties.items.items.$ref, "#/components/schemas/TestDefinition");
    assert.equal(pack.properties.red_team_runs.properties.items.items.$ref, "#/components/schemas/TestRun");
    assert.deepEqual(schemas.AgentEvidencePackResponse.required, ["pack", "markdown"]);
  });
});

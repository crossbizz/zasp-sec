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

describe("retained agent evidence pack on the export request", () => {
  const validate = compile("ComplianceExportInput");
  it("names a framework and control, or one agent alone", () => {
    for (const accepted of [{}, { framework: "eu_ai_act" }, { framework: "nist_ai_rmf_1_0", control_id: "GOVERN 1.6" }, { agent_id: agent }]) assert.equal(validate(accepted), true, JSON.stringify(accepted));
    for (const refused of [{ agent_id: "agent" }, { agent_id: agent, framework: "hipaa" }, { agent_id: agent, control_id: "ASI03" }, { agent: agent }]) assert.equal(validate(refused), false, JSON.stringify(refused));
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

describe("hosted gateway", () => {
  const server = "pid_61000001-0000-4000-8000-000000000001";
  const traffic = [
    ["/api/v1/gateway/mcp/{id}", "post", "callMCPGateway"], ["/api/v1/gateway/mcp/{id}", "delete", "closeMCPGatewaySession"],
    ["/api/v1/gateway/llm/v1/chat/completions", "post", "createGatewayChatCompletion"], ["/api/v1/gateway/llm/v1/responses", "post", "createGatewayResponse"], ["/api/v1/gateway/llm/v1/messages", "post", "createGatewayMessage"],
  ];
  const management = [
    ["/api/v1/gateway/policy", "get", "getGatewayPolicy"], ["/api/v1/gateway/policy", "put", "putGatewayPolicy"], ["/api/v1/gateway/mcp-servers", "get", "listMCPGatewayServers"],
    ["/api/v1/gateway/mcp-servers/{id}", "put", "putMCPGatewayServer"], ["/api/v1/gateway/mcp-servers/{id}", "delete", "deleteMCPGatewayServer"], ["/api/v1/gateway/activity", "get", "listGatewayActivity"],
  ];
  it("serves an agent's traffic to an API token only, and never takes an upstream credential in a body or a query", () => {
    for (const [path, method, id] of traffic) {
      const operation = document.paths[path][method];
      assert.equal(operation.operationId, id);
      // A browser session cannot send traffic through the gateway.
      assert.deepEqual(operation.security, [{ ProductAPIToken: [] }], id);
      const parameters = [...(document.paths[path].parameters ?? []), ...(operation.parameters ?? [])];
      assert.ok(parameters.every((parameter) => parameter.in !== "query"), id);
      const upstream = parameters.find((parameter) => parameter.name === "X-Zasp-Upstream-Authorization");
      assert.deepEqual([upstream.in, upstream.required], ["header", false], id);
      assert.match(upstream.description, /never stored or logged/);
      assert.ok(parameters.some((parameter) => parameter.name === "X-Zasp-Agent-Id" && parameter.in === "header"), id);
      for (const status of ["401", "403", "429", "503"]) assert.ok(operation.responses[status], `${id} ${status}`);
    }
    // An answer of the gateway is the upstream's JSON or its event stream.
    for (const [path, method] of traffic.filter((entry) => entry[1] === "post")) assert.deepEqual(Object.keys(document.paths[path][method].responses["200"].content), ["application/json", "text/event-stream"], path);
    // The GET stream of the MCP transport is not offered.
    assert.deepEqual(Object.keys(document.paths["/api/v1/gateway/mcp/{id}"]), ["parameters", "post", "delete"]);
    assert.ok(schemas.Permission.enum.includes("use_gateway"));
  });
  it("is managed with the default security, by version", () => {
    for (const [path, method, id] of management) {
      const operation = document.paths[path][method];
      assert.equal(operation.operationId, id);
      assert.equal(operation.security, undefined, id);
      if (method !== "get") assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref.split("/").at(-1)), ["BrowserMutationCSRFToken", "BrowserMutationOrigin", "IdempotencyKey", "ScheduleVersion"], id);
    }
    assert.deepEqual(Object.keys(document.paths["/api/v1/gateway/mcp-servers/{id}"].put.responses).slice(0, 2), ["200", "201"]);
    assert.ok(document.paths["/api/v1/gateway/mcp-servers/{id}"].delete.responses["204"]);
    assert.deepEqual(document.paths["/api/v1/gateway/activity"].get.parameters.map((parameter) => parameter.name), ["surface", "server_id", "agent_id", "decision", "before", "limit"]);
  });
  it("stores an address and lists for a server, and nothing that is a credential", () => {
    const input = compile("MCPGatewayServerInput");
    const valid = { name: "Tickets", upstream_url: "https://mcp.tickets.test/mcp", enabled: true, allowed_tools: [], denied_tools: ["delete_ticket"] };
    assert.equal(input(valid), true, JSON.stringify(input.errors));
    for (const changed of [{ ...valid, authorization: "Bearer abc" }, { ...valid, upstream_url: "http://mcp.tickets.test/mcp" }, { ...valid, denied_tools: ["delete ticket"] }, { ...valid, denied_tools: ["a", "a"] }, { ...valid, name: "" }, { name: "Tickets" }]) {
      assert.equal(input(changed), false, JSON.stringify(changed));
    }
    assert.deepEqual(Object.keys(schemas.MCPGatewayServer.properties).filter((name) => /secret|token|credential|authorization|password|key/i.test(name)), []);
    assert.deepEqual(schemas.MCPGatewayTool.required, ["name", "risk", "last_seen_at"]);
    assert.equal(schemas.MCPGatewayTool.additionalProperties, false);
    const policy = compile("GatewayPolicyInput");
    assert.equal(policy({ unapproved_servers: "refuse", denied_tool_risks: ["execute", "write"], requests_per_minute: 120 }), true);
    for (const changed of [{ unapproved_servers: "maybe", denied_tool_risks: [], requests_per_minute: 1 }, { unapproved_servers: "allow", denied_tool_risks: ["dangerous"], requests_per_minute: 1 }, { unapproved_servers: "allow", denied_tool_risks: ["read", "read"], requests_per_minute: 1 }, { unapproved_servers: "allow", denied_tool_risks: [], requests_per_minute: 100001 }]) {
      assert.equal(policy(changed), false, JSON.stringify(changed));
    }
  });
  it("records a decision with identifiers, a size and a digest, and no member for text", () => {
    const decision = compile("GatewayDecision");
    const record = {
      id: "pid_62000001-0000-4000-8000-000000000001", created_at: "2026-11-14T10:05:00Z", surface: "mcp", operation: "tools/call", direction: "response", decision: "block", reason: "guardrail",
      rules: [{ id: "injection.instruction_override", category: "prompt_injection", mode: "block", count: 1 }], bytes: 412, content_digest: `sha256:${"ab".repeat(32)}`, server_id: server, server_name: "Tickets",
      tool_name: "read_page", provider: null, model: null, agent_id: "support-agent", principal_id: agent,
    };
    assert.equal(decision(record), true, JSON.stringify(decision.errors));
    for (const member of ["text", "arguments", "result", "prompt", "content", "messages"]) assert.equal(decision({ ...record, [member]: "the customer's question" }), false, member);
    assert.equal(decision({ ...record, content_digest: "sha256:zz" }), false);
    assert.equal(decision({ ...record, reason: "because" }), false);
    assert.deepEqual(schemas.GatewayDecision.properties.reason.enum, ["none", "guardrail", "server_blocked", "server_unapproved", "server_disabled", "tool_denied", "tool_not_allowed", "tool_risk_denied", "tools_hidden", "stream_window_exceeded"]);
    assert.equal(schemas.GatewayDecision.additionalProperties, false);
  });
});

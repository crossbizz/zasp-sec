import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";

const repositoryRoot = resolve(import.meta.dirname, "..");
const documentPath = resolve(import.meta.dirname, "internal-health.yaml");
const serviceDocumentPath = resolve(repositoryRoot, "docs/internal/service-health-endpoints.md");
const packagePath = resolve(repositoryRoot, "package.json");

const paths = ["/healthz", "/metrics", "/readyz", "/version"];
const services = ["agentsec-api", "agentsec-worker", "event-ingest", "runtime-gateway"];
const metricsPattern = String.raw`^# HELP agentsec_up Process liveness\.\n# TYPE agentsec_up gauge\nagentsec_up\{service="(agentsec-api|agentsec-worker|event-ingest|runtime-gateway)"\} 1\n# HELP agentsec_ready Service readiness\.\n# TYPE agentsec_ready gauge\nagentsec_ready\{service="\1"\} [01]\n# HELP agentsec_build_info Build information\.\n# TYPE agentsec_build_info gauge\nagentsec_build_info\{service="\1",version="[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}"\} 1\n(?![\s\S])`;
const operationContract = {
  "/healthz": {
    get: ["getServiceLiveness", "Get process liveness.", { "200": "LivenessResponse", "404": "NotFoundResponse" }],
    head: ["headServiceLiveness", "Get process liveness headers.", { "200": "LivenessResponse", "404": "NotFoundResponse" }],
  },
  "/readyz": {
    get: ["getServiceReadiness", "Get process readiness.", { "200": "ReadyResponse", "404": "NotFoundResponse", "503": "NotReadyResponse" }],
    head: ["headServiceReadiness", "Get process readiness headers.", { "200": "ReadyResponse", "404": "NotFoundResponse", "503": "NotReadyResponse" }],
  },
  "/version": {
    get: ["getServiceVersion", "Get process build identity.", { "200": "VersionResponse", "404": "NotFoundResponse" }],
    head: ["headServiceVersion", "Get process build identity headers.", { "200": "VersionResponse", "404": "NotFoundResponse" }],
  },
  "/metrics": {
    get: ["getServiceMetrics", "Get bounded process health metrics.", { "200": "MetricsResponse", "404": "NotFoundResponse" }],
    head: ["headServiceMetrics", "Get bounded process health metric headers.", { "200": "MetricsResponse", "404": "NotFoundResponse" }],
  },
};

let documentText;
let document;
let serviceDocument;
let packageJSON;

function parseStrict(text) {
  return load(text, { schema: JSON_SCHEMA, json: false });
}

function assertRecord(value, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true, `${label} must be an object`);
}

function assertKeys(value, expected, label) {
  assertRecord(value, label);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} keys`);
}

function clone(value) {
  return structuredClone(value);
}

function assertLocalReference(value, label) {
  assert.deepEqual(value, { $ref: `#/components/${label}` });
}

function verifyResponseHeaders(headers) {
  assertKeys(headers, ["Cache-Control", "Content-Length", "X-Content-Type-Options"], "response headers");
  assertLocalReference(headers["Cache-Control"], "headers/CacheControl");
  assertLocalReference(headers["Content-Length"], "headers/ContentLength");
  assertLocalReference(headers["X-Content-Type-Options"], "headers/ContentTypeOptions");
}

function verifyOperation(operation, expected, label) {
  assertKeys(operation, ["operationId", "responses", "security", "summary"], label);
  const [operationId, summary, responses] = expected;
  assert.equal(operation.operationId, operationId);
  assert.equal(operation.summary, summary);
  assert.deepEqual(operation.security, []);
  assertKeys(operation.responses, Object.keys(responses), `${label} responses`);
  for (const [status, response] of Object.entries(responses)) {
    assertLocalReference(operation.responses[status], `responses/${response}`);
  }
}

function verifyDocument(value, rawText) {
  assertKeys(value, ["components", "info", "jsonSchemaDialect", "openapi", "paths", "security"], "root");
  assert.equal(value.openapi, "3.1.0");
  assert.equal(value.jsonSchemaDialect, "https://spec.openapis.org/oas/3.1/dialect/base");
  assert.deepEqual(value.info, {
    title: "Agent Security Internal Health API",
    version: "1.0.0",
    description: "Common process-local health contract for Agent Security Go commands.",
    license: { name: "Proprietary", identifier: "LicenseRef-Proprietary" },
  });
  assert.deepEqual(value.security, []);
  assert.deepEqual(Object.keys(value.paths).sort(), paths);
  for (const path of paths) {
    assertKeys(value.paths[path], ["get", "head"], path);
    verifyOperation(value.paths[path].get, operationContract[path].get, `${path} GET`);
    verifyOperation(value.paths[path].head, operationContract[path].head, `${path} HEAD`);
  }

  assertKeys(value.components, ["headers", "responses", "schemas"], "components");
  assert.deepEqual(value.components.headers, {
    CacheControl: {
      description: "Disable response caching.",
      required: true,
      schema: { type: "string", const: "no-store" },
    },
    ContentLength: {
      description: "Exact decimal byte length of the GET representation.",
      required: true,
      schema: { type: "string", minLength: 1, maxLength: 5, pattern: "^(?:0|[1-9][0-9]{0,4})$" },
    },
    ContentTypeOptions: {
      description: "Disable media-type sniffing.",
      required: true,
      schema: { type: "string", const: "nosniff" },
    },
  });

  assert.deepEqual(value.components.schemas, {
    LiveStatus: {
      type: "object",
      additionalProperties: false,
      required: ["status"],
      properties: { status: { type: "string", const: "live" } },
    },
    ReadyStatus: {
      type: "object",
      additionalProperties: false,
      required: ["status"],
      properties: { status: { type: "string", const: "ready" } },
    },
    NotReadyStatus: {
      type: "object",
      additionalProperties: false,
      required: ["status"],
      properties: { status: { type: "string", const: "not_ready" } },
    },
    VersionStatus: {
      type: "object",
      additionalProperties: false,
      required: ["service", "version"],
      properties: {
        service: { type: "string", enum: services },
        version: { type: "string", minLength: 1, maxLength: 64, pattern: "^[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}$" },
      },
    },
    MetricsText: {
      type: "string",
      minLength: 1,
      maxLength: 1024,
      pattern: metricsPattern,
      description: "Prometheus 0.0.4 text containing only agentsec_up, agentsec_ready, and agentsec_build_info gauges.",
    },
  });
  const metricsRegex = new RegExp(value.components.schemas.MetricsText.pattern);
  for (const service of services) {
    for (const ready of ["0", "1"]) {
      const body = `# HELP agentsec_up Process liveness.\n# TYPE agentsec_up gauge\nagentsec_up{service="${service}"} 1\n# HELP agentsec_ready Service readiness.\n# TYPE agentsec_ready gauge\nagentsec_ready{service="${service}"} ${ready}\n# HELP agentsec_build_info Build information.\n# TYPE agentsec_build_info gauge\nagentsec_build_info{service="${service}",version="1.2.3-rc_1+build"} 1\n`;
      assert.equal(metricsRegex.test(body), true, `${service} ready=${ready} metrics`);
    }
  }
  assert.equal(metricsRegex.test("agentsec_up 1\n"), false);
  assert.equal(metricsRegex.test("# HELP agentsec_up Process liveness.\n# TYPE agentsec_up gauge\nagentsec_up{service=\"agentsec-api\"} 1\n# HELP agentsec_ready Service readiness.\n# TYPE agentsec_ready gauge\nagentsec_ready{service=\"event-ingest\"} 1\n"), false);
  const validMetrics = `# HELP agentsec_up Process liveness.\n# TYPE agentsec_up gauge\nagentsec_up{service="agentsec-api"} 1\n# HELP agentsec_ready Service readiness.\n# TYPE agentsec_ready gauge\nagentsec_ready{service="agentsec-api"} 1\n# HELP agentsec_build_info Build information.\n# TYPE agentsec_build_info gauge\nagentsec_build_info{service="agentsec-api",version="1.0.0"} 1\n`;
  assert.equal(metricsRegex.test(`${validMetrics}\n`), false);

  assertKeys(value.components.responses, ["LivenessResponse", "MetricsResponse", "NotFoundResponse", "NotReadyResponse", "ReadyResponse", "VersionResponse"], "responses");
  for (const [name, mediaType, schema] of [
    ["LivenessResponse", "application/json", "LiveStatus"],
    ["ReadyResponse", "application/json", "ReadyStatus"],
    ["NotReadyResponse", "application/json", "NotReadyStatus"],
    ["VersionResponse", "application/json", "VersionStatus"],
    ["MetricsResponse", "text/plain; version=0.0.4; charset=utf-8", "MetricsText"],
  ]) {
    const response = value.components.responses[name];
    assertKeys(response, ["content", "description", "headers"], `${name} response`);
    assert.equal(typeof response.description, "string");
    assert.equal(response.description.length > 0, true);
    verifyResponseHeaders(response.headers);
    assertKeys(response.content, [mediaType], `${name} content`);
    assertLocalReference(response.content[mediaType].schema, `schemas/${schema}`);
  }
  const notFound = value.components.responses.NotFoundResponse;
  assertKeys(notFound, ["description", "headers"], "NotFoundResponse response");
  assert.equal(notFound.description, "A query-bearing or otherwise noncanonical target is not found.");
  verifyResponseHeaders(notFound.headers);

  assert.equal("servers" in value, false);
  assert.equal("tags" in value, false);
  assert.doesNotMatch(rawText.toLowerCase(), /(?:amazon|aws|azure|customer_|example\.com|google|localstack|openai|organization_|stytch)/);
  assert.doesNotMatch(rawText, /SessionJWT|ProductAPIToken|\/api\/v1|\/internal\/v1/);
}

function markdownRows(markdown) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function verifyServiceDocument(value) {
  const rows = markdownRows(value);
  assert.deepEqual(rows, [
    ["Command", "Module", "Service label", "Listener", "Paths"],
    ["---", "---", "---", "---", "---"],
    ["Platform API", "`services/platform/agentsec-api`", "`agentsec-api`", "internal `:8081`", "`/healthz`, `/readyz`, `/version`, `/metrics`"],
    ["Platform worker", "`services/platform/agentsec-worker`", "`agentsec-worker`", "internal `:8081`", "`/healthz`, `/readyz`, `/version`, `/metrics`"],
    ["Event ingest", "`services/event-ingest`", "`event-ingest`", "internal `:8081`", "`/healthz`, `/readyz`, `/version`, `/metrics`"],
    ["Runtime gateway", "`services/runtime-gateway`", "`runtime-gateway`", "internal `:8081`", "`/healthz`, `/readyz`, `/version`, `/metrics`"],
  ]);
  const prose = value.replace(/\s+/g, " ");
  for (const statement of [
    "GET returns the exact representation; HEAD returns the same status and representation length with no body.",
    "Liveness remains 200 independently of readiness.",
    "Readiness is 503 outside the serving lifetime and 200 only while serving.",
    "Shutdown withdraws readiness before the independently bounded five-second cleanup.",
    "Unknown paths and any query string are 404 with an empty body.",
    "Methods other than GET and HEAD are 405 with `Allow: GET, HEAD` and an empty body.",
    "No endpoint is part of the public product API or the `/internal/v1` data plane.",
    "M1-29 remains Pending.",
  ]) {
    assert.match(prose, new RegExp(statement.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
}

before(async () => {
  const [rootText, serviceText, packageText] = await Promise.all([
    readFile(documentPath, "utf8"),
    readFile(serviceDocumentPath, "utf8"),
    readFile(packagePath, "utf8"),
  ]);
  documentText = rootText;
  document = parseStrict(rootText);
  serviceDocument = serviceText;
  packageJSON = JSON.parse(packageText);
});

describe("M1-28 internal service health contract", () => {
  it("defines the exact self-contained internal OpenAPI contract", () => {
    verifyDocument(document, documentText);
  });

  it("registers exactly four commands with one shared lifecycle", () => {
    verifyServiceDocument(serviceDocument);
  });

  it("wires the exact root contract, lint, and verification commands", () => {
    assert.equal(
      packageJSON.scripts["health:contract:test"],
      "node --test openapi/internal-health.test.mjs && go test -C services/health -race -count=1 ./... && go test -C services/platform -race -count=1 ./healthserver ./agentsec-api ./agentsec-worker && go test -C services/event-ingest -race -count=1 ./... && go test -C services/runtime-gateway -race -count=1 ./...",
    );
    assert.equal(
      packageJSON.scripts["openapi:test"],
      "node --test openapi/openapi.test.mjs openapi/internal-health.test.mjs openapi/generated-client.test.mjs",
    );
    assert.equal(
      packageJSON.scripts["openapi:lint"],
      "REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true redocly lint openapi/openapi.yaml openapi/internal-health.yaml --config redocly.yaml",
    );
    assert.match(packageJSON.scripts.verify, /^npm run dependencies:check && npm run health:contract:test && npm run openapi:test/);
  });

  it("rejects duplicate YAML keys before semantic validation", () => {
    assert.throws(() => parseStrict(`${documentText}\npaths: {}\n`), /duplicated mapping key/i);
  });

  it("rejects hostile path, method, auth, response, and schema mutations", () => {
    const mutations = [
      ["extra path", (value) => { value.paths["/health"] = value.paths["/healthz"]; }],
      ["missing HEAD", (value) => { delete value.paths["/healthz"].head; }],
      ["query parameter", (value) => { value.paths["/healthz"].get.parameters = [{ name: "probe", in: "query" }]; }],
      ["product auth", (value) => { value.security = [{ SessionJWT: [] }]; }],
      ["remote response", (value) => { value.paths["/healthz"].get.responses["200"].$ref = "https://example.com/health.yaml"; }],
      ["collapsed readiness", (value) => { delete value.paths["/readyz"].get.responses["503"]; }],
      ["service catalog drift", (value) => { value.components.schemas.VersionStatus.properties.service.enum.push("other"); }],
      ["missing header", (value) => { delete value.components.responses.LivenessResponse.headers["Cache-Control"]; }],
      ["open status schema", (value) => { value.components.schemas.LiveStatus.additionalProperties = true; }],
      ["unconstrained metrics", (value) => { delete value.components.schemas.MetricsText.pattern; }],
      ["extra operation response", (value) => { value.paths["/healthz"].get.responses["500"] = { $ref: "#/components/responses/NotReadyResponse" }; }],
    ];
    for (const [name, mutate] of mutations) {
      const candidate = clone(document);
      mutate(candidate);
      assert.throws(() => verifyDocument(candidate, JSON.stringify(candidate)), undefined, name);
    }
  });

  it("rejects omitted, duplicated, or lifecycle-drifted service documentation", () => {
    const mutations = [
      serviceDocument.replace(/^\| Runtime gateway.*\n/m, ""),
      `${serviceDocument}\n| Runtime gateway | \`services/runtime-gateway\` | \`runtime-gateway\` | internal \`:8081\` | \`/healthz\`, \`/readyz\`, \`/version\`, \`/metrics\` |\n`,
      serviceDocument.replace("Readiness is 503 outside the serving lifetime", "Readiness is always 200"),
    ];
    for (const candidate of mutations) {
      assert.throws(() => verifyServiceDocument(candidate));
    }
  });
});

import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";

const repositoryRoot = resolve(import.meta.dirname, "..");
const documentPath = resolve(import.meta.dirname, "openapi.yaml");
const configPath = resolve(repositoryRoot, "redocly.yaml");
const packagePath = resolve(repositoryRoot, "package.json");

const productIDPattern = "^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const productCodePattern = "^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$";
const cursorPattern = "^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$";
const messagePattern = "^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F-\\x9F]+$";

let documentText;
let document;
let config;
let packageJSON;

function parseStrict(text) {
  return load(text, { schema: JSON_SCHEMA, json: false });
}

function assertKeys(value, expected, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true, `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} keys`);
}

function clone(value) {
  return structuredClone(value);
}

function walk(value, visit, path = "$") {
  visit(value, path);
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walk(entry, visit, `${path}[${index}]`));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      walk(entry, visit, `${path}.${key}`);
    }
  }
}

function verifyDocument(value, rawText) {
  assertKeys(value, ["openapi", "jsonSchemaDialect", "info", "paths", "security", "components"], "root");
  assert.equal(value.openapi, "3.1.0");
  assert.equal(value.jsonSchemaDialect, "https://spec.openapis.org/oas/3.1/dialect/base");
  assert.deepEqual(value.info, {
    title: "Agent Security Platform API",
    version: "1.0.0",
    description: "Stable product API contract.",
    license: { name: "Proprietary", identifier: "LicenseRef-Proprietary" },
  });
  assert.equal(value.paths !== null && typeof value.paths === "object" && !Array.isArray(value.paths), true);
  assert.equal(Object.keys(value.paths).length > 0, true);
  for (const path of Object.keys(value.paths)) {
    assert.match(path, /^\/api\/v1\/[a-z](?:[a-z0-9_/-]|\{[A-Za-z][A-Za-z0-9]*\})*$/);
  }
  assert.deepEqual(value.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);

  assertKeys(value.components, ["securitySchemes", "headers", "parameters", "schemas", "responses"], "components");
  assert.deepEqual(value.components.securitySchemes, {
    BrowserSession: {
      type: "apiKey",
      in: "cookie",
      name: "__Host-zasp_session",
      description: "Secure, HttpOnly, SameSite=Lax host-only human browser session.",
    },
	BrowserExpectedScope: {
	  type: "apiKey",
	  in: "header",
	  name: "X-Zasp-Expected-Scope",
	  description: "Exact canonical organization/workspace/environment scope captured by the browser before a scoped request. The server compares it with the authenticated session scope before data access; ProductAPIToken scope remains token-owned.",
	},
    ProductAPIToken: {
      type: "http",
      scheme: "bearer",
      bearerFormat: "ProductAPIToken",
      description: "Product automation token.",
    },
  });

  assert.deepEqual(value.components.headers, {
    WorkflowETag: {
      description: "Quoted durable resource version for optimistic concurrency.",
      schema: { type: "string", pattern: '^"[1-9][0-9]*"$' },
    },
    WorkflowAuditID: {
      description: "Durable audit record identifier for this mutation or its exact replay.",
      schema: { $ref: "#/components/schemas/ProductID" },
    },
    WorkflowMutationReceiptID: {
      description: "BrowserSession-only durable recovery receipt bound to the exact authenticated principal, scope, operation, intent, and attempt key. This header is absent for ProductAPIToken mutations and replays.",
      schema: { $ref: "#/components/schemas/ProductID" },
    },
    RetryAfter: {
      description: "Minimum whole seconds before retrying an accepted asynchronous mutation.",
      schema: { type: "string", pattern: "^[1-9][0-9]{0,2}$" },
    },
  });

  assert.deepEqual(value.components.parameters, {
		CSRFToken: {
			name: "X-CSRF-Token",
			in: "header",
			required: true,
			description: "Short-lived CSRF value bound to the authenticated browser session. Mutations also require an exact same-origin Origin header.",
			schema: { type: "string", minLength: 32, maxLength: 256 },
		},
    FreshAuth: {
      name: "X-Zasp-Fresh-Auth",
      in: "header",
      required: true,
      description: "Explicit fresh-auth confirmation required for an approval decision.",
      schema: { type: "string", const: "confirmed" },
    },
    IdempotencyKey: {
      name: "Idempotency-Key",
      in: "header",
      required: true,
      description: "Caller-generated key binding an exact workflow mutation and its durable response.",
      schema: { type: "string", minLength: 16, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]*$" },
    },
    PageCursor: {
      name: "cursor",
      in: "query",
      required: false,
      description: "Opaque cursor returned by the preceding page.",
      schema: { $ref: "#/components/schemas/Cursor" },
    },
    PageLimit: {
      name: "limit",
      in: "query",
      required: false,
      description: "Maximum number of records to return.",
      schema: { type: "integer", minimum: 1, maximum: 100, default: 50 },
    },
    ResourceVersion: {
      name: "If-Match",
      in: "header",
      required: true,
      description: "Quoted current durable resource version.",
      schema: { type: "string", pattern: '^"[1-9][0-9]*"$' },
    },
  });

  const foundationSchemas = {
    Cursor: {
      type: "string",
      minLength: 2,
      maxLength: 512,
      pattern: cursorPattern,
      description: "Opaque canonical base64url cursor without padding.",
    },
    PageInfo: {
      oneOf: [
        {
          type: "object",
          additionalProperties: false,
          required: ["next_cursor", "has_more"],
          properties: {
            next_cursor: { $ref: "#/components/schemas/Cursor" },
            has_more: { const: true },
          },
        },
        {
          type: "object",
          additionalProperties: false,
          required: ["next_cursor", "has_more"],
          properties: {
            next_cursor: { type: "null" },
            has_more: { const: false },
          },
        },
      ],
    },
    ProductID: {
      type: "string",
      minLength: 40,
      maxLength: 40,
      pattern: productIDPattern,
      description: "Canonical product identifier.",
    },
    ProductError: {
      type: "object",
      additionalProperties: false,
      required: ["code", "message", "correlation_id", "retryable"],
      properties: {
        code: { type: "string", minLength: 1, maxLength: 64, pattern: productCodePattern },
        message: { type: "string", minLength: 1, maxLength: 512, pattern: messagePattern },
        correlation_id: { $ref: "#/components/schemas/ProductID" },
        retryable: { type: "boolean" },
      },
    },
  };
  for (const [name, schema] of Object.entries(foundationSchemas)) {
    assert.deepEqual(value.components.schemas[name], schema, `foundation schema ${name}`);
  }

  assert.deepEqual(value.components.responses, {
    ProductErrorResponse: {
      description: "Request rejected with a product error.",
      content: {
        "application/json": {
          schema: { $ref: "#/components/schemas/ProductError" },
        },
      },
    },
  });

  const forbiddenKeys = new Set(["callbacks", "example", "examples", "externalDocs", "servers", "webhooks"]);
  walk(value, (entry, path) => {
    if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
      for (const key of Object.keys(entry)) {
        assert.equal(forbiddenKeys.has(key), false, `forbidden key ${path}.${key}`);
      }
    }
    if (typeof entry === "string" && path.endsWith(".$ref")) {
      assert.match(entry, /^#\/components\/(?:headers|parameters|responses|schemas|securitySchemes)\/[A-Za-z][A-Za-z0-9]*$/);
    }
  });
  assert.doesNotMatch(rawText.toLowerCase(), /(?:amazon|aws|azure|customer_|example\.com|localstack|openai|stytch)/);
}

before(async () => {
  const [rootText, configText, packageText] = await Promise.all([
    readFile(documentPath, "utf8"),
    readFile(configPath, "utf8"),
    readFile(packagePath, "utf8"),
  ]);
  documentText = rootText;
  document = parseStrict(rootText);
  config = parseStrict(configText);
  packageJSON = JSON.parse(packageText);
});

describe("M1-23 strict OpenAPI root", () => {
  it("defines the exact self-contained OpenAPI, auth, pagination, and error boundary", () => {
    verifyDocument(document, documentText);
  });

  it("uses only the exact pinned local linter command and justified rule exception", () => {
    assert.deepEqual(config, {
      extends: ["recommended"],
      rules: {
        "no-empty-servers": "off",
        "no-unused-components": "off",
      },
    });
    assert.equal(
      packageJSON.scripts["openapi:lint"],
      "REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true redocly lint openapi/openapi.yaml openapi/internal-health.yaml --config redocly.yaml",
    );
    assert.equal(
      packageJSON.scripts["openapi:test"],
      "node --test openapi/openapi.test.mjs openapi/internal-health.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs",
    );
    assert.equal(
      packageJSON.scripts.verify,
      "npm run dependencies:check && npm run health:contract:test && npm run openapi:test && npm run openapi:lint && npm run openapi:check && npm run ui-api:test && npm run ui-api:check && npm run raw-fetch:test && npm run saas:tenancy:test && npm run db:tenant-rls:test && npm test && npm run typecheck && npm run lint && npm run production:imports:test && npm run production:imports:source && npm run production:release:test && npm run build && npm run production:imports:compiled && npm run implementation:status:check",
    );
    assert.equal(packageJSON.devDependencies["@redocly/cli"], "2.43.1");
    assert.equal(packageJSON.devDependencies["js-yaml"], "4.1.1");
  });

  it("rejects duplicate YAML keys before semantic validation", () => {
    assert.throws(() => parseStrict(`${documentText}\npaths: {}\n`), /duplicated mapping key/i);
  });

  it("accepts only canonical unpadded base64url cursor encodings", () => {
    const pattern = new RegExp(document.components.schemas.Cursor.pattern, "u");
    for (const bytes of [Buffer.from([0]), Buffer.from([255]), Buffer.from([0, 0]), Buffer.from([255, 255]), Buffer.from("opaque cursor")]) {
      assert.equal(pattern.test(bytes.toString("base64url")), true);
    }
    for (const alias of ["AB", "AAB", "__", "___", "A", "AAAAA", "AA==", "AA+"]) {
      assert.equal(pattern.test(alias), false, `accepted noncanonical cursor ${alias}`);
    }
  });

  it("rejects every product-error control-character class", () => {
    const pattern = new RegExp(document.components.schemas.ProductError.properties.message.pattern, "u");
    for (const valid of ["Product failure.", "Échec du produit.", "安全な製品エラー。"]) {
      assert.equal(pattern.test(valid), true);
    }
    for (const invalid of ["\u0000", "\u001f", "\u007f", "\u0085", "\u009f", " leading", "trailing "]) {
      assert.equal(pattern.test(invalid), false, `accepted invalid message ${JSON.stringify(invalid)}`);
    }
  });

  it("rejects hostile root, authentication, pagination, and error mutations", () => {
    const mutations = [
      ["unknown root", (value) => { value.unknown = true; }],
      ["wrong OpenAPI", (value) => { value.openapi = "3.0.3"; }],
      ["wrong dialect", (value) => { value.jsonSchemaDialect = "https://json-schema.org/draft/2020-12/schema"; }],
      ["wrong info", (value) => { value.info.version = "v1"; }],
      ["external operation", (value) => { value.paths["/external/example"] = { get: {} }; }],
      ["anonymous auth", (value) => { value.security.push({}); }],
	  ["scope precondition omitted", (value) => { value.security = [{ BrowserSession: [] }, { ProductAPIToken: [] }]; }],
	  ["scope precondition as alternative", (value) => { value.security = [{ BrowserSession: [] }, { BrowserExpectedScope: [] }, { ProductAPIToken: [] }]; }],
	  ["AND auth", (value) => { value.security = [{ BrowserSession: [], BrowserExpectedScope: [], ProductAPIToken: [] }]; }],
      ["query token", (value) => { value.components.securitySchemes.ProductAPIToken = { type: "apiKey", in: "query", name: "token" }; }],
      ["bearer browser token", (value) => { value.components.securitySchemes.BrowserSession = { type: "http", scheme: "bearer" }; }],
      ["unbounded page", (value) => { value.components.parameters.PageLimit.schema.maximum = 1000; }],
      ["nonoptional cursor", (value) => { value.components.parameters.PageCursor.required = true; }],
      ["contradictory page info", (value) => { value.components.schemas.PageInfo.oneOf[0].properties.has_more.const = false; }],
      ["padded cursor", (value) => { value.components.schemas.Cursor.pattern = "^[A-Za-z0-9_=-]+$"; }],
      ["product ID drift", (value) => { value.components.schemas.ProductID.pattern = "^id_.+$"; }],
      ["error field", (value) => { value.components.schemas.ProductError.properties.debug = { type: "string" }; }],
      ["optional error field", (value) => { value.components.schemas.ProductError.required.pop(); }],
      ["remote ref", (value) => { value.components.responses.ProductErrorResponse.content["application/json"].schema.$ref = "https://example.com/error.yaml"; }],
      ["example", (value) => { value.components.schemas.ProductError.example = { code: "bad" }; }],
    ];

    for (const [name, mutate] of mutations) {
      const candidate = clone(document);
      mutate(candidate);
      assert.throws(() => verifyDocument(candidate, JSON.stringify(candidate)), undefined, name);
    }
  });
});

describe("production workflow concurrency contract", () => {
  it("publishes the three retained DELETE operations with no request body", () => {
    for (const path of ["/api/v1/policies/{id}", "/api/v1/integrations/{id}", "/api/v1/security-agents/{id}"]) {
      const operation = document.paths[path].delete;
      assert.equal(Object.hasOwn(operation, "requestBody"), false, path);
      assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
        "#/components/parameters/IdempotencyKey",
        "#/components/parameters/ResourceVersion",
      ], path);
    }
  });

  it("reports asynchronous integration revocation without claiming early deletion", () => {
    const responses = document.paths["/api/v1/integrations/{id}"].delete.responses;
    assert.deepEqual(Object.keys(responses).slice(0, 2), ["202", "204"]);
    assert.equal(responses["202"].content["application/json"].schema.$ref, "#/components/schemas/Integration");
    assert.equal(responses["202"].headers["Retry-After"].$ref, "#/components/headers/RetryAfter");
    assert.deepEqual(document.components.schemas.IntegrationStatus.enum, ["configured", "pending_authorization", "active", "degraded", "revoking"]);
  });

  it("separates server-assigned security-agent identity from create input", () => {
    assert.equal(document.paths["/api/v1/security-agents"].post.requestBody.content["application/json"].schema.$ref, "#/components/schemas/SecurityAgentInput");
    assert.equal(document.components.schemas.SecurityAgentInput.properties.id, undefined);
    assert.equal(document.components.schemas.SecurityAgentInput.required.includes("id"), false);
    assert.equal(document.components.schemas.SecurityAgentDefinition.required.includes("id"), true);
  });

  it("types idempotency, versions, fresh auth, and durable mutation receipts", () => {
    const creates = new Set(["createIntegration", "createSensorEnrollment", "createPolicy", "createSecurityAgent", "runSecurityAgent"]);
    const durableReceiptMutations = new Set([
      "createIntegration", "updateIntegration", "deleteIntegration",
	  "remediateIntegrationAuthorization", "authorizeIntegrationReference",
      "createPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy",
      "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
      "updateFinding", "acceptFindingRisk",
    ]);
    const operations = [
      "createIntegration", "updateIntegration", "deleteIntegration",
	  "remediateIntegrationAuthorization", "authorizeIntegrationReference",
      "createPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy",
      "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
      "updateFinding", "acceptFindingRisk",
    ];
    const located = new Map();
    for (const path of Object.values(document.paths)) {
      for (const operation of Object.values(path)) {
        if (operation?.operationId) located.set(operation.operationId, operation);
      }
    }
    for (const operationId of operations) {
      const operation = located.get(operationId);
      assert.ok(operation, operationId);
      const refs = (operation.parameters ?? []).map((parameter) => parameter.$ref);
      assert.ok(refs.includes("#/components/parameters/IdempotencyKey"), `${operationId} idempotency`);
      if (!creates.has(operationId)) assert.ok(refs.includes("#/components/parameters/ResourceVersion"), `${operationId} version`);
      if (operationId === "decideSecurityAgentApproval" || operationId === "authorizeIntegrationReference") assert.ok(refs.includes("#/components/parameters/FreshAuth"), `${operationId} fresh auth`);
      const success = Object.entries(operation.responses).find(([status]) => status.startsWith("2"))?.[1];
      const expectedHeaders = durableReceiptMutations.has(operationId)
        ? ["ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"]
        : ["ETag", "X-Audit-ID"];
	  if (operationId === "deleteIntegration") expectedHeaders.push("Retry-After");
	  if (operationId === "authorizeIntegrationReference") expectedHeaders.push("Cache-Control");
	  expectedHeaders.sort();
      assert.deepEqual(Object.keys(success.headers ?? {}).sort(), expectedHeaders);
    }
  });

  it("publishes bounded browser-only receipt reconciliation and acknowledgement", () => {
    const list = document.paths["/api/v1/workflow-mutation-receipts"].get;
    assert.equal(list.operationId, "listWorkflowMutationReceipts");
	assert.deepEqual(list.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
    assert.deepEqual(list.parameters, [{
      name: "limit",
      in: "query",
      required: false,
      schema: { type: "integer", minimum: 1, maximum: 50, default: 20 },
    }]);
    assert.equal(list.responses["200"].content["application/json"].schema.$ref, "#/components/schemas/WorkflowMutationReceiptPage");

    const acknowledge = document.paths["/api/v1/workflow-mutation-receipts/{id}/acknowledge"].post;
    assert.equal(acknowledge.operationId, "acknowledgeWorkflowMutationReceipt");
	assert.deepEqual(acknowledge.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
    assert.deepEqual(document.paths["/api/v1/workflow-mutation-receipts/{id}/acknowledge"].parameters, [{
      name: "id",
      in: "path",
      required: true,
      schema: { $ref: "#/components/schemas/ProductID" },
    }]);
    assert.deepEqual(acknowledge.parameters, [{ $ref: "#/components/parameters/CSRFToken" }]);
    assert.equal(acknowledge.requestBody.content["application/json"].schema.$ref, "#/components/schemas/EmptyInput");
    assert.deepEqual(Object.keys(acknowledge.responses), ["204", "400", "401", "403", "404", "default"]);

    const receipt = document.components.schemas.WorkflowMutationReceipt;
    assert.equal(receipt.additionalProperties, false);
    assert.deepEqual(receipt.required, ["id", "operation", "idempotency_key", "intent", "result", "resource_kind", "resource_id", "resource_version", "audit_id", "correlation_id", "created_at", "expires_at"]);
    assert.equal(document.components.schemas.WorkflowMutationReceiptPage.properties.items.maxItems, 50);
  });

	it("requires the browser scope precondition on every scoped session operation", () => {
		for (const path of ["/api/v1/session/scopes", "/api/v1/session/scope"]) {
			const operation = document.paths[path].get ?? document.paths[path].put;
			assert.deepEqual(operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }], path);
		}
		for (const path of ["/api/v1/session/bootstrap", "/api/v1/session/sign-out"]) {
			const operation = document.paths[path].get ?? document.paths[path].post;
			assert.deepEqual(operation.security, [{ BrowserSession: [] }], path);
		}
	});

  it("publishes exact receipt intent and authoritative result object shapes", () => {
    const receipt = document.components.schemas.WorkflowMutationReceipt;
    assert.equal(receipt.properties.intent.$ref, "#/components/schemas/WorkflowMutationIntent");
    assert.deepEqual(receipt.properties.result.oneOf, [
      { $ref: "#/components/schemas/Policy" },
      { $ref: "#/components/schemas/Integration" },
      { $ref: "#/components/schemas/SecurityAgentDefinition" },
      { $ref: "#/components/schemas/Finding" },
    ]);
    const intent = document.components.schemas.WorkflowMutationIntent;
    assert.equal(intent.additionalProperties, false);
    assert.deepEqual(intent.required, ["resource_id", "expected_version", "body"]);
    assert.deepEqual(intent.properties.body.oneOf, [
      { $ref: "#/components/schemas/Policy" },
      { $ref: "#/components/schemas/PolicyRolloutInput" },
      { $ref: "#/components/schemas/EmptyInput" },
      { $ref: "#/components/schemas/IntegrationInput" },
      { $ref: "#/components/schemas/IntegrationUpdateInput" },
      { $ref: "#/components/schemas/IntegrationAuthorizationRemediationInput" },
      { $ref: "#/components/schemas/SecurityAgentInput" },
      { $ref: "#/components/schemas/SecurityAgentDefinition" },
      { $ref: "#/components/schemas/FindingUpdateInput" },
      { $ref: "#/components/schemas/FindingAcceptanceInput" },
    ]);
  });

  it("publishes exactly the mounted Batch 4 risk slice and launch authorization operations without other overclaims", () => {
    const operations = new Map();
    for (const [path, pathItem] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(pathItem)) {
        if (operation?.operationId) operations.set(operation.operationId, { path, method, operation });
      }
    }
    assert.equal(operations.size, 84);
    for (const operationId of ["listFindings", "getFinding", "updateFinding", "acceptFindingRisk", "listAttackPaths", "getAttackPath", "getAttackPathBreakOptions", "authorizeIntegration", "authorizeIntegrationReference", "remediateIntegrationAuthorization", "completeIntegrationOAuthCallback"]) {
      assert.ok(operations.has(operationId), operationId);
    }
    for (const operationId of [
      "syncIntegration", "listIntegrationSyncs", "getIntegrationSync",
      "listSensors", "createSensorEnrollment", "getSensor", "updateSensor", "deleteSensor", "rotateSensorToken", "getSensorCoverage",
      "updateAgent", "createFindingTicket",
      "listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun",
      "listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun", "rerunAttackLabRun",
      "simulatePolicy", "listPolicyDecisions",
      "listSecurityActions", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
      "globalSearch", "createAIExplanation",
    ]) assert.equal(operations.has(operationId), false, operationId);
  });

  it("publishes strict browser-only integration authorization and OAuth callback contracts", () => {
    const authorizePath = document.paths["/api/v1/integrations/{id}/authorize"];
    assert.deepEqual(authorizePath.parameters, [{
      name: "id",
      in: "path",
      required: true,
      schema: { $ref: "#/components/schemas/ProductID" },
    }]);
    const authorize = authorizePath.post;
    assert.equal(authorize.operationId, "authorizeIntegration");
    assert.deepEqual(authorize.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
    assert.deepEqual(authorize.parameters, [
      { $ref: "#/components/parameters/CSRFToken" },
      { $ref: "#/components/parameters/IdempotencyKey" },
    ]);
    assert.equal(authorize.requestBody.required, true);
    assert.deepEqual(authorize.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/EmptyInput" });
    assert.deepEqual(authorize.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/IntegrationAuthorization" });
    assert.deepEqual(Object.keys(authorize.responses["200"].headers).sort(), ["Cache-Control", "Referrer-Policy"]);
    assert.deepEqual(authorize.responses["200"].headers["Cache-Control"].schema, { type: "string", const: "no-store" });
    assert.deepEqual(authorize.responses["200"].headers["Referrer-Policy"].schema, { type: "string", const: "no-referrer" });

    const result = document.components.schemas.IntegrationAuthorization;
    assert.equal(result.additionalProperties, false);
    assert.deepEqual(result.required, ["authorization_attempt_id", "authorization_url", "expires_at"]);
    assert.deepEqual(Object.keys(result.properties), ["authorization_attempt_id", "authorization_url", "expires_at"]);
    assert.deepEqual(result.properties.authorization_attempt_id, { $ref: "#/components/schemas/ProductID" });
    assert.deepEqual(result.properties.authorization_url, {
      type: "string",
      format: "uri",
      minLength: 10,
      maxLength: 4096,
      pattern: "^https://",
      description: "Provider authorization target containing opaque state but no provider credential or product secret.",
    });
    assert.deepEqual(result.properties.expires_at, { type: "string", format: "date-time" });
    for (const forbidden of ["state", "code", "verifier", "token", "secret", "credential", "refresh_token", "access_token"]) {
      assert.equal(Object.hasOwn(result.properties, forbidden), false, forbidden);
    }

    const callback = document.paths["/api/v1/integrations/oauth/callback"].get;
    assert.equal(callback.operationId, "completeIntegrationOAuthCallback");
    assert.deepEqual(callback.security, [{ BrowserSession: [] }]);
    assert.deepEqual(callback.parameters, [
      {
        name: "state",
        in: "query",
        required: true,
        description: "Opaque one-time state bound to the current browser session and authorization attempt.",
        schema: { $ref: "#/components/schemas/IntegrationOAuthCallbackValue" },
      },
      {
        name: "code",
        in: "query",
        required: false,
        description: "Provider authorization code. Required for the success form and mutually exclusive with error.",
        schema: { $ref: "#/components/schemas/IntegrationOAuthCallbackValue" },
      },
      {
        name: "error",
        in: "query",
        required: false,
        description: "Provider denial code. Required for the provider-error form and mutually exclusive with code.",
        schema: { $ref: "#/components/schemas/IntegrationOAuthProviderError" },
      },
    ]);
    assert.match(callback.description, /exactly code and state, or exactly error and state/);
    assert.match(callback.description, /Duplicate or additional parameters, including error_description and error_uri, are rejected/);
    assert.match(callback.description, /303.*same-origin relative path.*Cache-Control: no-store.*Referrer-Policy: no-referrer/s);
    assert.equal(Object.hasOwn(callback, "requestBody"), false);
    assert.deepEqual(Object.keys(callback.responses["303"]).sort(), ["description", "headers"]);
    assert.deepEqual(callback.responses["303"].headers.Location.schema, {
      type: "string",
      minLength: 1,
      maxLength: 2048,
      pattern: "^/(?!/)",
    });
    assert.deepEqual(callback.responses["303"].headers["Cache-Control"].schema, { type: "string", const: "no-store" });
    assert.deepEqual(callback.responses["303"].headers["Referrer-Policy"].schema, { type: "string", const: "no-referrer" });
    assert.deepEqual(document.components.schemas.IntegrationOAuthCallbackValue, {
      type: "string",
      minLength: 8,
      maxLength: 512,
      pattern: "^[A-Za-z0-9._~-]{8,512}$",
    });
    assert.deepEqual(document.components.schemas.IntegrationOAuthProviderError, {
      type: "string",
      enum: ["invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable"],
    });
  });

  it("publishes strict fresh browser-only reference authorization", () => {
    const path = document.paths["/api/v1/integrations/{id}/reference-authorization"];
    assert.deepEqual(path.parameters, [{
      name: "id",
      in: "path",
      required: true,
      schema: { $ref: "#/components/schemas/ProductID" },
    }]);
    const operation = path.post;
    assert.equal(operation.operationId, "authorizeIntegrationReference");
    assert.deepEqual(operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
    assert.deepEqual(operation.parameters, [
      { $ref: "#/components/parameters/CSRFToken" },
      { $ref: "#/components/parameters/FreshAuth" },
      { $ref: "#/components/parameters/IdempotencyKey" },
      { $ref: "#/components/parameters/ResourceVersion" },
    ]);
    assert.equal(operation.requestBody.required, true);
    assert.deepEqual(operation.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/EmptyInput" });
    const success = operation.responses["200"];
    assert.deepEqual(success.content["application/json"].schema, { $ref: "#/components/schemas/Integration" });
    assert.deepEqual(Object.keys(success.headers).sort(), ["Cache-Control", "ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"]);
    assert.deepEqual(success.headers["Cache-Control"].schema, { type: "string", const: "no-store" });
    assert.deepEqual(Object.keys(operation.responses), ["200", "400", "401", "403", "404", "409", "503", "default"]);
    assert.ok(document.components.schemas.WorkflowMutationReceipt.properties.operation.enum.includes("completeIntegrationReferenceAuthorization"));
  });

  it("binds risk reads and mutations to strict pagination, security, and recovery contracts", () => {
    for (const path of ["/api/v1/findings", "/api/v1/attack-paths"]) {
      assert.deepEqual(document.paths[path].get.parameters, [
        { $ref: "#/components/parameters/PageCursor" },
        { $ref: "#/components/parameters/PageLimit" },
      ]);
    }
    for (const name of ["FindingPage", "AttackPathPage"]) {
      const page = document.components.schemas[name];
      assert.deepEqual(page.required, ["items", "page_info"]);
      assert.equal(page.properties.items.maxItems, 100);
      assert.deepEqual(page.properties.page_info, { $ref: "#/components/schemas/PageInfo" });
    }
    assert.equal(document.components.schemas.BreakOptionPage.properties.items.maxItems, 8);

    for (const [path, method] of [["/api/v1/findings/{id}", "patch"], ["/api/v1/findings/{id}/accept-risk", "post"]]) {
      const operation = document.paths[path][method];
      assert.deepEqual(operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);
      assert.match(operation.description, /BrowserSession requests require the shared CSRF header.*ProductAPIToken requests omit/s);
      assert.deepEqual(operation.parameters, [
        { $ref: "#/components/parameters/CSRFToken" },
        { $ref: "#/components/parameters/IdempotencyKey" },
        { $ref: "#/components/parameters/ResourceVersion" },
      ]);
      assert.deepEqual(Object.keys(operation.responses["200"].headers).sort(), ["ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"]);
    }
    assert.deepEqual(document.components.schemas.WorkflowMutationReceipt.properties.operation.enum.slice(-2), ["updateFinding", "acceptFindingRisk"]);
    assert.equal(document.components.schemas.WorkflowMutationReceipt.properties.resource_kind.enum.includes("finding"), true);
    assert.deepEqual(document.components.schemas.WorkflowMutationReceipt.properties.result.oneOf.at(-1), { $ref: "#/components/schemas/Finding" });
    assert.deepEqual(document.components.schemas.WorkflowMutationIntent.properties.body.oneOf.slice(-2), [
      { $ref: "#/components/schemas/FindingUpdateInput" },
      { $ref: "#/components/schemas/FindingAcceptanceInput" },
    ]);
  });

  it("bounds Security Agent definition pagination with the shared opaque cursor contract", () => {
    const operation = document.paths["/api/v1/security-agents"].get;
    assert.deepEqual(operation.parameters, [
      { $ref: "#/components/parameters/PageCursor" },
      { $ref: "#/components/parameters/PageLimit" },
    ]);
    assert.deepEqual(document.components.schemas.SecurityAgentPage.required, ["items", "page_info"]);
    assert.deepEqual(document.components.schemas.SecurityAgentPage.properties.page_info, { $ref: "#/components/schemas/PageInfo" });
    assert.equal(document.components.schemas.SecurityAgentPage.properties.next_cursor, undefined);
  });

  it("bounds policy and integration pagination with the same exact cursor contract", () => {
    for (const [path, schemaName] of [["/api/v1/policies", "PolicyPage"], ["/api/v1/integrations", "IntegrationPage"]]) {
      assert.deepEqual(document.paths[path].get.parameters, [
        { $ref: "#/components/parameters/PageCursor" },
        { $ref: "#/components/parameters/PageLimit" },
      ]);
      const schema = document.components.schemas[schemaName];
      assert.deepEqual(schema.required, ["items", "page_info"]);
      assert.equal(schema.properties.items.maxItems, 100);
      assert.deepEqual(schema.properties.page_info, { $ref: "#/components/schemas/PageInfo" });
    }
  });
});

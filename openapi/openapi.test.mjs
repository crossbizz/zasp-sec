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
      "npm run dependencies:check && npm run health:contract:test && npm run openapi:test && npm run openapi:lint && npm run openapi:check && npm run ui-api:test && npm run ui-api:check && npm run raw-fetch:test && npm run saas:tenancy:test && npm run db:tenant-rls:test && npm test && npm run typecheck && npm run lint && npm run build",
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
      "createPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy",
      "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
    ]);
    const operations = [
      "createIntegration", "updateIntegration", "deleteIntegration",
      "createSensorEnrollment", "updateSensor", "deleteSensor", "rotateSensorToken",
      "createPolicy", "updatePolicy", "deletePolicy", "simulatePolicy", "rolloutPolicy", "disablePolicy",
      "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "cancelSecurityAgentRun", "decideSecurityAgentApproval",
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
      if (operationId === "decideSecurityAgentApproval") assert.ok(refs.includes("#/components/parameters/FreshAuth"), `${operationId} fresh auth`);
      const success = Object.entries(operation.responses).find(([status]) => status.startsWith("2"))?.[1];
      const expectedHeaders = durableReceiptMutations.has(operationId)
        ? ["ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"]
        : ["ETag", "X-Audit-ID"];
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
      { $ref: "#/components/schemas/SecurityAgentInput" },
      { $ref: "#/components/schemas/SecurityAgentDefinition" },
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

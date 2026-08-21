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
    BrowserMutationCSRFToken: {
      name: "X-CSRF-Token",
      in: "header",
      required: false,
      description: "Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.",
      schema: { type: "string", minLength: 32, maxLength: 256 },
    },
    BrowserMutationOrigin: {
      name: "Origin",
      in: "header",
      required: false,
      description: "Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The server requires the exact configured same-origin HTTPS origin.",
      schema: { type: "string", minLength: 9, maxLength: 2048, pattern: "^https://[^/?#]+$" },
    },
    FreshAuth: {
      name: "X-Zasp-Fresh-Auth",
      in: "header",
      required: true,
      description: "Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.",
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
    ScheduleVersion: {
      name: "If-Match",
      in: "header",
      required: true,
      description: "Quoted current schedule version, or quoted zero when creating the singleton schedule.",
      schema: { type: "string", pattern: '^"(?:0|[1-9][0-9]*)"$' },
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
  assert.doesNotMatch(rawText.toLowerCase(), /(?:amazon|azure|customer_|example\.com|localstack|openai|stytch)/);
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
  it("publishes the exact replay-safe sensor management surface", () => {
    const collection = document.paths["/api/v1/sensors"];
    const detail = document.paths["/api/v1/sensors/{id}"];
    const rotation = document.paths["/api/v1/sensors/{id}/rotate-token"].post;
    const coverage = document.paths["/api/v1/sensors/{id}/coverage"].get;
    assert.equal(collection.get.operationId, "listSensors");
    assert.equal(collection.post.operationId, "createSensorEnrollment");
    assert.equal(detail.get.operationId, "getSensor");
    assert.equal(detail.patch.operationId, "updateSensor");
    assert.equal(detail.delete.operationId, "deleteSensor");
    assert.equal(rotation.operationId, "rotateSensorToken");
    assert.equal(coverage.operationId, "getSensorCoverage");
    assert.equal(collection.get.responses["200"].content["application/json"].schema.$ref, "#/components/schemas/SensorPage");
    assert.equal(collection.post.responses["201"].content["application/json"].schema.$ref, "#/components/schemas/SensorEnrollment");
    assert.equal(rotation.responses["200"].content["application/json"].schema.$ref, "#/components/schemas/SensorEnrollment");
    for (const operation of [collection.post, detail.patch, detail.delete, rotation]) {
      const refs = operation.parameters.map((parameter) => parameter.$ref);
      assert.ok(refs.includes("#/components/parameters/IdempotencyKey"));
      assert.equal(operation.responses["409"].$ref, "#/components/responses/ProductErrorResponse");
    }
    assert.equal(detail.patch.parameters.some((value) => value.$ref === "#/components/parameters/ResourceVersion"), true);
    assert.equal(detail.delete.parameters.some((value) => value.$ref === "#/components/parameters/ResourceVersion"), true);
    assert.equal(rotation.parameters.some((value) => value.$ref === "#/components/parameters/ResourceVersion"), true);
    assert.deepEqual(document.components.schemas.SensorKind.enum, ["tetragon", "otlp"]);
    assert.deepEqual(document.components.schemas.SensorState.enum, ["pending", "active", "degraded", "revoked"]);
    assert.deepEqual(document.components.schemas.Sensor.required, ["id", "name", "kind", "mode", "state", "version", "token_expires_at", "last_heartbeat_at", "created_at", "updated_at"]);
    assert.deepEqual(document.components.schemas.SensorEnrollment.required, [...document.components.schemas.Sensor.required, "token"]);
    assert.equal(document.components.schemas.SensorEnrollment.properties.token.pattern, "^zasp_sensor_v1\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}$");
    assert.deepEqual(document.components.schemas.SensorPage.required, ["items", "page_info"]);
    assert.equal(document.components.schemas.SensorPage.properties.page_info.$ref, "#/components/schemas/PageInfo");
    assert.deepEqual(document.components.schemas.SensorCoverage.properties.status.enum, ["pending", "healthy", "degraded", "offline", "revoked"]);
  });

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
    assert.deepEqual(receipt.oneOf, [
      { $ref: "#/components/schemas/StandardWorkflowMutationReceipt" },
      { $ref: "#/components/schemas/OAuthCompletionWorkflowMutationReceipt" },
      { $ref: "#/components/schemas/ReferenceAuthorizationWorkflowMutationReceipt" },
      { $ref: "#/components/schemas/SyncIntegrationWorkflowMutationReceipt" },
      { $ref: "#/components/schemas/PutIntegrationScheduleWorkflowMutationReceipt" },
      { $ref: "#/components/schemas/DeleteIntegrationScheduleWorkflowMutationReceipt" },
    ]);
    const standard = document.components.schemas.StandardWorkflowMutationReceipt;
    assert.equal(standard.additionalProperties, false);
    assert.deepEqual(standard.required, ["id", "operation", "idempotency_key", "intent", "result", "resource_kind", "resource_id", "resource_version", "audit_id", "correlation_id", "created_at", "expires_at"]);
    const reference = document.components.schemas.ReferenceAuthorizationWorkflowMutationReceipt;
    assert.equal(reference.additionalProperties, false);
    assert.deepEqual(reference.required, standard.required);
    assert.deepEqual(reference.properties.operation, { type: "string", const: "completeIntegrationReferenceAuthorization" });
    assert.deepEqual(reference.properties.intent, { $ref: "#/components/schemas/ReferenceAuthorizationReceiptIntent" });
    assert.deepEqual(reference.properties.result, { $ref: "#/components/schemas/Integration" });
    assert.deepEqual(reference.properties.resource_kind, { type: "string", const: "integration" });
    const oauth = document.components.schemas.OAuthCompletionWorkflowMutationReceipt;
    assert.equal(oauth.additionalProperties, false);
    assert.deepEqual(oauth.required, standard.required);
    assert.deepEqual(oauth.properties.operation, { type: "string", const: "completeIntegrationOAuth" });
    assert.deepEqual(oauth.properties.intent, { $ref: "#/components/schemas/OAuthCompletionReceiptIntent" });
    assert.deepEqual(oauth.properties.result, { $ref: "#/components/schemas/Integration" });
    assert.deepEqual(oauth.properties.resource_kind, { type: "string", const: "integration" });
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
    const receipt = document.components.schemas.StandardWorkflowMutationReceipt;
    assert.equal(receipt.properties.intent.$ref, "#/components/schemas/WorkflowMutationIntent");
    assert.deepEqual(receipt.properties.result.oneOf, [
      { $ref: "#/components/schemas/Policy" },
      { $ref: "#/components/schemas/Integration" },
      { $ref: "#/components/schemas/IntegrationDeletionReceiptResult" },
      { $ref: "#/components/schemas/SecurityAgentDefinition" },
      { $ref: "#/components/schemas/Finding" },
    ]);
    const integrationDeletion = document.components.schemas.IntegrationDeletionReceiptResult;
    assert.equal(integrationDeletion.additionalProperties, false);
    assert.deepEqual(integrationDeletion.required, ["id", "status"]);
    assert.deepEqual(integrationDeletion.properties.id, { $ref: "#/components/schemas/ProductID" });
    assert.deepEqual(integrationDeletion.properties.status, { type: "string", const: "deleted" });
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
    const referenceIntent = document.components.schemas.ReferenceAuthorizationReceiptIntent;
    assert.deepEqual(referenceIntent.oneOf, [
      { $ref: "#/components/schemas/AWSReferenceAuthorizationReceiptIntent" },
      { $ref: "#/components/schemas/KubernetesReferenceAuthorizationReceiptIntent" },
    ]);
    for (const [name, provider, configuration] of [
      ["AWSReferenceAuthorizationReceiptIntent", "aws", "AWSReferenceAuthorizationConfiguration"],
      ["KubernetesReferenceAuthorizationReceiptIntent", "kubernetes", "KubernetesReferenceAuthorizationConfiguration"],
    ]) {
      const providerIntent = document.components.schemas[name];
      assert.equal(providerIntent.additionalProperties, false);
      assert.deepEqual(providerIntent.required, ["configuration", "expected_version", "idempotency_key", "integration_id", "provider", "scope"]);
      assert.deepEqual(providerIntent.properties.provider, { type: "string", const: provider });
      assert.deepEqual(providerIntent.properties.configuration, { $ref: `#/components/schemas/${configuration}` });
      assert.deepEqual(providerIntent.properties.scope, { $ref: "#/components/schemas/ReferenceAuthorizationReceiptScope" });
    }
    assert.equal(document.components.schemas.AWSReferenceAuthorizationConfiguration.properties.role_arn.pattern, "^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$");
    assert.equal(document.components.schemas.AWSReferenceAuthorizationConfiguration.properties.region.pattern, "^[a-z]{2}-[a-z]+-[1-9][0-9]?$");
    const oauthIntent = document.components.schemas.OAuthCompletionReceiptIntent;
    assert.equal(oauthIntent.additionalProperties, false);
    assert.deepEqual(oauthIntent.required, ["authorization_attempt_id", "integration_id", "provider"]);
    assert.deepEqual(oauthIntent.properties.authorization_attempt_id, { $ref: "#/components/schemas/ProductID" });
    assert.deepEqual(oauthIntent.properties.integration_id, { $ref: "#/components/schemas/ProductID" });
    assert.deepEqual(oauthIntent.properties.provider, { type: "string", pattern: "^(github|okta|nango:[a-z0-9][a-z0-9_-]{1,62})$" });
  });

  it("publishes the strict Task 4 sync, schedule, and freshness contract without internal execution authority", () => {
    const sync = document.paths["/api/v1/integrations/{id}/sync"].post;
    assert.equal(sync.operationId, "syncIntegration");
    assert.deepEqual(sync.parameters, [
      { $ref: "#/components/parameters/BrowserMutationCSRFToken" },
      { $ref: "#/components/parameters/BrowserMutationOrigin" },
      { $ref: "#/components/parameters/IdempotencyKey" },
      { $ref: "#/components/parameters/ResourceVersion" },
    ]);
    assert.deepEqual(sync.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/EmptyInput" });
    assert.deepEqual(Object.keys(sync.responses), ["202", "400", "401", "403", "404", "409", "503", "default"]);
    assert.deepEqual(sync.responses["202"].content["application/json"].schema, { $ref: "#/components/schemas/IntegrationSync" });
    assert.deepEqual(Object.keys(sync.responses["202"].headers).sort(), ["Cache-Control", "ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"]);

    const list = document.paths["/api/v1/integrations/{id}/syncs"].get;
    assert.equal(list.operationId, "listIntegrationSyncs");
    assert.deepEqual(list.parameters, [
      { $ref: "#/components/parameters/PageCursor" },
      { $ref: "#/components/parameters/PageLimit" },
    ]);
    assert.deepEqual(list.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/IntegrationSyncPage" });
    assert.deepEqual(Object.keys(list.responses["200"].headers), ["Cache-Control"]);

    const detail = document.paths["/api/v1/integrations/{id}/syncs/{syncId}"].get;
    assert.equal(detail.operationId, "getIntegrationSync");
    assert.deepEqual(detail.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/IntegrationSync" });
    assert.deepEqual(Object.keys(detail.responses["200"].headers).sort(), ["Cache-Control", "ETag"]);

    const schedulePath = document.paths["/api/v1/integrations/{id}/schedule"];
    assert.equal(schedulePath.get.operationId, "getIntegrationSchedule");
    assert.equal(schedulePath.put.operationId, "putIntegrationSchedule");
    assert.equal(schedulePath.delete.operationId, "deleteIntegrationSchedule");
    assert.deepEqual(schedulePath.put.parameters, [
      { $ref: "#/components/parameters/BrowserMutationCSRFToken" },
      { $ref: "#/components/parameters/BrowserMutationOrigin" },
      { $ref: "#/components/parameters/IdempotencyKey" },
      { $ref: "#/components/parameters/ScheduleVersion" },
    ]);
    assert.deepEqual(schedulePath.put.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/IntegrationScheduleInput" });
    assert.deepEqual(schedulePath.put.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/IntegrationSchedule" });
    assert.deepEqual(schedulePath.delete.parameters, [
      { $ref: "#/components/parameters/BrowserMutationCSRFToken" },
      { $ref: "#/components/parameters/BrowserMutationOrigin" },
      { $ref: "#/components/parameters/IdempotencyKey" },
      { $ref: "#/components/parameters/ResourceVersion" },
    ]);

    const freshness = document.paths["/api/v1/integrations/{id}/freshness"].get;
    assert.equal(freshness.operationId, "getIntegrationFreshness");
    assert.deepEqual(freshness.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/IntegrationFreshness" });
    assert.deepEqual(Object.keys(freshness.responses["200"].headers).sort(), ["Cache-Control", "ETag"]);

    const syncSchema = document.components.schemas.IntegrationSync;
    assert.equal(syncSchema.additionalProperties, false);
    assert.deepEqual(syncSchema.required, ["id", "integration_id", "trigger_kind", "status", "attempt", "requested_at", "started_at", "completed_at", "discovered_count", "changed_count", "removed_count", "snapshot_id", "last_error_code", "retry_at"]);
    assert.deepEqual(document.components.schemas.IntegrationSyncStatus.enum, ["queued", "running", "succeeded", "failed", "cancelled"]);
    assert.deepEqual(document.components.schemas.IntegrationSyncTriggerKind.enum, ["manual", "schedule", "retry"]);
    assert.deepEqual(document.components.schemas.CollectionFailureCode.enum, ["retryable", "rate_limited", "denied", "revoked", "malformed", "partial", "terminal", "cancelled", "outcome_unknown"]);
    assert.deepEqual(document.components.schemas.IntegrationSyncPage.required, ["items", "page_info"]);
    assert.equal(document.components.schemas.IntegrationSyncPage.properties.items.maxItems, 100);
    assert.deepEqual(document.components.schemas.IntegrationSyncPage.properties.page_info, { $ref: "#/components/schemas/PageInfo" });

    const schedule = document.components.schemas.IntegrationSchedule;
    assert.equal(schedule.additionalProperties, false);
    assert.deepEqual(schedule.required, ["integration_id", "cadence_seconds", "state", "time_zone", "next_run_at", "version", "created_at", "updated_at"]);
    assert.deepEqual(schedule.properties.time_zone, { type: "string", const: "UTC" });
    assert.deepEqual(document.components.schemas.IntegrationScheduleInput.required, ["cadence_seconds", "state"]);
    assert.deepEqual(document.components.schemas.IntegrationScheduleInput.properties.state.enum, ["enabled", "disabled"]);

    const freshnessSchema = document.components.schemas.IntegrationFreshness;
    assert.equal(freshnessSchema.additionalProperties, false);
    assert.deepEqual(freshnessSchema.required, ["integration_id", "version", "last_good", "latest_sync", "projections", "updated_at"]);
    assert.deepEqual(document.components.schemas.IntegrationProjectionStatus.required, ["state", "snapshot_id", "completed_at", "last_error_code"]);
    assert.deepEqual(document.components.schemas.IntegrationProjectionStatus.properties.state.enum, ["current", "pending", "degraded", "unavailable"]);

    const receipt = document.components.schemas.SyncIntegrationWorkflowMutationReceipt;
    assert.equal(receipt.additionalProperties, false);
    assert.deepEqual(receipt.required, document.components.schemas.StandardWorkflowMutationReceipt.required);
    assert.deepEqual(receipt.properties.operation, { type: "string", const: "syncIntegration" });
    assert.deepEqual(receipt.properties.resource_kind, { type: "string", const: "integration_sync" });
    assert.deepEqual(receipt.properties.result, { $ref: "#/components/schemas/IntegrationSync" });
    assert.deepEqual(receipt.properties.intent, { $ref: "#/components/schemas/SyncIntegrationReceiptIntent" });

    const putScheduleReceipt = document.components.schemas.PutIntegrationScheduleWorkflowMutationReceipt;
    assert.equal(putScheduleReceipt.additionalProperties, false);
    assert.deepEqual(putScheduleReceipt.properties.operation, { type: "string", const: "putIntegrationSchedule" });
    assert.deepEqual(putScheduleReceipt.properties.resource_kind, { type: "string", const: "integration_schedule" });
    assert.deepEqual(putScheduleReceipt.properties.intent, { $ref: "#/components/schemas/PutIntegrationScheduleReceiptIntent" });
    assert.deepEqual(putScheduleReceipt.properties.result, { $ref: "#/components/schemas/IntegrationSchedule" });
    const deleteScheduleReceipt = document.components.schemas.DeleteIntegrationScheduleWorkflowMutationReceipt;
    assert.equal(deleteScheduleReceipt.additionalProperties, false);
    assert.deepEqual(deleteScheduleReceipt.properties.operation, { type: "string", const: "deleteIntegrationSchedule" });
    assert.deepEqual(deleteScheduleReceipt.properties.resource_kind, { type: "string", const: "integration_schedule" });
    assert.deepEqual(deleteScheduleReceipt.properties.intent, { $ref: "#/components/schemas/DeleteIntegrationScheduleReceiptIntent" });
    assert.deepEqual(deleteScheduleReceipt.properties.result, { $ref: "#/components/schemas/IntegrationSchedule" });

    const raw = JSON.stringify({ sync, list, detail, schedulePath, freshness, syncSchema, schedule, freshnessSchema, receipt });
    for (const forbidden of ["job_id", "outbox_id", "manifest_key", "connection_reference", "credential_reference", "provider_cursor", "last_error"]) {
      assert.equal(raw.includes(`"${forbidden}"`), false, forbidden);
    }
  });

  it("publishes the mounted Security Agent activation, simulation, manual run, and approval surface without read overclaims", () => {
    const operations = new Map();
    for (const [path, pathItem] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(pathItem)) {
        if (operation?.operationId) operations.set(operation.operationId, { path, method, operation });
      }
    }
    assert.equal(operations.size, 105);
    for (const operationId of ["updateAgent", "listFindings", "getFinding", "updateFinding", "acceptFindingRisk", "createFindingTicket", "listAttackPaths", "getAttackPath", "getAttackPathBreakOptions", "globalSearch", "authorizeIntegration", "authorizeIntegrationReference", "remediateIntegrationAuthorization", "completeIntegrationOAuthCallback", "syncIntegration", "listIntegrationSyncs", "getIntegrationSync", "getIntegrationSchedule", "putIntegrationSchedule", "deleteIntegrationSchedule", "getIntegrationFreshness", "listSensors", "createSensorEnrollment", "getSensor", "updateSensor", "deleteSensor", "rotateSensorToken", "getSensorCoverage", "activateSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "decideSecurityAgentApproval"]) {
      assert.ok(operations.has(operationId), operationId);
    }
    for (const operationId of [
      "listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun",
      "listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun", "rerunAttackLabRun",
      "simulatePolicy", "listPolicyDecisions",
      "listSecurityActions", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval",
      "createAIExplanation",
    ]) assert.equal(operations.has(operationId), false, operationId);

    const simulation = operations.get("simulateSecurityAgent");
    assert.equal(simulation.path, "/api/v1/security-agents/{id}/simulate");
    assert.equal(simulation.method, "post");
    assert.deepEqual(simulation.operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);
    assert.deepEqual(simulation.operation.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/SecurityAgentSimulationInput" });
    assert.deepEqual(simulation.operation.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/SecurityAgentSimulation" });

    const run = operations.get("runSecurityAgent");
    assert.equal(run.path, "/api/v1/security-agents/{id}/runs");
    assert.equal(run.method, "post");
    assert.deepEqual(run.operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);
    assert.deepEqual(run.operation.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/SecurityAgentManualRunInput" });
    assert.deepEqual(run.operation.responses["202"].content["application/json"].schema, { $ref: "#/components/schemas/SecurityAgentRun" });

    const decision = operations.get("decideSecurityAgentApproval");
    assert.equal(decision.path, "/api/v1/security-agent-approvals/{id}/decision");
    assert.equal(decision.method, "post");
    assert.deepEqual(decision.operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }]);
    assert.deepEqual(decision.operation.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/SecurityAgentApprovalDecision" });
    assert.deepEqual(decision.operation.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/SecurityAgentApproval" });

    const globalSearch = operations.get("globalSearch");
    assert.equal(globalSearch.path, "/api/v1/search");
    assert.equal(globalSearch.method, "get");
    assert.deepEqual(globalSearch.operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);
    assert.deepEqual(globalSearch.operation.parameters, [
      { name: "q", in: "query", required: true, schema: { type: "string", minLength: 2, maxLength: 128, pattern: "^[A-Za-z0-9.:_/-](?:[A-Za-z0-9 .:_/-]{0,126}[A-Za-z0-9.:_/-])?$" } },
      { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 100, default: 20 } },
    ]);
    assert.deepEqual(globalSearch.operation.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/SearchResultPage" });
    assert.deepEqual(document.components.schemas.SearchResult.properties.type.enum, ["asset", "agent", "tool", "identity", "runtime", "finding"]);

    const findingTicket = operations.get("createFindingTicket");
    assert.equal(findingTicket.path, "/api/v1/findings/{id}/ticket");
    assert.equal(findingTicket.method, "post");
    assert.deepEqual(findingTicket.operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);
    assert.deepEqual(findingTicket.operation.parameters, [
      { $ref: "#/components/parameters/CSRFToken" },
      { $ref: "#/components/parameters/IdempotencyKey" },
      { $ref: "#/components/parameters/ResourceVersion" },
    ]);
    assert.equal(findingTicket.operation.requestBody, undefined);
    assert.deepEqual(findingTicket.operation.responses["201"].content["application/json"].schema, { $ref: "#/components/schemas/FindingTicket" });

    const updateAgent = operations.get("updateAgent");
    assert.equal(updateAgent.path, "/api/v1/agents/{id}");
    assert.equal(updateAgent.method, "patch");
    assert.deepEqual(updateAgent.operation.security, [{ BrowserSession: [], BrowserExpectedScope: [] }, { ProductAPIToken: [] }]);
    assert.deepEqual(updateAgent.operation.parameters, [
      { $ref: "#/components/parameters/CSRFToken" },
      { $ref: "#/components/parameters/IdempotencyKey" },
      { $ref: "#/components/parameters/ResourceVersion" },
    ]);
    assert.deepEqual(updateAgent.operation.requestBody.content["application/json"].schema, { $ref: "#/components/schemas/AgentOwnershipInput" });
    assert.deepEqual(updateAgent.operation.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/AgentMutation" });
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
    assert.deepEqual(document.components.schemas.ReferenceAuthorizationWorkflowMutationReceipt.properties.operation, { type: "string", const: "completeIntegrationReferenceAuthorization" });
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
    assert.deepEqual(document.components.schemas.StandardWorkflowMutationReceipt.properties.operation.enum.slice(-2), ["updateFinding", "acceptFindingRisk"]);
    assert.equal(document.components.schemas.StandardWorkflowMutationReceipt.properties.resource_kind.enum.includes("finding"), true);
    assert.deepEqual(document.components.schemas.StandardWorkflowMutationReceipt.properties.result.oneOf.at(-1), { $ref: "#/components/schemas/Finding" });
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

  it("publishes typed discovery inventory pages, details, evidence, and freshness", () => {
    for (const path of ["/api/v1/agents", "/api/v1/tools", "/api/v1/identities", "/api/v1/runtimes", "/api/v1/agents/{id}/capabilities", "/api/v1/agents/{id}/relationships", "/api/v1/agents/{id}/sessions"]) {
      assert.deepEqual(document.paths[path].get.parameters, [
        { $ref: "#/components/parameters/PageCursor" },
        { $ref: "#/components/parameters/PageLimit" },
      ]);
    }
    for (const name of ["InventoryPage", "CapabilityPage", "RelationshipPage", "AgentSessionPage"]) {
      const page = document.components.schemas[name];
      assert.deepEqual(page.required, ["items", "page_info"]);
      assert.equal(page.properties.items.maxItems, 100);
      assert.deepEqual(page.properties.page_info, { $ref: "#/components/schemas/PageInfo" });
    }
    assert.deepEqual(document.components.schemas.InventoryKind.enum, ["asset", "agent", "tool", "identity", "runtime"]);
    assert.deepEqual(document.components.schemas.InventoryFreshnessState.enum, ["fresh", "stale"]);
    assert.deepEqual(document.components.schemas.InventoryDetail.required, ["summary", "sources", "evidence"]);
    assert.deepEqual(document.components.schemas.InventorySourceObservation.required, ["integration_id", "provider", "source", "source_identifier", "snapshot_id", "generation", "evidence_id", "confidence_basis_points", "observed_at", "fresh_until", "projection_version", "winning"]);
    assert.deepEqual(document.components.schemas.InventoryEvidenceReference.required, ["id", "checksum", "media_type", "schema_version", "parser_version", "tool_version", "collected_at", "size_bytes"]);
    assert.equal(document.components.schemas.InventorySummary.properties.confidence_basis_points.maximum, 10000);
    assert.equal(document.components.schemas.InventorySummary.properties.credential_reference, undefined);
    assert.equal(document.components.schemas.InventoryEvidenceReference.properties.object_reference, undefined);
    for (const path of ["/api/v1/agents/{id}", "/api/v1/tools/{id}", "/api/v1/identities/{id}", "/api/v1/runtimes/{id}", "/api/v1/assets/{id}"]) {
      assert.deepEqual(document.paths[path].get.responses["200"].content["application/json"].schema, { $ref: "#/components/schemas/InventoryDetail" });
    }
  });
});

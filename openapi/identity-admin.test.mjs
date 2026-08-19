import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import { load, JSON_SCHEMA } from "js-yaml";

const root = resolve(import.meta.dirname, "..");

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
  ["listAPITokens", ["/api/v1/admin/api-tokens", "get"]],
  ["createAPIToken", ["/api/v1/admin/api-tokens", "post"]],
  ["listAPITokenRevealGrants", ["/api/v1/admin/api-token-reveal-grants", "get"]],
  ["revealAPIToken", ["/api/v1/admin/api-token-reveal-grants/{id}/reveal", "post"]],
  ["acknowledgeAPITokenRevealGrant", ["/api/v1/admin/api-token-reveal-grants/{id}", "delete"]],
  ["rotateAPIToken", ["/api/v1/admin/api-tokens/{id}/rotate", "post"]],
  ["revokeAPIToken", ["/api/v1/admin/api-tokens/{id}", "delete"]],
  ["listAuditEvents", ["/api/v1/audit-events", "get"]],
]);

const hiddenOperations = [
  "listGroupMappings", "updateGroupMappings",
  "listSSOConnections", "createSSOConnection", "deleteSSOConnection", "testSSOConnection",
  "listSCIMConnections", "createSCIMConnection", "deleteSCIMConnection", "createAuditExport", "getAuditExport",
];

const identityUIOperations = new Set([
  "getOrganization", "listWorkspaces", "createWorkspace", "updateWorkspace", "listEnvironments", "createEnvironment", "updateEnvironment",
  "listMembers", "updateMemberRole", "listBuiltInRoles",
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
  const published = new Set(Object.values(document.paths).flatMap((path) => Object.values(path).map((operation) => operation?.operationId).filter(Boolean)));
  for (const operationID of hiddenOperations) {
    assert.equal(published.has(operationID), false, `${operationID} must remain hidden until its durable provider/job lifecycle exists`);
    assert.equal(mapped.get(operationID), "planned");
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
});

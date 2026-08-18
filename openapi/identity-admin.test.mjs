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
  ["listBuiltInRoles", ["/api/v1/admin/roles", "get"]],
  ["listSSOConnections", ["/api/v1/admin/sso-connections", "get"]],
  ["createSSOConnection", ["/api/v1/admin/sso-connections", "post"]],
  ["deleteSSOConnection", ["/api/v1/admin/sso-connections/{id}", "delete"]],
  ["testSSOConnection", ["/api/v1/admin/sso-connections/{id}/test", "post"]],
  ["listSCIMConnections", ["/api/v1/admin/scim-connections", "get"]],
  ["createSCIMConnection", ["/api/v1/admin/scim-connections", "post"]],
  ["deleteSCIMConnection", ["/api/v1/admin/scim-connections/{id}", "delete"]],
]);

test("publishes the identity foundation operations as API-available product contracts", async () => {
  const [source, mapSource] = await Promise.all([
    readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
    readFile(resolve(root, "docs/product/ui-api-map.yaml"), "utf8"),
  ]);
  const document = load(source, { schema: JSON_SCHEMA, json: false });
  const map = load(mapSource, { schema: JSON_SCHEMA, json: false });
  const mapped = new Map(map.screens.flatMap((screen) => screen.actions.map((action) => [action.operation_id, action.availability])));

  for (const [operationID, [path, method]] of expectedOperations) {
    assert.equal(document.paths?.[path]?.[method]?.operationId, operationID);
    assert.equal(mapped.get(operationID), "api_available");
  }
  assert.equal([...mapped.values()].filter((value) => value === "available").length, 0);
});

test("uses strict product schemas and the shared stable error response", async () => {
  const source = await readFile(resolve(root, "openapi/openapi.yaml"), "utf8");
  const document = load(source, { schema: JSON_SCHEMA, json: false });
  for (const schema of ["Organization", "Workspace", "Environment", "Principal", "BuiltInRole", "SSOConnection", "SCIMConnection"]) {
    assert.equal(document.components?.schemas?.[schema]?.additionalProperties, false);
  }
  for (const [, [path, method]] of expectedOperations) {
    assert.equal(document.paths[path][method].responses?.["default"]?.$ref, "#/components/responses/ProductErrorResponse");
  }
});

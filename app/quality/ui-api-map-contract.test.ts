import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
type MapAction = { id: string; operation_id: string; availability: string };
type MapScreen = { id: string; label: string; actions: MapAction[] };
type MapDocument = { schema_version: number; screens: MapScreen[] };

const expectedMap: MapDocument = {
  schema_version: 1,
  screens: [
    {
      id: "identity_foundation",
      label: "Identity Foundation",
      actions: [
        { id: "view_current_organization", operation_id: "getOrganization", availability: "api_available" },
        { id: "view_workspaces", operation_id: "listWorkspaces", availability: "available" },
        { id: "create_workspace", operation_id: "createWorkspace", availability: "available" },
        { id: "view_workspace", operation_id: "getWorkspace", availability: "api_available" },
        { id: "update_workspace", operation_id: "updateWorkspace", availability: "available" },
        { id: "view_environments", operation_id: "listEnvironments", availability: "available" },
        { id: "create_environment", operation_id: "createEnvironment", availability: "available" },
        { id: "view_environment", operation_id: "getEnvironment", availability: "api_available" },
        { id: "update_environment", operation_id: "updateEnvironment", availability: "available" },
        { id: "view_current_principal", operation_id: "getCurrentPrincipal", availability: "api_available" },
        { id: "view_members", operation_id: "listMembers", availability: "available" },
        { id: "view_builtin_roles", operation_id: "listBuiltInRoles", availability: "available" },
        { id: "view_sso_connections", operation_id: "listSSOConnections", availability: "available" },
        { id: "create_sso_connection", operation_id: "createSSOConnection", availability: "available" },
        { id: "delete_sso_connection", operation_id: "deleteSSOConnection", availability: "available" },
        { id: "test_sso_connection", operation_id: "testSSOConnection", availability: "available" },
        { id: "view_scim_connections", operation_id: "listSCIMConnections", availability: "available" },
        { id: "create_scim_connection", operation_id: "createSCIMConnection", availability: "available" },
        { id: "delete_scim_connection", operation_id: "deleteSCIMConnection", availability: "available" },
        { id: "view_group_mappings", operation_id: "listGroupMappings", availability: "available" },
        { id: "update_group_mapping", operation_id: "updateGroupMappings", availability: "available" },
        { id: "view_api_tokens", operation_id: "listAPITokens", availability: "available" },
        { id: "create_api_token", operation_id: "createAPIToken", availability: "available" },
        { id: "revoke_api_token", operation_id: "revokeAPIToken", availability: "available" },
        { id: "view_audit_events", operation_id: "listAuditEvents", availability: "api_available" },
        { id: "create_audit_export", operation_id: "createAuditExport", availability: "api_available" },
        { id: "view_audit_export", operation_id: "getAuditExport", availability: "api_available" },
      ],
    },
    {
      id: "home",
      label: "Home",
      actions: [
        { id: "view_home_summary", operation_id: "getHomeSummary", availability: "planned" },
        { id: "search_all_entities", operation_id: "globalSearch", availability: "planned" },
      ],
    },
    {
      id: "integrations",
      label: "Integrations",
      actions: [
        { id: "search_integration_catalog", operation_id: "listIntegrationCatalog", availability: "api_available" },
        { id: "view_integrations", operation_id: "listIntegrations", availability: "api_available" },
        { id: "create_integration", operation_id: "createIntegration", availability: "api_available" },
        { id: "view_integration", operation_id: "getIntegration", availability: "api_available" },
        { id: "update_integration", operation_id: "updateIntegration", availability: "api_available" },
        { id: "delete_integration", operation_id: "deleteIntegration", availability: "api_available" },
        { id: "authorize_integration", operation_id: "authorizeIntegration", availability: "api_available" },
        { id: "sync_integration", operation_id: "syncIntegration", availability: "api_available" },
        { id: "view_integration_syncs", operation_id: "listIntegrationSyncs", availability: "api_available" },
        { id: "view_integration_sync", operation_id: "getIntegrationSync", availability: "api_available" },
        { id: "view_sensors", operation_id: "listSensors", availability: "api_available" },
        { id: "create_sensor_enrollment", operation_id: "createSensorEnrollment", availability: "api_available" },
        { id: "view_sensor", operation_id: "getSensor", availability: "api_available" },
        { id: "update_sensor", operation_id: "updateSensor", availability: "api_available" },
        { id: "delete_sensor", operation_id: "deleteSensor", availability: "api_available" },
        { id: "rotate_sensor_token", operation_id: "rotateSensorToken", availability: "api_available" },
        { id: "view_sensor_coverage", operation_id: "getSensorCoverage", availability: "api_available" },
      ],
    },
    {
      id: "inventory",
      label: "Inventory",
      actions: [
        { id: "view_agents", operation_id: "listAgents", availability: "api_available" },
        { id: "view_agent", operation_id: "getAgent", availability: "api_available" },
        { id: "update_agent", operation_id: "updateAgent", availability: "api_available" },
        { id: "view_agent_capabilities", operation_id: "getAgentCapabilities", availability: "api_available" },
        { id: "view_agent_relationships", operation_id: "getAgentRelationships", availability: "api_available" },
        { id: "view_agent_sessions", operation_id: "listAgentSessions", availability: "api_available" },
        { id: "view_tools", operation_id: "listTools", availability: "api_available" },
        { id: "view_tool", operation_id: "getTool", availability: "api_available" },
        { id: "view_identities", operation_id: "listIdentities", availability: "api_available" },
        { id: "view_identity", operation_id: "getIdentity", availability: "api_available" },
        { id: "view_runtimes", operation_id: "listRuntimes", availability: "api_available" },
        { id: "view_runtime", operation_id: "getRuntime", availability: "api_available" },
        { id: "view_asset", operation_id: "getAsset", availability: "api_available" },
      ],
    },
    {
      id: "system_health",
      label: "System Health",
      actions: [
        { id: "view_system_status", operation_id: "getSystemStatus", availability: "planned" },
        { id: "view_system_components", operation_id: "listSystemComponents", availability: "planned" },
        { id: "view_system_version", operation_id: "getSystemVersion", availability: "planned" },
      ],
    },
  ],
};

function exactKeys(value: unknown, expected: string[]) {
  expect(value).not.toBeNull();
  expect(Array.isArray(value)).toBe(false);
  expect(typeof value).toBe("object");
  expect(Object.keys(value as object).sort()).toEqual([...expected].sort());
}

function validateMap(value: unknown) {
  exactKeys(value, ["schema_version", "screens"]);
  const document = value as { schema_version: unknown; screens: unknown };
  expect(document.schema_version).toBe(1);
  expect(document.screens).toEqual(expectedMap.screens);

  const screenIDs = new Set<string>();
  const labels = new Set<string>();
  const actionIDs = new Set<string>();
  const operationIDs = new Set<string>();
  for (const screen of document.screens as Array<Record<string, unknown>>) {
    exactKeys(screen, ["id", "label", "actions"]);
    expect(screen.id).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
    expect(screen.label).toMatch(/^[A-Za-z][A-Za-z ]+$/);
    expect(screenIDs.has(screen.id as string)).toBe(false);
    expect(labels.has(screen.label as string)).toBe(false);
    screenIDs.add(screen.id as string);
    labels.add(screen.label as string);

    expect(Array.isArray(screen.actions)).toBe(true);
    for (const action of screen.actions as Array<Record<string, unknown>>) {
      exactKeys(action, ["id", "operation_id", "availability"]);
      expect(action.id).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
      expect(action.operation_id).toMatch(/^[a-z][A-Za-z0-9]*$/);
      expect(["planned", "api_available", "available"]).toContain(action.availability);
      expect(actionIDs.has(action.id as string)).toBe(false);
      expect(operationIDs.has(action.operation_id as string)).toBe(false);
      actionIDs.add(action.id as string);
      operationIDs.add(action.operation_id as string);
    }
  }
  return [...operationIDs];
}

function parseStrictMap(source: string) {
  expect(Buffer.byteLength(source, "utf8")).toBeLessThanOrEqual(16 * 1024);
  expect(source).not.toMatch(/[&*][A-Za-z0-9_-]+/);
  expect(source).not.toMatch(/^\s*<<\s*:/m);
  const parsed = load(source, { schema: JSON_SCHEMA, json: false });
  validateMap(parsed);
  return parsed;
}

function resolveAgainst(operationIDs: string[], available: Set<string>) {
  for (const operationID of operationIDs) {
    expect(available.has(operationID)).toBe(true);
  }
  return operationIDs;
}

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(section).slice(2);
}

describe("M1-25 UI API map seed", () => {
  it("binds the source task to the strict planned-map design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-25-ui-api-map-seed-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-25-ui-api-map-seed-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-25 - UI API map seed\*\*[\s\S]*?\*\*M1-26 - UI API coverage CI/)?.[0] ?? "";
    const compactDesign = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-24`");
    expect(section).toContain("Create `docs/product/ui-api-map.yaml`");
    expect(section).toContain("concrete Home and System Health entries");
    expect(section).toContain("Coverage script resolves both operation IDs once defined");
    for (const operationID of [
      "getHomeSummary",
      "globalSearch",
      "getSystemStatus",
      "listSystemComponents",
      "getSystemVersion",
    ]) {
      expect(compactDesign).toContain(operationID);
    }
    expect(compactDesign).toContain("Every action is explicitly `planned`");
    expect(compactDesign).toContain("no API is claimed implemented or callable");
    expect(plan).toContain("Every artifact or status behavior change has a witnessed tests-only RED");
    expect(plan).toContain("M1-26 remains Pending");
  });

  it("completes only M1-25 after M1-24 and preserves the blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-25 is Complete");
    expect(tracker).toContain("| Pending | 451 |");
    expect(tracker).toContain("| In progress | 90 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`451/90/184/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active.map(([task]) => task)).toEqual([
      "M4-23", "M4-22", "M4-21", "M4-20", "M4-19", "M4-18", "M4-17", "M4-16",
      "M4-15", "M4-14", "M4-13", "M4-12", "M4-11", "M4-10", "M4-09", "M4-08",
      "M4-07", "M4-06", "M4-05", "M4-04", "M4-03", "M4-02",
      "M4-01", "M4-01f", "M4-01e", "M4-01d", "M4-01c", "M4-01b", "M4-01a",
      "M3-52", "M3-52e", "M3-52d", "M3-52c", "M3-52b", "M3-52a", "M3-51",
      "M3-50", "M3-49", "M3-48", "M3-48h", "M3-48g", "M3-48f", "M3-48e", "M3-48d",
      "M3-48c3", "M3-48c2", "M3-48c1", "M3-48b", "M3-48a", "M3-47", "M3-46", "M3-45",
      "M3-44", "M3-43", "M3-43d", "M3-43c", "M3-43b", "M3-43a", "M3-42", "M3-41",
      "M3-40", "M3-39", "M3-38", "M3-37", "M3-36", "M3-35",
      "M3-34", "M3-33", "M3-32", "M3-31", "M3-30", "M3-29", "M3-28", "M3-27",
      "M3-26", "M3-25", "M3-24", "M3-23", "M3-22", "M3-22c", "M3-22b", "M3-22a",
      "M3-21", "M3-20", "M3-19", "M3-18", "M3-17", "M3-16", "M3-15", "M3-14",
    ]);
    expect(complete.filter(([task]) => task === "M1-24")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-25")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-26")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-26")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("accepts only the exact five-screen, 62-action mixed-lifecycle map", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");

    expect(parseStrictMap(source)).toEqual(expectedMap);
  });

  it("rejects hostile YAML and semantic seed mutations", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");
    expect(() => parseStrictMap(`${source}\nschema_version: 1\n`)).toThrow();
    expect(() => parseStrictMap("schema_version: &version 1\ncopy: *version\n")).toThrow();
    expect(() => parseStrictMap("schema_version: 1\nscreens:\n  - <<: {id: home}\n")).toThrow();

    for (const mutate of [
      (value: typeof expectedMap) => Object.assign(value, { extra: true }),
      (value: typeof expectedMap) => value.screens.reverse(),
      (value: typeof expectedMap) => value.screens[0].actions.pop(),
      (value: typeof expectedMap) => Object.assign(value.screens[0], { route: "/invented" }),
      (value: typeof expectedMap) => Object.assign(value.screens[0].actions[0], { availability: "active" }),
      (value: typeof expectedMap) => Object.assign(value.screens[2].actions[0], { operation_id: "getHomeSummary" }),
    ]) {
      const value = structuredClone(expectedMap);
      mutate(value);
      expect(() => validateMap(value)).toThrow();
    }
  });

  it("resolves every forward reference when all five operations are defined", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");
    const operationIDs = validateMap(parseStrictMap(source));
    const available = new Set(operationIDs);

    expect(resolveAgainst(operationIDs, available)).toEqual([
      "getOrganization",
      "listWorkspaces",
      "createWorkspace",
      "getWorkspace",
      "updateWorkspace",
      "listEnvironments",
      "createEnvironment",
      "getEnvironment",
      "updateEnvironment",
      "getCurrentPrincipal",
      "listMembers",
      "listBuiltInRoles",
      "listSSOConnections",
      "createSSOConnection",
      "deleteSSOConnection",
      "testSSOConnection",
      "listSCIMConnections",
      "createSCIMConnection",
      "deleteSCIMConnection",
      "listGroupMappings",
      "updateGroupMappings",
      "listAPITokens",
      "createAPIToken",
      "revokeAPIToken",
      "listAuditEvents",
      "createAuditExport",
      "getAuditExport",
      "getHomeSummary",
      "globalSearch",
      "listIntegrationCatalog",
      "listIntegrations",
      "createIntegration",
      "getIntegration",
      "updateIntegration",
      "deleteIntegration",
      "authorizeIntegration",
      "syncIntegration",
      "listIntegrationSyncs",
      "getIntegrationSync",
      "listSensors",
      "createSensorEnrollment",
      "getSensor",
      "updateSensor",
      "deleteSensor",
      "rotateSensorToken",
      "getSensorCoverage",
      "listAgents",
      "getAgent",
      "updateAgent",
      "getAgentCapabilities",
      "getAgentRelationships",
      "listAgentSessions",
      "listTools",
      "getTool",
      "listIdentities",
      "getIdentity",
      "listRuntimes",
      "getRuntime",
      "getAsset",
      "getSystemStatus",
      "listSystemComponents",
      "getSystemVersion",
    ]);
    available.delete("globalSearch");
    expect(() => resolveAgainst(operationIDs, available)).toThrow();
  });

  it("documents the planned seed without claiming current API coverage", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## UI-to-API map seed[\s\S]*?## Neon pooled proof/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toContain("`docs/product/ui-api-map.yaml`");
    expect(prose).toContain("Home");
    expect(prose).toContain("`getHomeSummary`");
    expect(prose).toContain("`globalSearch`");
    expect(prose).toContain("System Health");
    expect(prose).toContain("`getSystemStatus`");
    expect(prose).toContain("`listSystemComponents`");
    expect(prose).toContain("`getSystemVersion`");
    expect(prose).toContain("all five actions are `planned`");
    expect(prose).toContain("does not add or claim a current OpenAPI operation");
    expect(prose).toContain("M1-26 is Complete");
  });
});

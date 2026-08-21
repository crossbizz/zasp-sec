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
			id: "browser_session",
			label: "Browser Session",
			actions: [
				{ id: "start_browser_session", operation_id: "startSession", availability: "available" },
				{ id: "bootstrap_browser_session", operation_id: "bootstrapSession", availability: "available" },
				{ id: "complete_browser_session_callback", operation_id: "completeSessionCallback", availability: "available" },
				{ id: "sign_out_browser_session", operation_id: "signOutSession", availability: "available" },
				{ id: "list_browser_session_scopes", operation_id: "listSessionScopes", availability: "available" },
				{ id: "switch_browser_session_scope", operation_id: "switchSessionScope", availability: "available" },
			],
		},
    {
      id: "workflow_recovery",
      label: "Workflow Recovery",
      actions: [
        { id: "list_workflow_mutation_receipts", operation_id: "listWorkflowMutationReceipts", availability: "available" },
        { id: "acknowledge_workflow_mutation_receipt", operation_id: "acknowledgeWorkflowMutationReceipt", availability: "available" },
      ],
    },
    {
      id: "identity_foundation",
      label: "Identity Foundation",
      actions: [
        { id: "view_current_organization", operation_id: "getOrganization", availability: "available" },
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
        { id: "update_member_role", operation_id: "updateMemberRole", availability: "available" },
        { id: "view_builtin_roles", operation_id: "listBuiltInRoles", availability: "available" },
        { id: "view_sso_connections", operation_id: "listSSOConnections", availability: "planned" },
        { id: "create_sso_connection", operation_id: "createSSOConnection", availability: "planned" },
        { id: "delete_sso_connection", operation_id: "deleteSSOConnection", availability: "planned" },
        { id: "test_sso_connection", operation_id: "testSSOConnection", availability: "planned" },
        { id: "view_scim_connections", operation_id: "listSCIMConnections", availability: "planned" },
        { id: "create_scim_connection", operation_id: "createSCIMConnection", availability: "planned" },
        { id: "delete_scim_connection", operation_id: "deleteSCIMConnection", availability: "planned" },
        { id: "view_group_mappings", operation_id: "listGroupMappings", availability: "planned" },
        { id: "update_group_mapping", operation_id: "updateGroupMappings", availability: "planned" },
        { id: "view_api_tokens", operation_id: "listAPITokens", availability: "available" },
        { id: "create_api_token", operation_id: "createAPIToken", availability: "available" },
        { id: "view_api_token_reveal_grants", operation_id: "listAPITokenRevealGrants", availability: "available" },
        { id: "reveal_api_token", operation_id: "revealAPIToken", availability: "available" },
        { id: "acknowledge_api_token_reveal_grant", operation_id: "acknowledgeAPITokenRevealGrant", availability: "available" },
        { id: "rotate_api_token", operation_id: "rotateAPIToken", availability: "available" },
        { id: "revoke_api_token", operation_id: "revokeAPIToken", availability: "available" },
        { id: "view_audit_events", operation_id: "listAuditEvents", availability: "available" },
        { id: "create_audit_export", operation_id: "createAuditExport", availability: "planned" },
        { id: "view_audit_export", operation_id: "getAuditExport", availability: "planned" },
      ],
    },
    {
      id: "home",
      label: "Home",
      actions: [
        { id: "view_home_summary", operation_id: "getHomeSummary", availability: "available" },
        { id: "search_all_entities", operation_id: "globalSearch", availability: "available" },
      ],
    },
    {
      id: "findings",
      label: "Findings",
      actions: [
        { id: "view_findings", operation_id: "listFindings", availability: "available" },
        { id: "view_finding", operation_id: "getFinding", availability: "available" },
        { id: "update_finding", operation_id: "updateFinding", availability: "available" },
        { id: "accept_finding_risk", operation_id: "acceptFindingRisk", availability: "available" },
        { id: "create_finding_ticket", operation_id: "createFindingTicket", availability: "available" },
        { id: "create_ai_explanation", operation_id: "createAIExplanation", availability: "planned" },
      ],
    },
    {
      id: "attack_paths",
      label: "Attack Paths",
      actions: [
        { id: "view_attack_paths", operation_id: "listAttackPaths", availability: "available" },
        { id: "view_attack_path", operation_id: "getAttackPath", availability: "available" },
        { id: "view_attack_path_break_options", operation_id: "getAttackPathBreakOptions", availability: "available" },
      ],
    },
    {
      id: "integrations",
      label: "Integrations",
      actions: [
        { id: "search_integration_catalog", operation_id: "listIntegrationCatalog", availability: "available" },
        { id: "view_integrations", operation_id: "listIntegrations", availability: "available" },
        { id: "create_integration", operation_id: "createIntegration", availability: "available" },
        { id: "view_integration", operation_id: "getIntegration", availability: "available" },
        { id: "update_integration", operation_id: "updateIntegration", availability: "available" },
        { id: "delete_integration", operation_id: "deleteIntegration", availability: "available" },
        { id: "authorize_integration", operation_id: "authorizeIntegration", availability: "available" },
        { id: "authorize_integration_reference", operation_id: "authorizeIntegrationReference", availability: "available" },
        { id: "complete_integration_oauth_callback", operation_id: "completeIntegrationOAuthCallback", availability: "api_available" },
        { id: "remediate_integration_authorization", operation_id: "remediateIntegrationAuthorization", availability: "api_available" },
        { id: "sync_integration", operation_id: "syncIntegration", availability: "available" },
        { id: "view_integration_syncs", operation_id: "listIntegrationSyncs", availability: "available" },
        { id: "view_integration_sync", operation_id: "getIntegrationSync", availability: "available" },
        { id: "view_integration_schedule", operation_id: "getIntegrationSchedule", availability: "available" },
        { id: "update_integration_schedule", operation_id: "putIntegrationSchedule", availability: "available" },
        { id: "delete_integration_schedule", operation_id: "deleteIntegrationSchedule", availability: "available" },
        { id: "view_integration_freshness", operation_id: "getIntegrationFreshness", availability: "available" },
        { id: "view_sensors", operation_id: "listSensors", availability: "available" },
        { id: "create_sensor_enrollment", operation_id: "createSensorEnrollment", availability: "available" },
        { id: "view_sensor", operation_id: "getSensor", availability: "available" },
        { id: "update_sensor", operation_id: "updateSensor", availability: "available" },
        { id: "delete_sensor", operation_id: "deleteSensor", availability: "available" },
        { id: "rotate_sensor_token", operation_id: "rotateSensorToken", availability: "available" },
        { id: "view_sensor_coverage", operation_id: "getSensorCoverage", availability: "available" },
      ],
    },
    {
      id: "inventory",
      label: "Inventory",
      actions: [
        { id: "view_agents", operation_id: "listAgents", availability: "available" },
        { id: "view_agent", operation_id: "getAgent", availability: "available" },
        { id: "update_agent", operation_id: "updateAgent", availability: "available" },
        { id: "view_agent_capabilities", operation_id: "getAgentCapabilities", availability: "available" },
        { id: "view_agent_relationships", operation_id: "getAgentRelationships", availability: "available" },
        { id: "view_agent_sessions", operation_id: "listAgentSessions", availability: "available" },
        { id: "view_tools", operation_id: "listTools", availability: "available" },
        { id: "view_tool", operation_id: "getTool", availability: "available" },
        { id: "view_identities", operation_id: "listIdentities", availability: "available" },
        { id: "view_identity", operation_id: "getIdentity", availability: "available" },
        { id: "view_runtimes", operation_id: "listRuntimes", availability: "available" },
        { id: "view_runtime", operation_id: "getRuntime", availability: "available" },
        { id: "view_asset", operation_id: "getAsset", availability: "available" },
      ],
    },
    {
      id: "red_team",
      label: "Red Team",
      actions: [
        { id: "view_tests", operation_id: "listTests", availability: "planned" },
        { id: "create_test", operation_id: "createTest", availability: "planned" },
        { id: "view_test", operation_id: "getTest", availability: "planned" },
        { id: "update_test", operation_id: "updateTest", availability: "planned" },
        { id: "run_test", operation_id: "runTest", availability: "planned" },
        { id: "view_test_runs", operation_id: "listTestRuns", availability: "planned" },
        { id: "view_test_run", operation_id: "getTestRun", availability: "planned" },
        { id: "cancel_test_run", operation_id: "cancelTestRun", availability: "planned" },
        { id: "view_attack_lab_runs", operation_id: "listAttackLabRuns", availability: "planned" },
        { id: "create_attack_lab_run", operation_id: "createAttackLabRun", availability: "planned" },
        { id: "view_attack_lab_run", operation_id: "getAttackLabRun", availability: "planned" },
        { id: "cancel_attack_lab_run", operation_id: "cancelAttackLabRun", availability: "planned" },
        { id: "rerun_attack_lab_run", operation_id: "rerunAttackLabRun", availability: "planned" },
      ],
    },
    {
      id: "policies",
      label: "Policies",
      actions: [
        { id: "view_policies", operation_id: "listPolicies", availability: "available" },
        { id: "create_policy", operation_id: "createPolicy", availability: "available" },
        { id: "view_policy", operation_id: "getPolicy", availability: "available" },
        { id: "update_policy", operation_id: "updatePolicy", availability: "available" },
        { id: "delete_policy", operation_id: "deletePolicy", availability: "api_available" },
        { id: "simulate_policy", operation_id: "simulatePolicy", availability: "planned" },
        { id: "rollout_policy", operation_id: "rolloutPolicy", availability: "available" },
        { id: "disable_policy", operation_id: "disablePolicy", availability: "available" },
        { id: "view_policy_decisions", operation_id: "listPolicyDecisions", availability: "planned" },
      ],
    },
    {
      id: "system_health",
      label: "System Health",
      actions: [
        { id: "view_system_status", operation_id: "getSystemStatus", availability: "available" },
        { id: "view_system_components", operation_id: "listSystemComponents", availability: "available" },
        { id: "view_system_version", operation_id: "getSystemVersion", availability: "available" },
      ],
    },
    {
      id: "sessions",
      label: "Sessions",
      actions: [
        { id: "view_sessions", operation_id: "listSessions", availability: "available" },
        { id: "view_session", operation_id: "getSession", availability: "available" },
        { id: "view_session_events", operation_id: "listSessionEvents", availability: "available" },
        { id: "revoke_session", operation_id: "revokeSession", availability: "available" },
      ],
    },
    {
      id: "security_agents",
      label: "Security Agents",
      actions: [
        { id: "view_security_agent_templates", operation_id: "listSecurityAgentTemplates", availability: "available" },
        { id: "view_security_actions", operation_id: "listSecurityActions", availability: "planned" },
        { id: "view_security_agents", operation_id: "listSecurityAgents", availability: "available" },
        { id: "create_security_agent", operation_id: "createSecurityAgent", availability: "available" },
        { id: "view_security_agent", operation_id: "getSecurityAgent", availability: "available" },
        { id: "update_security_agent", operation_id: "updateSecurityAgent", availability: "available" },
        { id: "delete_security_agent", operation_id: "deleteSecurityAgent", availability: "available" },
        { id: "activate_security_agent", operation_id: "activateSecurityAgent", availability: "api_available" },
        { id: "simulate_security_agent", operation_id: "simulateSecurityAgent", availability: "api_available" },
        { id: "run_security_agent", operation_id: "runSecurityAgent", availability: "api_available" },
        { id: "view_security_agent_runs", operation_id: "listSecurityAgentRuns", availability: "available" },
        { id: "view_security_agent_run", operation_id: "getSecurityAgentRun", availability: "available" },
        { id: "cancel_security_agent_run", operation_id: "cancelSecurityAgentRun", availability: "available" },
        { id: "view_security_agent_approvals", operation_id: "listSecurityAgentApprovals", availability: "available" },
        { id: "view_security_agent_approval", operation_id: "getSecurityAgentApproval", availability: "available" },
        { id: "decide_security_agent_approval", operation_id: "decideSecurityAgentApproval", availability: "available" },
      ],
    },
    {
      id: "compliance",
      label: "Compliance",
      actions: [
        { id: "view_compliance_controls", operation_id: "listComplianceControls", availability: "available" },
        { id: "view_compliance_evidence", operation_id: "listComplianceEvidence", availability: "available" },
        { id: "create_compliance_export", operation_id: "createComplianceExport", availability: "planned" },
        { id: "view_compliance_export", operation_id: "getComplianceExport", availability: "planned" },
      ],
    },
    {
      id: "data_controls",
      label: "Data Controls",
      actions: [
        { id: "view_data_controls", operation_id: "getDataControls", availability: "available" },
        { id: "update_data_controls", operation_id: "updateDataControls", availability: "available" },
      ],
    },
    {
      id: "external_data_flows",
      label: "External Data Flows",
      actions: [
        { id: "view_external_data_flows", operation_id: "getExternalDataFlows", availability: "available" },
        { id: "update_external_data_flows", operation_id: "updateExternalDataFlows", availability: "planned" },
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
    expect(tracker).toContain("| Pending | 0 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 667 |");
    expect(tracker).toContain("| Blocked | 61 |");
    expect(tracker).toContain("`0/0/667/61`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active.map(([task]) => task)).toEqual([
    ]);
    expect(complete.filter(([task]) => task === "M1-24")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-25")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-26")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-26")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("accepts only the exact sixteen-screen, 140-action mixed-lifecycle map", async () => {
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
			(value: typeof expectedMap) => Object.assign(value.screens[4].actions[0], { operation_id: "getHomeSummary" }),
    ]) {
      const value = structuredClone(expectedMap);
      mutate(value);
      expect(() => validateMap(value)).toThrow();
    }
  });

  it("resolves every mapped operation when all references are defined", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");
    const operationIDs = validateMap(parseStrictMap(source));
    const available = new Set(operationIDs);

		expect(resolveAgainst(operationIDs, available)).toEqual([
			"startSession",
			"bootstrapSession",
			"completeSessionCallback",
			"signOutSession",
			"listSessionScopes",
			"switchSessionScope",
      "listWorkflowMutationReceipts",
      "acknowledgeWorkflowMutationReceipt",
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
      "updateMemberRole",
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
      "listAPITokenRevealGrants",
      "revealAPIToken",
      "acknowledgeAPITokenRevealGrant",
      "rotateAPIToken",
      "revokeAPIToken",
      "listAuditEvents",
      "createAuditExport",
      "getAuditExport",
      "getHomeSummary",
      "globalSearch",
      "listFindings",
      "getFinding",
      "updateFinding",
      "acceptFindingRisk",
      "createFindingTicket",
      "createAIExplanation",
      "listAttackPaths",
      "getAttackPath",
      "getAttackPathBreakOptions",
      "listIntegrationCatalog",
      "listIntegrations",
      "createIntegration",
      "getIntegration",
      "updateIntegration",
      "deleteIntegration",
      "authorizeIntegration",
      "authorizeIntegrationReference",
      "completeIntegrationOAuthCallback",
      "remediateIntegrationAuthorization",
      "syncIntegration",
      "listIntegrationSyncs",
      "getIntegrationSync",
      "getIntegrationSchedule",
      "putIntegrationSchedule",
      "deleteIntegrationSchedule",
      "getIntegrationFreshness",
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
      "listTests",
      "createTest",
      "getTest",
      "updateTest",
      "runTest",
      "listTestRuns",
      "getTestRun",
      "cancelTestRun",
      "listAttackLabRuns",
      "createAttackLabRun",
      "getAttackLabRun",
      "cancelAttackLabRun",
      "rerunAttackLabRun",
      "listPolicies",
      "createPolicy",
      "getPolicy",
      "updatePolicy",
      "deletePolicy",
      "simulatePolicy",
      "rolloutPolicy",
      "disablePolicy",
      "listPolicyDecisions",
      "getSystemStatus",
      "listSystemComponents",
      "getSystemVersion",
      "listSessions",
      "getSession",
      "listSessionEvents",
      "revokeSession",
      "listSecurityAgentTemplates",
      "listSecurityActions",
      "listSecurityAgents",
      "createSecurityAgent",
      "getSecurityAgent",
      "updateSecurityAgent",
      "deleteSecurityAgent",
      "activateSecurityAgent",
      "simulateSecurityAgent",
      "runSecurityAgent",
      "listSecurityAgentRuns",
      "getSecurityAgentRun",
      "cancelSecurityAgentRun",
      "listSecurityAgentApprovals",
      "getSecurityAgentApproval",
      "decideSecurityAgentApproval",
      "listComplianceControls",
      "listComplianceEvidence",
      "createComplianceExport",
      "getComplianceExport",
      "getDataControls",
      "updateDataControls",
      "getExternalDataFlows",
      "updateExternalDataFlows",
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
    expect(prose).toContain("Home summary is `api_available`");
    expect(prose).toContain("global search is `available`");
    expect(prose).toContain("three System Health actions are `available`");
    expect(prose).toContain("Twelve provider, export, and external-flow mutations remain `planned`");
    expect(prose).toContain("M1-26 is Complete");
  });
});

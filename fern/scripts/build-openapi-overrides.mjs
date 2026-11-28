#!/usr/bin/env node
// Builds fern/openapi-overrides.yml from openapi/openapi.yaml.
//
// The API contract has no tags and no SDK naming, and it is not edited for
// Fern. This script writes the Fern-only additions next to it:
//
//   - a tag per operation (the section of the API Reference),
//   - x-fern-sdk-group-name and x-fern-sdk-method-name (client.agents.list()),
//   - x-fern-audiences: [api-token] on every operation an API token may call,
//     so the SDKs hold only what automation can use,
//   - x-fern-pagination on the list operations that return a cursor,
//   - a sentence in the description of the operations a browser session only
//     may call.
//
// Usage:
//   node fern/scripts/build-openapi-overrides.mjs           write the file
//   node fern/scripts/build-openapi-overrides.mjs --check   fail if it is stale
//
// Every operation of the contract must be listed in OPERATIONS below. A new
// operation that is not listed fails the script, so the SDK naming is always a
// decision and never a default.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import yaml from "js-yaml";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const specPath = join(root, "openapi", "openapi.yaml");
const outPath = join(root, "fern", "openapi-overrides.yml");

// Sections of the API Reference: SDK group -> [tag, description].
const GROUPS = {
  cliAuth: ["CLI sign-in", "Browser-approved, Environment-scoped findings submission sessions for zaspctl."],
  browserSession: ["Browser session", "Sign-in, session bootstrap and scope switching of the web application. Browser only."],
  organization: ["Organization", "The Organization of the caller and the caller's own principal."],
  workspaces: ["Workspaces", "Workspaces of the Organization."],
  environments: ["Environments", "Environments of a Workspace. Inventory, findings and policy belong to one Environment."],
  members: ["Members and roles", "Members of the Organization, their roles and the built-in role catalog."],
  groupMappings: ["Group mappings", "SCIM group to Workspace, Environment and role mappings."],
  ssoConnections: ["SSO connections", "Enterprise single sign-on connections."],
  scimConnections: ["SCIM connections", "SCIM provisioning connections."],
  apiTokens: ["API tokens", "API tokens, their lifetime policy and one-time reveal grants."],
  audit: ["Audit log", "Audit events and audit exports."],
  integrations: ["Integrations", "The connector catalog, integrations, their authorization, syncs, schedules, freshness and remediation role."],
  sensors: ["Sensors", "Optional runtime sensor enrollments and their heartbeat coverage."],
  agents: ["Agents", "Discovered and declared agents, their capabilities, relationships, access, sessions and evidence pack."],
  tools: ["Tools", "Tools the inventory holds."],
  mcpServers: ["MCP servers", "Discovered MCP servers and the MCP registry decisions."],
  identities: ["Identities", "Non-human identities and credentials."],
  runtimes: ["Runtimes", "Runtimes agents run in."],
  assets: ["Assets", "One inventory asset by identifier."],
  search: ["Search", "Global search over the authorized inventory."],
  home: ["Overview", "The summary shown on the Overview page."],
  findings: ["Findings", "Exposure findings, status changes, risk acceptance and tickets."],
  attackPaths: ["Attack paths", "Evidence-backed attack paths and their break options."],
  tests: ["Red team tests", "Red team test definitions, schedules and the probe library."],
  testRuns: ["Red team runs", "Red team runs and their evidence."],
  attackLab: ["Attack lab", "Attack lab preflight and runs."],
  policies: ["Policies", "Runtime policies, rollout, simulation and decisions."],
  guardrails: ["Guardrails", "The guardrail policy of an Environment and the decision API."],
  gateway: ["Hosted gateway", "The hosted gateway's policy, registered MCP servers and decision records."],
  gatewayTraffic: ["Hosted gateway traffic", "The routes an agent's MCP and model traffic is sent to. Called by agents, not by automation."],
  securityAgents: ["Security Agents", "Security Agent definitions, templates, actions, activation and execution controls."],
  securityAgentRuns: ["Security Agent runs", "Security Agent runs, their activity, exports and recovery."],
  securityAgentApprovals: ["Security Agent approvals", "Approvals of supervised Security Agent actions."],
  sessions: ["Sessions", "Console sessions and runtime session investigations."],
  compliance: ["Compliance", "Framework controls, evidence and evidence exports."],
  settings: ["Data controls", "Data collection and retention controls, and external data flows."],
  system: ["System", "Status, components and version of the deployment."],
  recovery: ["Recovery", "Backup and restore operations."],
};

// operationId -> [SDK group, SDK method].
const OPERATIONS = {
  startCLILogin: ["cliAuth", "start"],
  approveCLILogin: ["cliAuth", "approve"],
  exchangeCLILogin: ["cliAuth", "exchange"],
  startSession: ["browserSession", "start"],
  bootstrapSession: ["browserSession", "bootstrap"],
  completeSessionCallback: ["browserSession", "completeCallback"],
  signOutSession: ["browserSession", "signOut"],
  listSessionScopes: ["browserSession", "listScopes"],
  switchSessionScope: ["browserSession", "switchScope"],

  getOrganization: ["organization", "get"],
  updateOrganization: ["organization", "update"],
  getCurrentPrincipal: ["organization", "getCurrentPrincipal"],
  listWorkspaces: ["workspaces", "list"],
  createWorkspace: ["workspaces", "create"],
  getWorkspace: ["workspaces", "get"],
  updateWorkspace: ["workspaces", "update"],
  listEnvironments: ["environments", "list"],
  createEnvironment: ["environments", "create"],
  getEnvironment: ["environments", "get"],
  updateEnvironment: ["environments", "update"],

  listMembers: ["members", "list"],
  updateMemberRole: ["members", "updateRole"],
  listMemberInvitations: ["members", "listInvitations"],
  inviteMember: ["members", "invite"],
  updateMemberProfile: ["members", "updateProfile"],
  removeMember: ["members", "remove"],
  getMemberAccess: ["members", "getAccess"],
  listBuiltInRoles: ["members", "listBuiltInRoles"],
  listGroupMappings: ["groupMappings", "list"],
  updateGroupMappings: ["groupMappings", "update"],
  listSSOConnections: ["ssoConnections", "list"],
  createSSOConnection: ["ssoConnections", "create"],
  deleteSSOConnection: ["ssoConnections", "delete"],
  testSSOConnection: ["ssoConnections", "test"],
  listSCIMConnections: ["scimConnections", "list"],
  createSCIMConnection: ["scimConnections", "create"],
  deleteSCIMConnection: ["scimConnections", "delete"],

  listAPITokens: ["apiTokens", "list"],
  createAPIToken: ["apiTokens", "create"],
  revokeAPIToken: ["apiTokens", "revoke"],
  rotateAPIToken: ["apiTokens", "rotate"],
  getAPITokenPolicy: ["apiTokens", "getPolicy"],
  putAPITokenPolicy: ["apiTokens", "putPolicy"],
  listAPITokenRevealGrants: ["apiTokens", "listRevealGrants"],
  revealAPIToken: ["apiTokens", "reveal"],
  acknowledgeAPITokenRevealGrant: ["apiTokens", "acknowledgeRevealGrant"],

  listAuditEvents: ["audit", "listEvents"],
  createAuditExport: ["audit", "createExport"],
  getAuditExport: ["audit", "getExport"],

  listIntegrationCatalog: ["integrations", "listCatalog"],
  listWorkflowMutationReceipts: ["integrations", "listMutationReceipts"],
  acknowledgeWorkflowMutationReceipt: ["integrations", "acknowledgeMutationReceipt"],
  listIntegrations: ["integrations", "list"],
  createIntegration: ["integrations", "create"],
  completeIntegrationOAuthCallback: ["integrations", "completeOAuthCallback"],
  getIntegration: ["integrations", "get"],
  updateIntegration: ["integrations", "update"],
  deleteIntegration: ["integrations", "delete"],
  syncIntegration: ["integrations", "sync"],
  listIntegrationSyncs: ["integrations", "listSyncs"],
  getIntegrationSync: ["integrations", "getSync"],
  getIntegrationSchedule: ["integrations", "getSchedule"],
  putIntegrationSchedule: ["integrations", "putSchedule"],
  deleteIntegrationSchedule: ["integrations", "deleteSchedule"],
  getIntegrationFreshness: ["integrations", "getFreshness"],
  getIntegrationSetupStatus: ["integrations", "getSetupStatus"],
  getIntegrationRemediationRole: ["integrations", "getRemediationRole"],
  putIntegrationRemediationRole: ["integrations", "putRemediationRole"],
  testIntegrationWebhook: ["integrations", "testWebhook"],
  getIntegrationWebhookStatus: ["integrations", "getWebhookStatus"],
  getSaaSSignInAttempt: ["integrations", "getSaaSSignInAttempt"],
  authorizeIntegration: ["integrations", "authorize"],
  authorizeIntegrationReference: ["integrations", "authorizeReference"],
  remediateIntegrationAuthorization: ["integrations", "remediateAuthorization"],

  listSensors: ["sensors", "list"],
  createSensorEnrollment: ["sensors", "createEnrollment"],
  getSensor: ["sensors", "get"],
  updateSensor: ["sensors", "update"],
  deleteSensor: ["sensors", "delete"],
  rotateSensorToken: ["sensors", "rotateToken"],
  getSensorCoverage: ["sensors", "getCoverage"],

  createGuardrailDecision: ["guardrails", "createDecision"],
  createCalibrationExport: ["guardrails", "createCalibrationExport"],
  getCalibrationExport: ["guardrails", "getCalibrationExport"],
  createCalibrationDownloadGrant: ["guardrails", "createCalibrationDownloadGrant"],
  downloadCalibrationExport: ["guardrails", "downloadCalibrationExport"],
  getCalibrationMetrics: ["guardrails", "getCalibrationMetrics"],
  submitAnalystFeedback: ["guardrails", "submitAnalystFeedback"],
  getRuleSuppressionMode: ["guardrails", "getRuleSuppressionMode"],
  putRuleSuppressionMode: ["guardrails", "putRuleSuppressionMode"],
  getGuardrailPolicy: ["guardrails", "getPolicy"],
  putGuardrailPolicy: ["guardrails", "putPolicy"],

  getGatewayPolicy: ["gateway", "getPolicy"],
  putGatewayPolicy: ["gateway", "putPolicy"],
  listMCPGatewayServers: ["gateway", "listServers"],
  putMCPGatewayServer: ["gateway", "putServer"],
  deleteMCPGatewayServer: ["gateway", "deleteServer"],
  listGatewayActivity: ["gateway", "listActivity"],
  issueRuntimeDelegation: ["gateway", "issueRuntimeDelegation"],
  verifyRuntimeDelegation: ["gateway", "verifyRuntimeDelegation"],
  callZaspMCP: ["gateway", "callZaspMCP"],
  callMCPGateway: ["gatewayTraffic", "callMcp"],
  closeMCPGatewaySession: ["gatewayTraffic", "closeMcpSession"],
  createGatewayChatCompletion: ["gatewayTraffic", "createChatCompletion"],
  createGatewayResponse: ["gatewayTraffic", "createResponse"],
  createGatewayMessage: ["gatewayTraffic", "createMessage"],

  listWorkforceInventory: ["agents", "listWorkforceInventory"],
  verifyAgentDiscovery: ["agents", "verifyAgentDiscovery"],
  draftAgentPurpose: ["agents", "draftAgentPurpose"],
  getAgentPostureSummary: ["agents", "getAgentPostureSummary"],
  listAgents: ["agents", "list"],
  getAgent: ["agents", "get"],
  updateAgent: ["agents", "update"],
  getAgentCapabilities: ["agents", "listCapabilities"],
  getAgentRelationships: ["agents", "listRelationships"],
  getAgentEvidencePack: ["agents", "getEvidencePack"],
  listAgentSessions: ["agents", "listSessions"],
  getAgentAccess: ["agents", "getAccess"],

  listTools: ["tools", "list"],
  getWorkloadContainment: ["guardrails", "getContainment"],
  authorizeWorkloadContainment: ["guardrails", "authorizeContainment"],
  releaseWorkloadContainment: ["guardrails", "releaseContainment"],
  getBrowserProfile: ["sensors", "getBrowserProfile"],
  registerBrowserProfile: ["sensors", "registerBrowserProfile"],
  retireBrowserProfile: ["sensors", "retireBrowserProfile"],
  recordBrowserOriginDays: ["sensors", "recordBrowserOriginDays"],
  getWorkloadCredentialBinding: ["guardrails", "getWorkloadBinding"],
  getWorkloadDelegations: ["gateway", "getWorkloadDelegations"],
  bindWorkloadCredential: ["guardrails", "bindWorkload"],
  getTicketVerification: ["tests", "getTicketVerification"],
  putTicketVerification: ["tests", "putTicketVerification"],
  getAgentActionAnalysis: ["agents", "getActionAnalysis"],
  putAgentActionAnalysis: ["agents", "putActionAnalysis"],
  getAgentPurpose: ["agents", "getPurpose"],
  putAgentPurpose: ["agents", "putPurpose"],
  getTool: ["tools", "get"],
  getEndpointPolicyCohort: ["sensors", "getEndpointPolicyCohort"],
  updateEndpointPolicyCohort: ["sensors", "updateEndpointPolicyCohort"],
  evaluateClaudeEnterpriseHook: ["guardrails", "evaluateClaudeEnterpriseHook"],
  getTicketCohort: ["sensors", "getTicketCohort"],
  publishTicketCohort: ["sensors", "publishTicketCohort"],
  registerEndpointDevice: ["sensors", "registerEndpointDevice"],
  listEndpointDevices: ["sensors", "listEndpointDevices"],
  getEndpointDevice: ["sensors", "getEndpointDevice"],
  rotateEndpointCredential: ["sensors", "rotateEndpointCredential"],
  retireEndpointDevice: ["sensors", "retireEndpointDevice"],
  publishEndpointPolicy: ["sensors", "publishEndpointPolicy"],
  exchangeEndpointEnrollment: ["sensors", "exchangeEndpointEnrollment"],
  recordEndpointHeartbeat: ["sensors", "recordEndpointHeartbeat"],
  recordEndpointInventory: ["sensors", "recordEndpointInventory"],
  recordEndpointObservations: ["sensors", "recordEndpointObservations"],
  fetchEndpointPolicy: ["sensors", "fetchEndpointPolicy"],
  listAgentSuggestions: ["policies", "listAgentSuggestions"],
  refreshAgentSuggestions: ["policies", "refreshAgentSuggestions"],
  reviewAgentSuggestion: ["policies", "reviewAgentSuggestion"],
  listAddonVersionInstallations: ["tools", "listAddonVersionInstallations"],
  getAddonScan: ["tools", "getAddonScan"],
  createPrivateAddonUpload: ["tools", "createPrivateAddonUpload"],
  attestAddonScan: ["tools", "attestAddonScan"],
  getAddonCIOrigin: ["tools", "getAddonCIOrigin"],
  submitAddonScan: ["tools", "submitAddonScan"],
  getAddonVersion: ["tools", "getAddonVersion"],
  deepScanAddonVersion: ["tools", "deepScanAddonVersion"],
  getAddonDeploymentApproval: ["tools", "getAddonDeploymentApproval"],
  reviewAddonDeploymentApproval: ["tools", "reviewAddonDeploymentApproval"],
  listAddonVersions: ["tools", "listAddonVersions"],
  reviewAddonVersion: ["tools", "reviewAddonVersion"],
  createWorkloadActionDecision: ["guardrails", "decideAction"],
  recordWorkloadActionOutcome: ["guardrails", "recordActionOutcome"],
  listMCPServers: ["mcpServers", "list"],
  listMCPRegistry: ["mcpServers", "listRegistry"],
  putMCPRegistryEntry: ["mcpServers", "putRegistryEntry"],
  listIdentities: ["identities", "list"],
  getIdentity: ["identities", "get"],
  listRuntimes: ["runtimes", "list"],
  getRuntime: ["runtimes", "get"],
  getAsset: ["assets", "get"],
  globalSearch: ["search", "query"],
  getHomeSummary: ["home", "getSummary"],

  listFindings: ["findings", "list"],
  getFinding: ["findings", "get"],
  updateFinding: ["findings", "update"],
  acceptFindingRisk: ["findings", "acceptRisk"],
  createFindingTicket: ["findings", "createTicket"],
  listAttackPaths: ["attackPaths", "list"],
  getAttackPath: ["attackPaths", "get"],
  getAttackPathBreakOptions: ["attackPaths", "getBreakOptions"],

  listPolicies: ["policies", "list"],
  createPolicy: ["policies", "create"],
  getPolicy: ["policies", "get"],
  updatePolicy: ["policies", "update"],
  deletePolicy: ["policies", "delete"],
  rolloutPolicy: ["policies", "rollout"],
  simulatePolicy: ["policies", "simulate"],
  listPolicyDecisions: ["policies", "listDecisions"],
  disablePolicy: ["policies", "disable"],

  listSecurityAgentTemplates: ["securityAgents", "listTemplates"],
  listSecurityActions: ["securityAgents", "listActions"],
  listCustomSecurityAgents: ["securityAgents", "listCustomSecurityAgents"],
  createCustomSecurityAgent: ["securityAgents", "createCustomSecurityAgent"],
  getCustomSecurityAgent: ["securityAgents", "getCustomSecurityAgent"],
  updateCustomSecurityAgent: ["securityAgents", "updateCustomSecurityAgent"],
  listSecurityAgents: ["securityAgents", "list"],
  createSecurityAgent: ["securityAgents", "create"],
  getSecurityAgent: ["securityAgents", "get"],
  updateSecurityAgent: ["securityAgents", "update"],
  deleteSecurityAgent: ["securityAgents", "delete"],
  getSecurityAgentActivation: ["securityAgents", "getActivation"],
  activateSecurityAgent: ["securityAgents", "activate"],
  getSecurityAgentExecutionControls: ["securityAgents", "getExecutionControls"],
  setSecurityAgentExecutionControl: ["securityAgents", "setExecutionControl"],
  setSecurityAgentPlannerPricing: ["securityAgents", "setPlannerPricing"],
  simulateSecurityAgent: ["securityAgents", "simulate"],
  runSecurityAgent: ["securityAgents", "run"],

  listSecurityAgentRuns: ["securityAgentRuns", "list"],
  getSecurityCaseVerification: ["securityAgentRuns", "getSecurityCaseVerification"],
  verifySecurityCase: ["securityAgentRuns", "verifySecurityCase"],
  getSecurityAgentRun: ["securityAgentRuns", "get"],
  getSecurityAgentAuditEvent: ["securityAgentRuns", "getAuditEvent"],
  listSecurityAgentRunActivity: ["securityAgentRuns", "listActivity"],
  listSecurityAgentActivityRuns: ["securityAgentRuns", "listForActivity"],
  getSecurityAgentExport: ["securityAgentRuns", "getExport"],
  createSecurityAgentExportDownloadGrant: ["securityAgentRuns", "createExportDownloadGrant"],
  downloadSecurityAgentExport: ["securityAgentRuns", "downloadExport"],
  cancelSecurityAgentRun: ["securityAgentRuns", "cancel"],
  closeSecurityAgentRun: ["securityAgentRuns", "close"],
  getSingleTestCleanupRecovery: ["securityAgentRuns", "getCleanupRecovery"],
  requestSingleTestCleanupRecovery: ["securityAgentRuns", "requestCleanupRecovery"],

  listSecurityAgentApprovals: ["securityAgentApprovals", "list"],
  getSecurityAgentApproval: ["securityAgentApprovals", "get"],
  decideSecurityAgentApproval: ["securityAgentApprovals", "decide"],

  listSessions: ["sessions", "list"],
  getSession: ["sessions", "get"],
  revokeSession: ["sessions", "revoke"],
  getAnalystThreads: ["sessions", "getAnalystThreads"],
  createAnalystThread: ["sessions", "createAnalystThread"],
  getStudioRemediationAdvisory: ["sessions", "getStudioRemediationAdvisory"],
  requestStudioRemediationAdvisory: ["sessions", "requestStudioRemediationAdvisory"],
  getAnalystThread: ["sessions", "getAnalystThread"],
  streamAnalystThread: ["sessions", "streamAnalystThread"],
  getSessionIntent: ["sessions", "getSessionIntent"],
  listSessionEvents: ["sessions", "listEvents"],
  getSessionEvent: ["sessions", "getEvent"],

  listComplianceEditions: ["compliance", "listEditions"],
  listComplianceCoverage: ["compliance", "listCoverage"],
  listComplianceCoverageEvidence: ["compliance", "listCoverageEvidence"],
  listComplianceControls: ["compliance", "listControls"],
  listComplianceEvidence: ["compliance", "listEvidence"],
  getComplianceEvidence: ["compliance", "getEvidence"],
  createComplianceExport: ["compliance", "createExport"],
  getComplianceExport: ["compliance", "getExport"],
  createComplianceDownloadGrant: ["compliance", "createDownloadGrant"],
  downloadComplianceExport: ["compliance", "downloadExport"],

  getOrganizationAIControls: ["settings", "getOrganizationAiControls"],
  updateOrganizationAIControls: ["settings", "updateOrganizationAiControls"],
  getEnvironmentAIControls: ["settings", "getEnvironmentAiControls"],
  updateEnvironmentAIControls: ["settings", "updateEnvironmentAiControls"],
  runModelQualification: ["settings", "runModelQualification"],
  getModelQualificationRun: ["settings", "getModelQualificationRun"],
  listModelQualifications: ["settings", "listModelQualifications"],
  getDataControls: ["settings", "getDataControls"],
  updateDataControls: ["settings", "updateDataControls"],
  getExternalDataFlows: ["settings", "getExternalDataFlows"],

  getSystemStatus: ["system", "getStatus"],
  listSystemComponents: ["system", "listComponents"],
  getSystemVersion: ["system", "getVersion"],

  putRecoveryIntent: ["recovery", "putRecoveryIntent"],
  getRecoveryIntent: ["recovery", "getRecoveryIntent"],
  startRecoveryBackup: ["recovery", "startBackup"],
  getRecoveryBackup: ["recovery", "getBackup"],
  startRecoveryRestore: ["recovery", "startRestore"],
  getRecoveryRestore: ["recovery", "getRestore"],

  listTests: ["tests", "list"],
  createTest: ["tests", "create"],
  getTest: ["tests", "get"],
  updateTest: ["tests", "update"],
  getTestSchedule: ["tests", "getSchedule"],
  putTestSchedule: ["tests", "putSchedule"],
  runTest: ["tests", "run"],
  getTestProbeCatalog: ["tests", "getProbeCatalog"],
  listTestRuns: ["testRuns", "list"],
  getTestRun: ["testRuns", "get"],
  cancelTestRun: ["testRuns", "cancel"],

  preflightAttackLabRun: ["attackLab", "preflight"],
  listAttackLabRuns: ["attackLab", "listRuns"],
  createAttackLabRun: ["attackLab", "createRun"],
  getAttackLabRun: ["attackLab", "getRun"],
  cancelAttackLabRun: ["attackLab", "cancelRun"],
  rerunAttackLabRun: ["attackLab", "rerunRun"],
};

const METHODS = ["get", "post", "put", "patch", "delete"];
const TOKEN_AUDIENCE = "api-token";
const BROWSER_ONLY = "Authentication: a browser session only. An API token is refused.";
const OPERATION_AUTH_NOTES = {
  evaluateClaudeEnterpriseHook: "The provider authenticates with a signed webhook delivery.",
  startCLILogin: "Authentication: public start, bound to a CLI PKCE challenge.",
  exchangeCLILogin: "Authentication: approved CLI request and its PKCE verifier.",
};
const NO_AUTH = "Authentication: none. The route is part of the browser sign-in flow.";

function resolve(spec, node) {
  let value = node;
  while (value && typeof value === "object" && typeof value.$ref === "string") {
    value = value.$ref.split("/").slice(1).reduce((current, key) => current[key], spec);
  }
  return value;
}

// The cursor member of the 200 response and the query parameter that takes it.
function pagination(spec, pathItem, operation) {
  const parameters = [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])].map((entry) => resolve(spec, entry));
  const request = parameters.find((entry) => entry.in === "query" && (entry.name === "cursor" || entry.name === "before"));
  const response = resolve(spec, operation.responses?.["200"]);
  const schema = resolve(spec, response?.content?.["application/json"]?.schema);
  const properties = schema?.properties;
  if (!request || !properties || !properties.items) return undefined;
  if (properties.page_info) return { cursor: `$request.${request.name}`, next_cursor: "$response.page_info.next_cursor", results: "$response.items" };
  if (properties.next_cursor) return { cursor: `$request.${request.name}`, next_cursor: "$response.next_cursor", results: "$response.items" };
  return undefined;
}

function build() {
  const spec = yaml.load(readFileSync(specPath, "utf8"));
  const overrides = { tags: [], paths: {} };
  const seen = new Set();
  const usedGroups = new Set();
  const problems = [];
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const method of METHODS) {
      const operation = pathItem[method];
      if (!operation) continue;
      const id = operation.operationId;
      const entry = OPERATIONS[id];
      if (!entry) { problems.push(`operation ${id} (${method.toUpperCase()} ${path}) is not listed in OPERATIONS`); continue; }
      seen.add(id);
      const [group, name] = entry;
      if (!GROUPS[group]) { problems.push(`operation ${id} names the unknown group ${group}`); continue; }
      usedGroups.add(group);
      const security = operation.security ?? spec.security ?? [];
      const acceptsToken = security.some((requirement) => Object.hasOwn(requirement, "ProductAPIToken"));
      const override = { tags: [GROUPS[group][0]], "x-fern-sdk-group-name": group, "x-fern-sdk-method-name": name };
      if (acceptsToken) {
        override["x-fern-audiences"] = [TOKEN_AUDIENCE];
      } else {
        const note = OPERATION_AUTH_NOTES[id] ?? (security.length === 0 ? NO_AUTH : BROWSER_ONLY);
        override.description = operation.description ? `${operation.description.trim()}\n\n${note}` : note;
      }
      const page = pagination(spec, pathItem, operation);
      if (page) override["x-fern-pagination"] = page;
      (overrides.paths[path] ??= {})[method] = override;
    }
  }
  for (const id of Object.keys(OPERATIONS)) if (!seen.has(id)) problems.push(`OPERATIONS lists ${id}, which the contract does not have`);
  const names = new Set();
  for (const [group, name] of Object.values(OPERATIONS)) {
    const key = `${group}.${name}`;
    if (names.has(key)) problems.push(`two operations are named ${key}`);
    names.add(key);
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  for (const [group, [name, description]] of Object.entries(GROUPS)) if (usedGroups.has(group)) overrides.tags.push({ name, description });
  const header = [
    "# Generated by fern/scripts/build-openapi-overrides.mjs from openapi/openapi.yaml.",
    "# Do not edit by hand: change the script and run `npm run docs:overrides`.",
    "",
  ].join("\n");
  return header + yaml.dump(overrides, { lineWidth: 160, noRefs: true, sortKeys: false });
}

const output = build();
if (process.argv.includes("--check")) {
  let current = "";
  try { current = readFileSync(outPath, "utf8"); } catch { /* missing file is stale */ }
  if (current !== output) {
    console.error("fern/openapi-overrides.yml is stale. Run: npm run docs:overrides");
    process.exit(1);
  }
  console.log("fern/openapi-overrides.yml is current");
} else {
  writeFileSync(outPath, output);
  console.log(`wrote ${outPath}`);
}

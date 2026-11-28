package apiserver

import (
	"errors"
	"net/http"
	"reflect"
)

var ErrInvalidComposition = errors.New("invalid API composition")

type Dependencies struct {
	Authorizer RequestAuthorizer
	Session    http.Handler
	Identity   http.Handler
	Inventory  http.Handler
	Risk       http.Handler
	Workflow   http.Handler
	Connector  http.Handler
}

type OperationDefinition struct {
	Method      string
	Pattern     string
	OperationID string
	Permission  string
	Security    []string
}

type dependencyKind uint8

const (
	sessionDependency dependencyKind = iota + 1
	identityDependency
	inventoryDependency
	riskDependency
	workflowDependency
	connectorDependency
	// evidencePackDependency is the agent evidence pack: a handler the
	// composition owns, which reads the other operations through the router.
	evidencePackDependency
	mcpDependency
)

type coreOperation struct {
	OperationDefinition
	dependency dependencyKind
}

var coreOperations = withBrowserExpectedScope([]coreOperation{
	{OperationDefinition{"POST", "/api/v1/addon-scan-uploads", "createPrivateAddonUpload", "manage_data_controls", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/cli/auth/start", "startCLILogin", "", []string{}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/cli/auth/approve", "approveCLILogin", "run_tests", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/cli/auth/exchange", "exchangeCLILogin", "", []string{}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/session/start", "startSession", "", []string{}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/session/bootstrap", "bootstrapSession", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/callback", "completeSessionCallback", "", []string{}}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/sign-out", "signOutSession", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/session/scopes", "listSessionScopes", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"PUT", "/api/v1/session/scope", "switchSessionScope", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/me", "getCurrentPrincipal", "", []string{"BrowserSession", "ProductAPIToken"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/organization", "getOrganization", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/organization", "updateOrganization", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/workspaces", "listWorkspaces", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/workspaces", "createWorkspace", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/workspaces/{id}", "getWorkspace", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/workspaces/{id}", "updateWorkspace", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/environments", "listEnvironments", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/environments", "createEnvironment", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/environments/{id}", "getEnvironment", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/environments/{id}", "updateEnvironment", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/members", "listMembers", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/roles", "listBuiltInRoles", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/admin/members/{id}", "updateMemberRole", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/members/{id}/access", "getMemberAccess", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/members/{id}", "removeMember", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/admin/members/{id}/profile", "updateMemberProfile", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/member-invitations", "inviteMember", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/member-invitations", "listMemberInvitations", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/group-mappings", "listGroupMappings", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/admin/group-mappings", "updateGroupMappings", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/sso-connections", "listSSOConnections", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/sso-connections", "createSSOConnection", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/sso-connections/{id}", "deleteSSOConnection", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/sso-connections/{id}/test", "testSSOConnection", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/scim-connections", "listSCIMConnections", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/scim-connections", "createSCIMConnection", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/scim-connections/{id}", "deleteSCIMConnection", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/api-tokens", "listAPITokens", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/api-tokens", "createAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/api-tokens/{id}/rotate", "rotateAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/api-token-policy", "getAPITokenPolicy", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PUT", "/api/v1/admin/api-token-policy", "putAPITokenPolicy", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/api-tokens/{id}", "revokeAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/api-token-reveal-grants", "listAPITokenRevealGrants", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/api-token-reveal-grants/{id}/reveal", "revealAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/api-token-reveal-grants/{id}", "acknowledgeAPITokenRevealGrant", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/audit-events", "listAuditEvents", "view_audit", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions", "listSessions", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions/{id}", "getSession", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions/{id}/events", "listSessionEvents", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions/{id}/events/{eventId}", "getSessionEvent", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/sessions/{id}", "revokeSession", "revoke_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/compliance/controls", "listComplianceControls", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/compliance/evidence", "listComplianceEvidence", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/organization/ai-controls", "getOrganizationAIControls", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/organization/ai-controls", "updateOrganizationAIControls", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/settings/ai-controls", "getEnvironmentAIControls", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/settings/ai-controls", "updateEnvironmentAIControls", "manage_data_controls", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/ai/qualifications", "listModelQualifications", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/settings/data-controls", "getDataControls", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/settings/data-controls", "updateDataControls", "manage_data_controls", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/settings/external-data-flows", "getExternalDataFlows", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/system/status", "getSystemStatus", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/system/components", "listSystemComponents", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/system/version", "getSystemVersion", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/recovery/intents/{id}", "getRecoveryIntent", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/recovery/intents/{id}", "putRecoveryIntent", "manage_identity", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/recovery/backups", "startRecoveryBackup", "manage_identity", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/recovery/backups/{id}", "getRecoveryBackup", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/recovery/restores", "startRecoveryRestore", "manage_identity", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/recovery/restores/{id}", "getRecoveryRestore", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/home/summary", "getHomeSummary", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/findings", "listFindings", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/findings/{id}", "getFinding", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"PATCH", "/api/v1/findings/{id}", "updateFinding", "manage_findings", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"POST", "/api/v1/findings/{id}/accept-risk", "acceptFindingRisk", "manage_findings", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"POST", "/api/v1/findings/{id}/ticket", "createFindingTicket", "manage_findings", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths", "listAttackPaths", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths/{id}", "getAttackPath", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths/{id}/break-options", "getAttackPathBreakOptions", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/search", "globalSearch", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/agents", "listAgents", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}", "getAgent", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"PATCH", "/api/v1/agents/{id}", "updateAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/suggestions", "listAgentSuggestions", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/agents/{id}/suggestions/refresh", "refreshAgentSuggestions", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/agents/{id}/suggestions/{toolId}/decision", "reviewAgentSuggestion", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/action-analysis", "getAgentActionAnalysis", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/agents/{id}/action-analysis", "putAgentActionAnalysis", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/chat/threads", "getAnalystThreads", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/chat/threads", "createAnalystThread", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/chat/threads/{id}", "getAnalystThread", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/chat/threads/{id}/stream", "streamAnalystThread", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/chat/threads/{id}/advisory", "getStudioRemediationAdvisory", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/chat/threads/{id}/advisory", "requestStudioRemediationAdvisory", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/sessions/{id}/intent", "getSessionIntent", "investigate_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/cases/{id}/verify", "getSecurityCaseVerification", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/cases/{id}/verify", "verifySecurityCase", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/custom", "listCustomSecurityAgents", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/custom", "createCustomSecurityAgent", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/custom/{id}", "getCustomSecurityAgent", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/security-agents/custom/{id}", "updateCustomSecurityAgent", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/agents/{id}/discovery/verify", "verifyAgentDiscovery", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/agents/{id}/purpose/draft", "draftAgentPurpose", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/addon-versions/{id}/deep-scan", "deepScanAddonVersion", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/agents/workforce", "listWorkforceInventory", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/posture-summary", "getAgentPostureSummary", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/purpose", "getAgentPurpose", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/agents/{id}/purpose", "putAgentPurpose", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/capabilities", "getAgentCapabilities", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/relationships", "getAgentRelationships", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/evidence-pack", "getAgentEvidencePack", "view", []string{"BrowserSession", "ProductAPIToken"}}, evidencePackDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/sessions", "listAgentSessions", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/access", "getAgentAccess", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/tools", "listTools", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/tools/{id}", "getTool", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/mcp-servers", "listMCPServers", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/mcp-registry", "listMCPRegistry", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"PUT", "/api/v1/mcp-registry", "putMCPRegistryEntry", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/identities", "listIdentities", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/identities/{id}", "getIdentity", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/runtimes", "listRuntimes", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/runtimes/{id}", "getRuntime", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/assets/{id}", "getAsset", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/browser-profiles/{id}", "getBrowserProfile", "manage_api_tokens", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/browser-profiles/{id}", "registerBrowserProfile", "manage_api_tokens", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/browser-profiles/{id}", "retireBrowserProfile", "manage_api_tokens", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/browser-profiles/{id}/observations", "recordBrowserOriginDays", "report_browser_usage", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/device-cohorts/{cohort}/pretool-policy", "getEndpointPolicyCohort", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/device-cohorts/{cohort}/pretool-policy", "updateEndpointPolicyCohort", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/device-cohorts/{cohort}/ticket-rollout", "getTicketCohort", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/device-cohorts/{cohort}/ticket-rollout", "publishTicketCohort", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/device-enrollments", "registerEndpointDevice", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/devices", "listEndpointDevices", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/devices/{id}", "getEndpointDevice", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/devices/{id}/credential-rotations", "rotateEndpointCredential", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/devices/{id}/retire", "retireEndpointDevice", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/devices/{id}/policy-bundle", "publishEndpointPolicy", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/device-enrollments/exchange", "exchangeEndpointEnrollment", "sync_endpoint", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/devices/{id}/heartbeat", "recordEndpointHeartbeat", "sync_endpoint", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/devices/{id}/inventory-snapshots", "recordEndpointInventory", "sync_endpoint", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/runtime/observations", "recordEndpointObservations", "sync_endpoint", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/devices/{id}/policy-bundle", "fetchEndpointPolicy", "sync_endpoint", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/sensors", "listSensors", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/sensors", "createSensorEnrollment", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/sensors/{id}", "getSensor", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/sensors/{id}", "updateSensor", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/sensors/{id}", "deleteSensor", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/sensors/{id}/rotate-token", "rotateSensorToken", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/sensors/{id}/coverage", "getSensorCoverage", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/workflow-mutation-receipts", "listWorkflowMutationReceipts", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/workflow-mutation-receipts/{id}/acknowledge", "acknowledgeWorkflowMutationReceipt", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies", "listPolicies", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies", "createPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies/{id}", "getPolicy", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/policies/{id}", "updatePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/policies/{id}", "deletePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/simulate", "simulatePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/rollout", "rolloutPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/disable", "disablePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies/{id}/decisions", "listPolicyDecisions", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integration-catalog", "listIntegrationCatalog", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations", "listIntegrations", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations", "createIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}", "getIntegration", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/integrations/{id}", "updateIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/integrations/{id}", "deleteIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/sync", "syncIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/syncs", "listIntegrationSyncs", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/syncs/{syncId}", "getIntegrationSync", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/sign-in-attempts/{attemptId}", "getSaaSSignInAttempt", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/schedule", "getIntegrationSchedule", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/integrations/{id}/schedule", "putIntegrationSchedule", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/integrations/{id}/schedule", "deleteIntegrationSchedule", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/freshness", "getIntegrationFreshness", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/setup-status", "getIntegrationSetupStatus", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/remediation-role", "getIntegrationRemediationRole", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/integrations/{id}/remediation-role", "putIntegrationRemediationRole", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/addon-scans/{id}", "getAddonScan", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/addon-scans/{id}/ci-attestation", "attestAddonScan", "submit_addon_scans", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/addon-versions/{id}/installations", "listAddonVersionInstallations", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/addon-versions/{id}/ci-origin", "getAddonCIOrigin", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/addon-scans", "submitAddonScan", "submit_addon_scans", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/addon-versions", "listAddonVersions", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/addon-versions/{id}", "getAddonVersion", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/addon-versions/{id}/deployment-approvals", "getAddonDeploymentApproval", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/addon-versions/{id}/deployment-approvals", "reviewAddonDeploymentApproval", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/addon-versions/{id}/review-decisions", "reviewAddonVersion", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/runtime/workload-bindings/{id}/containments/{runId}", "authorizeWorkloadContainment", "revoke_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/runtime/workload-bindings/{id}/containments/{runId}", "getWorkloadContainment", "revoke_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/runtime/workload-bindings/{id}/containments/{runId}", "releaseWorkloadContainment", "revoke_sessions", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/runtime/workload-bindings/{id}", "bindWorkloadCredential", "manage_api_tokens", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/runtime/workload-bindings/{id}", "getWorkloadCredentialBinding", "manage_api_tokens", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/runtime/action-decisions", "createWorkloadActionDecision", "decide_actions", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/runtime/actions/{actionId}/outcomes", "recordWorkloadActionOutcome", "decide_actions", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/guardrails/decisions", "createGuardrailDecision", "decide_guardrails", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/calibration/exports", "createCalibrationExport", "view_compliance", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/calibration/exports/{id}", "getCalibrationExport", "view_compliance", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/calibration/exports/{id}/download-grants", "createCalibrationDownloadGrant", "view_compliance", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/calibration/exports/{id}/download", "downloadCalibrationExport", "view_compliance", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/ai/qualifications/run", "runModelQualification", "manage_data_controls", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/ai/qualifications/runs/{id}", "getModelQualificationRun", "view_compliance", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/calibration/metrics", "getCalibrationMetrics", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/feedback", "submitAnalystFeedback", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/rules/{ruleId}/suppression-mode", "getRuleSuppressionMode", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/rules/{ruleId}/suppression-mode", "putRuleSuppressionMode", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/guardrails/policy", "getGuardrailPolicy", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/guardrails/policy", "putGuardrailPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/gateway/policy", "getGatewayPolicy", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/gateway/policy", "putGatewayPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/gateway/mcp-servers", "listMCPGatewayServers", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/gateway/mcp-servers/{id}", "putMCPGatewayServer", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/gateway/mcp-servers/{id}", "deleteMCPGatewayServer", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/gateway/activity", "listGatewayActivity", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/mcp", "callZaspMCP", "view", []string{"BrowserSession", "ProductAPIToken"}}, mcpDependency},
	{OperationDefinition{"GET", "/api/v1/runtime/workload-bindings/{id}/delegations", "getWorkloadDelegations", "manage_api_tokens", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/runtime/delegations/issue", "issueRuntimeDelegation", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/runtime/delegations/verify", "verifyRuntimeDelegation", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/gateway/mcp/{id}", "callMCPGateway", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/gateway/mcp/{id}", "closeMCPGatewaySession", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/gateway/llm/v1/chat/completions", "createGatewayChatCompletion", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/gateway/llm/v1/responses", "createGatewayResponse", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/gateway/llm/v1/messages", "createGatewayMessage", "use_gateway", []string{"ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/test-delivery", "testIntegrationWebhook", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/delivery-status", "getIntegrationWebhookStatus", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/authorize", "authorizeIntegration", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/reference-authorization", "authorizeIntegrationReference", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/authorization-remediation", "remediateIntegrationAuthorization", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/oauth/callback", "completeIntegrationOAuthCallback", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-templates", "listSecurityAgentTemplates", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-actions", "listSecurityActions", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-execution-controls", "getSecurityAgentExecutionControls", "manage_identity", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/security-agent-execution-controls", "setSecurityAgentExecutionControl", "manage_identity", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/security-agent-planner-pricing", "setSecurityAgentPlannerPricing", "manage_identity", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents", "listSecurityAgents", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents", "createSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/{id}", "getSecurityAgent", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/security-agents/{id}", "updateSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/security-agents/{id}", "deleteSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/{id}/activation", "activateSecurityAgent", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/{id}/activation", "getSecurityAgentActivation", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/{id}/simulate", "simulateSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents/{id}/runs", "runSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-runs", "listSecurityAgentRuns", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-runs/{id}", "getSecurityAgentRun", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-audit-events/{id}", "getSecurityAgentAuditEvent", "view_audit", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-activity/{kind}/{id}/runs", "listSecurityAgentActivityRuns", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-runs/{id}/activity/{kind}", "listSecurityAgentRunActivity", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agent-runs/{id}/cancel", "cancelSecurityAgentRun", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agent-runs/{id}/close", "closeSecurityAgentRun", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agent-runs/{id}/cleanup-recovery", "requestSingleTestCleanupRecovery", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-runs/{id}/cleanup-recovery", "getSingleTestCleanupRecovery", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-approvals", "listSecurityAgentApprovals", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-approvals/{id}", "getSecurityAgentApproval", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agent-approvals/{id}/decision", "decideSecurityAgentApproval", "manage_workflows", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/tests", "listTests", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/tests", "createTest", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/tests/{id}", "getTest", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/tests/{id}", "updateTest", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/tests/{id}/runs", "runTest", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/test-probes", "getTestProbeCatalog", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/tests/{id}/schedule", "getTestSchedule", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/tests/{id}/schedule", "putTestSchedule", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/test-runs", "listTestRuns", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/test-runs/{id}", "getTestRun", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/test-runs/{id}/ticket-verification", "getTicketVerification", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/test-runs/{id}/ticket-verification", "putTicketVerification", "run_tests", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/test-runs/{id}/cancel", "cancelTestRun", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/attack-lab/preflight", "preflightAttackLabRun", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/attack-lab/runs", "listAttackLabRuns", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/attack-lab/runs", "createAttackLabRun", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/attack-lab/runs/{id}", "getAttackLabRun", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/attack-lab/runs/{id}/cancel", "cancelAttackLabRun", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/attack-lab/runs/{id}/rerun", "rerunAttackLabRun", "run_tests", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
})

func withBrowserExpectedScope(operations []coreOperation) []coreOperation {
	for index := range operations {
		definition := &operations[index].OperationDefinition
		switch definition.OperationID {
		case "", "startSession", "bootstrapSession", "completeSessionCallback", "completeIntegrationOAuthCallback", "signOutSession":
			continue
		}
		for schemeIndex, scheme := range definition.Security {
			if scheme != "BrowserSession" {
				continue
			}
			definition.Security = append(definition.Security, "")
			copy(definition.Security[schemeIndex+1:], definition.Security[schemeIndex:])
			definition.Security[schemeIndex] = "BrowserExpectedScope"
			break
		}
	}
	return operations
}

func CoreOperations() []OperationDefinition {
	result := make([]OperationDefinition, len(coreOperations))
	for index, operation := range coreOperations {
		result[index] = operation.OperationDefinition
	}
	return result
}

func NewComposition(dependencies Dependencies) (http.Handler, error) {
	return newComposition(dependencies, nil)
}

func newComposition(dependencies Dependencies, exports http.Handler, compliance ...http.Handler) (http.Handler, error) {
	var complianceHandler http.Handler
	var agentExportHandler http.Handler
	if len(compliance) > 2 {
		return nil, ErrInvalidComposition
	}
	if len(compliance) >= 1 {
		complianceHandler = compliance[0]
	}
	if len(compliance) == 2 {
		agentExportHandler = compliance[1]
	}
	handlers := []http.Handler{dependencies.Session, dependencies.Identity, dependencies.Inventory, dependencies.Risk, dependencies.Workflow, dependencies.Connector}
	if complianceHandler != nil {
		handlers = append(handlers, complianceHandler)
	}
	if exports != nil {
		handlers = append(handlers, exports)
	}
	if agentExportHandler != nil {
		handlers = append(handlers, agentExportHandler)
	}
	seenHandlers := make(map[uintptr]struct{}, len(handlers))
	for _, handler := range handlers {
		identity, valid := handlerIdentity(handler)
		if !valid {
			return nil, ErrInvalidComposition
		}
		if _, duplicate := seenHandlers[identity]; duplicate {
			return nil, ErrInvalidComposition
		}
		seenHandlers[identity] = struct{}{}
	}
	// Seal discoverability to this router's actual production export surface.
	// A copy keeps disabled/enabled routers and the original dependencies independent.
	if session, ok := dependencies.Session.(*sessionHTTPHandler); ok {
		local := *session
		surface, installed := exports.(*auditExportProductionSurface)
		local.auditExportsInstalled = installed && surface != nil && surface.repository != nil && !nilInterface(surface.Handler)
		dependencies.Session = &local
	}

	operations := make([]Operation, 0, len(coreOperations))
	evidencePack := &agentEvidencePackHandler{}
	for _, definition := range coreOperations {
		handler := dependencyHandler(dependencies, definition.dependency)
		if definition.dependency == mcpDependency {
			handler = http.HandlerFunc(serveZaspMCP)
		}
		if definition.dependency == evidencePackDependency {
			handler = evidencePack
		}
		if stringIn(definition.OperationID, "getRecoveryIntent", "putRecoveryIntent") {
			endpoint := recoveryIntentEndpoint{}
			if surface, ok := handler.(*discoveryWorkflowSurface); ok {
				endpoint.db = surface.evidenceDB
			}
			handler = endpoint
		}
		if calibrationExportOperation(definition.OperationID) {
			endpoint := calibrationExportHTTP{}
			if surface, ok := handler.(*discoveryWorkflowSurface); ok {
				endpoint.db = surface.evidenceDB
			}
			switch c := complianceHandler.(type) {
			case *complianceProductionSurface:
				endpoint.reader = c.reader
			case *complianceHTTPHandler:
				endpoint.reader = c.reader
			}
			handler = endpoint
		}
		if complianceHandler != nil && stringIn(definition.OperationID, "listComplianceControls", "listComplianceEvidence") {
			handler = complianceHandler
		}
		security := make([]CredentialKind, 0, len(definition.Security))
		for _, scheme := range definition.Security {
			switch scheme {
			case "BrowserSession":
				security = append(security, CredentialBrowserSession)
			case "BrowserExpectedScope":
				// The exact header is a request precondition, not a credential.
			case "ProductAPIToken":
				security = append(security, CredentialBearerToken)
			}
		}
		requireCSRF := definition.OperationID == "signOutSession" || definition.OperationID == "switchSessionScope" || isMutation(definition.Method) && len(security) > 0
		operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Permission: definition.Permission, Security: security, RequireCSRF: requireCSRF, RequireFreshAuth: requiresFreshAuthentication(definition.OperationID), Handler: handler})
	}
	if exports != nil {
		operations = append(operations,
			Operation{Method: http.MethodPost, Pattern: "/api/v1/audit-exports", OperationID: "createAuditExport", Permission: "view_audit", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, RequireFreshAuth: true, Handler: exports},
			Operation{Method: http.MethodGet, Pattern: "/api/v1/audit-exports/{id}", OperationID: "getAuditExport", Permission: "view_audit", Security: []CredentialKind{CredentialBrowserSession}, Handler: exports},
		)
	}
	seenOperations := make(map[string]bool, len(operations))
	if complianceHandler != nil {
		_, readsOnly := complianceHandler.(*complianceReadSurface)
		for _, definition := range complianceOperations {
			// A storage-free surface never registers an export route.
			if readsOnly && !complianceReadOperation(definition.OperationID) {
				continue
			}
			operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Permission: "view_compliance", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: definition.Method == http.MethodPost, RequireFreshAuth: definition.OperationID == "createComplianceExport", Handler: complianceHandler})
		}
	}
	if agentExportHandler != nil {
		for _, definition := range securityAgentExportOperations {
			operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Permission: "view", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: definition.Method == http.MethodPost, Handler: agentExportHandler})
		}
	}
	for _, operation := range operations {
		if seenOperations[operation.OperationID] {
			return nil, ErrInvalidComposition
		}
		seenOperations[operation.OperationID] = true
	}
	router, err := NewRouter(operations)
	if err != nil {
		return nil, errors.Join(ErrInvalidComposition, err)
	}
	router.(*operationRouter).authorizer = dependencies.Authorizer
	return router, nil
}

func requiresFreshAuthentication(operationID string) bool {
	switch operationID {
	case "requestStudioRemediationAdvisory", "verifySecurityCase", "createCalibrationExport", "createCalibrationDownloadGrant", "runModelQualification", "submitAnalystFeedback", "putRuleSuppressionMode", "updateOrganizationAIControls", "updateEnvironmentAIControls", "registerBrowserProfile", "retireBrowserProfile":
		return true
	case "registerEndpointDevice", "rotateEndpointCredential", "retireEndpointDevice", "publishEndpointPolicy", "publishTicketCohort", "updateEndpointPolicyCohort":
		return true
	case "verifyAgentDiscovery", "draftAgentPurpose", "deepScanAddonVersion", "createCustomSecurityAgent", "updateCustomSecurityAgent", "reviewAddonDeploymentApproval", "reviewAddonVersion", "approveCLILogin", "createPrivateAddonUpload":
		return true
	case "updateOrganization", "inviteMember", "updateMemberProfile", "removeMember",
		"createWorkspace", "updateWorkspace", "createEnvironment", "updateEnvironment",
		"authorizeWorkloadContainment", "releaseWorkloadContainment", "bindWorkloadCredential", "updateMemberRole", "updateGroupMappings", "createAPIToken", "rotateAPIToken", "revokeAPIToken", "revealAPIToken", "acknowledgeAPITokenRevealGrant", "putAPITokenPolicy",
		"createSSOConnection", "deleteSSOConnection", "testSSOConnection", "createSCIMConnection", "deleteSCIMConnection",
		"revokeSession", "updateDataControls", "authorizeIntegration", "authorizeIntegrationReference", "remediateIntegrationAuthorization", "createSensorEnrollment", "rotateSensorToken":
		return true
	case "activateSecurityAgent", "decideSecurityAgentApproval", "setSecurityAgentExecutionControl", "setSecurityAgentPlannerPricing", "startRecoveryBackup", "startRecoveryRestore", "putRecoveryIntent":
		return true
	default:
		return false
	}
}

func handlerIdentity(handler http.Handler) (uintptr, bool) {
	if handler == nil {
		return 0, false
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return 0, false
		}
		identity := value.Pointer()
		return identity, identity != 0
	default:
		return 0, false
	}
}

func dependencyHandler(dependencies Dependencies, kind dependencyKind) http.Handler {
	switch kind {
	case sessionDependency:
		return dependencies.Session
	case identityDependency:
		return dependencies.Identity
	case inventoryDependency:
		return dependencies.Inventory
	case riskDependency:
		return dependencies.Risk
	case workflowDependency:
		return dependencies.Workflow
	case connectorDependency:
		return dependencies.Connector
	default:
		return nil
	}
}

package apiserver

import (
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"strings"
)

type authorizationOperationTarget struct{ Mode, Kind, Parameter string }

// Explicit operation inventory. Unknown operations cannot borrow the current
// environment's permission. Scope entries are product control-plane operations,
// not fallbacks for a missing resource or an unrecognized target identifier.
func authorizationTargetPolicy(operation string) (authorizationOperationTarget, error) {
	for _, group := range []struct{ mode, kind, parameter, operations string }{
		{"credential", "", "", "startSession bootstrapSession completeSessionCallback signOutSession listSessionScopes switchSessionScope getCurrentPrincipal"},
		{"scope", "organization_identity", "", "listMembers listBuiltInRoles updateMemberRole listSSOConnections createSSOConnection deleteSSOConnection testSSOConnection listSCIMConnections createSCIMConnection deleteSCIMConnection"},
		{"scope", "environment", "", "listGroupMappings updateGroupMappings listAPITokens createAPIToken rotateAPIToken revokeAPIToken listAPITokenRevealGrants revealAPIToken acknowledgeAPITokenRevealGrant getDataControls updateDataControls getExternalDataFlows getSystemStatus listSystemComponents getSystemVersion getSecurityAgentExecutionControls setSecurityAgentExecutionControl"},
		{"scope", "organization", "", "getOrganization"},
		{"scope", "environment", "", "createWorkspace createEnvironment startRecoveryBackup startRecoveryRestore createSensorEnrollment createPolicy createIntegration listIntegrationCatalog completeIntegrationOAuthCallback listSecurityAgentTemplates listSecurityActions createSecurityAgent createTest preflightAttackLabRun createAttackLabRun createComplianceExport createAuditExport"},
		{"collection", "workspace", "", "listWorkspaces"}, {"object", "workspace", "id", "getWorkspace updateWorkspace"},
		{"collection", "environment", "", "listEnvironments"}, {"object", "environment", "id", "getEnvironment updateEnvironment"},
		{"collection", "audit_event", "", "listAuditEvents"},
		{"collection", "session", "", "listSessions"}, {"object", "session", "id", "getSession listSessionEvents getSessionEvent revokeSession"},
		{"collection", "compliance_control", "", "listComplianceControls"}, {"collection", "compliance_evidence", "", "listComplianceEvidence"}, {"object", "compliance_evidence", "id", "getComplianceEvidence"},
		{"object", "recovery_backup", "id", "getRecoveryBackup"}, {"object", "recovery_restore", "id", "getRecoveryRestore"},
		{"collection", "*", "", "getHomeSummary globalSearch"},
		{"collection", "finding", "", "listFindings"}, {"object", "finding", "id", "getFinding updateFinding acceptFindingRisk createFindingTicket"},
		{"collection", "attack_path", "", "listAttackPaths"}, {"object", "attack_path", "id", "getAttackPath getAttackPathBreakOptions"},
		{"collection", "agent", "", "listAgents"}, {"object", "agent", "id", "getAgent updateAgent getAgentCapabilities getAgentRelationships listAgentSessions"},
		{"collection", "tool", "", "listTools"}, {"object", "tool", "id", "getTool"},
		{"collection", "identity", "", "listIdentities"}, {"object", "identity", "id", "getIdentity"},
		{"collection", "runtime", "", "listRuntimes"}, {"object", "runtime", "id", "getRuntime"}, {"object", "asset", "id", "getAsset"},
		{"collection", "sensor", "", "listSensors"}, {"object", "sensor", "id", "getSensor updateSensor deleteSensor rotateSensorToken getSensorCoverage"},
		{"collection", "workflow_receipt", "", "listWorkflowMutationReceipts"}, {"object", "workflow_receipt", "id", "acknowledgeWorkflowMutationReceipt"},
		{"collection", "policy", "", "listPolicies"}, {"object", "policy", "id", "getPolicy updatePolicy deletePolicy simulatePolicy rolloutPolicy disablePolicy listPolicyDecisions"},
		{"collection", "integration", "", "listIntegrations"}, {"object", "integration", "id", "getIntegration updateIntegration deleteIntegration syncIntegration listIntegrationSyncs getIntegrationSchedule putIntegrationSchedule deleteIntegrationSchedule getIntegrationFreshness getIntegrationSetupStatus testIntegrationWebhook getIntegrationWebhookStatus authorizeIntegration authorizeIntegrationReference remediateIntegrationAuthorization"},
		{"object", "discovery_sync", "syncId", "getIntegrationSync"},
		{"collection", "security_agent", "", "listSecurityAgents"}, {"object", "security_agent", "id", "getSecurityAgent updateSecurityAgent deleteSecurityAgent activateSecurityAgent getSecurityAgentActivation simulateSecurityAgent runSecurityAgent"},
		{"collection", "security_agent_run", "", "listSecurityAgentRuns"}, {"object", "security_agent_run", "id", "getSecurityAgentRun listSecurityAgentRunActivity cancelSecurityAgentRun requestSingleTestCleanupRecovery getSingleTestCleanupRecovery getSecurityAgentExport createSecurityAgentExportDownloadGrant downloadSecurityAgentExport"},
		{"object", "security_agent_audit", "id", "getSecurityAgentAuditEvent"}, {"object", "activity_target", "id", "listSecurityAgentActivityRuns"},
		{"collection", "security_agent_approval", "", "listSecurityAgentApprovals"}, {"object", "security_agent_approval", "id", "getSecurityAgentApproval decideSecurityAgentApproval"},
		{"collection", "test", "", "listTests"}, {"object", "test", "id", "getTest updateTest runTest"},
		{"collection", "test_run", "", "listTestRuns"}, {"object", "test_run", "id", "getTestRun cancelTestRun"},
		{"collection", "attack_lab_run", "", "listAttackLabRuns"}, {"object", "attack_lab_run", "id", "getAttackLabRun cancelAttackLabRun rerunAttackLabRun"},
		{"object", "compliance_export", "id", "getComplianceExport createComplianceDownloadGrant downloadComplianceExport"},
		{"object", "audit_export", "id", "getAuditExport"},
	} {
		for _, id := range strings.Fields(group.operations) {
			if operation == id {
				return authorizationOperationTarget{group.mode, group.kind, group.parameter}, nil
			}
		}
	}
	return authorizationOperationTarget{}, authorization.ErrInvalid
}

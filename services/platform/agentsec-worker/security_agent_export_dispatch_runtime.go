package main

import "github.com/zasp-ai/zasp-sec/services/platform/apiserver"

// Admission clears the parent lease and hands off to the durable export lane.
// It proves neither artifact availability nor a verified security outcome.
func validSecurityAgentExportDispatch(result apiserver.SecurityAgentExecuteResult, claim apiserver.SecurityAgentRunClaim) bool {
	value := result.ExportDispatch
	return value != nil && claim.Prepared &&
		result.State == "verifying" && result.RunID == claim.RunID &&
		result.Version > claim.Version && result.Version <= 1000000 &&
		result.StepID == value.StepID && result.Version == value.RunVersion &&
		result.EffectState == "" && result.OutcomeID == "" && result.ResultDigest == "" &&
		value.OrganizationID == claim.OrganizationID && value.WorkspaceID == claim.WorkspaceID && value.EnvironmentID == claim.EnvironmentID &&
		value.RunID == claim.RunID && value.State == "pending" &&
		validSecurityAgentPlannerProductID(value.StepID) && validSecurityAgentPlannerProductID(value.ExportID)
}

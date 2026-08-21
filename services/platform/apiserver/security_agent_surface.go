package apiserver

import "net/http"

func NewSecurityAgentWorkflowSurface(workflow, securityAgent http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(securityAgent) {
		return nil, ErrRepositoryConfiguration
	}
	return &securityAgentWorkflowSurface{workflow: workflow, securityAgent: securityAgent}, nil
}

type securityAgentWorkflowSurface struct {
	workflow      http.Handler
	securityAgent http.Handler
}

func (surface *securityAgentWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "activateSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval":
		surface.securityAgent.ServeHTTP(writer, request)
	default:
		surface.workflow.ServeHTTP(writer, request)
	}
}

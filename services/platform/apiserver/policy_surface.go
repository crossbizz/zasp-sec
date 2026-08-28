package apiserver

import "net/http"

func NewPolicyWorkflowSurface(workflow, policy http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(policy) {
		return nil, ErrRepositoryConfiguration
	}
	return &policyWorkflowSurface{workflow: workflow, policy: policy}, nil
}

type policyWorkflowSurface struct {
	workflow http.Handler
	policy   http.Handler
}

func (surface *policyWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if routed.OperationID == "simulatePolicy" || routed.OperationID == "listPolicyDecisions" {
		surface.policy.ServeHTTP(writer, request)
		return
	}
	surface.workflow.ServeHTTP(writer, request)
}

package apiserver

import "net/http"

func NewRecoveryWorkflowSurface(workflow, recovery http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(recovery) {
		return nil, ErrRepositoryConfiguration
	}
	return &recoveryWorkflowSurface{workflow: workflow, recovery: recovery}, nil
}

type recoveryWorkflowSurface struct {
	workflow http.Handler
	recovery http.Handler
}

func (surface *recoveryWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if stringIn(routed.OperationID, "startRecoveryBackup", "getRecoveryBackup", "startRecoveryRestore", "getRecoveryRestore") {
		surface.recovery.ServeHTTP(writer, request)
		return
	}
	surface.workflow.ServeHTTP(writer, request)
}

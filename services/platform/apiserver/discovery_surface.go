package apiserver

import "net/http"

// NewDiscoveryWorkflowSurface composes the public discovery lifecycle into the
// workflow route family without teaching the legacy workflow handler about
// collection execution internals.
func NewDiscoveryWorkflowSurface(workflow, discovery http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(discovery) {
		return nil, ErrRepositoryConfiguration
	}
	return &discoveryWorkflowSurface{workflow: workflow, discovery: discovery}, nil
}

type discoveryWorkflowSurface struct {
	workflow  http.Handler
	discovery http.Handler
}

func (surface *discoveryWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "syncIntegration", "listIntegrationSyncs", "getIntegrationSync", "getIntegrationSchedule", "putIntegrationSchedule", "deleteIntegrationSchedule", "getIntegrationFreshness":
		surface.discovery.ServeHTTP(writer, request)
	default:
		surface.workflow.ServeHTTP(writer, request)
	}
}

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
	evidenceDB JSONDatabase
	// guardrail serves the guardrail decision API and the Environment's
	// guardrail policy. It is nil where they are not composed.
	addons    *addonReviewHandler
	actions   *workloadActionHandler
	fleet     *endpointFleetHandler
	guardrail *guardrailHTTPHandler
	// gateway serves the hosted gateway: its traffic routes and their
	// management. It is nil where it is not composed.
	gateway   *hostedGatewayHandler
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
	case "getBrowserProfile", "registerBrowserProfile", "retireBrowserProfile", "recordBrowserOriginDays":
		if surface.evidenceDB == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		serveBrowserProfile(surface.evidenceDB, writer, request, routed)
	case "getTicketVerification", "putTicketVerification":
		if surface.evidenceDB == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		serveTicketProof(surface.evidenceDB, writer, request, routed)
	case "getAgentActionAnalysis", "putAgentActionAnalysis":
		if surface.evidenceDB == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		serveActionAnalysis(surface.evidenceDB, writer, request, routed)
	case "getAgentPurpose", "putAgentPurpose":
		if surface.evidenceDB == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		serveAgentPurpose(surface.evidenceDB, writer, request, routed)
	case "getTicketCohort", "publishTicketCohort":
		if surface.fleet == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.fleet.cohort(writer, request, routed)
	case "registerEndpointDevice", "listEndpointDevices", "getEndpointDevice", "rotateEndpointCredential", "retireEndpointDevice", "publishEndpointPolicy", "exchangeEndpointEnrollment", "recordEndpointHeartbeat", "recordEndpointInventory", "recordEndpointObservations", "fetchEndpointPolicy":
		if surface.fleet == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.fleet.serve(writer, request, routed)
	case "listAddonVersionInstallations", "getAddonScan", "attestAddonScan", "getAddonCIOrigin", "submitAddonScan", "listAddonVersions", "getAddonVersion", "reviewAddonVersion":
		if surface.addons == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.addons.ServeHTTP(writer, request, routed)
	case "authorizeWorkloadContainment", "releaseWorkloadContainment", "getWorkloadContainment":
		if surface.actions == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.actions.containment(writer, request, routed)
	case "bindWorkloadCredential", "getWorkloadCredentialBinding":
		if surface.actions == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.actions.binding(writer, request, routed)
	case "createWorkloadActionDecision", "recordWorkloadActionOutcome":
		if surface.actions == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.actions.serve(writer, request, routed)
	case "createGuardrailDecision", "getGuardrailPolicy", "putGuardrailPolicy":
		if surface.guardrail == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.guardrail.ServeHTTP(writer, request, routed.OperationID)
	case "callMCPGateway", "closeMCPGatewaySession", "createGatewayChatCompletion", "createGatewayResponse", "createGatewayMessage",
		"getGatewayPolicy", "putGatewayPolicy", "listMCPGatewayServers", "putMCPGatewayServer", "deleteMCPGatewayServer", "listGatewayActivity":
		if surface.gateway == nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		surface.gateway.ServeHTTP(writer, request, routed)
	case "syncIntegration", "listIntegrationSyncs", "getIntegrationSync", "getIntegrationSchedule", "putIntegrationSchedule", "deleteIntegrationSchedule", "getIntegrationFreshness", "getIntegrationSetupStatus", "getIntegrationRemediationRole", "putIntegrationRemediationRole":
		surface.discovery.ServeHTTP(writer, request)
	default:
		surface.workflow.ServeHTTP(writer, request)
	}
}

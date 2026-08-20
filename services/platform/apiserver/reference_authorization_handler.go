package apiserver

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
)

var strictQuotedVersionPattern = regexp.MustCompile(`^"[1-9][0-9]*"$`)

type ReferenceAuthorizationHTTPConfig struct {
	Repository ReferenceAuthorizationAuthority
	Workflows  connectorWorkflowReader
	Registry   *ReferenceConnectorRegistry
}

type referenceAuthorizationHTTPHandler struct {
	repository ReferenceAuthorizationAuthority
	workflows  connectorWorkflowReader
	registry   *ReferenceConnectorRegistry
}

func NewReferenceAuthorizationHTTPHandler(config ReferenceAuthorizationHTTPConfig) (http.Handler, error) {
	if nilInterface(config.Repository) || nilInterface(config.Workflows) || config.Registry == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &referenceAuthorizationHTTPHandler{repository: config.Repository, workflows: config.Workflows, registry: config.Registry}, nil
}

func (handler *referenceAuthorizationHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	integrationID := routed.PathParameters["id"]
	idempotencyKey := request.Header.Get("Idempotency-Key")
	expectedVersion, versionErr := parseReferenceAuthorizationVersion(request.Header.Values("If-Match"))
	if !identityOK || !routedOK || routed.OperationID != "authorizeIntegrationReference" || identity.CredentialKind != CredentialBrowserSession {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if request.Method != http.MethodPost || !identity.FreshAuthenticated || !exactHeaderValue(request.Header.Values("X-Zasp-Fresh-Auth"), "confirmed") || !validProductID(integrationID) || versionErr != nil || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) || decodeEmptyInput(request) != nil {
		if !identity.FreshAuthenticated {
			writeWorkflowMutationError(writer, request, ErrRepositoryAuthorization)
		} else {
			writeProductionError(writer, request, ErrRepositoryOperation)
		}
		return
	}
	replay, replayed, err := handler.repository.Replay(request.Context(), identity, ReferenceAuthorizationReplay{IntegrationID: integrationID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion})
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	if replayed {
		writeReferenceAuthorizationResult(writer, request, replay)
		return
	}
	workflow, err := handler.workflows.GetWorkflow(request.Context(), identity.Scope, "integration", integrationID)
	provider, configuration, reference, status, ok := authorizedReferenceIntegration(workflow, integrationID)
	if err != nil || !ok {
		writeProductionError(writer, request, firstError(err, ErrRepositoryNotFound))
		return
	}
	intent := referenceAuthorizationIntent(identity, integrationID, provider, idempotencyKey, expectedVersion, configuration)
	if workflow.Version != expectedVersion || !stringIn(status, "configured", "pending_authorization", "degraded") {
		writeWorkflowMutationError(writer, request, ErrRepositoryConflict)
		return
	}
	if err := handler.registry.Probe(request.Context(), ReferenceAuthorizationTarget{Provider: provider, IntegrationID: integrationID, ConnectionReference: reference, Configuration: configuration}); err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	auditID, auditErr := newWorkflowProductID()
	receiptID, receiptErr := newWorkflowProductID()
	correlationID := correlationIDFromContext(request.Context())
	if auditErr != nil || receiptErr != nil || !validProductID(correlationID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.Complete(request.Context(), identity, ReferenceAuthorizationCompletion{
		IntegrationID: integrationID, Provider: provider, ConnectionID: referenceConnectionID(identity.Scope, integrationID, provider), ConnectionReference: reference,
		IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, Configuration: configuration, Intent: intent,
		AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID,
	})
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	writeReferenceAuthorizationResult(writer, request, result)
}

func parseReferenceAuthorizationVersion(values []string) (int64, error) {
	if len(values) != 1 || !strictQuotedVersionPattern.MatchString(values[0]) {
		return 0, errPreconditionRequired
	}
	version, err := strconv.ParseInt(values[0][1:len(values[0])-1], 10, 64)
	if err != nil || version < 1 || version > 1000000 {
		return 0, errPreconditionRequired
	}
	return version, nil
}

func exactHeaderValue(values []string, expected string) bool {
	return len(values) == 1 && values[0] == expected
}

func authorizedReferenceIntegration(value WorkflowValue, expectedID string) (string, json.RawMessage, string, string, bool) {
	if value.Version < 1 || len(value.Body) < 2 || len(value.Body) > 16<<10 {
		return "", nil, "", "", false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(value.Body, &fields) != nil {
		return "", nil, "", "", false
	}
	var id, provider, status string
	if json.Unmarshal(fields["id"], &id) != nil || json.Unmarshal(fields["connector_key"], &provider) != nil || json.Unmarshal(fields["status"], &status) != nil || id != expectedID || !stringIn(provider, "aws", "kubernetes") || !stringIn(status, "configured", "pending_authorization", "degraded", "active") {
		return "", nil, "", "", false
	}
	configuration, reference, valid := parseReferenceAuthorizationConfiguration(provider, fields["configuration"])
	return provider, configuration, reference, status, valid
}

func writeReferenceAuthorizationResult(writer http.ResponseWriter, request *http.Request, result WorkflowMutationResult) {
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writer.Header().Set("X-Audit-ID", result.AuditID)
	writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	writeProductionResponse(writer, request, http.StatusOK, result.Body, nil)
}

// connectorSurfaceHandler keeps OAuth and reference authorization as distinct
// authorities while presenting the one connector dependency required by the
// generated operation router.
type connectorSurfaceHandler struct {
	oauth, reference http.Handler
}

func NewConnectorSurfaceHandler(oauth, reference http.Handler) (http.Handler, error) {
	if nilInterface(oauth) || nilInterface(reference) {
		return nil, ErrRepositoryConfiguration
	}
	return &connectorSurfaceHandler{oauth: oauth, reference: reference}, nil
}

func (handler *connectorSurfaceHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if ok && routed.OperationID == "authorizeIntegrationReference" {
		handler.reference.ServeHTTP(writer, request)
		return
	}
	handler.oauth.ServeHTTP(writer, request)
}

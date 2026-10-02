package apiserver

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
)

// This recognizes only forbidden authority overrides in otherwise structurally
// valid integration requests. Ordinary malformed requests retain their errors.
func integrationAuthorityOverride(intent json.RawMessage, operation string) bool {
	if !stringIn(operation, "createIntegration", "updateIntegration") {
		return false
	}
	var envelope struct {
		Body json.RawMessage `json:"body"`
	}
	if json.Unmarshal(intent, &envelope) != nil {
		return false
	}
	var input struct {
		ConnectorKey  string            `json:"connector_key"`
		Name          string            `json:"name"`
		Configuration map[string]string `json:"configuration"`
	}
	if json.Unmarshal(envelope.Body, &input) != nil || input.Name == "" || len(input.Name) > 128 || (operation == "createIntegration" && input.ConnectorKey == "") {
		return false
	}
	for _, key := range []string{"nango_url", "nango_base_url", "proxy_url", "provider_url"} {
		if _, present := input.Configuration[key]; present {
			return true
		}
	}
	return false
}

func (handler *workflowHTTPHandler) writeIntegrationRejection(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation, intent json.RawMessage, original error) {
	if !(errors.Is(original, ErrRepositoryOperation) || errors.Is(original, ErrRepositoryConflict)) || !integrationAuthorityOverride(intent, routed.OperationID) {
		writeWorkflowMutationError(writer, request, original)
		return
	}
	credential, _, ok := requestCredential(request)
	if !ok || credential.Kind != identity.CredentialKind {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	target := identity.Scope.EnvironmentID().String()
	_, checked := requestAuthorizationFromContext(request.Context())
	if routed.OperationID == "updateIntegration" {
		target = routed.PathParameters["id"]
		if !checked {
			if _, err := handler.repository.GetWorkflow(request.Context(), identity.Scope, "integration", target); err != nil {
				writeWorkflowMutationError(writer, request, err)
				return
			}
		}
		// The checked append independently validates both authoritative target
		// and live workflow row. A second generic preparation read here could
		// mask its credential/hidden-target classification after a lock wait.
	}
	auditor, ok := handler.repository.(integrationRejectionAuditor)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	auditID, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	err = auditor.AuditIntegrationRejection(request.Context(), identity, IntegrationRejection{CredentialDigest: digest[:], Operation: routed.OperationID, TargetID: target, AuditID: auditID, CorrelationID: correlationIDFromContext(request.Context())})
	if err != nil {
		if checked && errors.Is(err, ErrRepositoryConflict) {
			writeProductionStatusError(writer, request, http.StatusConflict, "authorization_changed", "Authorization changed; retry from a fresh request", true)
			return
		}
		writeWorkflowMutationError(writer, request, classifiedRejectionAuditError(err))
		return
	}
	writeWorkflowMutationError(writer, request, original)
}

func classifiedRejectionAuditError(err error) error {
	for _, permitted := range []error{ErrRepositoryAuthentication, ErrRepositoryAuthorization, ErrRepositoryNotFound} {
		if errors.Is(err, permitted) {
			return permitted
		}
	}
	return ErrRepositoryUnavailable
}

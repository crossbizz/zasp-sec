package apiserver

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

type SecurityAgentActivation struct {
	DefinitionID       string
	IdempotencyKey     string
	ExpectedVersion    int64
	TargetActivation   string
	FreshAuthExpiresAt time.Time
	AuditID            string
	CorrelationID      string
	ReceiptID          string
}

type SecurityAgentActivationResult struct {
	ID            string `json:"id"`
	Activation    string `json:"activation"`
	Enabled       bool   `json:"enabled"`
	Version       int64  `json:"version"`
	AuditID       string `json:"audit_id"`
	CorrelationID string `json:"correlation_id"`
	ReceiptID     string `json:"receipt_id"`
	Replayed      bool   `json:"replayed"`
}

type SecurityAgentPublicAuthority interface {
	ActivateSecurityAgent(context.Context, RequestIdentity, SecurityAgentActivation) (SecurityAgentActivationResult, error)
}

type SecurityAgentPublicHandlerConfig struct {
	Clock        func() time.Time
	NewProductID func() (string, error)
}

type securityAgentPublicHTTPHandler struct {
	repository  SecurityAgentPublicAuthority
	definitions http.Handler
	config      SecurityAgentPublicHandlerConfig
}

func NewSecurityAgentPublicHTTPHandler(repository SecurityAgentPublicAuthority, definitions http.Handler, config SecurityAgentPublicHandlerConfig) (http.Handler, error) {
	if nilInterface(repository) || nilInterface(definitions) || config.Clock == nil || config.NewProductID == nil || config.Clock().IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	return &securityAgentPublicHTTPHandler{repository: repository, definitions: definitions, config: config}, nil
}

func (handler *securityAgentPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if routed.OperationID != "activateSecurityAgent" {
		handler.definitions.ServeHTTP(writer, request)
		return
	}
	handler.activate(writer, request, routed)
}

func (handler *securityAgentPublicHTTPHandler) activate(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	idempotencyKey, expectedVersion, headersOK := discoveryMutationHeaders(request, false)
	definitionID := routed.PathParameters["id"]
	var input struct {
		Activation string `json:"activation"`
	}
	now := handler.config.Clock().UTC()
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || !identity.FreshAuthExpiresAt.After(now) || identity.FreshAuthExpiresAt.After(now.Add(5*time.Minute)) || !exactHeaderValue(request.Header.Values("X-Zasp-Fresh-Auth"), "confirmed") || !headersOK || !validProductID(definitionID) || decodeProductionJSON(request, &input) != nil || !stringIn(input.Activation, "validated", "supervised", "autonomous") {
		if ok && (!identity.FreshAuthenticated || identity.CredentialKind != CredentialBrowserSession || identity.FreshAuthExpiresAt.IsZero() || !identity.FreshAuthExpiresAt.After(now)) {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	auditID, auditErr := handler.config.NewProductID()
	receiptID, receiptErr := handler.config.NewProductID()
	correlationID := correlationIDFromContext(request.Context())
	if auditErr != nil || receiptErr != nil || !validProductID(auditID) || !validProductID(receiptID) || auditID == receiptID || !validProductID(correlationID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.ActivateSecurityAgent(request.Context(), identity, SecurityAgentActivation{
		DefinitionID: definitionID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, TargetActivation: input.Activation,
		FreshAuthExpiresAt: identity.FreshAuthExpiresAt.UTC(), AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID,
	})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	wantEnabled := input.Activation == "supervised" || input.Activation == "autonomous"
	if result.ID != definitionID || result.Activation != input.Activation || result.Enabled != wantEnabled || result.Version != expectedVersion+1 || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", result.AuditID)
	writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"id": result.ID, "activation": result.Activation, "enabled": result.Enabled, "version": result.Version}, nil)
}

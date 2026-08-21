package apiserver

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var securityAgentPlanHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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

type SecurityAgentSimulationRequest struct {
	DefinitionID, IdempotencyKey, RunID, Goal string
	ExpectedVersion                           int64
	EvidenceIDs                               []string
	ExpiresAt                                 time.Time
	AuditID, CorrelationID, ReceiptID         string
}

type SecurityAgentSimulationStep struct {
	Index            int    `json:"index"`
	Action           string `json:"action"`
	Authorization    string `json:"authorization"`
	ApprovalRequired bool   `json:"approval_required"`
}

type SecurityAgentSimulationResult struct {
	RunID, DefinitionID, PlanHash, CatalogVersion string
	DefinitionVersion, Version                    int64
	ExpiresAt                                     time.Time
	MatchedEvidenceIDs                            []string
	Summary                                       string
	Steps                                         []SecurityAgentSimulationStep
	SideEffects                                   int
	AuditID, CorrelationID, ReceiptID             string
	Replayed                                      bool
}

func (result *SecurityAgentSimulationResult) UnmarshalJSON(value []byte) error {
	type simulationWire struct {
		RunID              string                        `json:"run_id"`
		DefinitionID       string                        `json:"definition_id"`
		DefinitionVersion  int64                         `json:"definition_version"`
		PlanHash           string                        `json:"plan_hash"`
		CatalogVersion     string                        `json:"catalog_version"`
		ExpiresAt          time.Time                     `json:"expires_at"`
		MatchedEvidenceIDs []string                      `json:"matched_evidence_ids"`
		Summary            string                        `json:"summary"`
		Steps              []SecurityAgentSimulationStep `json:"steps"`
		SideEffects        int                           `json:"side_effects"`
		Version            int64                         `json:"version"`
		AuditID            string                        `json:"audit_id"`
		CorrelationID      string                        `json:"correlation_id"`
		ReceiptID          string                        `json:"receipt_id"`
		Replayed           bool                          `json:"replayed"`
	}
	var decoded simulationWire
	if decodeStrictDiscovery(value, &decoded) != nil {
		return ErrRepositoryUnavailable
	}
	*result = SecurityAgentSimulationResult{RunID: decoded.RunID, DefinitionID: decoded.DefinitionID, DefinitionVersion: decoded.DefinitionVersion, PlanHash: decoded.PlanHash, CatalogVersion: decoded.CatalogVersion, ExpiresAt: decoded.ExpiresAt, MatchedEvidenceIDs: decoded.MatchedEvidenceIDs, Summary: decoded.Summary, Steps: decoded.Steps, SideEffects: decoded.SideEffects, Version: decoded.Version, AuditID: decoded.AuditID, CorrelationID: decoded.CorrelationID, ReceiptID: decoded.ReceiptID, Replayed: decoded.Replayed}
	return nil
}

type SecurityAgentPublicAuthority interface {
	ActivateSecurityAgent(context.Context, RequestIdentity, SecurityAgentActivation) (SecurityAgentActivationResult, error)
	SimulateSecurityAgent(context.Context, RequestIdentity, SecurityAgentSimulationRequest) (SecurityAgentSimulationResult, error)
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
	if routed.OperationID != "activateSecurityAgent" && routed.OperationID != "simulateSecurityAgent" {
		handler.definitions.ServeHTTP(writer, request)
		return
	}
	if routed.OperationID == "activateSecurityAgent" {
		handler.activate(writer, request, routed)
		return
	}
	handler.simulate(writer, request, routed)
}

func (handler *securityAgentPublicHTTPHandler) simulate(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	idempotencyKey, expectedVersion, headersOK := discoveryMutationHeaders(request, false)
	definitionID := routed.PathParameters["id"]
	var input struct {
		Goal          string   `json:"goal"`
		EnvironmentID string   `json:"environment_id"`
		EvidenceIDs   []string `json:"evidence_ids"`
	}
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !headersOK || !validProductID(definitionID) || decodeProductionJSON(request, &input) != nil || input.EnvironmentID != identity.Scope.EnvironmentID().String() || !validSecurityAgentText(input.Goal, 1024) || len(input.EvidenceIDs) < 1 || len(input.EvidenceIDs) > 100 || !validUniqueProductIDs(input.EvidenceIDs) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	evidenceIDs := append([]string(nil), input.EvidenceIDs...)
	sort.Strings(evidenceIDs)
	ids := make([]string, 3)
	for index := range ids {
		value, err := handler.config.NewProductID()
		if err != nil || !validProductID(value) {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		ids[index] = value
	}
	if ids[0] == ids[1] || ids[0] == ids[2] || ids[1] == ids[2] {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	correlationID := correlationIDFromContext(request.Context())
	if !validProductID(correlationID) || correlationID == ids[0] || correlationID == ids[1] || correlationID == ids[2] {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	expiresAt := handler.config.Clock().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
	result, err := handler.repository.SimulateSecurityAgent(request.Context(), identity, SecurityAgentSimulationRequest{DefinitionID: definitionID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, RunID: ids[0], Goal: input.Goal, EvidenceIDs: evidenceIDs, ExpiresAt: expiresAt, AuditID: ids[1], CorrelationID: correlationID, ReceiptID: ids[2]})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validSecurityAgentSimulation(result, definitionID, expectedVersion, evidenceIDs, expiresAt) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", result.AuditID)
	if identity.CredentialKind == CredentialBrowserSession {
		writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"run_id": result.RunID, "definition_id": result.DefinitionID, "definition_version": result.DefinitionVersion, "plan_hash": result.PlanHash, "catalog_version": result.CatalogVersion, "expires_at": result.ExpiresAt, "matched_evidence_ids": result.MatchedEvidenceIDs, "summary": result.Summary, "steps": result.Steps, "side_effects": result.SideEffects, "version": result.Version}, nil)
}

func validSecurityAgentText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validSecurityAgentSimulation(result SecurityAgentSimulationResult, definitionID string, expectedVersion int64, evidenceIDs []string, expiresAt time.Time) bool {
	if !validProductID(result.RunID) || result.DefinitionID != definitionID || result.DefinitionVersion != expectedVersion || !securityAgentPlanHashPattern.MatchString(result.PlanHash) || result.CatalogVersion != "security-agent-actions-v1" || !result.ExpiresAt.Equal(expiresAt) || result.ExpiresAt.Location() != time.UTC || !reflectStringSlices(result.MatchedEvidenceIDs, evidenceIDs) || !validSecurityAgentText(result.Summary, 500) || len(result.Steps) < 1 || len(result.Steps) > 100 || result.SideEffects != 0 || result.Version != 1 || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) {
		return false
	}
	for index, step := range result.Steps {
		if step.Index != index || !validSecurityAgentText(step.Action, 128) || !stringIn(step.Authorization, "allow", "approval_required", "deny") || step.ApprovalRequired != (step.Authorization == "approval_required") {
			return false
		}
	}
	return true
}

func reflectStringSlices(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
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

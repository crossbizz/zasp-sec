package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

type SecurityAgentRunRequest struct {
	DefinitionID, IdempotencyKey, RunID, TriggerKind, TriggerID string
	ExpectedVersion                                             int64
	AuditID, CorrelationID, ReceiptID                           string
}

type SecurityAgentRunResult struct {
	ID                string   `json:"id"`
	AgentID           string   `json:"agent_id"`
	State             string   `json:"state"`
	EvidenceIDs       []string `json:"evidence_ids"`
	DefinitionVersion int64    `json:"definition_version"`
	Version           int64    `json:"version"`
	AuditID           string   `json:"audit_id"`
	CorrelationID     string   `json:"correlation_id"`
	ReceiptID         string   `json:"receipt_id"`
	Replayed          bool     `json:"replayed"`
}

type SecurityAgentRun struct {
	ID                string   `json:"id"`
	AgentID           string   `json:"agent_id"`
	State             string   `json:"state"`
	EvidenceIDs       []string `json:"evidence_ids"`
	DefinitionVersion int64    `json:"definition_version"`
	Version           int64    `json:"version"`
}

type SecurityAgentRunPageRequest struct {
	DefinitionID    string
	State           string
	BeforeCreatedAt time.Time
	BeforeID        string
	Limit           int
}

type SecurityAgentRunPage struct {
	Items         []SecurityAgentRun
	NextCreatedAt *time.Time
	NextID        string
}

type SecurityAgentPlanStep struct {
	ID            string `json:"id"`
	Index         int    `json:"index"`
	Action        string `json:"action"`
	Authorization string `json:"authorization"`
	State         string `json:"state"`
	Version       int64  `json:"version"`
}

type SecurityAgentPlanSummary struct {
	PlanHash       string                  `json:"plan_hash"`
	CatalogVersion string                  `json:"catalog_version"`
	ExpiresAt      time.Time               `json:"expires_at"`
	Steps          []SecurityAgentPlanStep `json:"steps"`
}

type SecurityAgentExecutionStep struct {
	StepID       string `json:"step_id"`
	Action       string `json:"action"`
	State        string `json:"state"`
	OutcomeID    string `json:"outcome_id,omitempty"`
	ResultDigest string `json:"result_digest,omitempty"`
	Version      int64  `json:"version"`
}

type SecurityAgentApproval struct {
	ID              string    `json:"id"`
	RunID           string    `json:"run_id"`
	StepID          string    `json:"step_id"`
	State           string    `json:"state"`
	ExpiresAt       time.Time `json:"expires_at"`
	Version         int64     `json:"version"`
	ExpectedEffect  string    `json:"expected_effect"`
	Reversible      bool      `json:"reversible"`
	TTLSeconds      int       `json:"ttl_seconds"`
	EvidenceSummary []string  `json:"evidence_summary"`
}

type SecurityAgentRunDetail struct {
	Run           SecurityAgentRun             `json:"run"`
	EvidenceIDs   []string                     `json:"evidence_ids"`
	Plan          *SecurityAgentPlanSummary    `json:"plan"`
	Authorization string                       `json:"authorization"`
	Approvals     []SecurityAgentApproval      `json:"approvals"`
	Execution     []SecurityAgentExecutionStep `json:"execution"`
	Verification  string                       `json:"verification"`
}

type SecurityAgentApprovalPageRequest struct {
	State           string
	RunID           string
	BeforeCreatedAt time.Time
	BeforeID        string
	Limit           int
}

type SecurityAgentApprovalPage struct {
	Items         []SecurityAgentApproval
	NextCreatedAt *time.Time
	NextID        string
}

type SecurityAgentCancelRequest struct {
	RunID, IdempotencyKey             string
	ExpectedVersion                   int64
	AuditID, CorrelationID, ReceiptID string
}

type SecurityAgentApprovalDecisionRequest struct {
	ApprovalID, IdempotencyKey, Decision string
	ExpectedVersion                      int64
	FreshAuthAt                          time.Time
	AuditID, CorrelationID, ReceiptID    string
}

type SecurityAgentApprovalResult struct {
	ID              string    `json:"id"`
	RunID           string    `json:"run_id"`
	StepID          string    `json:"step_id"`
	State           string    `json:"state"`
	ExpiresAt       time.Time `json:"expires_at"`
	Version         int64     `json:"version"`
	ExpectedEffect  string    `json:"expected_effect"`
	Reversible      bool      `json:"reversible"`
	TTLSeconds      int       `json:"ttl_seconds"`
	EvidenceSummary []string  `json:"evidence_summary"`
	AuditID         string    `json:"audit_id"`
	CorrelationID   string    `json:"correlation_id"`
	ReceiptID       string    `json:"receipt_id"`
	Replayed        bool      `json:"replayed"`
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
	RunSecurityAgent(context.Context, RequestIdentity, SecurityAgentRunRequest) (SecurityAgentRunResult, error)
	ListSecurityAgentRuns(context.Context, RequestIdentity, SecurityAgentRunPageRequest) (SecurityAgentRunPage, error)
	GetSecurityAgentRun(context.Context, RequestIdentity, string) (SecurityAgentRunDetail, error)
	CancelSecurityAgentRun(context.Context, RequestIdentity, SecurityAgentCancelRequest) (SecurityAgentRunResult, error)
	ListSecurityAgentApprovals(context.Context, RequestIdentity, SecurityAgentApprovalPageRequest) (SecurityAgentApprovalPage, error)
	GetSecurityAgentApproval(context.Context, RequestIdentity, string) (SecurityAgentApproval, error)
	DecideSecurityAgentApproval(context.Context, RequestIdentity, SecurityAgentApprovalDecisionRequest) (SecurityAgentApprovalResult, error)
}

type SecurityAgentPublicHandlerConfig struct {
	Clock        func() time.Time
	NewProductID func() (string, error)
	SigningKey   []byte
}

type securityAgentPublicHTTPHandler struct {
	repository  SecurityAgentPublicAuthority
	definitions http.Handler
	config      SecurityAgentPublicHandlerConfig
}

func NewSecurityAgentPublicHTTPHandler(repository SecurityAgentPublicAuthority, definitions http.Handler, config SecurityAgentPublicHandlerConfig) (http.Handler, error) {
	if nilInterface(repository) || nilInterface(definitions) || config.Clock == nil || config.NewProductID == nil || config.Clock().IsZero() || len(config.SigningKey) < 32 || len(config.SigningKey) > 4096 {
		return nil, ErrRepositoryConfiguration
	}
	config.SigningKey = append([]byte(nil), config.SigningKey...)
	return &securityAgentPublicHTTPHandler{repository: repository, definitions: definitions, config: config}, nil
}

func (handler *securityAgentPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if !stringIn(routed.OperationID, "activateSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval") {
		handler.definitions.ServeHTTP(writer, request)
		return
	}
	switch routed.OperationID {
	case "activateSecurityAgent":
		handler.activate(writer, request, routed)
	case "simulateSecurityAgent":
		handler.simulate(writer, request, routed)
	case "runSecurityAgent":
		handler.run(writer, request, routed)
	case "listSecurityAgentRuns":
		handler.listRuns(writer, request, routed)
	case "getSecurityAgentRun":
		handler.getRun(writer, request, routed)
	case "cancelSecurityAgentRun":
		handler.cancelRun(writer, request, routed)
	case "listSecurityAgentApprovals":
		handler.listApprovals(writer, request, routed)
	case "getSecurityAgentApproval":
		handler.getApproval(writer, request, routed)
	case "decideSecurityAgentApproval":
		handler.decideApproval(writer, request, routed)
	}
}

type securityAgentCursorPayload struct {
	Version         int    `json:"v"`
	OrganizationID  string `json:"o"`
	WorkspaceID     string `json:"w"`
	EnvironmentID   string `json:"e"`
	Operation       string `json:"p"`
	Limit           int    `json:"l"`
	DefinitionID    string `json:"a"`
	State           string `json:"s"`
	RunID           string `json:"r"`
	BeforeCreatedAt string `json:"t"`
	BeforeID        string `json:"i"`
}

func (handler *securityAgentPublicHTTPHandler) listRuns(writer http.ResponseWriter, request *http.Request, _ RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	query, queryOK := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"agent_id": 128, "status": 64, "environment_id": 128, "cursor": 512, "limit": 3})
	limit, limitOK := workflowPageLimit(query)
	definitionID, state := query.Get("agent_id"), query.Get("status")
	if !ok || request.Method != http.MethodGet || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !queryOK || !limitOK || definitionID != "" && !validProductID(definitionID) || state != "" && !validSecurityAgentRunState(state) || query.Has("environment_id") && query.Get("environment_id") != identity.Scope.EnvironmentID().String() {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	input := SecurityAgentRunPageRequest{DefinitionID: definitionID, State: state, Limit: limit}
	if cursor := query.Get("cursor"); cursor != "" {
		createdAt, beforeID, valid := handler.decodePageCursor(cursor, identity, "listSecurityAgentRuns", limit, definitionID, state, "")
		if !valid {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		input.BeforeCreatedAt, input.BeforeID = createdAt, beforeID
	} else if query.Has("cursor") {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	page, err := handler.repository.ListSecurityAgentRuns(request.Context(), identity, input)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	value := map[string]any{"items": page.Items}
	if page.NextCreatedAt != nil {
		value["next_cursor"] = handler.encodePageCursor(identity, "listSecurityAgentRuns", limit, definitionID, state, "", *page.NextCreatedAt, page.NextID)
	}
	writeJSONValue(writer, request, http.StatusOK, value, nil)
}

func (handler *securityAgentPublicHTTPHandler) getRun(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	runID := routed.PathParameters["id"]
	if !ok || request.Method != http.MethodGet || request.URL.RawQuery != "" || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(runID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetSecurityAgentRun(request.Context(), identity, runID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validSecurityAgentRunDetail(result, runID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *securityAgentPublicHTTPHandler) cancelRun(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	idempotencyKey, expectedVersion, headersOK := discoveryMutationHeaders(request, false)
	runID := routed.PathParameters["id"]
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !headersOK || !validProductID(runID) || requireZeroByteInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, valid := handler.newDistinctIDs(2, correlationIDFromContext(request.Context()))
	if !valid {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	input := SecurityAgentCancelRequest{RunID: runID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, AuditID: ids[0], CorrelationID: correlationIDFromContext(request.Context()), ReceiptID: ids[1]}
	result, err := handler.repository.CancelSecurityAgentRun(request.Context(), identity, input)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	read := SecurityAgentRun{ID: result.ID, AgentID: result.AgentID, State: result.State, EvidenceIDs: result.EvidenceIDs, DefinitionVersion: result.DefinitionVersion, Version: result.Version}
	if result.ID != runID || result.State != "cancelled" || result.Version != expectedVersion+1 || !validSecurityAgentRun(read) || !validProductID(result.AuditID) || !validProductID(result.ReceiptID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", result.AuditID)
	if identity.CredentialKind == CredentialBrowserSession {
		writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	}
	writeJSONValue(writer, request, http.StatusOK, read, nil)
}

func (handler *securityAgentPublicHTTPHandler) listApprovals(writer http.ResponseWriter, request *http.Request, _ RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	query, queryOK := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"state": 64, "run_id": 128, "cursor": 512, "limit": 3})
	limit, limitOK := workflowPageLimit(query)
	state, runID := query.Get("state"), query.Get("run_id")
	if !ok || request.Method != http.MethodGet || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !queryOK || !limitOK || state != "" && !validSecurityAgentApprovalState(state) || runID != "" && !validProductID(runID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	input := SecurityAgentApprovalPageRequest{State: state, RunID: runID, Limit: limit}
	if cursor := query.Get("cursor"); cursor != "" {
		createdAt, beforeID, valid := handler.decodePageCursor(cursor, identity, "listSecurityAgentApprovals", limit, "", state, runID)
		if !valid {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		input.BeforeCreatedAt, input.BeforeID = createdAt, beforeID
	} else if query.Has("cursor") {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	page, err := handler.repository.ListSecurityAgentApprovals(request.Context(), identity, input)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	value := map[string]any{"items": page.Items}
	if page.NextCreatedAt != nil {
		value["next_cursor"] = handler.encodePageCursor(identity, "listSecurityAgentApprovals", limit, "", state, runID, *page.NextCreatedAt, page.NextID)
	}
	writeJSONValue(writer, request, http.StatusOK, value, nil)
}

func (handler *securityAgentPublicHTTPHandler) getApproval(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	approvalID := routed.PathParameters["id"]
	if !ok || request.Method != http.MethodGet || request.URL.RawQuery != "" || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(approvalID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetSecurityAgentApproval(request.Context(), identity, approvalID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if result.ID != approvalID || !validSecurityAgentApproval(result) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *securityAgentPublicHTTPHandler) encodePageCursor(identity RequestIdentity, operation string, limit int, definitionID, state, runID string, beforeCreatedAt time.Time, beforeID string) string {
	payload, _ := json.Marshal(securityAgentCursorPayload{Version: 1, OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), Operation: operation, Limit: limit, DefinitionID: definitionID, State: state, RunID: runID, BeforeCreatedAt: beforeCreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z"), BeforeID: beforeID})
	mac := hmac.New(sha256.New, handler.config.SigningKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *securityAgentPublicHTTPHandler) decodePageCursor(value string, identity RequestIdentity, operation string, limit int, definitionID, state, runID string) (time.Time, string, bool) {
	if len(value) < 2 || len(value) > 512 {
		return time.Time{}, "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return time.Time{}, "", false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.config.SigningKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return time.Time{}, "", false
	}
	var raw map[string]json.RawMessage
	var cursor securityAgentCursorPayload
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 11 || decodeStrictDiscovery(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != identity.Scope.OrganizationID().String() || cursor.WorkspaceID != identity.Scope.WorkspaceID().String() || cursor.EnvironmentID != identity.Scope.EnvironmentID().String() || cursor.Operation != operation || cursor.Limit != limit || cursor.DefinitionID != definitionID || cursor.State != state || cursor.RunID != runID || !validProductID(cursor.BeforeID) {
		return time.Time{}, "", false
	}
	createdAt, err := time.Parse("2006-01-02T15:04:05.000000Z", cursor.BeforeCreatedAt)
	if err != nil || createdAt.Location() != time.UTC {
		return time.Time{}, "", false
	}
	return createdAt, cursor.BeforeID, true
}

func (handler *securityAgentPublicHTTPHandler) run(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	idempotencyKey, expectedVersion, headersOK := discoveryMutationHeaders(request, false)
	definitionID := routed.PathParameters["id"]
	var input struct {
		EnvironmentID string `json:"environment_id"`
		TriggerKind   string `json:"trigger_kind"`
		TriggerID     string `json:"trigger_id"`
	}
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !headersOK || !validProductID(definitionID) || decodeProductionJSON(request, &input) != nil || input.EnvironmentID != identity.Scope.EnvironmentID().String() || input.TriggerKind != "finding" || !validProductID(input.TriggerID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, valid := handler.newDistinctIDs(3, correlationIDFromContext(request.Context()))
	if !valid {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.RunSecurityAgent(request.Context(), identity, SecurityAgentRunRequest{DefinitionID: definitionID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, RunID: ids[0], TriggerKind: input.TriggerKind, TriggerID: input.TriggerID, AuditID: ids[1], CorrelationID: correlationIDFromContext(request.Context()), ReceiptID: ids[2]})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validSecurityAgentRunResult(result, SecurityAgentRunRequest{DefinitionID: definitionID, ExpectedVersion: expectedVersion, TriggerKind: input.TriggerKind, TriggerID: input.TriggerID}) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", result.AuditID)
	if identity.CredentialKind == CredentialBrowserSession {
		writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	}
	writeJSONValue(writer, request, http.StatusAccepted, map[string]any{"id": result.ID, "agent_id": result.AgentID, "state": result.State, "evidence_ids": result.EvidenceIDs, "definition_version": result.DefinitionVersion, "version": result.Version}, nil)
}

func (handler *securityAgentPublicHTTPHandler) decideApproval(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	idempotencyKey, expectedVersion, headersOK := discoveryMutationHeaders(request, false)
	approvalID := routed.PathParameters["id"]
	now := handler.config.Clock().UTC()
	var input struct {
		Decision string `json:"decision"`
	}
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || !identity.FreshAuthExpiresAt.After(now) || identity.FreshAuthExpiresAt.After(now.Add(5*time.Minute)) || !exactHeaderValue(request.Header.Values("X-Zasp-Fresh-Auth"), "confirmed") || !headersOK || !validProductID(approvalID) || decodeProductionJSON(request, &input) != nil || !stringIn(input.Decision, "approved", "rejected", "cancelled") {
		if ok && (identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || !identity.FreshAuthExpiresAt.After(now)) {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, valid := handler.newDistinctIDs(2, correlationIDFromContext(request.Context()))
	if !valid {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.DecideSecurityAgentApproval(request.Context(), identity, SecurityAgentApprovalDecisionRequest{ApprovalID: approvalID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, Decision: input.Decision, FreshAuthAt: now, AuditID: ids[0], CorrelationID: correlationIDFromContext(request.Context()), ReceiptID: ids[1]})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validSecurityAgentApprovalResult(result, SecurityAgentApprovalDecisionRequest{ApprovalID: approvalID, ExpectedVersion: expectedVersion, Decision: input.Decision}) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", result.AuditID)
	writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"id": result.ID, "run_id": result.RunID, "step_id": result.StepID, "state": result.State, "expires_at": result.ExpiresAt, "version": result.Version, "expected_effect": result.ExpectedEffect, "reversible": result.Reversible, "ttl_seconds": result.TTLSeconds, "evidence_summary": result.EvidenceSummary}, nil)
}

func (handler *securityAgentPublicHTTPHandler) newDistinctIDs(count int, correlationID string) ([]string, bool) {
	if count < 1 || count > 4 || !validProductID(correlationID) {
		return nil, false
	}
	values := make([]string, count)
	seen := map[string]struct{}{correlationID: {}}
	for index := range values {
		value, err := handler.config.NewProductID()
		if err != nil || !validProductID(value) {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		seen[value] = struct{}{}
		values[index] = value
	}
	return values, true
}

func validSecurityAgentRunResult(result SecurityAgentRunResult, input SecurityAgentRunRequest) bool {
	return validProductID(result.ID) && result.AgentID == input.DefinitionID && stringIn(result.State, "queued", "planning", "waiting_approval", "running", "verifying", "contained", "remediated", "needs_human", "failed", "inconclusive", "cancelled") && len(result.EvidenceIDs) == 1 && result.EvidenceIDs[0] == input.TriggerID && result.DefinitionVersion == input.ExpectedVersion && result.Version > 0 && result.Version <= 1000000 && validProductID(result.AuditID) && validProductID(result.CorrelationID) && validProductID(result.ReceiptID)
}

func validSecurityAgentApprovalResult(result SecurityAgentApprovalResult, input SecurityAgentApprovalDecisionRequest) bool {
	return result.ID == input.ApprovalID && validProductID(result.RunID) && validProductID(result.StepID) && result.State == input.Decision && !result.ExpiresAt.IsZero() && result.ExpiresAt.Location() == time.UTC && result.Version == input.ExpectedVersion+1 && result.ExpectedEffect == "Move finding to under review" && result.Reversible && result.TTLSeconds == 0 && len(result.EvidenceSummary) == 1 && validProductID(result.EvidenceSummary[0]) && validProductID(result.AuditID) && validProductID(result.CorrelationID) && validProductID(result.ReceiptID)
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

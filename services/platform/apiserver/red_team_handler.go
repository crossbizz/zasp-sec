package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type RedTeamPublicAuthority interface {
	ListRedTeamDefinitions(context.Context, RequestIdentity, RedTeamDefinitionPageRequest) (RedTeamDefinitionPage, error)
	GetRedTeamDefinition(context.Context, RequestIdentity, string) (RedTeamDefinition, error)
	CreateRedTeamDefinition(context.Context, RequestIdentity, RedTeamDefinitionMutation) (RedTeamDefinitionMutationResult, error)
	UpdateRedTeamDefinition(context.Context, RequestIdentity, RedTeamDefinitionMutation) (RedTeamDefinitionMutationResult, error)
	RunRedTeamTest(context.Context, RequestIdentity, RedTeamRunRequest) (RedTeamRunMutationResult, error)
	ListRedTeamRuns(context.Context, RequestIdentity, RedTeamRunPageRequest) (RedTeamRunPage, error)
	GetRedTeamRun(context.Context, RequestIdentity, string) (RedTeamRunDetail, error)
	CancelRedTeamRun(context.Context, RequestIdentity, RedTeamCancelRequest) (RedTeamRunMutationResult, error)
}

type redTeamPublicHTTPHandler struct {
	repository RedTeamPublicAuthority
	signingKey []byte
}

func NewRedTeamPublicHTTPHandler(repository RedTeamPublicAuthority, signingKey []byte) (http.Handler, error) {
	if nilInterface(repository) || len(signingKey) < 32 || len(signingKey) > 4096 {
		return nil, ErrRepositoryConfiguration
	}
	return &redTeamPublicHTTPHandler{repository: repository, signingKey: append([]byte(nil), signingKey...)}, nil
}

func (handler *redTeamPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "listTests":
		handler.listDefinitions(writer, request)
	case "createTest":
		handler.createDefinition(writer, request)
	case "getTest":
		handler.getDefinition(writer, request, routed.PathParameters["id"])
	case "updateTest":
		handler.updateDefinition(writer, request, routed.PathParameters["id"])
	case "runTest":
		handler.runTest(writer, request, routed.PathParameters["id"])
	case "listTestRuns":
		handler.listRuns(writer, request)
	case "getTestRun":
		handler.getRun(writer, request, routed.PathParameters["id"])
	case "cancelTestRun":
		handler.cancelRun(writer, request, routed.PathParameters["id"])
	default:
		writeProductionError(writer, request, ErrRepositoryOperation)
	}
}

func (handler *redTeamPublicHTTPHandler) listDefinitions(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	query, queryOK := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3})
	limit, limitOK := workflowPageLimit(query)
	if !ok || request.Method != http.MethodGet || !queryOK || !limitOK || !validRedTeamCredential(identity) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	after := ""
	if cursor := query.Get("cursor"); cursor != "" {
		var valid bool
		after, valid = handler.decodeCursor(cursor, identity, "listTests", limit)
		if !valid {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
	} else if query.Has("cursor") {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	page, err := handler.repository.ListRedTeamDefinitions(request.Context(), identity, RedTeamDefinitionPageRequest{After: after, Limit: limit})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	value := map[string]any{"items": page.Items}
	if page.NextCursor != nil {
		value["next_cursor"] = handler.encodeCursor(identity, "listTests", limit, *page.NextCursor)
	}
	writeJSONValue(writer, request, http.StatusOK, value, nil)
}

func (handler *redTeamPublicHTTPHandler) createDefinition(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	idempotency, expected, headersOK := discoveryMutationHeaders(request, true)
	var input struct {
		ID         string        `json:"id"`
		Name       string        `json:"name"`
		TargetID   string        `json:"target_id"`
		TargetKind string        `json:"target_kind"`
		Categories []string      `json:"categories"`
		Safety     RedTeamSafety `json:"safety"`
	}
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !headersOK || expected != 0 || decodeProductionJSON(request, &input) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.CreateRedTeamDefinition(request.Context(), identity, RedTeamDefinitionMutation{ID: input.ID, IdempotencyKey: idempotency, Name: input.Name, TargetID: input.TargetID, TargetKind: input.TargetKind, Categories: input.Categories, Safety: input.Safety, Enabled: true, CorrelationID: correlationIDFromContext(request.Context())})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validRedTeamDefinitionMutationResult(result, input.ID, 1, input.Name, input.TargetID, input.TargetKind, input.Categories, input.Safety, true) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeRedTeamMutationHeaders(writer, identity, result.Body.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusCreated, result.Body, nil)
}

func (handler *redTeamPublicHTTPHandler) getDefinition(writer http.ResponseWriter, request *http.Request, definitionID string) {
	identity, ok := IdentityFromRequest(request)
	if !ok || request.Method != http.MethodGet || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(definitionID) || requireZeroByteInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetRedTeamDefinition(request.Context(), identity, definitionID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *redTeamPublicHTTPHandler) updateDefinition(writer http.ResponseWriter, request *http.Request, definitionID string) {
	identity, ok := IdentityFromRequest(request)
	idempotency, expected, headersOK := discoveryMutationHeaders(request, false)
	var input struct {
		Name       string        `json:"name"`
		TargetID   string        `json:"target_id"`
		TargetKind string        `json:"target_kind"`
		Categories []string      `json:"categories"`
		Safety     RedTeamSafety `json:"safety"`
		Enabled    bool          `json:"enabled"`
	}
	if !ok || request.Method != http.MethodPatch || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(definitionID) || !headersOK || decodeProductionJSON(request, &input) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.UpdateRedTeamDefinition(request.Context(), identity, RedTeamDefinitionMutation{ID: definitionID, IdempotencyKey: idempotency, ExpectedVersion: expected, Name: input.Name, TargetID: input.TargetID, TargetKind: input.TargetKind, Categories: input.Categories, Safety: input.Safety, Enabled: input.Enabled, CorrelationID: correlationIDFromContext(request.Context())})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validRedTeamDefinitionMutationResult(result, definitionID, expected+1, input.Name, input.TargetID, input.TargetKind, input.Categories, input.Safety, input.Enabled) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeRedTeamMutationHeaders(writer, identity, result.Body.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusOK, result.Body, nil)
}

func (handler *redTeamPublicHTTPHandler) runTest(writer http.ResponseWriter, request *http.Request, definitionID string) {
	identity, ok := IdentityFromRequest(request)
	idempotency, definitionVersion, headersOK := discoveryMutationHeaders(request, false)
	var input struct {
		RunID string `json:"run_id"`
	}
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(definitionID) || !headersOK || decodeProductionJSON(request, &input) != nil || !validProductID(input.RunID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.RunRedTeamTest(request.Context(), identity, RedTeamRunRequest{DefinitionID: definitionID, DefinitionVersion: definitionVersion, RunID: input.RunID, IdempotencyKey: idempotency, CorrelationID: correlationIDFromContext(request.Context())})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) || !validRedTeamRun(result.Body) || result.Body.ID != input.RunID || result.Body.Version != 1 || result.Body.DefinitionID != definitionID || result.Body.DefinitionVersion != definitionVersion || result.Body.Status != "queued" || result.Body.Attempt != 0 {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeRedTeamMutationHeaders(writer, identity, result.Body.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusAccepted, result.Body, nil)
}

func (handler *redTeamPublicHTTPHandler) listRuns(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	query, queryOK := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 1024, "limit": 3})
	limit, limitOK := workflowPageLimit(query)
	if !ok || request.Method != http.MethodGet || !queryOK || !limitOK || !validRedTeamCredential(identity) || query.Has("cursor") && query.Get("cursor") == "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	input := RedTeamRunPageRequest{Limit: limit}
	if cursor := query.Get("cursor"); cursor != "" {
		createdAt, beforeID, valid := handler.decodeRunCursor(cursor, identity, limit)
		if !valid {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		input.BeforeCreatedAt, input.BeforeID = createdAt, beforeID
	}
	page, err := handler.repository.ListRedTeamRuns(request.Context(), identity, input)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	value := map[string]any{"items": page.Items}
	if page.NextCreatedAt != nil {
		value["next_cursor"] = handler.signCursor(redTeamJSON(redTeamCursor{Version: 1, OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), Operation: "listTestRuns", Limit: limit, AfterID: page.NextID, BeforeAt: page.NextCreatedAt.Format(time.RFC3339Nano)}))
	}
	writeJSONValue(writer, request, http.StatusOK, value, nil)
}

func (handler *redTeamPublicHTTPHandler) getRun(writer http.ResponseWriter, request *http.Request, runID string) {
	identity, ok := IdentityFromRequest(request)
	if !ok || request.Method != http.MethodGet || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(runID) || requireZeroByteInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetRedTeamRun(request.Context(), identity, runID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *redTeamPublicHTTPHandler) cancelRun(writer http.ResponseWriter, request *http.Request, runID string) {
	identity, ok := IdentityFromRequest(request)
	idempotency, expectedVersion, headersOK := discoveryMutationHeaders(request, false)
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !validRedTeamCredential(identity) || !validProductID(runID) || !headersOK || requireZeroByteInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.CancelRedTeamRun(request.Context(), identity, RedTeamCancelRequest{RunID: runID, ExpectedVersion: expectedVersion, IdempotencyKey: idempotency, CorrelationID: correlationIDFromContext(request.Context())})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) || !validRedTeamRun(result.Body) || result.Body.ID != runID || result.Body.Version != expectedVersion+1 || !result.Body.CancelRequested && result.Body.Status != "cancelled" {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeRedTeamMutationHeaders(writer, identity, result.Body.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusOK, result.Body, nil)
}

func writeRedTeamMutationHeaders(writer http.ResponseWriter, identity RequestIdentity, version int64, auditID, receiptID string) {
	writer.Header().Set("ETag", `"`+strconv.FormatInt(version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", auditID)
	if identity.CredentialKind == CredentialBrowserSession {
		writer.Header().Set("X-Mutation-Receipt-ID", receiptID)
	}
}

func validRedTeamDefinitionMutationResult(result RedTeamDefinitionMutationResult, id string, version int64, name, targetID, targetKind string, categories []string, safety RedTeamSafety, enabled bool) bool {
	return validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) && validRedTeamDefinition(result.Body) && result.Body.ID == id && result.Body.Version == version && result.Body.Name == name && result.Body.TargetID == targetID && result.Body.TargetKind == targetKind && equalStringSets(result.Body.Categories, categories) && equalRedTeamSafety(result.Body.Safety, safety) && result.Body.Enabled == enabled
}

type redTeamCursor struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	Operation      string `json:"p"`
	Limit          int    `json:"l"`
	AfterID        string `json:"a"`
	BeforeAt       string `json:"t,omitempty"`
}

func (handler *redTeamPublicHTTPHandler) encodeCursor(identity RequestIdentity, operation string, limit int, afterID string) string {
	value, _ := json.Marshal(redTeamCursor{Version: 1, OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), Operation: operation, Limit: limit, AfterID: afterID})
	return handler.signCursor(value)
}

func (handler *redTeamPublicHTTPHandler) decodeCursor(value string, identity RequestIdentity, operation string, limit int) (string, bool) {
	payload, ok := handler.verifyCursor(value)
	if !ok {
		return "", false
	}
	var cursor redTeamCursor
	if decodeStrictDiscovery(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != identity.Scope.OrganizationID().String() || cursor.WorkspaceID != identity.Scope.WorkspaceID().String() || cursor.EnvironmentID != identity.Scope.EnvironmentID().String() || cursor.Operation != operation || cursor.Limit != limit || !validProductID(cursor.AfterID) || cursor.BeforeAt != "" {
		return "", false
	}
	return cursor.AfterID, true
}

func (handler *redTeamPublicHTTPHandler) decodeRunCursor(value string, identity RequestIdentity, limit int) (time.Time, string, bool) {
	payload, ok := handler.verifyCursor(value)
	if !ok {
		return time.Time{}, "", false
	}
	var cursor redTeamCursor
	if decodeStrictDiscovery(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != identity.Scope.OrganizationID().String() || cursor.WorkspaceID != identity.Scope.WorkspaceID().String() || cursor.EnvironmentID != identity.Scope.EnvironmentID().String() || cursor.Operation != "listTestRuns" || cursor.Limit != limit || !validProductID(cursor.AfterID) {
		return time.Time{}, "", false
	}
	instant, err := time.Parse(time.RFC3339Nano, cursor.BeforeAt)
	return instant, cursor.AfterID, err == nil && instant.Location() == time.UTC
}

func (handler *redTeamPublicHTTPHandler) signCursor(payload []byte) string {
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *redTeamPublicHTTPHandler) verifyCursor(value string) (json.RawMessage, bool) {
	if len(value) < 2 || len(value) > 1024 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return nil, false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return payload, hmac.Equal(signature, mac.Sum(nil))
}

func validRedTeamCredential(identity RequestIdentity) bool {
	return validRequestIdentity(identity, false) && stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken))
}

func redTeamJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func NewRedTeamWorkflowSurface(workflow, redTeam http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(redTeam) {
		return nil, ErrRepositoryConfiguration
	}
	return &redTeamWorkflowSurface{workflow: workflow, redTeam: redTeam}, nil
}

type redTeamWorkflowSurface struct {
	workflow http.Handler
	redTeam  http.Handler
}

func (surface *redTeamWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if stringIn(routed.OperationID, "listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun") {
		surface.redTeam.ServeHTTP(writer, request)
		return
	}
	surface.workflow.ServeHTTP(writer, request)
}

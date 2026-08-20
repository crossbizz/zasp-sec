package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type DiscoveryPublicReadAuthority interface {
	GetIntegrationSync(context.Context, domain.Scope, string, string) (IntegrationSyncRecord, error)
	ListIntegrationSyncs(context.Context, domain.Scope, string, *time.Time, string, int) (IntegrationSyncPage, error)
	GetIntegrationSchedule(context.Context, domain.Scope, string) (IntegrationSchedule, error)
	GetIntegrationFreshness(context.Context, domain.Scope, string) (IntegrationFreshness, error)
}

type DiscoveryPublicMutationAuthority interface {
	RequestIntegrationSync(context.Context, RequestIdentity, PublicSyncRequest) (IntegrationSyncMutationResult, error)
	PutIntegrationSchedule(context.Context, RequestIdentity, PublicSchedulePut) (IntegrationScheduleMutationResult, error)
	DeleteIntegrationSchedule(context.Context, RequestIdentity, PublicScheduleDelete) (IntegrationScheduleMutationResult, error)
}

type DiscoveryPublicHandlerConfig struct {
	ParserVersion string
	ToolVersion   string
	NewProductID  func() (string, error)
}

type discoveryPublicHTTPHandler struct {
	repository DiscoveryPublicReadAuthority
	signingKey []byte
	config     DiscoveryPublicHandlerConfig
}

type discoverySyncCursor struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	IntegrationID  string `json:"i"`
	RequestedAt    string `json:"t"`
	SyncID         string `json:"s"`
}

var scheduleQuotedVersionPattern = regexp.MustCompile(`^"(0|[1-9][0-9]*)"$`)

func NewDiscoveryPublicHTTPHandler(repository DiscoveryPublicReadAuthority, signingKey []byte, configured ...DiscoveryPublicHandlerConfig) (http.Handler, error) {
	if nilInterface(repository) || len(signingKey) < 32 || len(signingKey) > 4096 || len(configured) > 1 {
		return nil, ErrRepositoryConfiguration
	}
	config := DiscoveryPublicHandlerConfig{ParserVersion: "parser-v1", ToolVersion: "tool-v1", NewProductID: newWorkflowProductID}
	if len(configured) == 1 {
		config = configured[0]
	}
	if !executionVersionPattern.MatchString(config.ParserVersion) || !executionVersionPattern.MatchString(config.ToolVersion) || config.NewProductID == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &discoveryPublicHTTPHandler{repository: repository, signingKey: append([]byte(nil), signingKey...), config: config}, nil
}

func (handler *discoveryPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	integrationID := routed.PathParameters["id"]
	if !identityOK || !routedOK {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if !validProductID(integrationID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	switch routed.OperationID {
	case "syncIntegration":
		handler.syncIntegration(writer, request, identity, integrationID)
	case "putIntegrationSchedule":
		handler.putSchedule(writer, request, identity, integrationID)
	case "deleteIntegrationSchedule":
		handler.deleteSchedule(writer, request, identity, integrationID)
	case "getIntegrationSync":
		if request.Method != http.MethodGet {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		handler.getSync(writer, request, identity, integrationID, routed.PathParameters["syncId"])
	case "listIntegrationSyncs":
		if request.Method != http.MethodGet {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		handler.listSyncs(writer, request, identity, integrationID)
	case "getIntegrationSchedule":
		if request.Method != http.MethodGet {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		handler.getSchedule(writer, request, identity, integrationID)
	case "getIntegrationFreshness":
		if request.Method != http.MethodGet {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		handler.getFreshness(writer, request, identity, integrationID)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func (handler *discoveryPublicHTTPHandler) syncIntegration(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	repository, ok := handler.repository.(DiscoveryPublicMutationAuthority)
	idempotencyKey, expectedVersion, valid := discoveryMutationHeaders(request, false)
	if !ok || request.Method != http.MethodPost || request.URL.RawQuery != "" || !valid || expectedVersion < 1 || decodeEmptyInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, receiptID, ok := handler.mutationProductIDs(identity, 4)
	correlationID := correlationIDFromContext(request.Context())
	if !ok || !validProductID(correlationID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	digest, ok := publicSyncIntentDigest(identity.Scope, integrationID, idempotencyKey, expectedVersion)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := repository.RequestIntegrationSync(request.Context(), identity, PublicSyncRequest{
		IntegrationID: integrationID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion,
		SyncID: ids[0], JobID: ids[1], OutboxID: ids[2], RequestDigest: digest, ParserVersion: handler.config.ParserVersion, ToolVersion: handler.config.ToolVersion,
		AuditID: ids[3], CorrelationID: correlationID, ReceiptID: receiptID,
	})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writeDiscoveryMutationHeaders(writer, result.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusAccepted, result.Value, nil)
}

func (handler *discoveryPublicHTTPHandler) putSchedule(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	repository, ok := handler.repository.(DiscoveryPublicMutationAuthority)
	idempotencyKey, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input struct {
		CadenceSeconds int    `json:"cadence_seconds"`
		State          string `json:"state"`
	}
	if !ok || request.Method != http.MethodPut || request.URL.RawQuery != "" || !valid || decodeProductionJSON(request, &input) != nil || input.CadenceSeconds < 300 || input.CadenceSeconds > 2678400 || !stringIn(input.State, "enabled", "disabled") {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, receiptID, ok := handler.mutationProductIDs(identity, 1)
	correlationID := correlationIDFromContext(request.Context())
	if !ok || !validProductID(correlationID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := repository.PutIntegrationSchedule(request.Context(), identity, PublicSchedulePut{IntegrationID: integrationID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, CadenceSeconds: input.CadenceSeconds, State: input.State, AuditID: ids[0], CorrelationID: correlationID, ReceiptID: receiptID})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writeDiscoveryMutationHeaders(writer, result.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusOK, result.Value, nil)
}

func (handler *discoveryPublicHTTPHandler) deleteSchedule(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	repository, ok := handler.repository.(DiscoveryPublicMutationAuthority)
	idempotencyKey, expectedVersion, valid := discoveryMutationHeaders(request, false)
	if !ok || request.Method != http.MethodDelete || request.URL.RawQuery != "" || !valid || expectedVersion < 1 || request.Body != nil && request.ContentLength != 0 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, receiptID, ok := handler.mutationProductIDs(identity, 1)
	correlationID := correlationIDFromContext(request.Context())
	if !ok || !validProductID(correlationID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := repository.DeleteIntegrationSchedule(request.Context(), identity, PublicScheduleDelete{IntegrationID: integrationID, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, AuditID: ids[0], CorrelationID: correlationID, ReceiptID: receiptID})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writeDiscoveryMutationHeaders(writer, result.Version, result.AuditID, result.ReceiptID)
	writer.WriteHeader(http.StatusNoContent)
}

func discoveryMutationHeaders(request *http.Request, allowZeroVersion bool) (string, int64, bool) {
	keys := request.Header.Values("Idempotency-Key")
	versions := request.Header.Values("If-Match")
	if len(keys) != 1 || !validPublicIdempotency(keys[0]) || len(versions) != 1 || !scheduleQuotedVersionPattern.MatchString(versions[0]) {
		return "", 0, false
	}
	value, err := strconv.ParseInt(versions[0][1:len(versions[0])-1], 10, 64)
	return keys[0], value, err == nil && value <= 1000000 && (allowZeroVersion || value > 0)
}

func (handler *discoveryPublicHTTPHandler) newProductIDs(count int) ([]string, bool) {
	values := make([]string, count)
	seen := make(map[string]struct{}, count)
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

func (handler *discoveryPublicHTTPHandler) mutationProductIDs(identity RequestIdentity, durableCount int) ([]string, string, bool) {
	if durableCount < 1 || identity.CredentialKind != CredentialBrowserSession && identity.CredentialKind != CredentialBearerToken {
		return nil, "", false
	}
	count := durableCount
	if identity.CredentialKind == CredentialBrowserSession {
		count++
	}
	values, ok := handler.newProductIDs(count)
	if !ok {
		return nil, "", false
	}
	if identity.CredentialKind == CredentialBearerToken {
		return values, "", true
	}
	return values[:durableCount], values[durableCount], true
}

func publicSyncIntentDigest(scope domain.Scope, integrationID, idempotencyKey string, expectedVersion int64) ([]byte, bool) {
	payload, err := json.Marshal(map[string]any{
		"body": map[string]any{}, "expected_version": expectedVersion, "idempotency_key": idempotencyKey, "integration_id": integrationID,
		"scope": map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String()},
	})
	if err != nil {
		return nil, false
	}
	digest := sha256.Sum256(payload)
	return digest[:], true
}

func writeDiscoveryMutationHeaders(writer http.ResponseWriter, version int64, auditID, receiptID string) {
	writer.Header().Set("ETag", quoteVersion(version))
	writer.Header().Set("X-Audit-ID", auditID)
	if receiptID != "" {
		writer.Header().Set("X-Mutation-Receipt-ID", receiptID)
	}
}

func (handler *discoveryPublicHTTPHandler) getSync(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID, syncID string) {
	if !validProductID(syncID) || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetIntegrationSync(request.Context(), identity.Scope, integrationID, syncID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writeJSONValue(writer, request, http.StatusOK, result.Value, nil)
}

func (handler *discoveryPublicHTTPHandler) listSyncs(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	limit, ok := workflowPageLimit(query)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	var beforeRequestedAt *time.Time
	beforeID := ""
	if values, exists := query["cursor"]; exists {
		instant, syncID, valid := handler.decodeSyncCursor(values[0], identity.Scope, integrationID)
		if !valid {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		beforeRequestedAt, beforeID = &instant, syncID
	}
	page, err := handler.repository.ListIntegrationSyncs(request.Context(), identity.Scope, integrationID, beforeRequestedAt, beforeID, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	pageInfo := map[string]any{"has_more": false, "next_cursor": nil}
	if page.NextRequestedAt != nil && page.NextID != "" {
		pageInfo["has_more"] = true
		pageInfo["next_cursor"] = handler.encodeSyncCursor(identity.Scope, integrationID, *page.NextRequestedAt, page.NextID)
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": page.Items, "page_info": pageInfo}, nil)
}

func (handler *discoveryPublicHTTPHandler) getSchedule(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	if request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetIntegrationSchedule(request.Context(), identity.Scope, integrationID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *discoveryPublicHTTPHandler) getFreshness(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	if request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.repository.GetIntegrationFreshness(request.Context(), identity.Scope, integrationID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *discoveryPublicHTTPHandler) encodeSyncCursor(scope domain.Scope, integrationID string, requestedAt time.Time, syncID string) string {
	payload, _ := json.Marshal(discoverySyncCursor{
		Version: 1, OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		IntegrationID: integrationID, RequestedAt: requestedAt.UTC().Format(time.RFC3339Nano), SyncID: syncID,
	})
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *discoveryPublicHTTPHandler) decodeSyncCursor(value string, scope domain.Scope, integrationID string) (time.Time, string, bool) {
	if len(value) < 2 || len(value) > 512 {
		return time.Time{}, "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return time.Time{}, "", false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return time.Time{}, "", false
	}
	var raw map[string]json.RawMessage
	var cursor discoverySyncCursor
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 7 || json.Unmarshal(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != scope.OrganizationID().String() || cursor.WorkspaceID != scope.WorkspaceID().String() || cursor.EnvironmentID != scope.EnvironmentID().String() || cursor.IntegrationID != integrationID || !validProductID(cursor.SyncID) {
		return time.Time{}, "", false
	}
	requestedAt, err := time.Parse(time.RFC3339Nano, cursor.RequestedAt)
	if err != nil || requestedAt.IsZero() || requestedAt.Location() != time.UTC || requestedAt.Format(time.RFC3339Nano) != cursor.RequestedAt {
		return time.Time{}, "", false
	}
	return requestedAt, cursor.SyncID, true
}

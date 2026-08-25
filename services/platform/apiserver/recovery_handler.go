package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type RecoveryPublicAuthority interface {
	StartBackup(context.Context, RequestIdentity, RecoveryBackupMutation) (RecoveryBackupMutationResult, error)
	GetBackup(context.Context, RequestIdentity, string) (RecoveryBackup, error)
	StartRestore(context.Context, RequestIdentity, RecoveryRestoreMutation) (RecoveryRestoreMutationResult, error)
	GetRestore(context.Context, RequestIdentity, string) (RecoveryRestore, error)
}

type RecoveryPublicHandlerConfig struct {
	NewProductID func() (string, error)
}

type recoveryPublicHTTPHandler struct {
	authority RecoveryPublicAuthority
	config    RecoveryPublicHandlerConfig
}

type recoveryBackupRequest struct {
	BackupID      string `json:"backup_id"`
	RetentionDays int    `json:"retention_days"`
}

type recoveryRestoreRequest struct {
	RestoreID         string                  `json:"restore_id"`
	TargetEnvironment string                  `json:"target_environment"`
	Manifest          RecoveryManifestLocator `json:"manifest"`
}

func NewRecoveryPublicHTTPHandler(authority RecoveryPublicAuthority, configured ...RecoveryPublicHandlerConfig) (http.Handler, error) {
	if nilInterface(authority) || len(configured) > 1 {
		return nil, ErrRepositoryConfiguration
	}
	config := RecoveryPublicHandlerConfig{NewProductID: newWorkflowProductID}
	if len(configured) == 1 {
		config = configured[0]
	}
	if config.NewProductID == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &recoveryPublicHTTPHandler{authority: authority, config: config}, nil
}

func (handler *recoveryPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if !identityOK || !routedOK || !validRequestIdentity(identity, false) {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "startRecoveryBackup":
		handler.startBackup(writer, request, identity)
	case "getRecoveryBackup":
		handler.getBackup(writer, request, identity, routed.PathParameters["id"])
	case "startRecoveryRestore":
		handler.startRestore(writer, request, identity)
	case "getRecoveryRestore":
		handler.getRestore(writer, request, identity, routed.PathParameters["id"])
	default:
		writeProductionError(writer, request, ErrRepositoryOperation)
	}
}

func (handler *recoveryPublicHTTPHandler) startBackup(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	idempotencyKey, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input recoveryBackupRequest
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || !valid || expectedVersion != 0 || decodeProductionJSON(request, &input) != nil || !validProductID(input.BackupID) || input.RetentionDays < 7 || input.RetentionDays > 90 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	auditID, receiptID, ok := handler.newMutationIDs()
	correlationID := correlationIDFromContext(request.Context())
	digest, digestOK := recoveryRequestDigest(identity.Scope, "startRecoveryBackup", idempotencyKey, input)
	if !ok || !validProductID(correlationID) || !digestOK {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	mutation := RecoveryBackupMutation{
		BackupID: input.BackupID, RetentionDays: input.RetentionDays, IdempotencyKey: idempotencyKey,
		RequestDigest: digest, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID,
	}
	result, err := handler.authority.StartBackup(request.Context(), identity, mutation)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validRecoveryMutationResultIdentity(identity, result.AuditID, result.CorrelationID, result.ReceiptID) || result.CorrelationID != correlationID || !result.Replayed && (result.AuditID != auditID || result.ReceiptID != receiptID) || !validRecoveryBackup(result.Body, identity.Scope) || result.Body.ID != input.BackupID || result.Body.Version != 1 || result.Body.State != "queued" || result.Body.RetentionDays != input.RetentionDays {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeRecoveryMutationHeaders(writer, identity, result.Body.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusAccepted, result.Body, nil)
}

func (handler *recoveryPublicHTTPHandler) getBackup(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, id string) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !validProductID(id) || request.Body != nil && request.ContentLength != 0 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.authority.GetBackup(request.Context(), identity, id)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if result.ID != id || !validRecoveryBackup(result, identity.Scope) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *recoveryPublicHTTPHandler) startRestore(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	idempotencyKey, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input recoveryRestoreRequest
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || !valid || expectedVersion != 0 || decodeProductionJSON(request, &input) != nil || !validProductID(input.RestoreID) || !validRecoveryTarget(input.TargetEnvironment, identity.Scope) || !validRecoveryManifestLocator(input.Manifest, identity.Scope) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	auditID, receiptID, ok := handler.newMutationIDs()
	correlationID := correlationIDFromContext(request.Context())
	digest, digestOK := recoveryRequestDigest(identity.Scope, "startRecoveryRestore", idempotencyKey, input)
	if !ok || !validProductID(correlationID) || !digestOK {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	mutation := RecoveryRestoreMutation{
		RestoreID: input.RestoreID, TargetEnvironment: input.TargetEnvironment, Manifest: input.Manifest,
		IdempotencyKey: idempotencyKey, RequestDigest: digest, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID,
	}
	result, err := handler.authority.StartRestore(request.Context(), identity, mutation)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if !validRecoveryMutationResultIdentity(identity, result.AuditID, result.CorrelationID, result.ReceiptID) || result.CorrelationID != correlationID || !result.Replayed && (result.AuditID != auditID || result.ReceiptID != receiptID) || !validRecoveryRestore(result.Body, identity.Scope) || result.Body.ID != input.RestoreID || result.Body.Version != 1 || result.Body.State != "queued" || result.Body.TargetEnvironment != input.TargetEnvironment || result.Body.Manifest == nil || *result.Body.Manifest != input.Manifest {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeRecoveryMutationHeaders(writer, identity, result.Body.Version, result.AuditID, result.ReceiptID)
	writeJSONValue(writer, request, http.StatusAccepted, result.Body, nil)
}

func (handler *recoveryPublicHTTPHandler) getRestore(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, id string) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !validProductID(id) || request.Body != nil && request.ContentLength != 0 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.authority.GetRestore(request.Context(), identity, id)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if result.ID != id || !validRecoveryRestore(result, identity.Scope) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *recoveryPublicHTTPHandler) newMutationIDs() (string, string, bool) {
	auditID, auditErr := handler.config.NewProductID()
	receiptID, receiptErr := handler.config.NewProductID()
	return auditID, receiptID, auditErr == nil && receiptErr == nil && validProductID(auditID) && validProductID(receiptID) && auditID != receiptID
}

func recoveryRequestDigest(scope domain.Scope, operation, idempotencyKey string, body any) ([]byte, bool) {
	payload, err := json.Marshal(map[string]any{
		"body": body, "expected_version": 0, "idempotency_key": idempotencyKey, "operation": operation,
		"scope": map[string]string{
			"organization_id": scope.OrganizationID().String(),
			"workspace_id":    scope.WorkspaceID().String(),
			"environment_id":  scope.EnvironmentID().String(),
		},
	})
	if err != nil {
		return nil, false
	}
	digest := sha256.Sum256(payload)
	return digest[:], true
}

func writeRecoveryMutationHeaders(writer http.ResponseWriter, identity RequestIdentity, version int64, auditID, receiptID string) {
	writer.Header().Set("ETag", quoteVersion(version))
	writer.Header().Set("X-Audit-ID", auditID)
	if identity.CredentialKind == CredentialBrowserSession {
		writer.Header().Set("X-Mutation-Receipt-ID", receiptID)
	}
}

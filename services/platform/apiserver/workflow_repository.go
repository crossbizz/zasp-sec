package apiserver

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresWorkflowListSQL               = `SELECT zasp_workflow_list($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''))`
	postgresWorkflowPageSQL               = `SELECT zasp_workflow_page($1, $2, $3, $4, NULLIF($5, ''), $6)`
	postgresWorkflowGetSQL                = `SELECT zasp_workflow_get($1, $2, $3, $4, $5)`
	postgresWorkflowReplaySQL             = `SELECT zasp_workflow_replay($1, $2, $3, $4, $5, $6, $7::jsonb)`
	postgresWorkflowMutateSQL             = `SELECT zasp_workflow_mutate($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13, $14, $15)`
	postgresWorkflowReceiptListSQL        = `SELECT zasp_workflow_receipt_list($1, $2, $3, $4, $5)`
	postgresWorkflowReceiptAcknowledgeSQL = `SELECT zasp_workflow_receipt_acknowledge($1, $2, $3, $4, $5)`
)

var workflowKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var policyIDPattern = regexp.MustCompile(`^policy-[a-z0-9][a-z0-9-]{0,120}$`)

type WorkflowValue struct {
	Body             json.RawMessage `json:"body"`
	Version          int64           `json:"version"`
	SecretGeneration int64           `json:"secret_generation"`
}

type WorkflowListPage struct {
	Items  []json.RawMessage
	NextID string
}

type WorkflowMutation struct {
	Action          string
	Kind            string
	ID              string
	Operation       string
	IdempotencyKey  string
	ExpectedVersion int64
	Intent          json.RawMessage
	Body            json.RawMessage
	AuditID         string
	CorrelationID   string
	ReceiptID       string
}

type workflowReplayEnvelope struct {
	Found  bool                   `json:"found"`
	Result WorkflowMutationResult `json:"result"`
}

type WorkflowMutationResult struct {
	WorkflowValue
	AuditID       string `json:"audit_id"`
	CorrelationID string `json:"correlation_id"`
	ReceiptID     string `json:"receipt_id"`
	Replayed      bool   `json:"replayed"`
}

type WorkflowMutationReceipt struct {
	ID              string          `json:"id"`
	Operation       string          `json:"operation"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Intent          json.RawMessage `json:"intent"`
	Result          json.RawMessage `json:"result"`
	ResourceKind    string          `json:"resource_kind"`
	ResourceID      string          `json:"resource_id"`
	ResourceVersion int64           `json:"resource_version"`
	AuditID         string          `json:"audit_id"`
	CorrelationID   string          `json:"correlation_id"`
	CreatedAt       time.Time       `json:"created_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

func (repository *PostgresRepository) ListWorkflows(ctx context.Context, scope domain.Scope, kind, parentField, parentID string) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil || !validWorkflowKind(kind) || !validParentFilter(parentField, parentID) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowListSQL, kind, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), parentField, parentID)
	return validWorkflowPage(payload, err)
}

func (repository *PostgresRepository) ListWorkflowPage(ctx context.Context, scope domain.Scope, kind, afterID string, limit int) (WorkflowListPage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil || !validWorkflowKind(kind) || limit < 1 || limit > 100 || afterID != "" && !validWorkflowID(kind, afterID) {
		return WorkflowListPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowPageSQL, kind, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit)
	if err != nil {
		return WorkflowListPage{}, err
	}
	var raw map[string]json.RawMessage
	var envelope struct {
		Items  []json.RawMessage `json:"items"`
		NextID *string           `json:"next_id"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 2 || raw["items"] == nil || raw["next_id"] == nil || json.Unmarshal(payload, &envelope) != nil || len(envelope.Items) > limit {
		return WorkflowListPage{}, ErrRepositoryUnavailable
	}
	for _, item := range envelope.Items {
		if !validJSONObjectBody(item) {
			return WorkflowListPage{}, ErrRepositoryUnavailable
		}
	}
	nextID := ""
	if envelope.NextID != nil {
		nextID = *envelope.NextID
		if !validWorkflowID(kind, nextID) || len(envelope.Items) != limit {
			return WorkflowListPage{}, ErrRepositoryUnavailable
		}
	}
	return WorkflowListPage{Items: envelope.Items, NextID: nextID}, nil
}

func (repository *PostgresRepository) GetWorkflow(ctx context.Context, scope domain.Scope, kind, id string) (WorkflowValue, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil || !validWorkflowID(kind, id) {
		return WorkflowValue{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowGetSQL, kind, id, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return WorkflowValue{}, err
	}
	var value WorkflowValue
	if json.Unmarshal(payload, &value) != nil || value.Version < 1 || value.SecretGeneration < 0 || !validJSONObjectBody(value.Body) {
		return WorkflowValue{}, ErrRepositoryUnavailable
	}
	return value, nil
}

func (repository *PostgresRepository) MutateWorkflow(ctx context.Context, identity RequestIdentity, mutation WorkflowMutation) (WorkflowMutationResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !validWorkflowMutation(mutation) {
		return WorkflowMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowMutateSQL,
		mutation.Action, mutation.Kind, mutation.ID,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(),
		identity.PrincipalID.String(), mutation.Operation, mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Intent, mutation.Body, mutation.AuditID, mutation.CorrelationID,
		mutation.ReceiptID,
	)
	if err != nil {
		return WorkflowMutationResult{}, err
	}
	var result WorkflowMutationResult
	if json.Unmarshal(payload, &result) != nil || result.Version < 1 || result.SecretGeneration < 0 || !validJSONObjectBody(result.Body) || !validMutationResultIDs(result, mutation) {
		return WorkflowMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) ListWorkflowMutationReceipts(ctx context.Context, identity RequestIdentity, limit int) ([]WorkflowMutationReceipt, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || limit < 1 || limit > 50 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowReceiptListSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), limit,
	)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	var envelope struct {
		Items []WorkflowMutationReceipt `json:"items"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 1 || raw["items"] == nil || json.Unmarshal(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		if !validWorkflowMutationReceipt(envelope.Items[index]) {
			return nil, ErrRepositoryUnavailable
		}
		envelope.Items[index].CreatedAt = envelope.Items[index].CreatedAt.UTC()
		envelope.Items[index].ExpiresAt = envelope.Items[index].ExpiresAt.UTC()
	}
	return envelope.Items, nil
}

func (repository *PostgresRepository) AcknowledgeWorkflowMutationReceipt(ctx context.Context, identity RequestIdentity, receiptID string) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) {
		return ErrRepositoryOperation
	}
	if _, err := domain.ParseProductID(receiptID); err != nil {
		return ErrRepositoryNotFound
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowReceiptAcknowledgeSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), receiptID,
	)
	if err != nil {
		return err
	}
	var value map[string]bool
	if json.Unmarshal(payload, &value) != nil || len(value) != 1 || !value["acknowledged"] {
		return ErrRepositoryUnavailable
	}
	return nil
}

func validWorkflowMutationReceipt(value WorkflowMutationReceipt) bool {
	if _, err := domain.ParseProductID(value.ID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(value.AuditID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(value.CorrelationID); err != nil {
		return false
	}
	operationKind, _, _, validOperation := workflowMutationTarget(value.Operation)
	return validOperation && operationKind == value.ResourceKind && len(value.IdempotencyKey) >= 16 && len(value.IdempotencyKey) <= 128 && validJSONObjectBody(value.Intent) && !containsSensitiveWorkflowField(value.Intent) && validJSONObjectBody(value.Result) && !containsSensitiveWorkflowField(value.Result) && validWorkflowID(value.ResourceKind, value.ResourceID) && value.ResourceVersion > 0 && !value.CreatedAt.IsZero() && value.ExpiresAt.After(value.CreatedAt) && !value.ExpiresAt.After(value.CreatedAt.Add(7*24*time.Hour))
}

func (repository *PostgresRepository) ReplayWorkflow(ctx context.Context, identity RequestIdentity, operation, idempotencyKey string, intent json.RawMessage) (WorkflowMutationResult, bool, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !workflowKeyPattern.MatchString(operation) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !validJSONObjectBody(intent) || containsSensitiveWorkflowField(intent) {
		return WorkflowMutationResult{}, false, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowReplaySQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), operation, idempotencyKey, intent,
	)
	if err != nil {
		return WorkflowMutationResult{}, false, err
	}
	var envelope workflowReplayEnvelope
	if json.Unmarshal(payload, &envelope) != nil {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	if !envelope.Found {
		return WorkflowMutationResult{}, false, nil
	}
	if envelope.Result.Version < 1 || envelope.Result.SecretGeneration < 0 || !validJSONObjectBody(envelope.Result.Body) || !envelope.Result.Replayed {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	if _, err := domain.ParseProductID(envelope.Result.AuditID); err != nil {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	if _, err := domain.ParseProductID(envelope.Result.CorrelationID); err != nil {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	if _, err := domain.ParseProductID(envelope.Result.ReceiptID); err != nil {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	return envelope.Result, true, nil
}

func validMutationResultIDs(result WorkflowMutationResult, mutation WorkflowMutation) bool {
	if _, err := domain.ParseProductID(result.AuditID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(result.CorrelationID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(result.ReceiptID); err != nil {
		return false
	}
	return result.Replayed || (result.AuditID == mutation.AuditID && result.CorrelationID == mutation.CorrelationID)
}

func validWorkflowPage(payload json.RawMessage, err error) (json.RawMessage, error) {
	payload, err = validJSONObject(payload, err)
	if err != nil {
		return nil, err
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(payload, &page) != nil || len(page.Items) > 1000 {
		return nil, ErrRepositoryUnavailable
	}
	for _, item := range page.Items {
		if !validJSONObjectBody(item) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return payload, nil
}

func validWorkflowMutation(value WorkflowMutation) bool {
	if !validWorkflowID(value.Kind, value.ID) || !workflowKeyPattern.MatchString(value.Operation) || len(value.IdempotencyKey) < 16 || len(value.IdempotencyKey) > 128 || !validJSONObjectBody(value.Intent) || containsSensitiveWorkflowField(value.Intent) || !validJSONObjectBody(value.Body) || containsSensitiveWorkflowField(value.Body) {
		return false
	}
	if _, err := domain.ParseProductID(value.AuditID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(value.CorrelationID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(value.ReceiptID); err != nil {
		return false
	}
	switch value.Action {
	case "create":
		return value.ExpectedVersion == 0
	case "update", "delete", "rotate_secret":
		return value.ExpectedVersion > 0
	default:
		return false
	}
}

func validWorkflowKind(value string) bool {
	switch value {
	case "policy", "integration", "sensor", "security_agent", "security_agent_run", "security_agent_approval":
		return true
	default:
		return false
	}
}

func validWorkflowID(kind, id string) bool {
	if !validWorkflowKind(kind) {
		return false
	}
	if kind == "policy" {
		return policyIDPattern.MatchString(id)
	}
	_, err := domain.ParseProductID(id)
	return err == nil
}

func validParentFilter(field, id string) bool {
	if field == "" && id == "" {
		return true
	}
	if field != "policy_id" && field != "agent_id" && field != "run_id" {
		return false
	}
	return workflowKeyPattern.MatchString(id)
}

func validJSONObjectBody(value json.RawMessage) bool {
	return len(value) >= 2 && len(value) <= 16*1024 && json.Valid(value) && value[0] == '{'
}

func containsSensitiveWorkflowField(value json.RawMessage) bool {
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return true
	}
	var visit func(any) bool
	visit = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for key, nested := range typed {
				lower := strings.ToLower(key)
				opaqueReference := strings.HasSuffix(lower, "_reference")
				if lower == "token" || strings.Contains(lower, "password") || strings.Contains(lower, "secret") && !opaqueReference || strings.Contains(lower, "credential_value") {
					return true
				}
				if visit(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range typed {
				if visit(nested) {
					return true
				}
			}
		}
		return false
	}
	return visit(decoded)
}

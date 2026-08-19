package apiserver

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresWorkflowListSQL   = `SELECT zasp_workflow_list($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''))`
	postgresWorkflowGetSQL    = `SELECT zasp_workflow_get($1, $2, $3, $4, $5)`
	postgresWorkflowMutateSQL = `SELECT zasp_workflow_mutate($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13)`
)

var workflowKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var policyIDPattern = regexp.MustCompile(`^policy-[a-z0-9][a-z0-9-]{0,120}$`)

type WorkflowValue struct {
	Body             json.RawMessage `json:"body"`
	Version          int64           `json:"version"`
	SecretGeneration int64           `json:"secret_generation"`
}

type WorkflowMutation struct {
	Action          string
	Kind            string
	ID              string
	Operation       string
	IdempotencyKey  string
	ExpectedVersion int64
	Body            json.RawMessage
	AuditID         string
	CorrelationID   string
}

type WorkflowMutationResult struct {
	WorkflowValue
	AuditID       string `json:"audit_id"`
	CorrelationID string `json:"correlation_id"`
	Replayed      bool   `json:"replayed"`
}

func (repository *PostgresRepository) ListWorkflows(ctx context.Context, scope domain.Scope, kind, parentField, parentID string) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil || !validWorkflowKind(kind) || !validParentFilter(parentField, parentID) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowListSQL, kind, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), parentField, parentID)
	return validWorkflowPage(payload, err)
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
		identity.PrincipalID.String(), mutation.Operation, mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Body, mutation.AuditID, mutation.CorrelationID,
	)
	if err != nil {
		return WorkflowMutationResult{}, err
	}
	var result WorkflowMutationResult
	if json.Unmarshal(payload, &result) != nil || result.Version < 1 || result.SecretGeneration < 0 || !validJSONObjectBody(result.Body) || result.AuditID != mutation.AuditID || result.CorrelationID != mutation.CorrelationID {
		return WorkflowMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
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
	if !validWorkflowID(value.Kind, value.ID) || !workflowKeyPattern.MatchString(value.Operation) || len(value.IdempotencyKey) < 16 || len(value.IdempotencyKey) > 128 || !validJSONObjectBody(value.Body) || containsSensitiveWorkflowField(value.Body) {
		return false
	}
	if _, err := domain.ParseProductID(value.AuditID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(value.CorrelationID); err != nil {
		return false
	}
	switch value.Action {
	case "create":
		return value.ExpectedVersion == 0
	case "update", "delete", "rotate_secret", "audit":
		return value.ExpectedVersion > 0
	default:
		return false
	}
}

func validWorkflowKind(value string) bool {
	switch value {
	case "policy", "integration", "sensor", "security_agent", "security_agent_run", "security_agent_approval", "policy_decision":
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
				if lower == "token" || strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "credential_value") {
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

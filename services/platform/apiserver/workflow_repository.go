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
	postgresConnectorWorkflowMutateSQL    = `SELECT zasp_connector_workflow_mutate($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13, $14, $15)`
	postgresWorkflowReceiptListSQL        = `SELECT zasp_workflow_receipt_list($1, $2, $3, $4, $5)`
	postgresWorkflowReceiptAcknowledgeSQL = `SELECT zasp_workflow_receipt_acknowledge($1, $2, $3, $4, $5)`
	postgresWorkflowReceiptCleanupSQL     = `SELECT zasp_workflow_receipt_cleanup($1)`
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
	statement := postgresWorkflowPageSQL
	arguments := []any{kind, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit}
	if repository.securityAgentExecution {
		if kind != "security_agent" {
			return WorkflowListPage{}, ErrRepositoryOperation
		}
		statement = postgresSecurityAgentDefinitionPageSQL
		arguments = []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit}
	}
	payload, err := repository.database.QueryJSON(ctx, statement, arguments...)
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
	statement := postgresWorkflowGetSQL
	arguments := []any{kind, id, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	if repository.securityAgentExecution {
		if kind != "security_agent" {
			return WorkflowValue{}, ErrRepositoryOperation
		}
		statement = postgresSecurityAgentDefinitionValueSQL
		arguments = []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id}
	}
	payload, err := repository.database.QueryJSON(ctx, statement, arguments...)
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
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !validWorkflowMutation(mutation) || !validMutationReceiptIdentity(identity, mutation.ReceiptID) {
		return WorkflowMutationResult{}, ErrRepositoryOperation
	}
	query := postgresWorkflowMutateSQL
	arguments := []any{
		mutation.Action, mutation.Kind, mutation.ID,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(),
		identity.PrincipalID.String(), mutation.Operation, mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Intent, mutation.Body, mutation.AuditID, mutation.CorrelationID,
		mutation.ReceiptID,
	}
	if repository.securityAgentExecution {
		if mutation.Kind != "security_agent" {
			return WorkflowMutationResult{}, ErrRepositoryOperation
		}
		query = postgresSecurityAgentDefinitionMutateSQL
		arguments = []any{mutation.Action, mutation.ID, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), mutation.Operation, mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Intent, mutation.Body, mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID}
	}
	if mutation.Kind == "integration" && repository.connectorWorkflows {
		query = postgresConnectorWorkflowMutateSQL
	}
	payload, err := repository.database.QueryJSON(ctx, query, arguments...)
	if err != nil {
		return WorkflowMutationResult{}, err
	}
	var result WorkflowMutationResult
	if json.Unmarshal(payload, &result) != nil || result.Version < 1 || result.SecretGeneration < 0 || !validJSONObjectBody(result.Body) || !validMutationResultIDs(result, mutation) {
		return WorkflowMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) CleanupExpiredWorkflowMutationReceipts(ctx context.Context, limit int) (int, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || limit < 1 || limit > 1000 {
		return 0, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresWorkflowReceiptCleanupSQL, limit)
	if err != nil {
		return 0, err
	}
	var raw map[string]json.RawMessage
	var result struct {
		Deleted int `json:"deleted"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 1 || raw["deleted"] == nil || json.Unmarshal(payload, &result) != nil || result.Deleted < 0 || result.Deleted > limit {
		return 0, ErrRepositoryUnavailable
	}
	return result.Deleted, nil
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
		if !validWorkflowMutationReceipt(envelope.Items[index]) || !validDiscoveryWorkflowReceipt(envelope.Items[index], identity) || !canonicalizeWorkflowMutationReceiptResult(&envelope.Items[index]) {
			return nil, ErrRepositoryUnavailable
		}
		envelope.Items[index].CreatedAt = envelope.Items[index].CreatedAt.UTC()
		envelope.Items[index].ExpiresAt = envelope.Items[index].ExpiresAt.UTC()
	}
	return envelope.Items, nil
}

func canonicalizeWorkflowMutationReceiptResult(value *WorkflowMutationReceipt) bool {
	if value.ResourceKind != "finding" {
		return true
	}
	var finding RiskFinding
	if decodeStrictRisk(value.Result, &finding) != nil || !validRiskFinding(finding) || finding.ID != value.ResourceID || finding.Version != value.ResourceVersion {
		return false
	}
	normalizeRiskFinding(&finding)
	result, err := json.Marshal(finding)
	if err != nil {
		return false
	}
	value.Result = result
	return true
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
	return validOperation && operationKind == value.ResourceKind && len(value.IdempotencyKey) >= 16 && len(value.IdempotencyKey) <= 128 && workflowKeyPattern.MatchString(value.IdempotencyKey) && validJSONObjectBody(value.Intent) && !containsSensitiveWorkflowField(value.Intent) && validJSONObjectBody(value.Result) && !containsSensitiveWorkflowField(value.Result) && validWorkflowID(value.ResourceKind, value.ResourceID) && value.ResourceVersion > 0 && !value.CreatedAt.IsZero() && value.ExpiresAt.After(value.CreatedAt) && !value.ExpiresAt.After(value.CreatedAt.Add(7*24*time.Hour)) && validIntegrationWorkflowReceipt(value)
}

func validIntegrationWorkflowReceipt(value WorkflowMutationReceipt) bool {
	if !stringIn(value.Operation, "createIntegration", "updateIntegration", "deleteIntegration") {
		return true
	}
	if !exactJSONFields(value.Intent, "body", "expected_version", "resource_id") {
		return false
	}
	var intent struct {
		Body            json.RawMessage `json:"body"`
		ExpectedVersion int64           `json:"expected_version"`
		ResourceID      string          `json:"resource_id"`
	}
	if decodeStrictDiscovery(value.Intent, &intent) != nil {
		return false
	}
	if value.Operation == "createIntegration" {
		if intent.ExpectedVersion != 0 || intent.ResourceID != "" || value.ResourceVersion != 1 {
			return false
		}
	} else if intent.ExpectedVersion < 1 || intent.ResourceID != value.ResourceID || intent.ExpectedVersion != value.ResourceVersion-1 {
		return false
	}
	if value.Operation == "deleteIntegration" && !exactJSONFields(intent.Body) {
		return false
	}
	if value.Operation == "deleteIntegration" && exactJSONFields(value.Result, "id", "status") {
		var result struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		return exactJSONFields(value.Result, "id", "status") && decodeStrictDiscovery(value.Result, &result) == nil && result.ID == value.ResourceID && result.Status == "deleted"
	}
	var result struct {
		ID            string            `json:"id"`
		ConnectorKey  string            `json:"connector_key"`
		Name          string            `json:"name"`
		Configuration map[string]string `json:"configuration"`
		Status        string            `json:"status"`
		CreatedAt     time.Time         `json:"created_at"`
		UpdatedAt     time.Time         `json:"updated_at"`
	}
	if !exactJSONFields(value.Result, "connector_key", "configuration", "created_at", "id", "name", "status", "updated_at") || decodeStrictDiscovery(value.Result, &result) != nil || result.ID != value.ResourceID || len(result.ConnectorKey) < 1 || len(result.ConnectorKey) > 63 || len(result.Name) < 1 || len(result.Name) > 128 || len(result.Configuration) < 1 || len(result.Configuration) > 16 || !stringIn(result.Status, "configured", "pending_authorization", "active", "degraded", "revoking") || result.CreatedAt.IsZero() || result.UpdatedAt.Before(result.CreatedAt) {
		return false
	}
	for key, item := range result.Configuration {
		if len(key) < 1 || len(key) > 128 || len(item) < 1 || len(item) > 2048 {
			return false
		}
	}
	if value.Operation == "deleteIntegration" {
		return result.Status == "revoking"
	}
	if value.Operation == "createIntegration" {
		var body struct {
			ConnectorKey  string            `json:"connector_key"`
			Name          string            `json:"name"`
			Configuration map[string]string `json:"configuration"`
		}
		return exactJSONFields(intent.Body, "connector_key", "configuration", "name") && decodeStrictDiscovery(intent.Body, &body) == nil && body.ConnectorKey == result.ConnectorKey && body.Name == result.Name && equalWorkflowStringMaps(body.Configuration, result.Configuration)
	}
	var body struct {
		Name          string            `json:"name"`
		Configuration map[string]string `json:"configuration"`
	}
	return exactJSONFields(intent.Body, "configuration", "name") && decodeStrictDiscovery(intent.Body, &body) == nil && body.Name == result.Name && equalWorkflowStringMaps(body.Configuration, result.Configuration)
}

func equalWorkflowStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validDiscoveryWorkflowReceipt(value WorkflowMutationReceipt, identity RequestIdentity) bool {
	if !stringIn(value.Operation, "syncIntegration", "putIntegrationSchedule", "deleteIntegrationSchedule") {
		return true
	}
	if !exactJSONFields(value.Intent, "body", "expected_version", "idempotency_key", "integration_id", "scope") {
		return false
	}
	var intent struct {
		Body            json.RawMessage `json:"body"`
		ExpectedVersion int64           `json:"expected_version"`
		IdempotencyKey  string          `json:"idempotency_key"`
		IntegrationID   string          `json:"integration_id"`
		Scope           struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
		} `json:"scope"`
	}
	if decodeStrictDiscovery(value.Intent, &intent) != nil || !exactJSONFields(extractJSONField(value.Intent, "scope"), "environment_id", "organization_id", "workspace_id") || intent.IdempotencyKey != value.IdempotencyKey || !validProductID(intent.IntegrationID) || intent.Scope.OrganizationID != identity.Scope.OrganizationID().String() || intent.Scope.WorkspaceID != identity.Scope.WorkspaceID().String() || intent.Scope.EnvironmentID != identity.Scope.EnvironmentID().String() {
		return false
	}
	if value.Operation == "syncIntegration" {
		var result IntegrationSync
		return value.ResourceKind == "integration_sync" && intent.ExpectedVersion > 0 && value.ResourceVersion > 0 && exactJSONFields(intent.Body) && exactJSONFields(value.Result, publicIntegrationSyncFields...) && decodeStrictDiscovery(value.Result, &result) == nil && validPublicIntegrationSync(result, intent.IntegrationID, value.ResourceID) && result.TriggerKind == "manual" && result.Status == "queued" && result.Attempt == 0 && result.DiscoveredCount == 0 && result.ChangedCount == 0 && result.RemovedCount == 0
	}
	var result IntegrationSchedule
	if value.ResourceKind != "integration_schedule" || intent.ExpectedVersion < 0 || value.ResourceID != intent.IntegrationID || value.ResourceVersion != intent.ExpectedVersion+1 || !exactJSONFields(value.Result, publicIntegrationScheduleFields...) || decodeStrictDiscovery(value.Result, &result) != nil || !validPublicIntegrationSchedule(result, intent.IntegrationID) || result.Version != value.ResourceVersion {
		return false
	}
	if value.Operation == "putIntegrationSchedule" {
		var body struct {
			CadenceSeconds int    `json:"cadence_seconds"`
			State          string `json:"state"`
		}
		return exactJSONFields(intent.Body, "cadence_seconds", "state") && decodeStrictDiscovery(intent.Body, &body) == nil && body.CadenceSeconds == result.CadenceSeconds && body.State == result.State && stringIn(body.State, "enabled", "disabled")
	}
	return intent.ExpectedVersion > 0 && exactJSONFields(intent.Body) && result.State == "deleted" && result.NextRunAt == nil
}

func (repository *PostgresRepository) ReplayWorkflow(ctx context.Context, identity RequestIdentity, operation, idempotencyKey string, intent json.RawMessage) (WorkflowMutationResult, bool, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !workflowKeyPattern.MatchString(operation) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) || !validJSONObjectBody(intent) || containsSensitiveWorkflowField(intent) {
		return WorkflowMutationResult{}, false, ErrRepositoryOperation
	}
	statement := postgresWorkflowReplaySQL
	if repository.securityAgentExecution {
		statement = postgresSecurityAgentDefinitionReplaySQL
	}
	payload, err := repository.database.QueryJSON(ctx, statement,
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
	if !validMutationReceiptIdentity(identity, envelope.Result.ReceiptID) {
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
	if result.ReceiptID != "" {
		if _, err := domain.ParseProductID(result.ReceiptID); err != nil {
			return false
		}
	}
	if (result.ReceiptID == "") != (mutation.ReceiptID == "") {
		return false
	}
	if !result.Replayed && result.ReceiptID != mutation.ReceiptID {
		return false
	}
	return result.Replayed || (result.AuditID == mutation.AuditID && result.CorrelationID == mutation.CorrelationID)
}

func validMutationReceiptIdentity(identity RequestIdentity, receiptID string) bool {
	if identity.CredentialKind == CredentialBearerToken {
		return receiptID == ""
	}
	if identity.CredentialKind != CredentialBrowserSession {
		return false
	}
	_, err := domain.ParseProductID(receiptID)
	return err == nil
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
	if !validWorkflowID(value.Kind, value.ID) || !workflowKeyPattern.MatchString(value.Operation) || len(value.IdempotencyKey) < 16 || len(value.IdempotencyKey) > 128 || !workflowKeyPattern.MatchString(value.IdempotencyKey) || !validJSONObjectBody(value.Intent) || containsSensitiveWorkflowField(value.Intent) || !validJSONObjectBody(value.Body) || containsSensitiveWorkflowField(value.Body) {
		return false
	}
	if _, err := domain.ParseProductID(value.AuditID); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(value.CorrelationID); err != nil {
		return false
	}
	if value.ReceiptID != "" {
		if _, err := domain.ParseProductID(value.ReceiptID); err != nil {
			return false
		}
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
	case "policy", "integration", "integration_sync", "integration_schedule", "sensor", "security_agent", "security_agent_run", "security_agent_approval":
		return true
	default:
		return false
	}
}

func validWorkflowID(kind, id string) bool {
	if kind == "finding" {
		_, err := domain.ParseProductID(id)
		return err == nil
	}
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

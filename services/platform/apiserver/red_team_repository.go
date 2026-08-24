package apiserver

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const (
	postgresRedTeamListDefinitionsSQL  = `SELECT zasp_red_team_list_definitions($1,$2,$3,NULLIF($4,''),$5)`
	postgresRedTeamGetDefinitionSQL    = `SELECT zasp_red_team_get_definition($1,$2,$3,$4)`
	postgresRedTeamCreateDefinitionSQL = `SELECT zasp_red_team_create_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12)`
	postgresRedTeamUpdateDefinitionSQL = `SELECT zasp_red_team_update_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14)`
	postgresRedTeamRunTestSQL          = `SELECT zasp_red_team_run_test($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresRedTeamListRunsSQL         = `SELECT zasp_red_team_list_runs($1,$2,$3,$4,NULLIF($5,''),$6)`
	postgresRedTeamGetRunSQL           = `SELECT zasp_red_team_get_run($1,$2,$3,$4)`
	postgresRedTeamCancelRunSQL        = `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,$5,$6,$7,$8)`
)

type RedTeamSafety struct {
	Environment         string   `json:"environment"`
	CredentialClass     string   `json:"credential_class"`
	ExpectedSideEffects []string `json:"expected_side_effects"`
}

type RedTeamDefinition struct {
	ID         string        `json:"id"`
	Version    int64         `json:"version"`
	Name       string        `json:"name"`
	TargetID   string        `json:"target_id"`
	TargetKind string        `json:"target_kind"`
	Categories []string      `json:"categories"`
	Safety     RedTeamSafety `json:"safety"`
	Enabled    bool          `json:"enabled"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

type RedTeamDefinitionPage struct {
	Items      []RedTeamDefinition `json:"items"`
	NextCursor *string             `json:"next_cursor"`
}

type RedTeamDefinitionPageRequest struct {
	After string
	Limit int
}

type RedTeamDefinitionMutation struct {
	ID              string
	IdempotencyKey  string
	ExpectedVersion int64
	Name            string
	TargetID        string
	TargetKind      string
	Categories      []string
	Safety          RedTeamSafety
	Enabled         bool
	CorrelationID   string
}

type RedTeamDefinitionMutationResult struct {
	Body          RedTeamDefinition `json:"body"`
	AuditID       string            `json:"audit_id"`
	CorrelationID string            `json:"correlation_id"`
	ReceiptID     string            `json:"receipt_id"`
	Replayed      bool              `json:"replayed"`
}

type RedTeamRun struct {
	ID                string     `json:"id"`
	Version           int64      `json:"version"`
	DefinitionID      string     `json:"definition_id"`
	DefinitionVersion int64      `json:"definition_version"`
	Status            string     `json:"status"`
	Attempt           int        `json:"attempt"`
	CancelRequested   bool       `json:"cancel_requested"`
	QueuedAt          time.Time  `json:"queued_at"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	Verdict           string     `json:"verdict,omitempty"`
	ErrorCode         string     `json:"error_code,omitempty"`
	EvidenceReference string     `json:"evidence_reference,omitempty"`
}

type RedTeamAttempt struct {
	Attempt           int       `json:"attempt"`
	Verdict           string    `json:"verdict"`
	Objective         string    `json:"objective"`
	Behavior          string    `json:"behavior"`
	ErrorCode         string    `json:"error_code,omitempty"`
	Evidence          []string  `json:"evidence"`
	EvidenceReference string    `json:"evidence_reference"`
	CompletedAt       time.Time `json:"completed_at"`
}

type RedTeamRunDetail struct {
	RedTeamRun
	Attempts []RedTeamAttempt `json:"attempts"`
}

type RedTeamRunPage struct {
	Items         []RedTeamRun
	NextCreatedAt *time.Time
	NextID        string
}

type RedTeamRunPageRequest struct {
	BeforeCreatedAt time.Time
	BeforeID        string
	Limit           int
}

type RedTeamRunRequest struct {
	DefinitionID      string
	DefinitionVersion int64
	RunID             string
	IdempotencyKey    string
	CorrelationID     string
}

type RedTeamCancelRequest struct {
	RunID           string
	ExpectedVersion int64
	IdempotencyKey  string
	CorrelationID   string
}

type RedTeamRunMutationResult struct {
	Body          RedTeamRun `json:"body"`
	AuditID       string     `json:"audit_id"`
	CorrelationID string     `json:"correlation_id"`
	ReceiptID     string     `json:"receipt_id"`
	Replayed      bool       `json:"replayed"`
}

func (repository *PostgresRepository) ListRedTeamDefinitions(ctx context.Context, identity RequestIdentity, input RedTeamDefinitionPageRequest) (RedTeamDefinitionPage, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || input.Limit < 1 || input.Limit > 100 || input.After != "" && !validProductID(input.After) {
		return RedTeamDefinitionPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamListDefinitionsSQL, redTeamScopeArguments(identity, input.After, input.Limit)...)
	if err != nil {
		return RedTeamDefinitionPage{}, discoveryProviderError(err)
	}
	var page RedTeamDefinitionPage
	if !exactJSONFields(payload, "items", "next_cursor") || decodeStrictDiscovery(payload, &page) != nil || len(page.Items) > input.Limit {
		return RedTeamDefinitionPage{}, ErrRepositoryUnavailable
	}
	for index := range page.Items {
		if !validRedTeamDefinition(page.Items[index]) || index > 0 && page.Items[index-1].ID >= page.Items[index].ID {
			return RedTeamDefinitionPage{}, ErrRepositoryUnavailable
		}
	}
	if page.NextCursor != nil && (len(page.Items) != input.Limit || !validProductID(*page.NextCursor) || page.Items[len(page.Items)-1].ID != *page.NextCursor) {
		return RedTeamDefinitionPage{}, ErrRepositoryUnavailable
	}
	return page, nil
}

func (repository *PostgresRepository) GetRedTeamDefinition(ctx context.Context, identity RequestIdentity, definitionID string) (RedTeamDefinition, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validProductID(definitionID) {
		return RedTeamDefinition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamGetDefinitionSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID)
	if err != nil {
		return RedTeamDefinition{}, discoveryProviderError(err)
	}
	var result RedTeamDefinition
	if !exactJSONFields(payload, "categories", "created_at", "enabled", "id", "name", "safety", "target_id", "target_kind", "updated_at", "version") || decodeStrictDiscovery(payload, &result) != nil || result.ID != definitionID || !validRedTeamDefinition(result) {
		return RedTeamDefinition{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) CreateRedTeamDefinition(ctx context.Context, identity RequestIdentity, input RedTeamDefinitionMutation) (RedTeamDefinitionMutationResult, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validRedTeamDefinitionMutation(input, false) {
		return RedTeamDefinitionMutationResult{}, ErrRepositoryOperation
	}
	categories, safety, err := redTeamDefinitionJSON(input)
	if err != nil {
		return RedTeamDefinitionMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamCreateDefinitionSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.ID, input.Name, input.TargetID, input.TargetKind, categories, safety, input.CorrelationID)
	if err != nil {
		return RedTeamDefinitionMutationResult{}, discoveryProviderError(err)
	}
	return decodeRedTeamDefinitionMutation(payload, input, 1)
}

func (repository *PostgresRepository) UpdateRedTeamDefinition(ctx context.Context, identity RequestIdentity, input RedTeamDefinitionMutation) (RedTeamDefinitionMutationResult, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validRedTeamDefinitionMutation(input, true) {
		return RedTeamDefinitionMutationResult{}, ErrRepositoryOperation
	}
	categories, safety, err := redTeamDefinitionJSON(input)
	if err != nil {
		return RedTeamDefinitionMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamUpdateDefinitionSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.ID, input.ExpectedVersion, input.Name, input.TargetID, input.TargetKind, categories, safety, input.Enabled, input.CorrelationID)
	if err != nil {
		return RedTeamDefinitionMutationResult{}, discoveryProviderError(err)
	}
	return decodeRedTeamDefinitionMutation(payload, input, input.ExpectedVersion+1)
}

func (repository *PostgresRepository) RunRedTeamTest(ctx context.Context, identity RequestIdentity, input RedTeamRunRequest) (RedTeamRunMutationResult, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validProductID(input.DefinitionID) || input.DefinitionVersion < 1 || input.DefinitionVersion > 1000000 || !validProductID(input.RunID) || !validPublicIdempotency(input.IdempotencyKey) || !validProductID(input.CorrelationID) {
		return RedTeamRunMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamRunTestSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.DefinitionID, input.DefinitionVersion, input.RunID, input.CorrelationID)
	if err != nil {
		return RedTeamRunMutationResult{}, discoveryProviderError(err)
	}
	var result RedTeamRunMutationResult
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed") || decodeStrictDiscovery(payload, &result) != nil || !validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) || !validRedTeamRun(result.Body) || result.Body.ID != input.RunID || result.Body.DefinitionID != input.DefinitionID || result.Body.DefinitionVersion != input.DefinitionVersion || !result.Replayed && result.CorrelationID != input.CorrelationID {
		return RedTeamRunMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) ListRedTeamRuns(ctx context.Context, identity RequestIdentity, input RedTeamRunPageRequest) (RedTeamRunPage, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || input.Limit < 1 || input.Limit > 100 || input.BeforeCreatedAt.IsZero() != (input.BeforeID == "") || !input.BeforeCreatedAt.IsZero() && (input.BeforeCreatedAt.Location() != time.UTC || !validProductID(input.BeforeID)) {
		return RedTeamRunPage{}, ErrRepositoryOperation
	}
	var before any
	if !input.BeforeCreatedAt.IsZero() {
		before = input.BeforeCreatedAt
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamListRunsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), before, input.BeforeID, input.Limit)
	if err != nil {
		return RedTeamRunPage{}, discoveryProviderError(err)
	}
	var wire struct {
		Items      []RedTeamRun `json:"items"`
		NextCursor *struct {
			QueuedAt time.Time `json:"queued_at"`
			ID       string    `json:"id"`
		} `json:"next_cursor"`
	}
	if !exactJSONFields(payload, "items", "next_cursor") || decodeStrictDiscovery(payload, &wire) != nil || len(wire.Items) > input.Limit {
		return RedTeamRunPage{}, ErrRepositoryUnavailable
	}
	page := RedTeamRunPage{Items: wire.Items}
	for _, item := range wire.Items {
		if !validRedTeamRun(item) {
			return RedTeamRunPage{}, ErrRepositoryUnavailable
		}
	}
	if wire.NextCursor != nil {
		if len(wire.Items) != input.Limit || !canonicalRedTeamTime(wire.NextCursor.QueuedAt) || !validProductID(wire.NextCursor.ID) {
			return RedTeamRunPage{}, ErrRepositoryUnavailable
		}
		page.NextCreatedAt, page.NextID = &wire.NextCursor.QueuedAt, wire.NextCursor.ID
	}
	return page, nil
}

func (repository *PostgresRepository) GetRedTeamRun(ctx context.Context, identity RequestIdentity, runID string) (RedTeamRunDetail, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validProductID(runID) {
		return RedTeamRunDetail{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamGetRunSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID)
	if err != nil {
		return RedTeamRunDetail{}, discoveryProviderError(err)
	}
	var result RedTeamRunDetail
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != runID || !validRedTeamRun(result.RedTeamRun) || len(result.Attempts) > 5 {
		return RedTeamRunDetail{}, ErrRepositoryUnavailable
	}
	for index, attempt := range result.Attempts {
		if attempt.Attempt != index+1 || !validRedTeamAttempt(attempt) {
			return RedTeamRunDetail{}, ErrRepositoryUnavailable
		}
	}
	return result, nil
}

func (repository *PostgresRepository) CancelRedTeamRun(ctx context.Context, identity RequestIdentity, input RedTeamCancelRequest) (RedTeamRunMutationResult, error) {
	if !validRedTeamRepositoryRequest(repository, ctx, identity) || !validProductID(input.RunID) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validPublicIdempotency(input.IdempotencyKey) || !validProductID(input.CorrelationID) {
		return RedTeamRunMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamCancelRunSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.RunID, input.ExpectedVersion, input.CorrelationID)
	if err != nil {
		return RedTeamRunMutationResult{}, discoveryProviderError(err)
	}
	var result RedTeamRunMutationResult
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed") || decodeStrictDiscovery(payload, &result) != nil || !validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) || !result.Replayed && result.CorrelationID != input.CorrelationID || result.Body.ID != input.RunID || result.Body.Version != input.ExpectedVersion+1 || !validRedTeamRun(result.Body) || !result.Body.CancelRequested && result.Body.Status != "cancelled" {
		return RedTeamRunMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validRedTeamRepositoryRequest(repository *PostgresRepository, ctx context.Context, identity RequestIdentity) bool {
	return repository != nil && repository.schema == RedTeamExecutionSchemaVersion && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil && validRequestIdentity(identity, false) && stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken))
}

func redTeamScopeArguments(identity RequestIdentity, trailing ...any) []any {
	return append([]any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}, trailing...)
}

func validRedTeamDefinitionMutation(value RedTeamDefinitionMutation, update bool) bool {
	if !validProductID(value.ID) || !validPublicIdempotency(value.IdempotencyKey) || !validProductID(value.CorrelationID) || update != (value.ExpectedVersion > 0) || value.ExpectedVersion > 1000000 || len(value.Name) < 1 || len(value.Name) > 128 || value.Name != strings.TrimSpace(value.Name) || !validProductID(value.TargetID) || !stringIn(value.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || len(value.Categories) < 1 || len(value.Categories) > 16 || !validRedTeamSafety(value.Safety) {
		return false
	}
	seen := map[string]struct{}{}
	for _, category := range value.Categories {
		if !stringIn(category, "prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information") {
			return false
		}
		if _, duplicate := seen[category]; duplicate {
			return false
		}
		seen[category] = struct{}{}
	}
	return true
}

func validRedTeamSafety(value RedTeamSafety) bool {
	if !stringIn(value.Environment, "development", "test", "staging") || !stringIn(value.CredentialClass, "read_only", "test_write") || len(value.ExpectedSideEffects) < 1 || len(value.ExpectedSideEffects) > 16 {
		return false
	}
	for _, item := range value.ExpectedSideEffects {
		if len(item) < 1 || len(item) > 256 || item != strings.TrimSpace(item) {
			return false
		}
	}
	return true
}

func redTeamDefinitionJSON(value RedTeamDefinitionMutation) (json.RawMessage, json.RawMessage, error) {
	categories := append([]string(nil), value.Categories...)
	sort.Strings(categories)
	categoriesValue, err := json.Marshal(categories)
	if err != nil {
		return nil, nil, err
	}
	safetyValue, err := json.Marshal(map[string]any{"environment": value.Safety.Environment, "credential_class": value.Safety.CredentialClass, "expected_side_effects": value.Safety.ExpectedSideEffects})
	if err != nil {
		return nil, nil, err
	}
	return categoriesValue, safetyValue, nil
}

func decodeRedTeamDefinitionMutation(payload json.RawMessage, input RedTeamDefinitionMutation, expectedVersion int64) (RedTeamDefinitionMutationResult, error) {
	var result RedTeamDefinitionMutationResult
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed") || decodeStrictDiscovery(payload, &result) != nil || !validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) || !result.Replayed && result.CorrelationID != input.CorrelationID || !validRedTeamDefinition(result.Body) || result.Body.ID != input.ID || result.Body.Version != expectedVersion || result.Body.Name != input.Name || result.Body.TargetID != input.TargetID || result.Body.TargetKind != input.TargetKind || !equalStringSets(result.Body.Categories, input.Categories) || !equalRedTeamSafety(result.Body.Safety, input.Safety) {
		return RedTeamDefinitionMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validRedTeamMutationIdentity(auditID, correlationID, receiptID string) bool {
	return validProductID(auditID) && validProductID(correlationID) && validProductID(receiptID) && auditID != correlationID && auditID != receiptID && correlationID != receiptID
}

func validRedTeamDefinition(value RedTeamDefinition) bool {
	return validProductID(value.ID) && value.Version >= 1 && value.Version <= 1000000 && validRedTeamDefinitionMutation(RedTeamDefinitionMutation{ID: value.ID, IdempotencyKey: "definition-read-0001", ExpectedVersion: value.Version, Name: value.Name, TargetID: value.TargetID, TargetKind: value.TargetKind, Categories: value.Categories, Safety: value.Safety, Enabled: value.Enabled, CorrelationID: value.ID}, true) && canonicalRedTeamTime(value.CreatedAt) && canonicalRedTeamTime(value.UpdatedAt) && !value.UpdatedAt.Before(value.CreatedAt)
}

func validRedTeamRun(value RedTeamRun) bool {
	return validProductID(value.ID) && value.Version >= 1 && value.Version <= 1000000 && validProductID(value.DefinitionID) && value.DefinitionVersion >= 1 && value.DefinitionVersion <= 1000000 && stringIn(value.Status, "queued", "leased", "retryable", "complete", "failed", "cancelled") && value.Attempt >= 0 && value.Attempt <= 5 && canonicalRedTeamTime(value.QueuedAt) && (value.StartedAt == nil || canonicalRedTeamTime(*value.StartedAt)) && (value.CompletedAt == nil || canonicalRedTeamTime(*value.CompletedAt)) && (value.Verdict == "" || stringIn(value.Verdict, "pass", "fail", "engine_error")) && (value.ErrorCode == "" || stringIn(value.ErrorCode, "retryable", "rate_limited", "denied", "malformed", "outcome_unknown", "cancelled", "exhausted")) && (value.EvidenceReference == "" || len(value.EvidenceReference) <= 1024)
}

func validRedTeamAttempt(value RedTeamAttempt) bool {
	if value.Attempt < 1 || value.Attempt > 5 || !stringIn(value.Verdict, "pass", "fail", "engine_error") || len(value.Objective) < 1 || len(value.Objective) > 512 || len(value.Behavior) < 1 || len(value.Behavior) > 2048 || len(value.ErrorCode) > 64 || len(value.Evidence) > 64 || len(value.EvidenceReference) < 1 || len(value.EvidenceReference) > 1024 || !canonicalRedTeamTime(value.CompletedAt) {
		return false
	}
	for _, item := range value.Evidence {
		if len(item) < 1 || len(item) > 512 {
			return false
		}
	}
	return true
}

func canonicalRedTeamTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func equalStringSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func equalRedTeamSafety(left, right RedTeamSafety) bool {
	return left.Environment == right.Environment && left.CredentialClass == right.CredentialClass && equalStringSets(left.ExpectedSideEffects, right.ExpectedSideEffects)
}

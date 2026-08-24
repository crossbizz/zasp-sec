package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

const (
	postgresAttackLabListRunsSQL = `SELECT zasp_attack_lab_list_runs($1,$2,$3,$4,NULLIF($5,''),$6)`
	postgresAttackLabGetRunSQL   = `SELECT zasp_attack_lab_get_run($1,$2,$3,$4)`
	postgresAttackLabCreateSQL   = `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresAttackLabCancelSQL   = `SELECT zasp_attack_lab_cancel_run($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresAttackLabRerunSQL    = `SELECT zasp_attack_lab_rerun($1,$2,$3,$4,$5,$6,$7,$8,$9)`
)

type AttackLabSandboxLimits struct {
	CPU              string `json:"cpu"`
	Memory           string `json:"memory"`
	EphemeralStorage string `json:"ephemeral_storage"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
}

type AttackLabRun struct {
	ID                string                 `json:"id"`
	Version           int64                  `json:"version"`
	SourceRunID       string                 `json:"source_run_id"`
	DefinitionID      string                 `json:"definition_id"`
	DefinitionVersion int64                  `json:"definition_version"`
	TargetID          string                 `json:"target_id"`
	TargetKind        string                 `json:"target_kind"`
	Environment       string                 `json:"environment"`
	CredentialClass   string                 `json:"credential_class"`
	Destination       string                 `json:"destination"`
	Status            string                 `json:"status"`
	Attempt           int                    `json:"attempt"`
	CancelRequested   bool                   `json:"cancel_requested"`
	CleanupState      string                 `json:"cleanup_state"`
	Limits            AttackLabSandboxLimits `json:"limits"`
	QueuedAt          time.Time              `json:"queued_at"`
	StartedAt         *time.Time             `json:"started_at,omitempty"`
	CompletedAt       *time.Time             `json:"completed_at,omitempty"`
	Verdict           string                 `json:"verdict,omitempty"`
	ErrorCode         string                 `json:"error_code,omitempty"`
	EvidenceReference string                 `json:"evidence_reference,omitempty"`
}

type AttackLabAttempt struct {
	Attempt           int       `json:"attempt"`
	EvidenceState     string    `json:"evidence_state"`
	Verdict           string    `json:"verdict,omitempty"`
	CriterionObserved bool      `json:"criterion_observed"`
	CanaryTouched     bool      `json:"canary_touched"`
	CleanupCompleted  bool      `json:"cleanup_completed"`
	ErrorCode         string    `json:"error_code,omitempty"`
	Evidence          []string  `json:"evidence"`
	EvidenceReference string    `json:"evidence_reference,omitempty"`
	CompletedAt       time.Time `json:"completed_at"`
}

type AttackLabRunDetail struct {
	AttackLabRun
	Attempts []AttackLabAttempt `json:"attempts"`
}

type AttackLabRunPage struct {
	Items         []AttackLabRun
	NextCreatedAt *time.Time
	NextID        string
}

type AttackLabRunPageRequest struct {
	BeforeCreatedAt time.Time
	BeforeID        string
	Limit           int
}

type AttackLabCreateRequest struct {
	RunID          string
	SourceRunID    string
	Approved       bool
	IdempotencyKey string
	CorrelationID  string
}

type AttackLabCancelRequest struct {
	RunID           string
	ExpectedVersion int64
	IdempotencyKey  string
	CorrelationID   string
}

type AttackLabRerunRequest struct {
	SourceRunID     string
	RunID           string
	ExpectedVersion int64
	IdempotencyKey  string
	CorrelationID   string
}

type AttackLabMutationResult struct {
	Body          AttackLabRun `json:"body"`
	AuditID       string       `json:"audit_id"`
	CorrelationID string       `json:"correlation_id"`
	ReceiptID     string       `json:"receipt_id"`
	Replayed      bool         `json:"replayed"`
}

func (repository *PostgresRepository) ListAttackLabRuns(ctx context.Context, identity RequestIdentity, input AttackLabRunPageRequest) (AttackLabRunPage, error) {
	if !validAttackLabRepositoryRequest(repository, ctx, identity) || input.Limit < 1 || input.Limit > 100 || input.BeforeCreatedAt.IsZero() != (input.BeforeID == "") || !input.BeforeCreatedAt.IsZero() && (input.BeforeCreatedAt.Location() != time.UTC || !validProductID(input.BeforeID)) {
		return AttackLabRunPage{}, ErrRepositoryOperation
	}
	var before any
	if !input.BeforeCreatedAt.IsZero() {
		before = input.BeforeCreatedAt
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabListRunsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), before, input.BeforeID, input.Limit)
	if err != nil {
		return AttackLabRunPage{}, discoveryProviderError(err)
	}
	var wire struct {
		Items      []AttackLabRun `json:"items"`
		NextCursor *struct {
			QueuedAt time.Time `json:"queued_at"`
			ID       string    `json:"id"`
		} `json:"next_cursor"`
	}
	if !exactJSONFields(payload, "items", "next_cursor") || decodeStrictDiscovery(payload, &wire) != nil || len(wire.Items) > input.Limit {
		return AttackLabRunPage{}, ErrRepositoryUnavailable
	}
	page := AttackLabRunPage{Items: wire.Items}
	for index, item := range wire.Items {
		if !validAttackLabRun(item) || index > 0 && !attackLabRunAfter(wire.Items[index-1], item) {
			return AttackLabRunPage{}, ErrRepositoryUnavailable
		}
	}
	if wire.NextCursor != nil {
		if len(wire.Items) != input.Limit || !canonicalRedTeamTime(wire.NextCursor.QueuedAt) || !validProductID(wire.NextCursor.ID) {
			return AttackLabRunPage{}, ErrRepositoryUnavailable
		}
		page.NextCreatedAt, page.NextID = &wire.NextCursor.QueuedAt, wire.NextCursor.ID
	}
	return page, nil
}

func (repository *PostgresRepository) GetAttackLabRun(ctx context.Context, identity RequestIdentity, runID string) (AttackLabRunDetail, error) {
	if !validAttackLabRepositoryRequest(repository, ctx, identity) || !validProductID(runID) {
		return AttackLabRunDetail{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabGetRunSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID)
	if err != nil {
		return AttackLabRunDetail{}, discoveryProviderError(err)
	}
	var result AttackLabRunDetail
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != runID || !validAttackLabRun(result.AttackLabRun) || len(result.Attempts) > 5 {
		return AttackLabRunDetail{}, ErrRepositoryUnavailable
	}
	prior := 0
	for _, attempt := range result.Attempts {
		if !validAttackLabAttempt(attempt) || attempt.Attempt <= prior || attempt.Attempt > result.Attempt || attempt.EvidenceReference != result.EvidenceReference {
			return AttackLabRunDetail{}, ErrRepositoryUnavailable
		}
		prior = attempt.Attempt
	}
	if result.Status == "complete" {
		if len(result.Attempts) != 1 || result.Attempts[0].Attempt != result.Attempt || result.Attempts[0].Verdict != result.Verdict || result.CompletedAt == nil || !result.Attempts[0].CompletedAt.Equal(*result.CompletedAt) {
			return AttackLabRunDetail{}, ErrRepositoryUnavailable
		}
	} else if len(result.Attempts) != 0 {
		return AttackLabRunDetail{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) CreateAttackLabRun(ctx context.Context, identity RequestIdentity, input AttackLabCreateRequest) (AttackLabMutationResult, error) {
	if !validAttackLabRepositoryRequest(repository, ctx, identity) || !validProductID(input.RunID) || !validProductID(input.SourceRunID) || input.RunID == input.SourceRunID || !input.Approved || !validPublicIdempotency(input.IdempotencyKey) || !validProductID(input.CorrelationID) {
		return AttackLabMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabCreateSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.RunID, input.SourceRunID, input.CorrelationID)
	if err != nil {
		return AttackLabMutationResult{}, discoveryProviderError(err)
	}
	return decodeAttackLabMutation(payload, input.RunID, input.SourceRunID, 1, input.CorrelationID)
}

func (repository *PostgresRepository) CancelAttackLabRun(ctx context.Context, identity RequestIdentity, input AttackLabCancelRequest) (AttackLabMutationResult, error) {
	if !validAttackLabRepositoryRequest(repository, ctx, identity) || !validProductID(input.RunID) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validPublicIdempotency(input.IdempotencyKey) || !validProductID(input.CorrelationID) {
		return AttackLabMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabCancelSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.RunID, input.ExpectedVersion, input.CorrelationID)
	if err != nil {
		return AttackLabMutationResult{}, discoveryProviderError(err)
	}
	result, err := decodeAttackLabMutation(payload, input.RunID, "", input.ExpectedVersion+1, input.CorrelationID)
	if err != nil || !result.Body.CancelRequested && result.Body.Status != "cancelled" {
		return AttackLabMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) RerunAttackLabRun(ctx context.Context, identity RequestIdentity, input AttackLabRerunRequest) (AttackLabMutationResult, error) {
	if !validAttackLabRepositoryRequest(repository, ctx, identity) || !validProductID(input.SourceRunID) || !validProductID(input.RunID) || input.SourceRunID == input.RunID || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validPublicIdempotency(input.IdempotencyKey) || !validProductID(input.CorrelationID) {
		return AttackLabMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAttackLabRerunSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.SourceRunID, input.ExpectedVersion, input.RunID, input.CorrelationID)
	if err != nil {
		return AttackLabMutationResult{}, discoveryProviderError(err)
	}
	return decodeAttackLabMutation(payload, input.RunID, "", 1, input.CorrelationID)
}

func decodeAttackLabMutation(payload json.RawMessage, runID, sourceRedTeamRunID string, expectedVersion int64, correlationID string) (AttackLabMutationResult, error) {
	var result AttackLabMutationResult
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed") || decodeStrictDiscovery(payload, &result) != nil || !validRedTeamMutationIdentity(result.AuditID, result.CorrelationID, result.ReceiptID) || !result.Replayed && result.CorrelationID != correlationID || result.Body.ID != runID || result.Body.Version != expectedVersion || sourceRedTeamRunID != "" && result.Body.SourceRunID != sourceRedTeamRunID || !validAttackLabRun(result.Body) {
		return AttackLabMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validAttackLabRepositoryRequest(repository *PostgresRepository, ctx context.Context, identity RequestIdentity) bool {
	return repository != nil && repository.schema == AttackLabExecutionSchemaVersion && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil && validRedTeamCredential(identity)
}

func validAttackLabRun(value AttackLabRun) bool {
	if !validProductID(value.ID) || value.Version < 1 || value.Version > 1000000 || !validProductID(value.SourceRunID) || !validProductID(value.DefinitionID) || value.DefinitionVersion < 1 || value.DefinitionVersion > 1000000 || !validProductID(value.TargetID) || !stringIn(value.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || !stringIn(value.Environment, "development", "test", "staging") || !stringIn(value.CredentialClass, "read_only", "test_write") || !validAttackLabDestination(value.Destination) || value.Attempt < 0 || value.Attempt > 5 || value.Limits != (AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}) || !canonicalRedTeamTime(value.QueuedAt) || value.StartedAt != nil && (!canonicalRedTeamTime(*value.StartedAt) || value.StartedAt.Before(value.QueuedAt)) || value.CompletedAt != nil && (!canonicalRedTeamTime(*value.CompletedAt) || value.CompletedAt.Before(value.QueuedAt) || value.StartedAt != nil && value.CompletedAt.Before(*value.StartedAt)) || value.EvidenceReference != "" && !canonicalInventoryText(value.EvidenceReference, 1, 1024) {
		return false
	}
	started, completed, verdict, failure, evidence := value.StartedAt != nil, value.CompletedAt != nil, value.Verdict != "", value.ErrorCode != "", value.EvidenceReference != ""
	switch value.Status {
	case "queued":
		return value.Attempt == 0 && !value.CancelRequested && value.CleanupState == "pending" && !started && !completed && !verdict && !failure && !evidence
	case "leased", "running":
		return value.Attempt >= 1 && value.CleanupState == "pending" && started && !completed && !verdict && !failure && !evidence
	case "retryable":
		return value.Attempt >= 1 && value.Attempt < 5 && !value.CancelRequested && value.CleanupState == "pending" && started && !completed && !verdict && stringIn(value.ErrorCode, "retryable", "outcome_unknown") && !evidence
	case "cleanup":
		return value.Attempt >= 1 && value.CleanupState == "in_progress" && started && !completed && !verdict && !failure && !evidence
	case "complete":
		return value.Attempt >= 1 && !value.CancelRequested && value.CleanupState == "complete" && started && completed && stringIn(value.Verdict, "verified", "not_reproduced", "inconclusive") && (evidence && !failure || !evidence && value.Verdict == "inconclusive" && value.ErrorCode == "outcome_unknown")
	case "failed":
		return value.Attempt >= 1 && started && completed && !verdict && stringIn(value.ErrorCode, "denied", "malformed", "outcome_unknown", "cleanup_failed", "exhausted") && !evidence && (value.ErrorCode == "cleanup_failed" && value.CleanupState == "failed" || value.ErrorCode != "cleanup_failed" && value.CleanupState == "complete")
	case "cancelled":
		return value.CancelRequested && value.CleanupState == "complete" && completed && !verdict && value.ErrorCode == "cancelled" && (value.Attempt == 0 && !started && !evidence || value.Attempt >= 1 && started)
	default:
		return false
	}
}

func validAttackLabAttempt(value AttackLabAttempt) bool {
	if value.Attempt < 1 || value.Attempt > 5 || !canonicalRedTeamTime(value.CompletedAt) || !value.CleanupCompleted || value.Verdict == "verified" && (!value.CriterionObserved || !value.CanaryTouched) || value.Verdict == "not_reproduced" && (value.CriterionObserved || value.CanaryTouched) {
		return false
	}
	if value.EvidenceState == "unavailable" {
		return len(value.Evidence) == 0 && value.EvidenceReference == "" && !value.CriterionObserved && !value.CanaryTouched && (value.Verdict == "inconclusive" && value.ErrorCode == "outcome_unknown" || value.Verdict == "" && value.ErrorCode == "cancelled")
	}
	if value.EvidenceState != "complete" || len(value.Evidence) != 5 || !canonicalInventoryText(value.EvidenceReference, 1, 1024) || !(stringIn(value.Verdict, "verified", "not_reproduced", "inconclusive") || value.Verdict == "" && value.ErrorCode == "cancelled") {
		return false
	}
	prefixes := [...]string{"semantic:", "gateway:", "egress:", "kubernetes:", "cloud:"}
	for index, item := range value.Evidence {
		if !canonicalInventoryText(item, 1, 512) || !strings.HasPrefix(item, prefixes[index]) || len(item) == len(prefixes[index]) {
			return false
		}
	}
	return value.ErrorCode == "" || value.Verdict == "inconclusive" && stringIn(value.ErrorCode, "denied", "malformed", "outcome_unknown", "cleanup_failed", "exhausted", "cancelled") || value.Verdict == "" && value.ErrorCode == "cancelled"
}

func validAttackLabDestination(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func attackLabRunAfter(prior, current AttackLabRun) bool {
	return prior.QueuedAt.After(current.QueuedAt) || prior.QueuedAt.Equal(current.QueuedAt) && prior.ID > current.ID
}

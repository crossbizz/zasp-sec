package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresRiskFindingGetSQL      = `SELECT zasp_risk_finding_get($1, $2, $3, $4)`
	postgresRiskFindingPageSQL     = `SELECT zasp_risk_finding_page($1, $2, $3, NULLIF($4, ''), $5)`
	postgresRiskAttackPathGetSQL   = `SELECT zasp_risk_attack_path_get($1, $2, $3, $4)`
	postgresRiskAttackPathPageSQL  = `SELECT zasp_risk_attack_path_page($1, $2, $3, NULLIF($4, ''), $5)`
	postgresRiskBreakOptionsGetSQL = `SELECT zasp_risk_break_options_get($1, $2, $3, $4)`
	postgresRiskHighPathCountSQL   = `SELECT to_jsonb(zasp_risk_high_path_count($1, $2, $3))`
	postgresRiskFindingMutateSQL   = `SELECT zasp_risk_mutate($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), $11, $12, NULLIF($13, ''))`
)

type RiskFactor struct {
	Name       string `json:"name"`
	EvidenceID string `json:"evidence_id"`
}

type RiskFinding struct {
	ID                string       `json:"id"`
	Source            string       `json:"source"`
	Rule              string       `json:"rule,omitempty"`
	Title             string       `json:"title"`
	Severity          string       `json:"severity"`
	Status            string       `json:"status"`
	AgentID           string       `json:"agent_id,omitempty"`
	PathID            string       `json:"path_id,omitempty"`
	ComplianceContext string       `json:"compliance_context,omitempty"`
	EvidenceIDs       []string     `json:"evidence_ids"`
	RiskFactors       []RiskFactor `json:"risk_factors"`
	AcceptanceReason  string       `json:"acceptance_reason,omitempty"`
	Version           int64        `json:"version"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

type RiskFindingPage struct {
	Items  []RiskFinding
	NextID string
}

type RiskAttackPath struct {
	ID          string    `json:"id"`
	EntryID     string    `json:"entry_id"`
	SinkID      string    `json:"sink_id"`
	NodeIDs     []string  `json:"node_ids"`
	State       string    `json:"state"`
	EvidenceIDs []string  `json:"evidence_ids"`
	BlockedEdge int       `json:"blocked_edge"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RiskAttackPathPage struct {
	Items  []RiskAttackPath
	NextID string
}

type RiskBreakOption struct {
	PathID     string `json:"path_id"`
	TargetID   string `json:"target_id"`
	EvidenceID string `json:"evidence_id"`
	Kind       string `json:"kind"`
	Rank       int    `json:"rank"`
}

type RiskFindingMutation struct {
	Operation       string
	FindingID       string
	IdempotencyKey  string
	ExpectedVersion int64
	Status          string
	Reason          string
	AuditID         string
	CorrelationID   string
	ReceiptID       string
}

type RiskFindingMutationResult struct {
	Body          RiskFinding `json:"body"`
	Version       int64       `json:"version"`
	AuditID       string      `json:"audit_id"`
	CorrelationID string      `json:"correlation_id"`
	ReceiptID     string      `json:"receipt_id,omitempty"`
	Replayed      bool        `json:"replayed"`
}

func (repository *PostgresRepository) ReplayRiskFinding(ctx context.Context, identity RequestIdentity, operation, idempotencyKey string, intent json.RawMessage) (RiskFindingMutationResult, bool, error) {
	replayed, found, err := repository.ReplayWorkflow(ctx, identity, operation, idempotencyKey, intent)
	if err != nil || !found {
		return RiskFindingMutationResult{}, found, err
	}
	var finding RiskFinding
	if decodeStrictRisk(replayed.Body, &finding) != nil || !validRiskFinding(finding) || finding.Version != replayed.Version {
		return RiskFindingMutationResult{}, false, ErrRepositoryUnavailable
	}
	normalizeRiskFinding(&finding)
	return RiskFindingMutationResult{Body: finding, Version: replayed.Version, AuditID: replayed.AuditID, CorrelationID: replayed.CorrelationID, ReceiptID: replayed.ReceiptID, Replayed: true}, true, nil
}

func (repository *PostgresRepository) GetRiskFinding(ctx context.Context, scope domain.Scope, id string) (RiskFinding, error) {
	if !validRiskRead(repository, ctx, scope, id) {
		return RiskFinding{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskFindingGetSQL, id, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return RiskFinding{}, riskProviderError(err)
	}
	var result RiskFinding
	if decodeStrictRisk(payload, &result) != nil || !validRiskFinding(result) {
		return RiskFinding{}, ErrRepositoryUnavailable
	}
	normalizeRiskFinding(&result)
	return result, nil
}

func (repository *PostgresRepository) ListRiskFindingPage(ctx context.Context, scope domain.Scope, afterID string, limit int) (RiskFindingPage, error) {
	if !validRiskPage(repository, ctx, scope, afterID, limit) {
		return RiskFindingPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskFindingPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit)
	return decodeRiskFindingPage(payload, err, limit)
}

func decodeRiskFindingPage(payload json.RawMessage, err error, limit int) (RiskFindingPage, error) {
	if err != nil {
		return RiskFindingPage{}, riskProviderError(err)
	}
	var envelope struct {
		Items  []RiskFinding `json:"items"`
		NextID *string       `json:"next_id"`
	}
	if decodeStrictRisk(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return RiskFindingPage{}, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		if !validRiskFinding(envelope.Items[index]) {
			return RiskFindingPage{}, ErrRepositoryUnavailable
		}
		normalizeRiskFinding(&envelope.Items[index])
	}
	nextID := ""
	if envelope.NextID != nil {
		nextID = *envelope.NextID
		if !validProductID(nextID) || len(envelope.Items) != limit || len(envelope.Items) == 0 || envelope.Items[len(envelope.Items)-1].ID != nextID {
			return RiskFindingPage{}, ErrRepositoryUnavailable
		}
	}
	return RiskFindingPage{Items: envelope.Items, NextID: nextID}, nil
}

func (repository *PostgresRepository) GetRiskAttackPath(ctx context.Context, scope domain.Scope, id string) (RiskAttackPath, error) {
	if !validRiskRead(repository, ctx, scope, id) {
		return RiskAttackPath{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskAttackPathGetSQL, id, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return RiskAttackPath{}, riskProviderError(err)
	}
	var result RiskAttackPath
	if decodeStrictRisk(payload, &result) != nil || !validRiskAttackPath(result) {
		return RiskAttackPath{}, ErrRepositoryUnavailable
	}
	normalizeRiskAttackPath(&result)
	return result, nil
}

func (repository *PostgresRepository) ListRiskAttackPathPage(ctx context.Context, scope domain.Scope, afterID string, limit int) (RiskAttackPathPage, error) {
	if !validRiskPage(repository, ctx, scope, afterID, limit) {
		return RiskAttackPathPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskAttackPathPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit)
	if err != nil {
		return RiskAttackPathPage{}, riskProviderError(err)
	}
	var envelope struct {
		Items  []RiskAttackPath `json:"items"`
		NextID *string          `json:"next_id"`
	}
	if decodeStrictRisk(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return RiskAttackPathPage{}, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		if !validRiskAttackPath(envelope.Items[index]) {
			return RiskAttackPathPage{}, ErrRepositoryUnavailable
		}
		normalizeRiskAttackPath(&envelope.Items[index])
	}
	nextID := ""
	if envelope.NextID != nil {
		nextID = *envelope.NextID
		if !validProductID(nextID) || len(envelope.Items) != limit || len(envelope.Items) == 0 || envelope.Items[len(envelope.Items)-1].ID != nextID {
			return RiskAttackPathPage{}, ErrRepositoryUnavailable
		}
	}
	return RiskAttackPathPage{Items: envelope.Items, NextID: nextID}, nil
}

func (repository *PostgresRepository) GetRiskBreakOptions(ctx context.Context, scope domain.Scope, pathID string) ([]RiskBreakOption, error) {
	if !validRiskRead(repository, ctx, scope, pathID) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskBreakOptionsGetSQL, pathID, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return nil, riskProviderError(err)
	}
	var envelope struct {
		Items []RiskBreakOption `json:"items"`
	}
	if decodeStrictRisk(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > 8 {
		return nil, ErrRepositoryUnavailable
	}
	seen := map[string]struct{}{}
	for index, option := range envelope.Items {
		if option.PathID != pathID || !validProductID(option.TargetID) || !validProductID(option.EvidenceID) || option.Kind != "remove_node" && option.Kind != "enforce_policy" || option.Rank != index+1 {
			return nil, ErrRepositoryUnavailable
		}
		key := option.Kind + "\x00" + option.TargetID
		if _, exists := seen[key]; exists {
			return nil, ErrRepositoryUnavailable
		}
		seen[key] = struct{}{}
	}
	return envelope.Items, nil
}

func (repository *PostgresRepository) CountHighRiskPaths(ctx context.Context, scope domain.Scope) (int64, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope.Validate() != nil {
		return 0, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskHighPathCountSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return 0, riskProviderError(err)
	}
	var result int64
	if decodeStrictRisk(payload, &result) != nil || result < 0 {
		return 0, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) MutateRiskFinding(ctx context.Context, identity RequestIdentity, mutation RiskFindingMutation) (RiskFindingMutationResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !validRiskFindingMutation(mutation) || !validMutationReceiptIdentity(identity, mutation.ReceiptID) {
		return RiskFindingMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRiskFindingMutateSQL,
		mutation.Operation, mutation.FindingID,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Status, mutation.Reason, mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID,
	)
	if err != nil {
		return RiskFindingMutationResult{}, riskProviderError(err)
	}
	var result RiskFindingMutationResult
	if decodeStrictRisk(payload, &result) != nil || !validRiskFinding(result.Body) || result.Version != result.Body.Version || result.Version != mutation.ExpectedVersion+1 || result.AuditID != mutation.AuditID || result.CorrelationID != mutation.CorrelationID || result.ReceiptID != mutation.ReceiptID {
		return RiskFindingMutationResult{}, ErrRepositoryUnavailable
	}
	normalizeRiskFinding(&result.Body)
	return result, nil
}

func validRiskRead(repository *PostgresRepository, ctx context.Context, scope domain.Scope, id string) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && scope.Validate() == nil && validProductID(id)
}

func validRiskPage(repository *PostgresRepository, ctx context.Context, scope domain.Scope, afterID string, limit int) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && scope.Validate() == nil && limit >= 1 && limit <= 100 && (afterID == "" || validProductID(afterID))
}

func validProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validRiskFinding(value RiskFinding) bool {
	if !validProductID(value.ID) || value.Source != "posture" && value.Source != "prowler" || len(value.Title) < 1 || len(value.Title) > 256 || !stringIn(value.Severity, "critical", "high", "medium", "low") || !stringIn(value.Status, "open", "under_review", "resolved", "accepted") || len(value.EvidenceIDs) < 1 || len(value.EvidenceIDs) > 64 || value.RiskFactors == nil || len(value.RiskFactors) > 16 || value.Version < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.Rule != "" && len(value.Rule) > 64 || value.ComplianceContext != "" && len(value.ComplianceContext) > 128 || value.Status == "accepted" != (len(value.AcceptanceReason) >= 1 && len(value.AcceptanceReason) <= 512) {
		return false
	}
	if value.AgentID != "" && !validProductID(value.AgentID) || value.PathID != "" && !validProductID(value.PathID) {
		return false
	}
	seenEvidence := map[string]struct{}{}
	for _, id := range value.EvidenceIDs {
		if !validProductID(id) {
			return false
		}
		if _, duplicate := seenEvidence[id]; duplicate {
			return false
		}
		seenEvidence[id] = struct{}{}
	}
	seenFactors := map[string]struct{}{}
	for _, factor := range value.RiskFactors {
		if len(factor.Name) < 1 || len(factor.Name) > 64 || !validProductID(factor.EvidenceID) {
			return false
		}
		key := factor.Name + "\x00" + factor.EvidenceID
		if _, duplicate := seenFactors[key]; duplicate {
			return false
		}
		seenFactors[key] = struct{}{}
	}
	return true
}

func validRiskAttackPath(value RiskAttackPath) bool {
	if !validProductID(value.ID) || !validProductID(value.EntryID) || !validProductID(value.SinkID) || len(value.NodeIDs) < 2 || len(value.NodeIDs) > 8 || !stringIn(value.State, "potential", "observed", "verified", "blocked") || len(value.EvidenceIDs) < 1 || len(value.EvidenceIDs) > 16 || value.Version < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || value.NodeIDs[0] != value.EntryID || value.NodeIDs[len(value.NodeIDs)-1] != value.SinkID {
		return false
	}
	if value.State == "blocked" {
		if value.BlockedEdge < 0 || value.BlockedEdge >= len(value.NodeIDs)-1 {
			return false
		}
	} else if value.BlockedEdge != -1 {
		return false
	}
	return validUniqueProductIDs(value.NodeIDs) && validUniqueProductIDs(value.EvidenceIDs)
}

func validUniqueProductIDs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validProductID(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validRiskFindingMutation(value RiskFindingMutation) bool {
	if !validProductID(value.FindingID) || len(value.IdempotencyKey) < 16 || len(value.IdempotencyKey) > 128 || !workflowKeyPattern.MatchString(value.IdempotencyKey) || value.ExpectedVersion < 1 || !validProductID(value.AuditID) || !validProductID(value.CorrelationID) {
		return false
	}
	switch value.Operation {
	case "updateFinding":
		return stringIn(value.Status, "open", "under_review", "resolved") && value.Reason == ""
	case "acceptFindingRisk":
		return value.Status == "accepted" && len(value.Reason) >= 1 && len(value.Reason) <= 512 && strings.TrimSpace(value.Reason) == value.Reason
	default:
		return false
	}
}

func decodeStrictRisk(payload json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrRepositoryUnavailable
	}
	return nil
}

func normalizeRiskFinding(value *RiskFinding) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func normalizeRiskAttackPath(value *RiskAttackPath) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
}

func stringIn(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func riskProviderError(err error) error {
	if err == ErrRepositoryOperation {
		return ErrRepositoryUnavailable
	}
	return err
}

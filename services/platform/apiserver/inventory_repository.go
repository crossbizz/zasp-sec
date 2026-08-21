package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const TypedInventorySchemaVersion = "typed-inventory-cutover-v1"

const (
	postgresInventoryReadinessSQL     = `SELECT to_jsonb(zasp_inventory_readiness($1, $2))`
	postgresInventoryPageSQL          = `SELECT zasp_inventory_page($1, $2, $3, $4, NULLIF($5, ''), $6)`
	postgresInventoryDetailSQL        = `SELECT zasp_inventory_detail($1, $2, $3, $4, $5)`
	postgresInventoryUpdateAgentSQL   = `SELECT zasp_inventory_update_agent($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)`
	postgresInventoryCapabilitiesSQL  = `SELECT zasp_inventory_agent_capabilities_page($1, $2, $3, $4, NULLIF($5, ''), $6)`
	postgresInventoryRelationshipsSQL = `SELECT zasp_inventory_agent_relationships_page($1, $2, $3, $4, NULLIF($5, ''), $6)`
	postgresInventorySessionsSQL      = `SELECT zasp_inventory_agent_sessions_page($1, $2, $3, $4, NULLIF($5, ''), $6)`
	postgresInventoryHomeSummarySQL   = `SELECT zasp_inventory_home_summary($1, $2, $3)`
)

type InventoryKind string

const (
	InventoryKindAsset    InventoryKind = "asset"
	InventoryKindAgent    InventoryKind = "agent"
	InventoryKindTool     InventoryKind = "tool"
	InventoryKindIdentity InventoryKind = "identity"
	InventoryKindRuntime  InventoryKind = "runtime"
)

type InventorySummary struct {
	ID                    string        `json:"id"`
	Name                  string        `json:"name"`
	Kind                  InventoryKind `json:"kind"`
	Owner                 string        `json:"owner"`
	Team                  string        `json:"team"`
	Tags                  []string      `json:"tags"`
	EvidenceID            string        `json:"evidence_id"`
	ConfidenceBasisPoints int           `json:"confidence_basis_points"`
	FirstSeen             string        `json:"first_seen"`
	LastSeen              string        `json:"last_seen"`
	ObservedAt            string        `json:"observed_at"`
	FreshUntil            string        `json:"fresh_until"`
	FreshnessState        string        `json:"freshness_state"`
	Version               int64         `json:"version"`
}

type InventorySourceObservation struct {
	IntegrationID         string `json:"integration_id"`
	Provider              string `json:"provider"`
	Source                string `json:"source"`
	SourceIdentifier      string `json:"source_identifier"`
	SnapshotID            string `json:"snapshot_id"`
	Generation            int64  `json:"generation"`
	EvidenceID            string `json:"evidence_id"`
	ConfidenceBasisPoints int    `json:"confidence_basis_points"`
	ObservedAt            string `json:"observed_at"`
	FreshUntil            string `json:"fresh_until"`
	ProjectionVersion     int    `json:"projection_version"`
	Winning               bool   `json:"winning"`
}

type InventoryEvidenceReference struct {
	ID            string `json:"id"`
	Checksum      string `json:"checksum"`
	MediaType     string `json:"media_type"`
	SchemaVersion string `json:"schema_version"`
	ParserVersion string `json:"parser_version"`
	ToolVersion   string `json:"tool_version"`
	CollectedAt   string `json:"collected_at"`
	SizeBytes     int64  `json:"size_bytes"`
}

type InventoryDetail struct {
	Summary  InventorySummary             `json:"summary"`
	Sources  []InventorySourceObservation `json:"sources"`
	Evidence []InventoryEvidenceReference `json:"evidence"`
}

type InventoryPage struct {
	Items   []InventorySummary `json:"items"`
	NextKey string             `json:"-"`
}

type AgentOwnershipInput struct {
	Owner string   `json:"owner"`
	Team  string   `json:"team"`
	Tags  []string `json:"tags"`
}

type AgentMutationResult struct {
	Agent         InventorySummary `json:"agent"`
	AuditID       string           `json:"audit_id"`
	CorrelationID string           `json:"correlation_id"`
	Replayed      bool             `json:"replayed"`
}

type Capability struct {
	AgentID     string   `json:"agent_id"`
	TargetID    string   `json:"target_id"`
	TargetKind  string   `json:"target_kind"`
	Category    string   `json:"category"`
	Outcome     string   `json:"outcome"`
	State       string   `json:"state"`
	Reachable   bool     `json:"reachable"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type CapabilityPage struct {
	Items   []Capability `json:"items"`
	NextKey string       `json:"-"`
}

type Relationship struct {
	ID         string `json:"id"`
	FromID     string `json:"from_id"`
	ToID       string `json:"to_id"`
	Type       string `json:"type"`
	EvidenceID string `json:"evidence_id"`
}

type RelationshipPage struct {
	Items   []Relationship `json:"items"`
	NextKey string         `json:"-"`
}

type AgentSession struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	StartedAt string `json:"started_at"`
}

type SessionPage struct {
	Items   []AgentSession `json:"items"`
	NextKey string         `json:"-"`
}

type HomeSummary struct {
	AgentCount               int64 `json:"agent_count"`
	HighRiskPaths            int64 `json:"high_risk_paths"`
	VerifiedChanges          int64 `json:"verified_changes"`
	BlockedChanges           int64 `json:"blocked_changes"`
	PendingApprovals         int64 `json:"pending_approvals"`
	OldestApprovalAgeSeconds int64 `json:"oldest_approval_age_seconds"`
	NeedsHumanRuns           int64 `json:"needs_human_runs"`
	FailedRuns               int64 `json:"failed_runs"`
	InconclusiveRuns         int64 `json:"inconclusive_runs"`
	RecentContained          int64 `json:"recent_contained"`
	RecentRemediated         int64 `json:"recent_remediated"`
	Healthy                  bool  `json:"healthy"`
	AttentionRequired        bool  `json:"attention_required"`
}

type InventoryRepository interface {
	ListInventoryPage(context.Context, domain.Scope, InventoryKind, string, int) (InventoryPage, error)
	GetInventory(context.Context, domain.Scope, domain.ProductID, InventoryKind) (InventoryDetail, error)
	ListAgentCapabilitiesPage(context.Context, domain.Scope, domain.ProductID, string, int) (CapabilityPage, error)
	ListAgentRelationshipsPage(context.Context, domain.Scope, domain.ProductID, string, int) (RelationshipPage, error)
	ListAgentSessionsPage(context.Context, domain.Scope, domain.ProductID, string, int) (SessionPage, error)
	GetHomeSummary(context.Context, domain.Scope) (HomeSummary, error)
	UpdateAgentOwnership(context.Context, RequestIdentity, domain.ProductID, int64, string, AgentOwnershipInput, string, string) (AgentMutationResult, error)
}

type PostgresInventoryRepository struct{ database JSONDatabase }

func NewPostgresInventoryRepository(database JSONDatabase) (*PostgresInventoryRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := database.SchemaVersion(ctx)
	if err != nil || !isTypedInventorySchema(version) {
		return nil, ErrRepositoryConfiguration
	}
	readySQL, checksum, fingerprint, ok := exactProductReadiness(version)
	if !ok {
		return nil, ErrRepositoryConfiguration
	}
	payload, err := database.QueryJSON(ctx, readySQL, checksum, fingerprint)
	var ready bool
	if err != nil || decodeStrictInventory(payload, &ready) != nil || !ready {
		return nil, ErrRepositoryConfiguration
	}
	return &PostgresInventoryRepository{database: database}, nil
}

func (repository *PostgresInventoryRepository) ListInventoryPage(ctx context.Context, scope domain.Scope, kind InventoryKind, after string, limit int) (InventoryPage, error) {
	if !validInventoryCall(repository, ctx, scope, kind, after, limit) {
		return InventoryPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventoryPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), kind, after, limit)
	if err != nil {
		return InventoryPage{}, inventoryProviderError(err)
	}
	var envelope struct {
		Items  []InventorySummary `json:"items"`
		NextID *string            `json:"next_id"`
	}
	if decodeStrictInventory(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for index := range envelope.Items {
		if !validInventorySummary(envelope.Items[index], kind) || prior != "" && envelope.Items[index].ID <= prior {
			return InventoryPage{}, ErrRepositoryUnavailable
		}
		prior = envelope.Items[index].ID
	}
	next := ""
	if envelope.NextID != nil {
		next = *envelope.NextID
		if len(envelope.Items) != limit || next == "" || envelope.Items[len(envelope.Items)-1].ID != next {
			return InventoryPage{}, ErrRepositoryUnavailable
		}
	}
	return InventoryPage{Items: envelope.Items, NextKey: next}, nil
}

func (repository *PostgresInventoryRepository) GetInventory(ctx context.Context, scope domain.Scope, id domain.ProductID, kind InventoryKind) (InventoryDetail, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || id.IsZero() || !validInventoryKind(kind) {
		return InventoryDetail{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventoryDetailSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id.String(), kind)
	if err != nil {
		return InventoryDetail{}, inventoryProviderError(err)
	}
	var detail InventoryDetail
	if decodeStrictInventory(payload, &detail) != nil || detail.Summary.ID != id.String() || !validInventoryDetail(detail, kind) {
		return InventoryDetail{}, ErrRepositoryUnavailable
	}
	return detail, nil
}

func (repository *PostgresInventoryRepository) ListAgentCapabilitiesPage(ctx context.Context, scope domain.Scope, id domain.ProductID, after string, limit int) (CapabilityPage, error) {
	if !validInventorySubresourceCall(repository, ctx, scope, id, after, limit) {
		return CapabilityPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventoryCapabilitiesSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id.String(), after, limit)
	if err != nil {
		return CapabilityPage{}, inventoryProviderError(err)
	}
	var envelope struct {
		Items   []Capability `json:"items"`
		NextKey *string      `json:"next_key"`
	}
	if decodeStrictInventory(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return CapabilityPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for _, item := range envelope.Items {
		key := capabilityKey(item)
		if !validCapability(item, id.String()) || prior != "" && key <= prior {
			return CapabilityPage{}, ErrRepositoryUnavailable
		}
		prior = key
	}
	next, ok := validInventoryNextKey(envelope.NextKey, prior, len(envelope.Items), limit)
	if !ok {
		return CapabilityPage{}, ErrRepositoryUnavailable
	}
	return CapabilityPage{Items: envelope.Items, NextKey: next}, nil
}

func (repository *PostgresInventoryRepository) ListAgentRelationshipsPage(ctx context.Context, scope domain.Scope, id domain.ProductID, after string, limit int) (RelationshipPage, error) {
	if !validInventorySubresourceCall(repository, ctx, scope, id, after, limit) {
		return RelationshipPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventoryRelationshipsSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id.String(), after, limit)
	if err != nil {
		return RelationshipPage{}, inventoryProviderError(err)
	}
	var envelope struct {
		Items   []Relationship `json:"items"`
		NextKey *string        `json:"next_key"`
	}
	if decodeStrictInventory(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return RelationshipPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for _, item := range envelope.Items {
		if !validRelationship(item, id.String()) || prior != "" && item.ID <= prior {
			return RelationshipPage{}, ErrRepositoryUnavailable
		}
		prior = item.ID
	}
	next, ok := validInventoryNextKey(envelope.NextKey, prior, len(envelope.Items), limit)
	if !ok {
		return RelationshipPage{}, ErrRepositoryUnavailable
	}
	return RelationshipPage{Items: envelope.Items, NextKey: next}, nil
}

func (repository *PostgresInventoryRepository) ListAgentSessionsPage(ctx context.Context, scope domain.Scope, id domain.ProductID, after string, limit int) (SessionPage, error) {
	if !validInventorySubresourceCall(repository, ctx, scope, id, after, limit) {
		return SessionPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventorySessionsSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id.String(), after, limit)
	if err != nil {
		return SessionPage{}, inventoryProviderError(err)
	}
	var envelope struct {
		Items   []AgentSession `json:"items"`
		NextKey *string        `json:"next_key"`
	}
	if decodeStrictInventory(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return SessionPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for _, item := range envelope.Items {
		if !validProductID(item.ID) || item.AgentID != id.String() || !validInventoryTime(item.StartedAt) || prior != "" && item.ID <= prior {
			return SessionPage{}, ErrRepositoryUnavailable
		}
		prior = item.ID
	}
	next, ok := validInventoryNextKey(envelope.NextKey, prior, len(envelope.Items), limit)
	if !ok {
		return SessionPage{}, ErrRepositoryUnavailable
	}
	return SessionPage{Items: envelope.Items, NextKey: next}, nil
}

func (repository *PostgresInventoryRepository) GetHomeSummary(ctx context.Context, scope domain.Scope) (HomeSummary, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil {
		return HomeSummary{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventoryHomeSummarySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return HomeSummary{}, inventoryProviderError(err)
	}
	var summary HomeSummary
	if decodeStrictInventory(payload, &summary) != nil || !validHomeSummary(summary) {
		return HomeSummary{}, ErrRepositoryUnavailable
	}
	return summary, nil
}

func (repository *PostgresInventoryRepository) UpdateAgentOwnership(ctx context.Context, identity RequestIdentity, id domain.ProductID, expectedVersion int64, idempotencyKey string, input AgentOwnershipInput, auditID, correlationID string) (AgentMutationResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || id.IsZero() || expectedVersion < 1 || expectedVersion >= 1000000 || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) || !validAgentOwnershipInput(input) || !validProductID(auditID) || !validProductID(correlationID) {
		return AgentMutationResult{}, ErrRepositoryOperation
	}
	tags, err := json.Marshal(input.Tags)
	if err != nil {
		return AgentMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresInventoryUpdateAgentSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), id.String(), idempotencyKey, expectedVersion, input.Owner, input.Team, json.RawMessage(tags), auditID, correlationID,
	)
	if err != nil {
		return AgentMutationResult{}, inventoryProviderError(err)
	}
	var result AgentMutationResult
	if decodeStrictInventory(payload, &result) != nil || result.Agent.ID != id.String() || result.Agent.Version != expectedVersion+1 || !validInventorySummary(result.Agent, InventoryKindAgent) || result.Agent.Owner != input.Owner || result.Agent.Team != input.Team || !equalInventoryStrings(result.Agent.Tags, input.Tags) || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !result.Replayed && (result.AuditID != auditID || result.CorrelationID != correlationID) {
		return AgentMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validInventoryCall(repository *PostgresInventoryRepository, ctx context.Context, scope domain.Scope, kind InventoryKind, after string, limit int) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil && scope.Validate() == nil && validInventoryKind(kind) && (after == "" || validProductID(after)) && limit >= 1 && limit <= 100
}

func validInventorySubresourceCall(repository *PostgresInventoryRepository, ctx context.Context, scope domain.Scope, id domain.ProductID, after string, limit int) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil && scope.Validate() == nil && !id.IsZero() && len(after) <= 512 && printableInventoryString(after, 0, 512, true) && limit >= 1 && limit <= 100
}

func validInventoryKind(kind InventoryKind) bool {
	return kind == InventoryKindAsset || kind == InventoryKindAgent || kind == InventoryKindTool || kind == InventoryKindIdentity || kind == InventoryKindRuntime
}

func validAgentOwnershipInput(input AgentOwnershipInput) bool {
	if !canonicalInventoryText(input.Owner, 1, 128) || !canonicalInventoryText(input.Team, 1, 128) || input.Tags == nil || len(input.Tags) > 32 {
		return false
	}
	prior := ""
	for _, tag := range input.Tags {
		if !canonicalInventoryText(tag, 1, 64) || prior != "" && tag <= prior {
			return false
		}
		prior = tag
	}
	return true
}

func canonicalInventoryText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func equalInventoryStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validInventorySummary(item InventorySummary, kind InventoryKind) bool {
	if !validProductID(item.ID) || item.Kind != kind || !printableInventoryString(item.Name, 1, 256, false) || !printableInventoryString(item.Owner, 0, 128, true) || !printableInventoryString(item.Team, 0, 128, true) || item.Tags == nil || len(item.Tags) > 32 || !validProductID(item.EvidenceID) || item.ConfidenceBasisPoints < 1 || item.ConfidenceBasisPoints > 10000 || item.Version < 1 || item.FreshnessState != "fresh" && item.FreshnessState != "stale" {
		return false
	}
	prior := ""
	for _, tag := range item.Tags {
		if !printableInventoryString(tag, 1, 64, false) || prior != "" && tag <= prior {
			return false
		}
		prior = tag
	}
	first, okFirst := parseInventoryTime(item.FirstSeen)
	last, okLast := parseInventoryTime(item.LastSeen)
	observed, okObserved := parseInventoryTime(item.ObservedAt)
	fresh, okFresh := parseInventoryTime(item.FreshUntil)
	return okFirst && okLast && okObserved && okFresh && !last.Before(first) && fresh.After(observed)
}

func validInventoryDetail(detail InventoryDetail, kind InventoryKind) bool {
	if !validInventorySummary(detail.Summary, kind) || detail.Sources == nil || len(detail.Sources) < 1 || len(detail.Sources) > 64 || detail.Evidence == nil || len(detail.Evidence) < 1 || len(detail.Evidence) > 64 {
		return false
	}
	evidence := make(map[string]struct{}, len(detail.Evidence))
	for _, item := range detail.Evidence {
		if !validEvidenceReference(item) {
			return false
		}
		if _, exists := evidence[item.ID]; exists {
			return false
		}
		evidence[item.ID] = struct{}{}
	}
	winners := 0
	prior := ""
	for _, source := range detail.Sources {
		key := source.IntegrationID + "\x1f" + source.Provider + "\x1f" + source.Source + "\x1f" + source.SourceIdentifier
		if prior != "" && key <= prior || !validSourceObservation(source) {
			return false
		}
		prior = key
		if _, exists := evidence[source.EvidenceID]; !exists {
			return false
		}
		if source.Winning {
			winners++
			if source.EvidenceID != detail.Summary.EvidenceID || source.ConfidenceBasisPoints != detail.Summary.ConfidenceBasisPoints || source.ObservedAt != detail.Summary.ObservedAt || source.FreshUntil != detail.Summary.FreshUntil {
				return false
			}
		}
	}
	return winners == 1
}

func validSourceObservation(source InventorySourceObservation) bool {
	_, observed := parseInventoryTime(source.ObservedAt)
	_, fresh := parseInventoryTime(source.FreshUntil)
	checksum, checksumErr := hex.DecodeString(strings.TrimPrefix(source.SourceIdentifier, "sha256:"))
	return validProductID(source.IntegrationID) && validProductID(source.SnapshotID) && validProductID(source.EvidenceID) && stringIn(source.Provider, "aws", "kubernetes", "github", "okta") && printableInventoryString(source.Source, 1, 64, false) && len(source.SourceIdentifier) == len("sha256:")+sha256.Size*2 && strings.HasPrefix(source.SourceIdentifier, "sha256:") && checksumErr == nil && len(checksum) == sha256.Size && source.Generation > 0 && source.ConfidenceBasisPoints >= 1 && source.ConfidenceBasisPoints <= 10000 && source.ProjectionVersion >= 1 && observed && fresh
}

func validEvidenceReference(item InventoryEvidenceReference) bool {
	if !validProductID(item.ID) || len(item.Checksum) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(item.Checksum, "sha256:") || item.MediaType == "" || len(item.MediaType) > 128 || !printableInventoryString(item.MediaType, 1, 128, false) || !printableInventoryString(item.SchemaVersion, 1, 64, false) || !printableInventoryString(item.ParserVersion, 1, 64, false) || !printableInventoryString(item.ToolVersion, 1, 64, false) || !validInventoryTime(item.CollectedAt) || item.SizeBytes < 1 || item.SizeBytes > 512<<20 {
		return false
	}
	checksum, err := hex.DecodeString(strings.TrimPrefix(item.Checksum, "sha256:"))
	return err == nil && len(checksum) == sha256.Size
}

func validCapability(item Capability, agentID string) bool {
	if item.AgentID != agentID || !validProductID(item.TargetID) || !stringIn(item.TargetKind, "tool", "identity", "resource", "action") || !stringIn(item.Category, "data_read", "data_write", "action_execute", "identity_assume", "network_egress", "administration") || !stringIn(item.Outcome, "read", "write", "execute", "assume", "connect", "administer") || !stringIn(item.State, "reachable", "observed", "verified", "blocked") || item.EvidenceIDs == nil || len(item.EvidenceIDs) < 1 || len(item.EvidenceIDs) > 64 {
		return false
	}
	for index, id := range item.EvidenceIDs {
		if !validProductID(id) || index > 0 && id <= item.EvidenceIDs[index-1] {
			return false
		}
	}
	return true
}

func capabilityKey(item Capability) string {
	return item.TargetID + "\x1f" + item.Category + "\x1f" + item.Outcome
}

func validRelationship(item Relationship, agentID string) bool {
	return validProductID(item.ID) && validProductID(item.FromID) && validProductID(item.ToID) && item.FromID != item.ToID && (item.FromID == agentID || item.ToID == agentID) && printableInventoryString(item.Type, 1, 64, false) && validProductID(item.EvidenceID)
}

func validInventoryNextKey(next *string, prior string, count, limit int) (string, bool) {
	if next == nil {
		return "", true
	}
	return *next, count == limit && count > 0 && *next == prior && printableInventoryString(*next, 1, 512, false)
}

func validHomeSummary(summary HomeSummary) bool {
	values := []int64{summary.AgentCount, summary.HighRiskPaths, summary.VerifiedChanges, summary.BlockedChanges, summary.PendingApprovals, summary.OldestApprovalAgeSeconds, summary.NeedsHumanRuns, summary.FailedRuns, summary.InconclusiveRuns, summary.RecentContained, summary.RecentRemediated}
	for _, value := range values {
		if value < 0 {
			return false
		}
	}
	return summary.Healthy != summary.AttentionRequired
}

func parseInventoryTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil && parsed.Location() == time.UTC && strings.HasSuffix(value, "Z") && parsed.Format(time.RFC3339Nano) == value
}

func validInventoryTime(value string) bool {
	_, ok := parseInventoryTime(value)
	return ok
}

func printableInventoryString(value string, minimum, maximum int, allowEmpty bool) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || !allowEmpty && strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return allowEmpty || value != ""
}

func decodeStrictInventory(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrRepositoryUnavailable
	}
	return nil
}

func inventoryProviderError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "reference") || strings.Contains(err.Error(), "token") {
		return ErrRepositoryUnavailable
	}
	if errors.Is(err, ErrRepositoryNotFound) || errors.Is(err, ErrRepositoryConflict) || errors.Is(err, ErrRepositoryOperation) {
		return err
	}
	return ErrRepositoryUnavailable
}

package reconciliation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type FindingSource string
type FindingSeverity string
type FindingStatus string
type AttackPathState string

const (
	FindingSourcePosture FindingSource   = "posture"
	FindingSourceProwler FindingSource   = "prowler"
	SeverityCritical     FindingSeverity = "critical"
	SeverityHigh         FindingSeverity = "high"
	SeverityMedium       FindingSeverity = "medium"
	SeverityLow          FindingSeverity = "low"
	FindingOpen          FindingStatus   = "open"
	FindingUnderReview   FindingStatus   = "under_review"
	FindingResolved      FindingStatus   = "resolved"
	FindingAccepted      FindingStatus   = "accepted"
	PathPotential        AttackPathState = "potential"
	PathObserved         AttackPathState = "observed"
	PathVerified         AttackPathState = "verified"
	PathBlocked          AttackPathState = "blocked"
)

type RiskFactor struct {
	Name       string
	EvidenceID domain.ProductID
}

type Finding struct {
	ID, AgentID, PathID domain.ProductID
	Scope               domain.Scope
	Source              FindingSource
	Rule                PostureRule
	Title               string
	Severity            FindingSeverity
	Status              FindingStatus
	ComplianceContext   string
	EvidenceIDs         []domain.ProductID
	Factors             []RiskFactor
	AcceptanceReason    string
}

type FindingFilter struct{ VisibleByDefault bool }
type TicketWebhook func(context.Context, []byte, string) (string, error)

type FindingStore struct {
	mu     sync.RWMutex
	values map[domain.ProductID]Finding
}

func NewFindingStore(values []Finding) (*FindingStore, error) {
	if len(values) == 0 || len(values) > 10_000 {
		return nil, ErrReconciliation
	}
	store := &FindingStore{values: make(map[domain.ProductID]Finding, len(values))}
	for _, value := range values {
		if !validFinding(value) {
			return nil, ErrReconciliation
		}
		if _, exists := store.values[value.ID]; exists {
			return nil, ErrReconciliation
		}
		store.values[value.ID] = cloneFinding(value)
	}
	return store, nil
}

func (store *FindingStore) List(ctx context.Context, scope domain.Scope, filter FindingFilter) ([]Finding, error) {
	if !store.usable() || !active(ctx) || scope.Validate() != nil {
		return nil, ErrReconciliation
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := []Finding{}
	for _, value := range store.values {
		if value.Scope == scope && (!filter.VisibleByDefault || visibleFinding(value)) {
			result = append(result, cloneFinding(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID.String() < result[j].ID.String() })
	return result, nil
}

func (store *FindingStore) Get(ctx context.Context, scope domain.Scope, id domain.ProductID) (Finding, error) {
	if !store.usable() || !active(ctx) || scope.Validate() != nil || id.IsZero() {
		return Finding{}, ErrReconciliation
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.values[id]
	if !ok || value.Scope != scope {
		return Finding{}, ErrInventoryNotFound
	}
	return cloneFinding(value), nil
}

func (store *FindingStore) Update(ctx context.Context, scope domain.Scope, id domain.ProductID, status FindingStatus) (Finding, error) {
	if status != FindingOpen && status != FindingUnderReview && status != FindingResolved {
		return Finding{}, ErrInventoryInvalid
	}
	return store.update(ctx, scope, id, func(value *Finding) { value.Status, value.AcceptanceReason = status, "" })
}

func (store *FindingStore) AcceptRisk(ctx context.Context, scope domain.Scope, id domain.ProductID, reason string) (Finding, error) {
	if !bounded(reason, 512) {
		return Finding{}, ErrInventoryInvalid
	}
	return store.update(ctx, scope, id, func(value *Finding) { value.Status, value.AcceptanceReason = FindingAccepted, reason })
}

func (store *FindingStore) CreateTicket(ctx context.Context, scope domain.Scope, id domain.ProductID, secret []byte, webhook TicketWebhook) (ticket string, err error) {
	if len(secret) < 16 || len(secret) > 256 || webhook == nil {
		return "", ErrInventoryConfiguration
	}
	value, err := store.Get(ctx, scope, id)
	if err != nil {
		return "", err
	}
	if !active(ctx) {
		return "", ErrInventoryInvalid
	}
	payload, err := json.Marshal(map[string]string{"agent_id": value.AgentID.String(), "finding_id": value.ID.String(), "severity": string(value.Severity), "title": value.Title})
	if err != nil {
		return "", ErrInventoryInvalid
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	defer func() {
		if recover() != nil {
			ticket, err = "", ErrInventoryInvalid
		}
	}()
	ticket, err = webhook(ctx, payload, hex.EncodeToString(mac.Sum(nil)))
	if err != nil || !bounded(ticket, 128) {
		return "", ErrInventoryInvalid
	}
	return ticket, nil
}

func (store *FindingStore) update(ctx context.Context, scope domain.Scope, id domain.ProductID, mutate func(*Finding)) (Finding, error) {
	if !store.usable() || !active(ctx) || scope.Validate() != nil || id.IsZero() {
		return Finding{}, ErrInventoryInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.values[id]
	if !ok || value.Scope != scope {
		return Finding{}, ErrInventoryNotFound
	}
	mutate(&value)
	store.values[id] = value
	return cloneFinding(value), nil
}

func (store *FindingStore) usable() bool { return store != nil && store.values != nil }
func visibleFinding(value Finding) bool {
	return value.Source != FindingSourceProwler || !value.AgentID.IsZero() || !value.PathID.IsZero() || value.ComplianceContext != ""
}
func cloneFinding(value Finding) Finding {
	value.EvidenceIDs = append([]domain.ProductID(nil), value.EvidenceIDs...)
	value.Factors = append([]RiskFactor(nil), value.Factors...)
	return value
}
func validFinding(value Finding) bool {
	if value.ID.IsZero() || value.Scope.Validate() != nil || !bounded(value.Title, 256) || !validSeverity(value.Severity) || !validFindingStatus(value.Status) || len(value.EvidenceIDs) == 0 || len(value.EvidenceIDs) > 64 || len(value.Factors) > 16 {
		return false
	}
	if value.Source == FindingSourcePosture && (value.AgentID.IsZero() || !validPostureRule(value.Rule)) {
		return false
	}
	if value.Source != FindingSourcePosture && value.Source != FindingSourceProwler {
		return false
	}
	seen := map[domain.ProductID]struct{}{}
	for _, id := range value.EvidenceIDs {
		if id.IsZero() {
			return false
		}
		if _, ok := seen[id]; ok {
			return false
		}
		seen[id] = struct{}{}
	}
	factorNames := map[string]struct{}{}
	for _, factor := range value.Factors {
		if !bounded(factor.Name, 64) || factor.EvidenceID.IsZero() {
			return false
		}
		if _, ok := seen[factor.EvidenceID]; !ok {
			return false
		}
		if _, ok := factorNames[factor.Name]; ok {
			return false
		}
		factorNames[factor.Name] = struct{}{}
	}
	if value.Source == FindingSourceProwler && value.Rule != "" {
		return false
	}
	if (value.Status == FindingAccepted) != (value.AcceptanceReason != "") {
		return false
	}
	return optional(value.ComplianceContext, 128) && optional(value.AcceptanceReason, 512)
}
func validSeverity(value FindingSeverity) bool {
	return value == SeverityCritical || value == SeverityHigh || value == SeverityMedium || value == SeverityLow
}
func validFindingStatus(value FindingStatus) bool {
	return value == FindingOpen || value == FindingUnderReview || value == FindingResolved || value == FindingAccepted
}

type AttackPath struct {
	ID, EntryID, SinkID domain.ProductID
	Scope               domain.Scope
	NodeIDs             []domain.ProductID
	State               AttackPathState
	EvidenceIDs         []domain.ProductID
	BlockedEdge         int
}
type BreakOption struct {
	PathID, TargetID, EvidenceID domain.ProductID
	Kind                         string
	Rank                         int
}
type AttackPathStore struct {
	values map[domain.ProductID]AttackPath
}

func NewAttackPathStore(values []AttackPath) (*AttackPathStore, error) {
	if len(values) == 0 || len(values) > 1_000 {
		return nil, ErrReconciliation
	}
	store := &AttackPathStore{values: make(map[domain.ProductID]AttackPath, len(values))}
	for _, value := range values {
		if !validAttackPath(value) {
			return nil, ErrReconciliation
		}
		if _, exists := store.values[value.ID]; exists {
			return nil, ErrReconciliation
		}
		store.values[value.ID] = cloneAttackPath(value)
	}
	return store, nil
}
func (store *AttackPathStore) List(ctx context.Context, scope domain.Scope) ([]AttackPath, error) {
	if store == nil || store.values == nil || !active(ctx) || scope.Validate() != nil {
		return nil, ErrReconciliation
	}
	result := []AttackPath{}
	for _, value := range store.values {
		if value.Scope == scope {
			result = append(result, cloneAttackPath(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID.String() < result[j].ID.String() })
	return result, nil
}
func (store *AttackPathStore) Get(ctx context.Context, scope domain.Scope, id domain.ProductID) (AttackPath, error) {
	if store == nil || store.values == nil || !active(ctx) || scope.Validate() != nil || id.IsZero() {
		return AttackPath{}, ErrReconciliation
	}
	value, ok := store.values[id]
	if !ok || value.Scope != scope {
		return AttackPath{}, ErrInventoryNotFound
	}
	return cloneAttackPath(value), nil
}
func (store *AttackPathStore) BreakOptions(ctx context.Context, scope domain.Scope, id domain.ProductID) ([]BreakOption, error) {
	value, err := store.Get(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	evidence := value.EvidenceIDs[0]
	result := []BreakOption{{PathID: id, TargetID: value.NodeIDs[1], EvidenceID: evidence, Kind: "remove_node", Rank: 1}}
	if value.BlockedEdge >= 0 {
		result = append(result, BreakOption{PathID: id, TargetID: value.NodeIDs[value.BlockedEdge], EvidenceID: evidence, Kind: "enforce_policy", Rank: 2})
	}
	return result, nil
}
func validAttackPath(value AttackPath) bool {
	if value.ID.IsZero() || value.Scope.Validate() != nil || len(value.NodeIDs) < 2 || len(value.NodeIDs) > 8 || value.EntryID != value.NodeIDs[0] || value.SinkID != value.NodeIDs[len(value.NodeIDs)-1] || !validAttackPathState(value.State) || len(value.EvidenceIDs) == 0 || len(value.EvidenceIDs) > 16 || value.BlockedEdge < -1 || value.BlockedEdge >= len(value.NodeIDs)-1 {
		return false
	}
	seen := map[domain.ProductID]struct{}{}
	for _, id := range value.NodeIDs {
		if id.IsZero() {
			return false
		}
		if _, ok := seen[id]; ok {
			return false
		}
		seen[id] = struct{}{}
	}
	evidenceSeen := map[domain.ProductID]struct{}{}
	for _, id := range value.EvidenceIDs {
		if id.IsZero() {
			return false
		}
		if _, ok := evidenceSeen[id]; ok {
			return false
		}
		evidenceSeen[id] = struct{}{}
	}
	return true
}
func validAttackPathState(value AttackPathState) bool {
	return value == PathPotential || value == PathObserved || value == PathVerified || value == PathBlocked
}
func cloneAttackPath(value AttackPath) AttackPath {
	value.NodeIDs = append([]domain.ProductID(nil), value.NodeIDs...)
	value.EvidenceIDs = append([]domain.ProductID(nil), value.EvidenceIDs...)
	return value
}

type HomeSummaryInput struct {
	Scope                           domain.Scope
	AgentCount, HighRiskPaths       int
	SourceStale, CoverageDegraded   bool
	VerifiedChanges, BlockedChanges int
}
type HomeSummary struct {
	AgentCount, HighRiskPaths, VerifiedChanges, BlockedChanges int
	Healthy, AttentionRequired                                 bool
}

func BuildHomeSummary(ctx context.Context, input HomeSummaryInput) (HomeSummary, error) {
	if !active(ctx) || input.Scope.Validate() != nil || input.AgentCount < 0 || input.HighRiskPaths < 0 || input.VerifiedChanges < 0 || input.BlockedChanges < 0 {
		return HomeSummary{}, ErrReconciliation
	}
	attention := input.SourceStale || input.CoverageDegraded || input.HighRiskPaths > 0
	return HomeSummary{AgentCount: input.AgentCount, HighRiskPaths: input.HighRiskPaths, VerifiedChanges: input.VerifiedChanges, BlockedChanges: input.BlockedChanges, Healthy: !attention, AttentionRequired: attention}, nil
}

type SearchRecord struct {
	ID         domain.ProductID
	Scope      domain.Scope
	Type, Name string
}
type SearchService struct{ values []SearchRecord }

func NewSearchService(values []SearchRecord) (*SearchService, error) {
	if len(values) == 0 || len(values) > 10_000 {
		return nil, ErrReconciliation
	}
	seen := map[domain.ProductID]struct{}{}
	for _, value := range values {
		if value.ID.IsZero() || value.Scope.Validate() != nil || !bounded(value.Type, 32) || !bounded(value.Name, 256) {
			return nil, ErrReconciliation
		}
		if _, ok := seen[value.ID]; ok {
			return nil, ErrReconciliation
		}
		seen[value.ID] = struct{}{}
	}
	return &SearchService{values: append([]SearchRecord(nil), values...)}, nil
}
func (service *SearchService) Query(ctx context.Context, scope domain.Scope, query string, limit int) ([]SearchRecord, error) {
	if service == nil || !active(ctx) || scope.Validate() != nil || !safeSearchQuery(query) || limit < 1 || limit > 100 {
		return nil, ErrInventoryInvalid
	}
	query = strings.ToLower(query)
	result := []SearchRecord{}
	for _, value := range service.values {
		if value.Scope == scope && (strings.Contains(strings.ToLower(value.Name), query) || strings.Contains(strings.ToLower(value.Type), query) || strings.Contains(strings.ToLower(value.ID.String()), query)) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID.String() < result[j].ID.String() })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func safeSearchQuery(value string) bool {
	if len(value) < 2 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(" .:_-/", character)) {
			return false
		}
	}
	return true
}

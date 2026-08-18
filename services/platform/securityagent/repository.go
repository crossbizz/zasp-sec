package securityagent

import (
	"context"
	"sort"
	"sync"
	"time"
)

type RunStep struct {
	ID, OrganizationID, RunID string
	Index                     int
	ActionKey, State          string
	Version                   int64
}
type ApprovalState string

const (
	ApprovalPending   ApprovalState = "pending"
	ApprovalApproved  ApprovalState = "approved"
	ApprovalRejected  ApprovalState = "rejected"
	ApprovalCancelled ApprovalState = "cancelled"
)

type Approval struct {
	ID, OrganizationID, RunID, StepID string
	State                             ApprovalState
	CreatedAt                         time.Time
	ExpiresAt                         time.Time
	ApproverID                        string
	FreshAuthAt                       time.Time
	Version                           int64
}
type IdempotencyRecord struct{ OrganizationID, RunID, StepID, ActionKey, State, OutcomeID string }

type MemoryRepository struct {
	mu            sync.RWMutex
	agents        map[string]SecurityAgent
	runs          map[string]SecurityAgentRun
	steps         map[string]RunStep
	approvals     map[string]Approval
	claims        map[string]IdempotencyRecord
	controls      map[string]TemporaryControl
	cleanupAudits []CleanupAudit
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{agents: map[string]SecurityAgent{}, runs: map[string]SecurityAgentRun{}, steps: map[string]RunStep{}, approvals: map[string]Approval{}, claims: map[string]IdempotencyRecord{}, controls: map[string]TemporaryControl{}}
}

func (repo *MemoryRepository) CreateAgent(ctx context.Context, value SecurityAgent) error {
	if invalidContext(ctx) || repo == nil || ValidateAgent(value) != nil || value.Version < 0 || !value.DeletedAt.IsZero() {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, exists := repo.agents[key]; exists {
		return ErrRejected
	}
	value.Version = 1
	repo.agents[key] = cloneAgent(value)
	return nil
}
func (repo *MemoryRepository) GetAgent(ctx context.Context, organizationID, id string) (SecurityAgent, error) {
	if invalidContext(ctx) || repo == nil {
		return SecurityAgent{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return SecurityAgent{}, err
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	value, ok := repo.agents[key]
	if !ok {
		return SecurityAgent{}, ErrRejected
	}
	return cloneAgent(value), nil
}
func (repo *MemoryRepository) ListAgents(ctx context.Context, organizationID, cursor string, limit int) ([]SecurityAgent, string, error) {
	if invalidContext(ctx) || repo == nil || !bounded(organizationID, 128) || limit <= 0 || limit > 100 || (cursor != "" && !bounded(cursor, 128)) {
		return nil, "", ErrRejected
	}
	repo.mu.RLock()
	values := []SecurityAgent{}
	for _, value := range repo.agents {
		if value.OrganizationID == organizationID && value.ID > cursor {
			values = append(values, cloneAgent(value))
		}
	}
	repo.mu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	next := ""
	if len(values) > limit {
		next = values[limit-1].ID
		values = values[:limit]
	}
	return values, next, nil
}
func (repo *MemoryRepository) UpdateAgent(ctx context.Context, value SecurityAgent, expectedVersion int64) error {
	if invalidContext(ctx) || repo == nil || ValidateAgent(value) != nil || expectedVersion <= 0 {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	current, ok := repo.agents[key]
	if !ok || current.Version != expectedVersion || value.Version != expectedVersion || !current.DeletedAt.IsZero() {
		return ErrRejected
	}
	value.Version++
	repo.agents[key] = cloneAgent(value)
	return nil
}
func (repo *MemoryRepository) SoftDeleteAgent(ctx context.Context, organizationID, id string, expectedVersion int64, at time.Time) error {
	if invalidContext(ctx) || repo == nil || at.Location() != time.UTC || at.IsZero() || expectedVersion <= 0 {
		return ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	value, ok := repo.agents[key]
	if !ok || value.Version != expectedVersion || !value.DeletedAt.IsZero() {
		return ErrRejected
	}
	value.Enabled = false
	value.DeletedAt = at
	value.Version++
	repo.agents[key] = value
	return nil
}
func (repo *MemoryRepository) MatchAgents(ctx context.Context, organizationID string, trigger Trigger) ([]SecurityAgent, error) {
	if invalidContext(ctx) || repo == nil || !bounded(organizationID, 128) || !bounded(trigger.Kind, 64) || !bounded(trigger.Source, 64) {
		return nil, ErrRejected
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	result := []SecurityAgent{}
	for _, value := range repo.agents {
		if value.OrganizationID == organizationID && value.Enabled && value.DeletedAt.IsZero() && value.Trigger == trigger {
			result = append(result, cloneAgent(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (repo *MemoryRepository) CreateRun(ctx context.Context, value SecurityAgentRun) error {
	if invalidContext(ctx) || repo == nil || !validRun(value) {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, ok := repo.runs[key]; ok {
		return ErrRejected
	}
	repo.runs[key] = cloneRun(value)
	return nil
}
func (repo *MemoryRepository) GetRun(ctx context.Context, organizationID, id string) (SecurityAgentRun, error) {
	if invalidContext(ctx) || repo == nil {
		return SecurityAgentRun{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return SecurityAgentRun{}, err
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	value, ok := repo.runs[key]
	if !ok {
		return SecurityAgentRun{}, ErrRejected
	}
	return cloneRun(value), nil
}
func (repo *MemoryRepository) ListRuns(ctx context.Context, organizationID string) ([]SecurityAgentRun, error) {
	if invalidContext(ctx) || repo == nil || !bounded(organizationID, 128) {
		return nil, ErrRejected
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	result := []SecurityAgentRun{}
	for _, value := range repo.runs {
		if value.OrganizationID == organizationID {
			result = append(result, cloneRun(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (repo *MemoryRepository) TransitionRun(ctx context.Context, organizationID, id string, expected, next RunState, expectedVersion int64) (SecurityAgentRun, error) {
	if invalidContext(ctx) || repo == nil || expectedVersion <= 0 || !CanTransition(expected, next) {
		return SecurityAgentRun{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return SecurityAgentRun{}, err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	value, ok := repo.runs[key]
	if !ok || value.State != expected || value.Version != expectedVersion {
		return SecurityAgentRun{}, ErrRejected
	}
	value.State = next
	value.Version++
	repo.runs[key] = value
	return cloneRun(value), nil
}

func (repo *MemoryRepository) AppendStep(ctx context.Context, value RunStep) error {
	if invalidContext(ctx) || repo == nil || !validStep(value) {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, ok := repo.steps[key]; ok {
		return ErrRejected
	}
	for _, current := range repo.steps {
		if current.OrganizationID == value.OrganizationID && current.RunID == value.RunID && current.Index == value.Index {
			return ErrRejected
		}
	}
	repo.steps[key] = value
	return nil
}
func (repo *MemoryRepository) ListSteps(ctx context.Context, organizationID, runID string) ([]RunStep, error) {
	if invalidContext(ctx) || repo == nil || !bounded(organizationID, 128) || !bounded(runID, 128) {
		return nil, ErrRejected
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	result := []RunStep{}
	for _, value := range repo.steps {
		if value.OrganizationID == organizationID && value.RunID == runID {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Index < result[j].Index })
	return result, nil
}
func (repo *MemoryRepository) UpdateStep(ctx context.Context, value RunStep, expectedVersion int64) error {
	if invalidContext(ctx) || repo == nil || !validStep(value) || expectedVersion <= 0 {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	current, ok := repo.steps[key]
	if !ok || current.Version != expectedVersion || value.Version != expectedVersion || current.Index != value.Index || current.RunID != value.RunID {
		return ErrRejected
	}
	value.Version++
	repo.steps[key] = value
	return nil
}

func (repo *MemoryRepository) CreateApproval(ctx context.Context, value Approval) error {
	if invalidContext(ctx) || repo == nil || !validApproval(value) || value.State != ApprovalPending {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, ok := repo.approvals[key]; ok {
		return ErrRejected
	}
	repo.approvals[key] = value
	return nil
}
func (repo *MemoryRepository) GetApproval(ctx context.Context, organizationID, id string) (Approval, error) {
	if invalidContext(ctx) || repo == nil {
		return Approval{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return Approval{}, err
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	value, ok := repo.approvals[key]
	if !ok {
		return Approval{}, ErrRejected
	}
	return value, nil
}
func (repo *MemoryRepository) ListApprovals(ctx context.Context, organizationID, runID string) ([]Approval, error) {
	if invalidContext(ctx) || repo == nil || !bounded(organizationID, 128) || !bounded(runID, 128) {
		return nil, ErrRejected
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	result := []Approval{}
	for _, value := range repo.approvals {
		if value.OrganizationID == organizationID && value.RunID == runID {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (repo *MemoryRepository) ListOrganizationApprovals(ctx context.Context, organizationID string) ([]Approval, error) {
	if invalidContext(ctx) || repo == nil || !bounded(organizationID, 128) {
		return nil, ErrRejected
	}
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	result := []Approval{}
	for _, value := range repo.approvals {
		if value.OrganizationID == organizationID {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (repo *MemoryRepository) DecideApproval(ctx context.Context, organizationID, id, approverID string, at time.Time, decision ApprovalState, expectedVersion int64) (Approval, error) {
	if invalidContext(ctx) || repo == nil || !bounded(approverID, 128) || at.Location() != time.UTC || at.IsZero() || !contains([]ApprovalState{ApprovalApproved, ApprovalRejected, ApprovalCancelled}, decision) || expectedVersion <= 0 {
		return Approval{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return Approval{}, err
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	value, ok := repo.approvals[key]
	if !ok || value.State != ApprovalPending || !at.Before(value.ExpiresAt) || value.Version != expectedVersion {
		return Approval{}, ErrRejected
	}
	value.State = decision
	value.ApproverID = approverID
	value.FreshAuthAt = at
	value.Version++
	repo.approvals[key] = value
	return value, nil
}

func (repo *MemoryRepository) ClaimAction(ctx context.Context, value IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if invalidContext(ctx) || repo == nil || !validClaim(value) {
		return IdempotencyRecord{}, false, ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.RunID, value.StepID, value.ActionKey)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if current, ok := repo.claims[key]; ok {
		if current != value {
			return IdempotencyRecord{}, false, ErrRejected
		}
		return current, false, nil
	}
	repo.claims[key] = value
	return value, true, nil
}

func invalidContext(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }
func validRun(value SecurityAgentRun) bool {
	return bounded(value.ID, 128) && bounded(value.OrganizationID, 128) && bounded(value.AgentID, 128) && value.State == RunQueued && uniqueBounded(value.TriggerEvidenceIDs, 128) && value.DefinitionVersion > 0 && value.Version == 1
}
func validStep(value RunStep) bool {
	return bounded(value.ID, 128) && bounded(value.OrganizationID, 128) && bounded(value.RunID, 128) && value.Index >= 0 && value.Index < 100 && bounded(value.ActionKey, 128) && contains([]string{"queued", "authorized", "executing", "verifying", "succeeded", "failed"}, value.State) && value.Version == 1
}
func validApproval(value Approval) bool {
	return bounded(value.ID, 128) && bounded(value.OrganizationID, 128) && bounded(value.RunID, 128) && bounded(value.StepID, 128) && value.CreatedAt.Location() == time.UTC && !value.CreatedAt.IsZero() && value.ExpiresAt.Location() == time.UTC && value.ExpiresAt.After(value.CreatedAt) && value.Version == 1
}
func validClaim(value IdempotencyRecord) bool {
	return bounded(value.OrganizationID, 128) && bounded(value.RunID, 128) && bounded(value.StepID, 128) && bounded(value.ActionKey, 128) && contains([]string{"pending", "succeeded", "failed"}, value.State) && bounded(value.OutcomeID, 128)
}
func cloneAgent(value SecurityAgent) SecurityAgent {
	value.Scope.EnvironmentIDs = cloneStrings(value.Scope.EnvironmentIDs)
	value.AllowedActions = cloneStrings(value.AllowedActions)
	return value
}
func cloneRun(value SecurityAgentRun) SecurityAgentRun {
	value.TriggerEvidenceIDs = cloneStrings(value.TriggerEvidenceIDs)
	return value
}

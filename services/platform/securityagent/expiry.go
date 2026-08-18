package securityagent

import (
	"context"
	"sort"
	"time"
)

type ControlState string

const (
	ControlActive        ControlState = "active"
	ControlClaimed       ControlState = "claimed"
	ControlDisabled      ControlState = "disabled"
	ControlCleanupFailed ControlState = "cleanup_failed"
)

type TemporaryControl struct {
	ID, OrganizationID, RunID, StepID string
	Kind, TargetID, Scope             string
	ExpiresAt                         time.Time
	State                             ControlState
	ClaimedBy                         string
	Version                           int64
}
type CleanupAudit struct {
	OrganizationID, ControlID, State string
	At                               time.Time
}
type TemporaryControlService interface {
	DisableTemporaryControl(context.Context, TemporaryControl, string) (string, error)
	VerifyTemporaryControlAbsent(context.Context, TemporaryControl) error
}
type ExpiryReport struct{ Cleaned, Failed int }
type ExpiryWorker struct {
	repository *MemoryRepository
	service    TemporaryControlService
}

func NewExpiryWorker(repository *MemoryRepository, service TemporaryControlService) (*ExpiryWorker, error) {
	if repository == nil || service == nil {
		return nil, ErrRejected
	}
	return &ExpiryWorker{repository: repository, service: service}, nil
}

func (repository *MemoryRepository) CreateTemporaryControl(ctx context.Context, value TemporaryControl) error {
	if invalidContext(ctx) || repository == nil || !validTemporaryControl(value) || value.State != ControlActive || value.ClaimedBy != "" {
		return ErrRejected
	}
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, ok := repository.controls[key]; ok {
		return ErrRejected
	}
	repository.controls[key] = value
	return nil
}
func (repository *MemoryRepository) GetTemporaryControl(ctx context.Context, organizationID, id string) (TemporaryControl, error) {
	if invalidContext(ctx) || repository == nil {
		return TemporaryControl{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, id)
	if err != nil {
		return TemporaryControl{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	value, ok := repository.controls[key]
	if !ok {
		return TemporaryControl{}, ErrRejected
	}
	return value, nil
}
func (repository *MemoryRepository) ClaimExpiredControls(ctx context.Context, organizationID string, now time.Time, workerID string, limit int) ([]TemporaryControl, error) {
	if invalidContext(ctx) || repository == nil || !bounded(organizationID, 128) || !bounded(workerID, 128) || now.Location() != time.UTC || limit <= 0 || limit > 100 {
		return nil, ErrRejected
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	keys := []string{}
	for key, value := range repository.controls {
		if value.OrganizationID == organizationID && value.State == ControlActive && !value.ExpiresAt.After(now) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	result := make([]TemporaryControl, 0, len(keys))
	for _, key := range keys {
		value := repository.controls[key]
		value.State = ControlClaimed
		value.ClaimedBy = workerID
		value.Version++
		repository.controls[key] = value
		result = append(result, value)
	}
	return result, nil
}
func (repository *MemoryRepository) finishTemporaryControl(value TemporaryControl, state ControlState, now time.Time) error {
	key, _ := idempotencyKey(value.OrganizationID, value.ID)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, ok := repository.controls[key]
	if !ok || current.State != ControlClaimed || current.Version != value.Version || current.ClaimedBy != value.ClaimedBy {
		return ErrRejected
	}
	current.State = state
	current.Version++
	repository.controls[key] = current
	auditState := "cleanup_failed"
	if state == ControlDisabled {
		auditState = "cleaned"
	}
	repository.cleanupAudits = append(repository.cleanupAudits, CleanupAudit{OrganizationID: value.OrganizationID, ControlID: value.ID, State: auditState, At: now})
	return nil
}
func (repository *MemoryRepository) CleanupAudits(ctx context.Context, organizationID string) []CleanupAudit {
	if invalidContext(ctx) || repository == nil || !bounded(organizationID, 128) {
		return []CleanupAudit{}
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	result := []CleanupAudit{}
	for _, value := range repository.cleanupAudits {
		if value.OrganizationID == organizationID {
			result = append(result, value)
		}
	}
	return result
}
func (worker *ExpiryWorker) RunOnce(ctx context.Context, organizationID string, now time.Time, workerID string, limit int) (ExpiryReport, error) {
	if worker == nil || worker.repository == nil || worker.service == nil {
		return ExpiryReport{}, ErrRejected
	}
	controls, err := worker.repository.ClaimExpiredControls(ctx, organizationID, now, workerID, limit)
	if err != nil {
		return ExpiryReport{}, err
	}
	report := ExpiryReport{}
	failed := false
	for _, control := range controls {
		key, _ := idempotencyKey(control.OrganizationID, control.RunID, control.StepID, control.ID)
		state, disableErr := worker.service.DisableTemporaryControl(ctx, control, key)
		verifyErr := error(nil)
		if disableErr == nil && state == "disabled" {
			verifyErr = worker.service.VerifyTemporaryControlAbsent(ctx, control)
		}
		if disableErr != nil || state != "disabled" || verifyErr != nil {
			_ = worker.repository.finishTemporaryControl(control, ControlCleanupFailed, now)
			report.Failed++
			failed = true
			continue
		}
		if worker.repository.finishTemporaryControl(control, ControlDisabled, now) != nil {
			report.Failed++
			failed = true
			continue
		}
		report.Cleaned++
	}
	if failed {
		return report, ErrRejected
	}
	return report, nil
}
func validTemporaryControl(value TemporaryControl) bool {
	return bounded(value.ID, 128) && bounded(value.OrganizationID, 128) && bounded(value.RunID, 128) && bounded(value.StepID, 128) && contains([]string{"policy", "session_isolation"}, value.Kind) && bounded(value.TargetID, 128) && bounded(value.Scope, 128) && value.ExpiresAt.Location() == time.UTC && !value.ExpiresAt.IsZero() && value.Version == 1
}

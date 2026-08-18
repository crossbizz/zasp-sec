package admincontrol

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrRejected = errors.New("admin control operation rejected")

type RetainedRecord struct {
	ID, Class string
	CreatedAt time.Time
}
type RetentionPolicy struct {
	EnvironmentID string
	RetentionDays int
	ChangedBy     string
}
type RetentionAudit struct {
	EnvironmentID, ChangedBy string
	DeletedIDs               []string
	AppliedAt                time.Time
}
type RetentionWorker struct{}

func NewRetentionWorker() *RetentionWorker { return &RetentionWorker{} }
func (*RetentionWorker) Apply(ctx context.Context, records []RetainedRecord, policy RetentionPolicy, now time.Time) ([]RetainedRecord, RetentionAudit, error) {
	if ctx == nil || ctx.Err() != nil || !bounded(policy.EnvironmentID, 128) || !bounded(policy.ChangedBy, 128) || policy.RetentionDays < 1 || policy.RetentionDays > 3650 || now.Location() != time.UTC || len(records) > 10000 {
		return nil, RetentionAudit{}, ErrRejected
	}
	cutoff := now.Add(-time.Duration(policy.RetentionDays) * 24 * time.Hour)
	remaining := make([]RetainedRecord, 0, len(records))
	deleted := []string{}
	seen := map[string]bool{}
	for _, record := range records {
		if seen[record.ID] || !bounded(record.ID, 128) || !contains([]string{"event", "evidence", "audit"}, record.Class) || record.CreatedAt.Location() != time.UTC || record.CreatedAt.After(now) {
			return nil, RetentionAudit{}, ErrRejected
		}
		seen[record.ID] = true
		if record.CreatedAt.Before(cutoff) {
			deleted = append(deleted, record.ID)
		} else {
			remaining = append(remaining, record)
		}
	}
	sort.Strings(deleted)
	sort.Slice(remaining, func(i, j int) bool { return remaining[i].ID < remaining[j].ID })
	return remaining, RetentionAudit{EnvironmentID: policy.EnvironmentID, ChangedBy: policy.ChangedBy, DeletedIDs: deleted, AppliedAt: now}, nil
}

type ExternalFlow struct {
	ID         string   `json:"id"`
	Required   bool     `json:"required"`
	Categories []string `json:"categories"`
	Enabled    bool     `json:"enabled"`
	Health     string   `json:"health"`
}
type FlowAudit struct{ FlowID, Change string }
type ExternalFlowStore struct {
	mu     sync.RWMutex
	values map[string]ExternalFlow
	audits []FlowAudit
}

func NewExternalFlowStore(values []ExternalFlow) *ExternalFlowStore {
	store := &ExternalFlowStore{values: map[string]ExternalFlow{}}
	for _, value := range values {
		if validateFlow(value, nil) == nil {
			store.values[value.ID] = cloneFlow(value)
		}
	}
	return store
}
func (s *ExternalFlowStore) List(ctx context.Context) ([]ExternalFlow, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make([]ExternalFlow, 0, len(s.values))
	for _, value := range s.values {
		values = append(values, cloneFlow(value))
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, nil
}
func (s *ExternalFlowStore) requiredReady() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range []string{"identity", "database"} {
		value, ok := s.values[id]
		if !ok || !value.Required || !value.Enabled {
			return false
		}
	}
	return true
}
func (s *ExternalFlowStore) Update(ctx context.Context, value ExternalFlow) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.values[value.ID]
	if !ok || validateFlow(value, &current) != nil {
		return ErrRejected
	}
	s.values[value.ID] = cloneFlow(value)
	s.audits = append(s.audits, FlowAudit{FlowID: value.ID, Change: "external_flow_updated"})
	return nil
}
func (s *ExternalFlowStore) Audits() []FlowAudit {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]FlowAudit(nil), s.audits...)
}
func validateFlow(value ExternalFlow, current *ExternalFlow) error {
	if !bounded(value.ID, 64) || len(value.Categories) == 0 || len(value.Categories) > 16 || !contains([]string{"healthy", "degraded", "disabled"}, value.Health) {
		return ErrRejected
	}
	if contains([]string{"identity", "database"}, value.ID) && (!value.Required || !value.Enabled) {
		return ErrRejected
	}
	if current != nil && current.Required && (!value.Required || !value.Enabled) {
		return ErrRejected
	}
	seen := map[string]bool{}
	for _, category := range value.Categories {
		if seen[category] || !contains([]string{"identity_metadata", "product_usage", "redacted_summary", "remote_telemetry"}, category) {
			return ErrRejected
		}
		seen[category] = true
	}
	if value.ID == "analytics" && contains(value.Categories, "raw_security_evidence") {
		return ErrRejected
	}
	return nil
}

type ComponentProbe struct {
	ID       string    `json:"id"`
	Required bool      `json:"required"`
	State    string    `json:"state"`
	FreshAt  time.Time `json:"fresh_at"`
}
type SystemStatus struct {
	SecurityPlaneHealthy bool      `json:"security_plane_healthy"`
	OptionalDegraded     bool      `json:"optional_degraded"`
	FreshAt              time.Time `json:"fresh_at"`
}
type SystemProbes struct {
	version    string
	components []ComponentProbe
}

func NewSystemProbes(version string, components []ComponentProbe) *SystemProbes {
	return &SystemProbes{version: version, components: append([]ComponentProbe(nil), components...)}
}
func (s *SystemProbes) Status(ctx context.Context, now time.Time) (SystemStatus, error) {
	components, err := s.Components(ctx, now)
	if err != nil {
		return SystemStatus{}, err
	}
	status := SystemStatus{SecurityPlaneHealthy: true, FreshAt: now}
	for _, component := range components {
		if component.Required && component.State != "healthy" {
			status.SecurityPlaneHealthy = false
		}
		if !component.Required && component.State != "healthy" {
			status.OptionalDegraded = true
		}
	}
	return status, nil
}
func (s *SystemProbes) Components(ctx context.Context, now time.Time) ([]ComponentProbe, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !bounded(s.version, 64) || len(s.components) == 0 || len(s.components) > 100 || now.Location() != time.UTC {
		return nil, ErrRejected
	}
	values := append([]ComponentProbe(nil), s.components...)
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value.ID] || !bounded(value.ID, 64) || !contains([]string{"healthy", "degraded", "unavailable"}, value.State) || value.FreshAt.Location() != time.UTC || value.FreshAt.After(now) || now.Sub(value.FreshAt) > 24*time.Hour {
			return nil, ErrRejected
		}
		seen[value.ID] = true
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, nil
}
func (s *SystemProbes) Version(ctx context.Context) (string, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !bounded(s.version, 64) {
		return "", ErrRejected
	}
	return s.version, nil
}

func bounded(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func cloneFlow(value ExternalFlow) ExternalFlow {
	value.Categories = append([]string(nil), value.Categories...)
	return value
}

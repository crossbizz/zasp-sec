package integration

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type IDGenerator func() (domain.ProductID, error)

type IntegrationStatus string

const (
	IntegrationPendingAuthorization IntegrationStatus = "pending_authorization"
	IntegrationActive               IntegrationStatus = "active"
)

type SyncStatus string

const (
	SyncQueued    SyncStatus = "queued"
	SyncRunning   SyncStatus = "running"
	SyncSucceeded SyncStatus = "succeeded"
	SyncFailed    SyncStatus = "failed"
)

type Integration struct {
	id                   domain.ProductID
	scope                domain.Scope
	connectorKey         string
	name                 string
	configuration        map[string]string
	status               IntegrationStatus
	createdAt, updatedAt time.Time
}

func (value Integration) ID() domain.ProductID { return value.id }
func (value Integration) Scope() domain.Scope  { return value.scope }
func (value Integration) ConnectorKey() string { return value.connectorKey }
func (value Integration) Name() string         { return value.name }
func (value Integration) Configuration() map[string]string {
	return cloneConfiguration(value.configuration)
}
func (value Integration) Status() IntegrationStatus { return value.status }
func (value Integration) CreatedAt() time.Time      { return value.createdAt }
func (value Integration) UpdatedAt() time.Time      { return value.updatedAt }

type IntegrationSync struct {
	id, integrationID    domain.ProductID
	scope                domain.Scope
	jobID                string
	status               SyncStatus
	createdAt, updatedAt time.Time
}

func (value IntegrationSync) ID() domain.ProductID            { return value.id }
func (value IntegrationSync) IntegrationID() domain.ProductID { return value.integrationID }
func (value IntegrationSync) Scope() domain.Scope             { return value.scope }
func (value IntegrationSync) JobID() string                   { return value.jobID }
func (value IntegrationSync) Status() SyncStatus              { return value.status }
func (value IntegrationSync) CreatedAt() time.Time            { return value.createdAt }
func (value IntegrationSync) UpdatedAt() time.Time            { return value.updatedAt }

type MemoryStore struct {
	mu           sync.RWMutex
	generate     IDGenerator
	now          func() time.Time
	integrations map[domain.ProductID]Integration
	syncs        map[domain.ProductID]IntegrationSync
	jobs         map[string]domain.ProductID
}

func NewMemoryStore(generate IDGenerator, now func() time.Time) *MemoryStore {
	return &MemoryStore{generate: generate, now: now, integrations: map[domain.ProductID]Integration{}, syncs: map[domain.ProductID]IntegrationSync{}, jobs: map[string]domain.ProductID{}}
}

func (store *MemoryStore) usable() bool {
	if store == nil || store.generate == nil || store.now == nil || store.integrations == nil || store.syncs == nil || store.jobs == nil {
		return false
	}
	now := store.now()
	return canonicalTime(now)
}

func (store *MemoryStore) create(ctx context.Context, scope domain.Scope, connectorKey, name string, config map[string]string) (Integration, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil {
		return Integration{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, existing := range store.integrations {
		if existing.scope == scope && existing.name == name {
			return Integration{}, ErrConflict
		}
	}
	id, err := store.generate()
	if err != nil || id.IsZero() {
		return Integration{}, ErrInvalid
	}
	if _, exists := store.integrations[id]; exists {
		return Integration{}, ErrConflict
	}
	now := store.now()
	value := Integration{id: id, scope: scope, connectorKey: connectorKey, name: name, configuration: cloneConfiguration(config), status: IntegrationPendingAuthorization, createdAt: now, updatedAt: now}
	store.integrations[id] = value
	return cloneIntegration(value), nil
}

func (store *MemoryStore) list(ctx context.Context, scope domain.Scope) ([]Integration, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := []Integration{}
	for _, value := range store.integrations {
		if value.scope == scope {
			result = append(result, cloneIntegration(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id.String() < result[j].id.String() })
	return result, nil
}

func (store *MemoryStore) get(ctx context.Context, scope domain.Scope, id domain.ProductID) (Integration, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return Integration{}, ErrInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, exists := store.integrations[id]
	if !exists {
		return Integration{}, ErrNotFound
	}
	if value.scope != scope {
		return Integration{}, ErrForbidden
	}
	return cloneIntegration(value), nil
}

func (store *MemoryStore) update(ctx context.Context, scope domain.Scope, id domain.ProductID, connectorKey, name string, config map[string]string) (Integration, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return Integration{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.integrations[id]
	if !exists {
		return Integration{}, ErrNotFound
	}
	if value.scope != scope {
		return Integration{}, ErrForbidden
	}
	if value.connectorKey != connectorKey {
		return Integration{}, ErrConflict
	}
	for otherID, other := range store.integrations {
		if otherID != id && other.scope == scope && other.name == name {
			return Integration{}, ErrConflict
		}
	}
	value.name, value.configuration, value.updatedAt = name, cloneConfiguration(config), store.now()
	store.integrations[id] = value
	return cloneIntegration(value), nil
}

func (store *MemoryStore) authorize(ctx context.Context, scope domain.Scope, id domain.ProductID) (Integration, error) {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return Integration{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.integrations[id]
	if !exists {
		return Integration{}, ErrNotFound
	}
	if value.scope != scope {
		return Integration{}, ErrForbidden
	}
	value.status, value.updatedAt = IntegrationActive, store.now()
	store.integrations[id] = value
	return cloneIntegration(value), nil
}

func (store *MemoryStore) delete(ctx context.Context, scope domain.Scope, id domain.ProductID) error {
	if !store.usable() || !validContext(ctx) || scope.Validate() != nil || id.IsZero() {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.integrations[id]
	if !exists {
		return ErrNotFound
	}
	if value.scope != scope {
		return ErrForbidden
	}
	for _, sync := range store.syncs {
		if sync.integrationID == id {
			return ErrConflict
		}
	}
	delete(store.integrations, id)
	return nil
}

func cloneConfiguration(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
func cloneIntegration(value Integration) Integration {
	value.configuration = cloneConfiguration(value.configuration)
	return value
}
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Round(0) == value
}
func validContext(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }

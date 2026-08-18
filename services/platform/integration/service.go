package integration

import (
	"context"
	"regexp"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var jobPattern = regexp.MustCompile(`^job_[A-Za-z0-9_-]{4,123}$`)

type IntegrationInput struct {
	ConnectorKey, Name string
	Configuration      map[string]string
}
type IntegrationUpdate struct {
	Name          string
	Configuration map[string]string
}
type IntegrationSyncJob struct {
	JobID          string           `json:"job_id"`
	OrganizationID domain.ProductID `json:"organization_id"`
	WorkspaceID    domain.ProductID `json:"workspace_id"`
	EnvironmentID  domain.ProductID `json:"environment_id"`
	IntegrationID  domain.ProductID `json:"integration_id"`
	SyncID         domain.ProductID `json:"sync_id"`
}

type Service struct {
	store   *MemoryStore
	catalog *Catalog
	now     func() time.Time
}

func NewService(store *MemoryStore, catalog *Catalog, now func() time.Time) (*Service, error) {
	if store == nil || !store.usable() || catalog == nil || catalog.values == nil || now == nil || !canonicalTime(now()) {
		return nil, ErrConfiguration
	}
	return &Service{store: store, catalog: catalog, now: now}, nil
}

func (service *Service) Catalog(ctx context.Context, filter CatalogFilter) ([]PublicManifest, error) {
	if service == nil || service.catalog == nil {
		return nil, ErrConfiguration
	}
	return service.catalog.SearchContext(ctx, filter)
}
func (service *Service) List(ctx context.Context, scope domain.Scope) ([]Integration, error) {
	if service == nil || service.store == nil {
		return nil, ErrConfiguration
	}
	return service.store.list(ctx, scope)
}
func (service *Service) Get(ctx context.Context, scope domain.Scope, id domain.ProductID) (Integration, error) {
	if service == nil || service.store == nil {
		return Integration{}, ErrConfiguration
	}
	return service.store.get(ctx, scope, id)
}

func (service *Service) Create(ctx context.Context, scope domain.Scope, input IntegrationInput) (Integration, error) {
	if service == nil || !validText(input.Name, 128) || service.catalog.ValidateSetup(input.ConnectorKey, input.Configuration) != nil {
		return Integration{}, ErrInvalid
	}
	return service.store.create(ctx, scope, input.ConnectorKey, input.Name, input.Configuration)
}

func (service *Service) Update(ctx context.Context, scope domain.Scope, id domain.ProductID, input IntegrationUpdate) (Integration, error) {
	if service == nil || service.store == nil || service.catalog == nil {
		return Integration{}, ErrConfiguration
	}
	current, err := service.store.get(ctx, scope, id)
	if err != nil {
		return Integration{}, err
	}
	if !validText(input.Name, 128) || service.catalog.ValidateSetup(current.connectorKey, input.Configuration) != nil {
		return Integration{}, ErrInvalid
	}
	return service.store.update(ctx, scope, id, current.connectorKey, input.Name, input.Configuration)
}

func (service *Service) Delete(ctx context.Context, scope domain.Scope, id domain.ProductID) error {
	if service == nil || service.store == nil {
		return ErrConfiguration
	}
	return service.store.delete(ctx, scope, id)
}
func (service *Service) Authorize(ctx context.Context, scope domain.Scope, id domain.ProductID) (Integration, error) {
	if service == nil || service.store == nil {
		return Integration{}, ErrConfiguration
	}
	return service.store.authorize(ctx, scope, id)
}

func (service *Service) Sync(ctx context.Context, scope domain.Scope, integrationID domain.ProductID, jobID string) (IntegrationSync, IntegrationSyncJob, error) {
	if service == nil || !jobPattern.MatchString(jobID) || !validContext(ctx) {
		return IntegrationSync{}, IntegrationSyncJob{}, ErrInvalid
	}
	service.store.mu.Lock()
	defer service.store.mu.Unlock()
	integration, exists := service.store.integrations[integrationID]
	if !exists {
		return IntegrationSync{}, IntegrationSyncJob{}, ErrNotFound
	}
	if integration.scope != scope {
		return IntegrationSync{}, IntegrationSyncJob{}, ErrForbidden
	}
	if integration.status != IntegrationActive {
		return IntegrationSync{}, IntegrationSyncJob{}, ErrTransition
	}
	key := scope.OrganizationID().String() + "\x00" + jobID
	if id, exists := service.store.jobs[key]; exists {
		value := service.store.syncs[id]
		if value.integrationID != integrationID || value.scope != scope {
			return IntegrationSync{}, IntegrationSyncJob{}, ErrConflict
		}
		return value, jobFor(value), nil
	}
	id, err := service.store.generate()
	if err != nil || id.IsZero() {
		return IntegrationSync{}, IntegrationSyncJob{}, ErrInvalid
	}
	if _, exists := service.store.syncs[id]; exists {
		return IntegrationSync{}, IntegrationSyncJob{}, ErrConflict
	}
	now := service.store.now()
	value := IntegrationSync{id: id, integrationID: integrationID, scope: scope, jobID: jobID, status: SyncQueued, createdAt: now, updatedAt: now}
	service.store.syncs[id], service.store.jobs[key] = value, id
	return value, jobFor(value), nil
}

func (service *Service) Transition(ctx context.Context, job IntegrationSyncJob, next SyncStatus) (IntegrationSync, error) {
	if service == nil || !validContext(ctx) || !jobPattern.MatchString(job.JobID) {
		return IntegrationSync{}, ErrInvalid
	}
	service.store.mu.Lock()
	defer service.store.mu.Unlock()
	value, exists := service.store.syncs[job.SyncID]
	if !exists || jobFor(value) != job {
		return IntegrationSync{}, ErrForbidden
	}
	valid := value.status == SyncQueued && next == SyncRunning || value.status == SyncRunning && (next == SyncSucceeded || next == SyncFailed)
	if !valid {
		return IntegrationSync{}, ErrTransition
	}
	value.status, value.updatedAt = next, service.store.now()
	service.store.syncs[value.id] = value
	return value, nil
}

func (service *Service) ListSyncs(ctx context.Context, scope domain.Scope, integrationID domain.ProductID) ([]IntegrationSync, error) {
	if service == nil || service.store == nil {
		return nil, ErrConfiguration
	}
	if _, err := service.store.get(ctx, scope, integrationID); err != nil {
		return nil, err
	}
	service.store.mu.RLock()
	defer service.store.mu.RUnlock()
	result := []IntegrationSync{}
	for _, value := range service.store.syncs {
		if value.scope == scope && value.integrationID == integrationID {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id.String() < result[j].id.String() })
	return result, nil
}

func (service *Service) GetSync(ctx context.Context, scope domain.Scope, integrationID, syncID domain.ProductID) (IntegrationSync, error) {
	if service == nil || service.store == nil {
		return IntegrationSync{}, ErrConfiguration
	}
	if _, err := service.store.get(ctx, scope, integrationID); err != nil {
		return IntegrationSync{}, err
	}
	service.store.mu.RLock()
	defer service.store.mu.RUnlock()
	value, exists := service.store.syncs[syncID]
	if !exists {
		return IntegrationSync{}, ErrNotFound
	}
	if value.scope != scope || value.integrationID != integrationID {
		return IntegrationSync{}, ErrForbidden
	}
	return value, nil
}

func jobFor(value IntegrationSync) IntegrationSyncJob {
	return IntegrationSyncJob{JobID: value.jobID, OrganizationID: value.scope.OrganizationID(), WorkspaceID: value.scope.WorkspaceID(), EnvironmentID: value.scope.EnvironmentID(), IntegrationID: value.integrationID, SyncID: value.id}
}

package identity

import (
	"context"
	"sort"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type GroupMappingInput struct {
	GroupReference  string
	Role            Role
	WorkspaceID     domain.ProductID
	EnvironmentID   domain.ProductID
	ExpectedVersion uint64
}

type GroupMapping struct {
	organizationID domain.ProductID
	groupReference string
	role           Role
	workspaceID    domain.ProductID
	environmentID  domain.ProductID
	version        uint64
}

func (mapping GroupMapping) OrganizationID() domain.ProductID { return mapping.organizationID }
func (mapping GroupMapping) GroupReference() string           { return mapping.groupReference }
func (mapping GroupMapping) Role() Role                       { return mapping.role }
func (mapping GroupMapping) WorkspaceID() domain.ProductID    { return mapping.workspaceID }
func (mapping GroupMapping) EnvironmentID() domain.ProductID  { return mapping.environmentID }
func (mapping GroupMapping) Version() uint64                  { return mapping.version }

func (mapping GroupMapping) valid() bool {
	return validProductID(mapping.organizationID) && validGroupReference(mapping.groupReference) &&
		mapping.role.valid() && validProductID(mapping.workspaceID) && validProductID(mapping.environmentID) &&
		mapping.organizationID != mapping.workspaceID && mapping.organizationID != mapping.environmentID &&
		mapping.workspaceID != mapping.environmentID && mapping.version > 0
}

type GroupMappingStore struct {
	mu       sync.RWMutex
	identity *MemoryStore
	values   map[domain.ProductID]map[string]GroupMapping
}

func NewGroupMappingStore(identity *MemoryStore) (*GroupMappingStore, error) {
	if identity == nil {
		return nil, ErrConfiguration
	}
	return &GroupMappingStore{identity: identity, values: map[domain.ProductID]map[string]GroupMapping{}}, nil
}

func (store *GroupMappingStore) Upsert(ctx context.Context, organizationID domain.ProductID, input GroupMappingInput) (GroupMapping, error) {
	if store == nil || store.identity == nil || !validContext(ctx) || !validProductID(organizationID) ||
		!validGroupReference(input.GroupReference) || !input.Role.valid() ||
		!validProductID(input.WorkspaceID) || !validProductID(input.EnvironmentID) {
		return GroupMapping{}, ErrInvalidRecord
	}
	workspace, err := store.identity.GetWorkspace(ctx, organizationID, input.WorkspaceID)
	if err != nil {
		return GroupMapping{}, err
	}
	environment, err := store.identity.GetEnvironment(ctx, organizationID, input.EnvironmentID)
	if err != nil || environment.workspaceID != workspace.id {
		return GroupMapping{}, ErrForbidden
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	organizationValues := store.values[organizationID]
	if organizationValues == nil {
		organizationValues = map[string]GroupMapping{}
		store.values[organizationID] = organizationValues
	}
	existing, exists := organizationValues[input.GroupReference]
	if (!exists && input.ExpectedVersion != 0) || (exists && existing.version != input.ExpectedVersion) {
		return GroupMapping{}, ErrConflict
	}
	mapping := GroupMapping{
		organizationID: organizationID, groupReference: input.GroupReference, role: input.Role,
		workspaceID: input.WorkspaceID, environmentID: input.EnvironmentID, version: input.ExpectedVersion + 1,
	}
	if !mapping.valid() {
		return GroupMapping{}, ErrInvalidRecord
	}
	organizationValues[input.GroupReference] = mapping
	return mapping, nil
}

func (store *GroupMappingStore) List(ctx context.Context, organizationID domain.ProductID) ([]GroupMapping, error) {
	if store == nil || !validContext(ctx) || !validProductID(organizationID) {
		return nil, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]GroupMapping, 0, len(store.values[organizationID]))
	for _, mapping := range store.values[organizationID] {
		if !mapping.valid() || mapping.organizationID != organizationID {
			return nil, ErrInvalidRecord
		}
		result = append(result, mapping)
	}
	sort.Slice(result, func(first, second int) bool { return result[first].groupReference < result[second].groupReference })
	return result, nil
}

func (store *GroupMappingStore) Resolve(ctx context.Context, organizationID domain.ProductID, groupReferences []string) ([]GroupMapping, error) {
	if len(groupReferences) == 0 || len(groupReferences) > 100 {
		return nil, ErrInvalidRecord
	}
	wanted := make(map[string]struct{}, len(groupReferences))
	for _, reference := range groupReferences {
		if !validGroupReference(reference) {
			return nil, ErrInvalidRecord
		}
		if _, duplicate := wanted[reference]; duplicate {
			return nil, ErrInvalidRecord
		}
		wanted[reference] = struct{}{}
	}
	values, err := store.List(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	result := make([]GroupMapping, 0, len(values))
	for _, mapping := range values {
		if _, ok := wanted[mapping.groupReference]; ok {
			result = append(result, mapping)
		}
	}
	return result, nil
}

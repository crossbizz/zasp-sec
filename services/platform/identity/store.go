package identity

import (
	"context"
	"sort"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type IDGenerator func() (domain.ProductID, error)

type WorkspaceGrant struct {
	id             domain.ProductID
	organizationID domain.ProductID
	principalID    domain.ProductID
	workspaceID    domain.ProductID
	environmentID  domain.ProductID
	role           Role
}

func NewWorkspaceGrant(id, organizationID, principalID, workspaceID, environmentID domain.ProductID, role Role) (WorkspaceGrant, error) {
	grant := WorkspaceGrant{
		id: id, organizationID: organizationID, principalID: principalID,
		workspaceID: workspaceID, environmentID: environmentID, role: role,
	}
	if !grant.valid() {
		return WorkspaceGrant{}, ErrInvalidRecord
	}
	return grant, nil
}

func (grant WorkspaceGrant) valid() bool {
	return validProductID(grant.id) && validProductID(grant.organizationID) && validProductID(grant.principalID) &&
		validProductID(grant.workspaceID) && validProductID(grant.environmentID) && grant.role.valid() &&
		grant.id != grant.organizationID && grant.organizationID != grant.principalID &&
		grant.organizationID != grant.workspaceID && grant.organizationID != grant.environmentID &&
		grant.workspaceID != grant.environmentID
}

func (grant WorkspaceGrant) ID() domain.ProductID             { return grant.id }
func (grant WorkspaceGrant) OrganizationID() domain.ProductID { return grant.organizationID }
func (grant WorkspaceGrant) PrincipalID() domain.ProductID    { return grant.principalID }
func (grant WorkspaceGrant) WorkspaceID() domain.ProductID    { return grant.workspaceID }
func (grant WorkspaceGrant) EnvironmentID() domain.ProductID  { return grant.environmentID }
func (grant WorkspaceGrant) Role() Role                       { return grant.role }

type MemoryStore struct {
	mu            sync.RWMutex
	generate      IDGenerator
	organizations map[string]Organization
	principals    map[string]Principal
	grants        map[domain.ProductID]WorkspaceGrant
	workspaces    map[domain.ProductID]Workspace
	defaultScopes map[domain.ProductID]domain.ProductID
	environments  map[domain.ProductID][]Environment
	invitations   map[string]ExternalInvitation
}

func NewMemoryStore(generate IDGenerator) (*MemoryStore, error) {
	if generate == nil {
		return nil, ErrConfiguration
	}
	return &MemoryStore{
		generate: generate, organizations: map[string]Organization{}, principals: map[string]Principal{},
		grants: map[domain.ProductID]WorkspaceGrant{}, workspaces: map[domain.ProductID]Workspace{},
		defaultScopes: map[domain.ProductID]domain.ProductID{},
		environments:  map[domain.ProductID][]Environment{}, invitations: map[string]ExternalInvitation{},
	}, nil
}

func (store *MemoryStore) ReconcileOrganization(ctx context.Context, external ExternalOrganization) (Organization, error) {
	if store == nil || !validContext(ctx) || !external.valid() {
		return Organization{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.organizations[external.Reference]; ok {
		if existing.name != external.Name || existing.domain != external.Domain {
			return Organization{}, ErrConflict
		}
		return existing, nil
	}
	id, err := store.nextID()
	if err != nil {
		return Organization{}, err
	}
	organization := Organization{id: id, externalRef: external.Reference, name: external.Name, domain: external.Domain}
	if !organization.valid() {
		return Organization{}, ErrInvalidRecord
	}
	store.organizations[external.Reference] = organization
	return organization, nil
}

func (store *MemoryStore) ReconcilePrincipal(ctx context.Context, organizationID domain.ProductID, external ExternalPrincipal, role Role) (Principal, error) {
	if store == nil || !validContext(ctx) || !validProductID(organizationID) || !external.valid() || !role.valid() {
		return Principal{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	organization, ok := store.organizations[external.organizationReference]
	if !ok || organization.id != organizationID {
		return Principal{}, ErrForbidden
	}
	key := external.organizationReference + "\x00" + external.memberReference
	if existing, ok := store.principals[key]; ok {
		if existing.organizationID != organizationID || existing.role != role {
			return Principal{}, ErrConflict
		}
		if !existing.active {
			existing.active = true
			store.principals[key] = existing
		}
		return existing, nil
	}
	id, err := store.nextID()
	if err != nil {
		return Principal{}, err
	}
	principal, err := newPrincipal(id, organizationID, external.organizationReference, external.memberReference, role)
	if err != nil {
		return Principal{}, err
	}
	store.principals[key] = principal
	return principal, nil
}

func (store *MemoryStore) RecordInvitation(ctx context.Context, organizationID domain.ProductID, invitation ExternalInvitation) error {
	if store == nil || !validContext(ctx) || !validProductID(organizationID) || !invitation.valid() {
		return ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	organization, ok := store.organizations[invitation.organizationReference]
	if !ok || organization.id != organizationID {
		return ErrForbidden
	}
	key := invitation.organizationReference + "\x00" + invitation.memberReference
	if existing, ok := store.invitations[key]; ok && existing != invitation {
		return ErrConflict
	}
	store.invitations[key] = invitation
	return nil
}

func (store *MemoryStore) invitation(organizationReference, memberReference string) (ExternalInvitation, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.invitations[organizationReference+"\x00"+memberReference]
	return value, ok
}

func (store *MemoryStore) EnsureDefaultScopes(ctx context.Context, organizationID domain.ProductID) (Workspace, []Environment, error) {
	if store == nil || !validContext(ctx) || !validProductID(organizationID) {
		return Workspace{}, nil, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.organizationExistsLocked(organizationID) {
		return Workspace{}, nil, ErrNotFound
	}
	if workspaceID, ok := store.defaultScopes[organizationID]; ok {
		workspace := store.workspaces[workspaceID]
		return workspace, append([]Environment(nil), store.environments[workspace.id]...), nil
	}
	workspaceID, err := store.nextID()
	if err != nil {
		return Workspace{}, nil, err
	}
	workspace := Workspace{id: workspaceID, organizationID: organizationID, name: "Default"}
	environments := make([]Environment, 0, 3)
	for _, name := range []string{"production", "staging", "development"} {
		id, err := store.nextID()
		if err != nil {
			return Workspace{}, nil, err
		}
		environments = append(environments, Environment{id: id, organizationID: organizationID, workspaceID: workspaceID, name: name})
	}
	store.workspaces[workspaceID] = workspace
	store.defaultScopes[organizationID] = workspaceID
	store.environments[workspaceID] = environments
	return workspace, append([]Environment(nil), environments...), nil
}

func (store *MemoryStore) GetOrganization(ctx context.Context, authenticatedOrganization domain.ProductID) (Organization, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) {
		return Organization{}, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, organization := range store.organizations {
		if organization.id == authenticatedOrganization {
			return organization, nil
		}
	}
	return Organization{}, ErrNotFound
}

func (store *MemoryStore) ListWorkspaces(ctx context.Context, authenticatedOrganization domain.ProductID) ([]Workspace, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) {
		return nil, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Workspace, 0)
	for _, workspace := range store.workspaces {
		if workspace.organizationID == authenticatedOrganization {
			result = append(result, workspace)
		}
	}
	sort.Slice(result, func(first, second int) bool { return result[first].id.String() < result[second].id.String() })
	return result, nil
}

func (store *MemoryStore) CreateWorkspace(ctx context.Context, authenticatedOrganization domain.ProductID, name string) (Workspace, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validName(name) {
		return Workspace{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.organizationExistsLocked(authenticatedOrganization) {
		return Workspace{}, ErrNotFound
	}
	for _, workspace := range store.workspaces {
		if workspace.organizationID == authenticatedOrganization && workspace.name == name {
			return Workspace{}, ErrConflict
		}
	}
	id, err := store.nextID()
	if err != nil {
		return Workspace{}, err
	}
	workspace := Workspace{id: id, organizationID: authenticatedOrganization, name: name}
	if !workspace.valid() {
		return Workspace{}, ErrInvalidRecord
	}
	store.workspaces[id] = workspace
	return workspace, nil
}

func (store *MemoryStore) GetWorkspace(ctx context.Context, authenticatedOrganization, workspaceID domain.ProductID) (Workspace, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(workspaceID) {
		return Workspace{}, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	workspace, ok := store.workspaces[workspaceID]
	if !ok {
		return Workspace{}, ErrNotFound
	}
	if workspace.organizationID != authenticatedOrganization {
		return Workspace{}, ErrForbidden
	}
	return workspace, nil
}

func (store *MemoryStore) UpdateWorkspace(ctx context.Context, authenticatedOrganization, workspaceID domain.ProductID, name string) (Workspace, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(workspaceID) || !validName(name) {
		return Workspace{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	workspace, ok := store.workspaces[workspaceID]
	if !ok {
		return Workspace{}, ErrNotFound
	}
	if workspace.organizationID != authenticatedOrganization {
		return Workspace{}, ErrForbidden
	}
	for id, candidate := range store.workspaces {
		if id != workspaceID && candidate.organizationID == authenticatedOrganization && candidate.name == name {
			return Workspace{}, ErrConflict
		}
	}
	workspace.name = name
	store.workspaces[workspaceID] = workspace
	return workspace, nil
}

func (store *MemoryStore) ListEnvironments(ctx context.Context, authenticatedOrganization, workspaceID domain.ProductID) ([]Environment, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(workspaceID) {
		return nil, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	workspace, ok := store.workspaces[workspaceID]
	if !ok {
		return nil, ErrNotFound
	}
	if workspace.organizationID != authenticatedOrganization {
		return nil, ErrForbidden
	}
	result := append([]Environment(nil), store.environments[workspaceID]...)
	sort.Slice(result, func(first, second int) bool { return result[first].id.String() < result[second].id.String() })
	return result, nil
}

func (store *MemoryStore) CreateEnvironment(ctx context.Context, authenticatedOrganization, workspaceID domain.ProductID, name string) (Environment, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(workspaceID) || !validName(name) {
		return Environment{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	workspace, ok := store.workspaces[workspaceID]
	if !ok {
		return Environment{}, ErrNotFound
	}
	if workspace.organizationID != authenticatedOrganization {
		return Environment{}, ErrForbidden
	}
	for _, environment := range store.environments[workspaceID] {
		if environment.name == name {
			return Environment{}, ErrConflict
		}
	}
	id, err := store.nextID()
	if err != nil {
		return Environment{}, err
	}
	environment := Environment{id: id, organizationID: authenticatedOrganization, workspaceID: workspaceID, name: name}
	if !environment.valid() {
		return Environment{}, ErrInvalidRecord
	}
	store.environments[workspaceID] = append(store.environments[workspaceID], environment)
	return environment, nil
}

func (store *MemoryStore) GetEnvironment(ctx context.Context, authenticatedOrganization, environmentID domain.ProductID) (Environment, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(environmentID) {
		return Environment{}, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.environmentLocked(authenticatedOrganization, environmentID)
}

func (store *MemoryStore) UpdateEnvironment(ctx context.Context, authenticatedOrganization, environmentID domain.ProductID, name string) (Environment, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(environmentID) || !validName(name) {
		return Environment{}, ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	environment, err := store.environmentLocked(authenticatedOrganization, environmentID)
	if err != nil {
		return Environment{}, err
	}
	values := store.environments[environment.workspaceID]
	for _, candidate := range values {
		if candidate.id != environmentID && candidate.name == name {
			return Environment{}, ErrConflict
		}
	}
	for index := range values {
		if values[index].id == environmentID {
			values[index].name = name
			environment = values[index]
			break
		}
	}
	store.environments[environment.workspaceID] = values
	return environment, nil
}

func (store *MemoryStore) GetPrincipal(ctx context.Context, authenticatedOrganization, principalID domain.ProductID) (Principal, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(principalID) {
		return Principal{}, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, principal := range store.principals {
		if principal.id != principalID {
			continue
		}
		if principal.organizationID != authenticatedOrganization {
			return Principal{}, ErrForbidden
		}
		return principal, nil
	}
	return Principal{}, ErrNotFound
}

func (store *MemoryStore) ListPrincipals(ctx context.Context, authenticatedOrganization domain.ProductID) ([]Principal, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) {
		return nil, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Principal, 0)
	for _, principal := range store.principals {
		if principal.organizationID == authenticatedOrganization {
			result = append(result, principal)
		}
	}
	sort.Slice(result, func(first, second int) bool { return result[first].id.String() < result[second].id.String() })
	return result, nil
}

func (store *MemoryStore) organizationExistsLocked(id domain.ProductID) bool {
	for _, organization := range store.organizations {
		if organization.id == id {
			return true
		}
	}
	return false
}

func (store *MemoryStore) environmentLocked(organizationID, environmentID domain.ProductID) (Environment, error) {
	for _, values := range store.environments {
		for _, environment := range values {
			if environment.id != environmentID {
				continue
			}
			if environment.organizationID != organizationID {
				return Environment{}, ErrForbidden
			}
			return environment, nil
		}
	}
	return Environment{}, ErrNotFound
}

func (store *MemoryStore) CreateGrant(ctx context.Context, authenticatedOrganization domain.ProductID, grant WorkspaceGrant) error {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !grant.valid() {
		return ErrInvalidRecord
	}
	if grant.organizationID != authenticatedOrganization {
		return ErrForbidden
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.grants[grant.id]; ok {
		if existing != grant {
			return ErrConflict
		}
		return nil
	}
	store.grants[grant.id] = grant
	return nil
}

func (store *MemoryStore) ListGrants(ctx context.Context, authenticatedOrganization, principalID domain.ProductID) ([]WorkspaceGrant, error) {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(principalID) {
		return nil, ErrInvalidRecord
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]WorkspaceGrant, 0)
	for _, grant := range store.grants {
		if grant.organizationID == authenticatedOrganization && grant.principalID == principalID {
			result = append(result, grant)
		}
	}
	sort.Slice(result, func(first, second int) bool { return result[first].id.String() < result[second].id.String() })
	return result, nil
}

func (store *MemoryStore) DeleteGrant(ctx context.Context, authenticatedOrganization, grantID domain.ProductID) error {
	if store == nil || !validContext(ctx) || !validProductID(authenticatedOrganization) || !validProductID(grantID) {
		return ErrInvalidRecord
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	grant, ok := store.grants[grantID]
	if !ok {
		return ErrNotFound
	}
	if grant.organizationID != authenticatedOrganization {
		return ErrForbidden
	}
	delete(store.grants, grantID)
	return nil
}

func (store *MemoryStore) nextID() (domain.ProductID, error) {
	id, err := store.generate()
	if err != nil || !validProductID(id) {
		return domain.ProductID{}, ErrInvalidRecord
	}
	return id, nil
}

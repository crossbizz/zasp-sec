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
		environments: map[domain.ProductID][]Environment{}, invitations: map[string]ExternalInvitation{},
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
	if workspace, ok := store.workspaces[organizationID]; ok {
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
	store.workspaces[organizationID] = workspace
	store.environments[workspaceID] = environments
	return workspace, append([]Environment(nil), environments...), nil
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

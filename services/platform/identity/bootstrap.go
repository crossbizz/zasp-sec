package identity

import "context"

type ProvisionResult struct {
	Organization Organization
	Invitation   ExternalInvitation
}

type BootstrapSession struct {
	Organization Organization
	Principal    Principal
	Invitation   ExternalInvitation
	Workspace    Workspace
	Environments []Environment
}

type BootstrapService struct {
	adapter *Adapter
	store   *MemoryStore
}

func NewBootstrapService(adapter *Adapter, store *MemoryStore) (*BootstrapService, error) {
	if adapter == nil || store == nil || nilInterface(adapter.driver) || store.generate == nil {
		return nil, ErrConfiguration
	}
	return &BootstrapService{adapter: adapter, store: store}, nil
}

func (service *BootstrapService) Provision(ctx context.Context, name, domainName, adminEmail string) (ProvisionResult, error) {
	if service == nil || service.adapter == nil || service.store == nil || !validContext(ctx) {
		return ProvisionResult{}, ErrInvalidRecord
	}
	externalOrganization, err := service.adapter.EnsureOrganization(ctx, name, domainName)
	if err != nil {
		return ProvisionResult{}, err
	}
	organization, err := service.store.ReconcileOrganization(ctx, externalOrganization)
	if err != nil {
		return ProvisionResult{}, err
	}
	invitation, err := service.adapter.InviteAdmin(ctx, externalOrganization.Reference, adminEmail)
	if err != nil {
		return ProvisionResult{}, err
	}
	if err := service.store.RecordInvitation(ctx, organization.id, invitation); err != nil {
		return ProvisionResult{}, err
	}
	return ProvisionResult{Organization: organization, Invitation: invitation}, nil
}

func (service *BootstrapService) FirstSignIn(ctx context.Context, external ExternalPrincipal) (BootstrapSession, error) {
	if service == nil || service.adapter == nil || service.store == nil || !validContext(ctx) || !external.valid() {
		return BootstrapSession{}, ErrAuthentication
	}
	externalOrganization, err := service.adapter.Organization(ctx, external.organizationReference)
	if err != nil {
		return BootstrapSession{}, ErrAuthentication
	}
	organization, err := service.store.ReconcileOrganization(ctx, externalOrganization)
	if err != nil {
		return BootstrapSession{}, err
	}
	invitation, found := service.store.invitation(external.organizationReference, external.memberReference)
	if !found || invitation.organizationReference != external.organizationReference || invitation.memberReference != external.memberReference {
		return BootstrapSession{}, ErrForbidden
	}
	principal, err := service.store.ReconcilePrincipal(ctx, organization.id, external, RoleOrganizationAdmin)
	if err != nil {
		return BootstrapSession{}, err
	}
	workspace, environments, err := service.store.EnsureDefaultScopes(ctx, organization.id)
	if err != nil {
		return BootstrapSession{}, err
	}
	return BootstrapSession{
		Organization: organization, Principal: principal, Invitation: invitation,
		Workspace: workspace, Environments: append([]Environment(nil), environments...),
	}, nil
}

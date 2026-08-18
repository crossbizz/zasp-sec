package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var fixtureNow = time.Date(2026, 8, 18, 13, 0, 0, 0, time.UTC)

func TestAdapterAndSessionAuthenticationReturnOnlyProductPrincipal(t *testing.T) {
	driver := newFakeStytchDriver()
	adapter, err := NewAdapter(driver, func() time.Time { return fixtureNow })
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewSessionAuthenticator(adapter)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := authenticator.Authenticate(context.Background(), "Bearer header.payload.signature")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if principal.OrganizationReference() != driver.organization.Reference || principal.MemberReference() != driver.session.MemberReference ||
		principal.SessionReference() != driver.session.SessionReference || !principal.ExpiresAt().Equal(driver.session.ExpiresAt) {
		t.Fatalf("principal = %#v", principal)
	}
	if fmt.Sprintf("%T", principal) != "identity.ExternalPrincipal" {
		t.Fatalf("principal leaked adapter type: %T", principal)
	}

	for _, header := range []string{"", "Bearer", "bearer header.payload.signature", "Bearer raw", "Bearer a.b.c extra"} {
		if _, err := authenticator.Authenticate(context.Background(), header); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("header %q error = %v", header, err)
		}
	}
	driver.session.Active = false
	if _, err := authenticator.Authenticate(context.Background(), "Bearer header.payload.signature"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("inactive session error = %v", err)
	}
}

func TestFreshAuthRevalidatesAndFailsClosed(t *testing.T) {
	driver := newFakeStytchDriver()
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	principal, err := adapter.Authenticate(context.Background(), "header.payload.signature")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewFreshAuthGuard(adapter, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := guard.Run(context.Background(), principal, func(context.Context, ExternalPrincipal) error {
		calls++
		return nil
	}); err != nil || calls != 1 || driver.revalidateCalls != 1 {
		t.Fatalf("fresh run = err %v calls %d remote %d", err, calls, driver.revalidateCalls)
	}

	for _, name := range []string{"revoked", "outage", "old", "foreign"} {
		t.Run(name, func(t *testing.T) {
			clone := *driver
			clone.session = driverFixtureSession()
			clone.revalidateErr = nil
			mutateDriver := &clone
			switch name {
			case "revoked":
				mutateDriver.session.Active = false
			case "outage":
				mutateDriver.revalidateErr = errors.New("provider detail")
			case "old":
				mutateDriver.session.AuthenticatedAt = fixtureNow.Add(-10 * time.Minute)
			case "foreign":
				mutateDriver.session.OrganizationReference = "organization-live-foreign"
			}
			currentAdapter, _ := NewAdapter(mutateDriver, func() time.Time { return fixtureNow })
			currentGuard, _ := NewFreshAuthGuard(currentAdapter, 5*time.Minute)
			if err := currentGuard.Run(context.Background(), principal, func(context.Context, ExternalPrincipal) error {
				t.Fatal("guarded operation ran")
				return nil
			}); !errors.Is(err, ErrFreshAuthentication) {
				t.Fatalf("Run() error = %v", err)
			}
		})
	}
}

func TestOrganizationPrincipalAndDefaultScopeReconciliationIsIdempotent(t *testing.T) {
	store := newFixtureStore(t)
	first, err := store.ReconcileOrganization(context.Background(), ExternalOrganization{
		Reference: "organization-live-a", Name: "Acme", Domain: "acme.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.ReconcileOrganization(context.Background(), ExternalOrganization{
		Reference: "organization-live-a", Name: "Acme", Domain: "acme.example",
	})
	if err != nil || repeated != first {
		t.Fatalf("repeated organization = %#v, %v", repeated, err)
	}
	second, err := store.ReconcileOrganization(context.Background(), ExternalOrganization{
		Reference: "organization-live-b", Name: "Beta", Domain: "beta.example",
	})
	if err != nil || second.ID() == first.ID() {
		t.Fatalf("second organization = %#v, %v", second, err)
	}

	external := mustExternalPrincipal(t, driverFixtureSession())
	principal, err := store.ReconcilePrincipal(context.Background(), first.ID(), external, RoleOrganizationAdmin)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.ReconcilePrincipal(context.Background(), first.ID(), external, RoleOrganizationAdmin)
	if err != nil || again != principal {
		t.Fatalf("repeated principal = %#v, %v", again, err)
	}
	workspace, environments, err := store.EnsureDefaultScopes(context.Background(), first.ID())
	if err != nil {
		t.Fatal(err)
	}
	workspaceAgain, environmentsAgain, err := store.EnsureDefaultScopes(context.Background(), first.ID())
	if err != nil || workspaceAgain != workspace || !reflect.DeepEqual(environmentsAgain, environments) || len(environments) != 3 {
		t.Fatalf("default scopes = %#v %#v, %v", workspaceAgain, environmentsAgain, err)
	}
	if []string{environments[0].Name(), environments[1].Name(), environments[2].Name()}[0] != "production" {
		t.Fatal("default environment order changed")
	}
}

func TestBuiltInRolePermissionSnapshot(t *testing.T) {
	want := map[Role][]Permission{
		RoleOrganizationAdmin: {PermissionView, PermissionManageIdentity, PermissionManageIntegrations, PermissionManageFindings, PermissionManagePolicies, PermissionRunTests, PermissionManageAgents, PermissionApproveActions, PermissionExportEvidence, PermissionViewAudit},
		RoleSecurityAdmin:     {PermissionView, PermissionManageIntegrations, PermissionManageFindings, PermissionManagePolicies, PermissionRunTests, PermissionManageAgents, PermissionApproveActions, PermissionExportEvidence, PermissionViewAudit},
		RoleSecurityEngineer:  {PermissionView, PermissionManageFindings, PermissionManagePolicies, PermissionRunTests, PermissionManageAgents, PermissionApproveActions},
		RoleDeveloperOwner:    {PermissionView, PermissionManageIntegrations, PermissionRunTests},
		RoleComplianceViewer:  {PermissionView, PermissionExportEvidence, PermissionViewAudit},
		RoleReadOnlyViewer:    {PermissionView},
	}
	if got := BuiltInRoles(); !reflect.DeepEqual(got, want) {
		t.Fatalf("role snapshot = %#v", got)
	}
	got := BuiltInRoles()
	got[RoleOrganizationAdmin][0] = Permission("forged")
	if BuiltInRoles()[RoleOrganizationAdmin][0] != PermissionView {
		t.Fatal("role snapshot aliases mutable caller state")
	}
}

func TestWorkspaceGrantStoreResolverAndAuthorizationStayOrganizationScoped(t *testing.T) {
	store := newFixtureStore(t)
	organizationA := fixtureID(t, 1)
	organizationB := fixtureID(t, 2)
	principalID := fixtureID(t, 3)
	scopeA := fixtureScope(t, organizationA, 4)
	scopeOtherWorkspace := fixtureScope(t, organizationA, 7)
	scopeForeign := fixtureScope(t, organizationB, 10)
	grant, err := NewWorkspaceGrant(fixtureID(t, 20), organizationA, principalID, scopeA.WorkspaceID(), scopeA.EnvironmentID(), RoleSecurityEngineer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(context.Background(), organizationA, grant); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(context.Background(), organizationB, grant); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign CreateGrant() error = %v", err)
	}
	listed, err := store.ListGrants(context.Background(), organizationA, principalID)
	if err != nil || len(listed) != 1 || listed[0] != grant {
		t.Fatalf("ListGrants() = %#v, %v", listed, err)
	}
	if foreign, err := store.ListGrants(context.Background(), organizationB, principalID); err != nil || len(foreign) != 0 {
		t.Fatalf("foreign ListGrants() = %#v, %v", foreign, err)
	}

	principal := mustProductPrincipal(t, principalID, organizationA, RoleReadOnlyViewer)
	authorizer, err := NewAuthorizationService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Resolve(context.Background(), principal, scopeA, PermissionManagePolicies); err != nil {
		t.Fatalf("authorized Resolve() error = %v", err)
	}
	for _, scope := range []domain.Scope{scopeOtherWorkspace, scopeForeign} {
		if _, err := authorizer.Resolve(context.Background(), principal, scope, PermissionManagePolicies); !errors.Is(err, ErrForbidden) {
			t.Fatalf("cross-scope Resolve() error = %v", err)
		}
	}
	calls := 0
	if err := authorizer.Run(context.Background(), principal, scopeA, PermissionManagePolicies, func(context.Context, AuthorizationContext) error {
		calls++
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("authorized Run() = %v, calls %d", err, calls)
	}
	if err := authorizer.Run(context.Background(), principal, scopeForeign, PermissionManagePolicies, func(context.Context, AuthorizationContext) error {
		calls++
		return nil
	}); !errors.Is(err, ErrForbidden) || calls != 1 {
		t.Fatalf("foreign Run() = %v, calls %d", err, calls)
	}
	if err := store.DeleteGrant(context.Background(), organizationA, grant.ID()); err != nil {
		t.Fatal(err)
	}
	if after, _ := store.ListGrants(context.Background(), organizationA, principalID); len(after) != 0 {
		t.Fatalf("grant remained after delete: %#v", after)
	}
}

func TestFirstAdminBootstrapEndToEndIsIdempotent(t *testing.T) {
	driver := newFakeStytchDriver()
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	store := newFixtureStore(t)
	bootstrap, err := NewBootstrapService(adapter, store)
	if err != nil {
		t.Fatal(err)
	}

	first, err := bootstrap.Provision(context.Background(), "Acme", "acme.example", "admin@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := bootstrap.Provision(context.Background(), "Acme", "acme.example", "admin@acme.example")
	if err != nil || second != first || driver.ensureOrganizationCalls != 2 || driver.inviteCalls != 2 {
		t.Fatalf("repeated Provision() = %#v, %v", second, err)
	}

	external := mustExternalPrincipal(t, driverFixtureSession())
	session, err := bootstrap.FirstSignIn(context.Background(), external)
	if err != nil {
		t.Fatal(err)
	}
	again, err := bootstrap.FirstSignIn(context.Background(), external)
	if err != nil || again.Organization != session.Organization || again.Principal != session.Principal || again.Workspace != session.Workspace || !reflect.DeepEqual(again.Environments, session.Environments) {
		t.Fatalf("repeated FirstSignIn() = %#v, %v", again, err)
	}
	if session.Principal.Role() != RoleOrganizationAdmin || len(session.Environments) != 3 || session.Invitation.Email() != "admin@acme.example" {
		t.Fatalf("bootstrap session = %#v", session)
	}
	if driver.persistedSecret != "" {
		t.Fatal("bootstrap persisted a raw authentication secret")
	}
}

type fakeStytchDriver struct {
	session                 DriverSession
	organization            DriverOrganization
	invitation              DriverInvitation
	revalidateErr           error
	revalidateCalls         int
	ensureOrganizationCalls int
	inviteCalls             int
	persistedSecret         string
}

func newFakeStytchDriver() *fakeStytchDriver {
	return &fakeStytchDriver{
		session:      driverFixtureSession(),
		organization: DriverOrganization{Reference: "organization-live-a", Name: "Acme", Domain: "acme.example"},
		invitation:   DriverInvitation{MemberReference: "member-live-a", OrganizationReference: "organization-live-a", Email: "admin@acme.example"},
	}
}

func driverFixtureSession() DriverSession {
	return DriverSession{
		MemberReference: "member-live-a", OrganizationReference: "organization-live-a", SessionReference: "member-session-live-a",
		AuthenticatedAt: fixtureNow.Add(-time.Minute), ExpiresAt: fixtureNow.Add(time.Hour), Active: true,
	}
}

func (driver *fakeStytchDriver) AuthenticateJWT(context.Context, string) (DriverSession, error) {
	return driver.session, nil
}

func (driver *fakeStytchDriver) RevalidateSession(context.Context, string) (DriverSession, error) {
	driver.revalidateCalls++
	return driver.session, driver.revalidateErr
}

func (driver *fakeStytchDriver) GetOrganization(context.Context, string) (DriverOrganization, error) {
	return driver.organization, nil
}

func (driver *fakeStytchDriver) EnsureOrganization(context.Context, string, string) (DriverOrganization, error) {
	driver.ensureOrganizationCalls++
	return driver.organization, nil
}

func (driver *fakeStytchDriver) InviteAdmin(context.Context, string, string) (DriverInvitation, error) {
	driver.inviteCalls++
	return driver.invitation, nil
}

func (driver *fakeStytchDriver) ListSSOConnections(context.Context, string) ([]DriverSSOConnection, error) {
	return []DriverSSOConnection{{Reference: "sso-live-a", OrganizationReference: driver.organization.Reference, Status: "active"}}, nil
}

func (driver *fakeStytchDriver) ListSCIMConnections(context.Context, string) ([]DriverSCIMConnection, error) {
	return []DriverSCIMConnection{{Reference: "scim-live-a", OrganizationReference: driver.organization.Reference, Status: "active"}}, nil
}

func fixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fixtureScope(t *testing.T, organization domain.ProductID, offset int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(organization, fixtureID(t, offset), fixtureID(t, offset+1))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func newFixtureStore(t *testing.T) *MemoryStore {
	t.Helper()
	var mu sync.Mutex
	next := 100
	store, err := NewMemoryStore(func() (domain.ProductID, error) {
		mu.Lock()
		defer mu.Unlock()
		next++
		return fixtureID(t, next), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func mustExternalPrincipal(t *testing.T, session DriverSession) ExternalPrincipal {
	t.Helper()
	principal, err := newExternalPrincipal(session)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func mustProductPrincipal(t *testing.T, id, organization domain.ProductID, role Role) Principal {
	t.Helper()
	principal, err := newPrincipal(id, organization, "organization-live-a", "member-live-a", role)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

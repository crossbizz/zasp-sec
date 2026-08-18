package identity

import (
	"context"
	"reflect"
	"strings"
	"time"
)

const maximumJWTBytes = 8 * 1024

type StytchDriver interface {
	AuthenticateJWT(context.Context, string) (DriverSession, error)
	RevalidateSession(context.Context, string) (DriverSession, error)
	GetOrganization(context.Context, string) (DriverOrganization, error)
	EnsureOrganization(context.Context, string, string) (DriverOrganization, error)
	InviteAdmin(context.Context, string, string) (DriverInvitation, error)
	ListSSOConnections(context.Context, string) ([]DriverSSOConnection, error)
	ListSCIMConnections(context.Context, string) ([]DriverSCIMConnection, error)
}

type Adapter struct {
	driver StytchDriver
	now    func() time.Time
}

func NewAdapter(driver StytchDriver, now func() time.Time) (*Adapter, error) {
	if nilInterface(driver) || now == nil {
		return nil, ErrConfiguration
	}
	current := now()
	if !canonicalTime(current) {
		return nil, ErrConfiguration
	}
	return &Adapter{driver: driver, now: now}, nil
}

func (adapter *Adapter) Authenticate(ctx context.Context, jwt string) (ExternalPrincipal, error) {
	if adapter == nil || nilInterface(adapter.driver) || !validContext(ctx) || !validJWT(jwt) {
		return ExternalPrincipal{}, ErrAuthentication
	}
	session, err := authenticateDriver(adapter.driver, ctx, jwt)
	if err != nil {
		return ExternalPrincipal{}, ErrProvider
	}
	return adapter.validateSession(session)
}

func (adapter *Adapter) Revalidate(ctx context.Context, principal ExternalPrincipal) (ExternalPrincipal, error) {
	if adapter == nil || nilInterface(adapter.driver) || !validContext(ctx) || !principal.valid() {
		return ExternalPrincipal{}, ErrAuthentication
	}
	session, err := revalidateDriver(adapter.driver, ctx, principal.sessionReference)
	if err != nil {
		return ExternalPrincipal{}, ErrProvider
	}
	validated, err := adapter.validateSession(session)
	if err != nil || validated.memberReference != principal.memberReference ||
		validated.organizationReference != principal.organizationReference || validated.sessionReference != principal.sessionReference {
		return ExternalPrincipal{}, ErrAuthentication
	}
	return validated, nil
}

func (adapter *Adapter) Organization(ctx context.Context, reference string) (ExternalOrganization, error) {
	if adapter == nil || !validContext(ctx) || !validReference(reference, "organization-") {
		return ExternalOrganization{}, ErrInvalidRecord
	}
	raw, err := getOrganizationDriver(adapter.driver, ctx, reference)
	organization := ExternalOrganization{Reference: raw.Reference, Name: raw.Name, Domain: raw.Domain}
	if err != nil {
		return ExternalOrganization{}, ErrProvider
	}
	if !organization.valid() || organization.Reference != reference {
		return ExternalOrganization{}, ErrInvalidRecord
	}
	return organization, nil
}

func (adapter *Adapter) EnsureOrganization(ctx context.Context, name, domainName string) (ExternalOrganization, error) {
	if adapter == nil || !validContext(ctx) || !validName(name) || !validDomain(domainName) {
		return ExternalOrganization{}, ErrInvalidRecord
	}
	raw, err := ensureOrganizationDriver(adapter.driver, ctx, name, domainName)
	organization := ExternalOrganization{Reference: raw.Reference, Name: raw.Name, Domain: raw.Domain}
	if err != nil {
		return ExternalOrganization{}, ErrProvider
	}
	if !organization.valid() || organization.Name != name || organization.Domain != domainName {
		return ExternalOrganization{}, ErrInvalidRecord
	}
	return organization, nil
}

func (adapter *Adapter) InviteAdmin(ctx context.Context, organizationReference, email string) (ExternalInvitation, error) {
	if adapter == nil || !validContext(ctx) || !validReference(organizationReference, "organization-") || !validEmail(email) {
		return ExternalInvitation{}, ErrInvalidRecord
	}
	raw, err := inviteAdminDriver(adapter.driver, ctx, organizationReference, email)
	if err != nil {
		return ExternalInvitation{}, ErrProvider
	}
	invitation, err := newExternalInvitation(raw)
	if err != nil || invitation.organizationReference != organizationReference || invitation.email != email {
		return ExternalInvitation{}, ErrInvalidRecord
	}
	return invitation, nil
}

func (adapter *Adapter) ListSSOConnections(ctx context.Context, organizationReference string) ([]DriverSSOConnection, error) {
	if adapter == nil || !validContext(ctx) || !validReference(organizationReference, "organization-") {
		return nil, ErrInvalidRecord
	}
	values, err := listSSODriver(adapter.driver, ctx, organizationReference)
	if err != nil {
		return nil, ErrProvider
	}
	result := append([]DriverSSOConnection(nil), values...)
	for _, value := range result {
		if !validReference(value.Reference, "sso-") || value.OrganizationReference != organizationReference || !validConnectionStatus(value.Status) {
			return nil, ErrInvalidRecord
		}
	}
	return result, nil
}

func (adapter *Adapter) ListSCIMConnections(ctx context.Context, organizationReference string) ([]DriverSCIMConnection, error) {
	if adapter == nil || !validContext(ctx) || !validReference(organizationReference, "organization-") {
		return nil, ErrInvalidRecord
	}
	values, err := listSCIMDriver(adapter.driver, ctx, organizationReference)
	if err != nil {
		return nil, ErrProvider
	}
	result := append([]DriverSCIMConnection(nil), values...)
	for _, value := range result {
		if !validReference(value.Reference, "scim-") || value.OrganizationReference != organizationReference || !validConnectionStatus(value.Status) {
			return nil, ErrInvalidRecord
		}
	}
	return result, nil
}

func (adapter *Adapter) validateSession(session DriverSession) (ExternalPrincipal, error) {
	principal, err := newExternalPrincipal(session)
	if err != nil {
		return ExternalPrincipal{}, ErrAuthentication
	}
	now := adapter.now()
	if !canonicalTime(now) || principal.authenticatedAt.After(now) || !principal.expiresAt.After(now) {
		return ExternalPrincipal{}, ErrAuthentication
	}
	return principal, nil
}

func validJWT(value string) bool {
	if value == "" || len(value) > maximumJWTBytes || strings.TrimSpace(value) != value {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
				!(character >= '0' && character <= '9') && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func validConnectionStatus(value string) bool {
	return value == "active" || value == "pending" || value == "disabled"
}

func validContext(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func authenticateDriver(driver StytchDriver, ctx context.Context, jwt string) (result DriverSession, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.AuthenticateJWT(ctx, jwt)
}

func revalidateDriver(driver StytchDriver, ctx context.Context, reference string) (result DriverSession, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.RevalidateSession(ctx, reference)
}

func getOrganizationDriver(driver StytchDriver, ctx context.Context, reference string) (result DriverOrganization, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.GetOrganization(ctx, reference)
}

func ensureOrganizationDriver(driver StytchDriver, ctx context.Context, name, domainName string) (result DriverOrganization, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.EnsureOrganization(ctx, name, domainName)
}

func inviteAdminDriver(driver StytchDriver, ctx context.Context, organizationReference, email string) (result DriverInvitation, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.InviteAdmin(ctx, organizationReference, email)
}

func listSSODriver(driver StytchDriver, ctx context.Context, organizationReference string) (result []DriverSSOConnection, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.ListSSOConnections(ctx, organizationReference)
}

func listSCIMDriver(driver StytchDriver, ctx context.Context, organizationReference string) (result []DriverSCIMConnection, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.ListSCIMConnections(ctx, organizationReference)
}

func providerRecovery(resultErr *error) {
	if recover() != nil {
		*resultErr = ErrProvider
	}
}

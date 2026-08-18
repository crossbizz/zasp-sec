package identity

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var (
	ErrConfiguration       = errors.New("identity configuration rejected")
	ErrAuthentication      = errors.New("authentication rejected")
	ErrFreshAuthentication = errors.New("fresh authentication rejected")
	ErrProvider            = errors.New("identity provider rejected")
	ErrInvalidRecord       = errors.New("identity record rejected")
	ErrConflict            = errors.New("identity conflict")
	ErrNotFound            = errors.New("identity record not found")
	ErrForbidden           = errors.New("authorization rejected")
	ErrWebhookVerification = errors.New("webhook verification rejected")
	ErrDeprovision         = errors.New("identity deprovision rejected")
)

type DriverSession struct {
	MemberReference       string
	OrganizationReference string
	SessionReference      string
	AuthenticatedAt       time.Time
	ExpiresAt             time.Time
	Active                bool
}

type DriverOrganization struct {
	Reference string
	Name      string
	Domain    string
}

type DriverInvitation struct {
	MemberReference       string
	OrganizationReference string
	Email                 string
}

type DriverSSOConnection struct {
	Reference             string
	OrganizationReference string
	Status                string
	DisplayName           string
	Protocol              string
	IdentityProvider      string
}

type DriverSCIMConnection struct {
	Reference             string
	OrganizationReference string
	Status                string
	DisplayName           string
	IdentityProvider      string
	BaseURL               string
}

type DriverSSOConfig struct {
	DisplayName      string
	Protocol         string
	IdentityProvider string
}

type DriverSCIMConfig struct {
	DisplayName      string
	IdentityProvider string
}

type DriverSCIMCredential struct {
	Connection  DriverSCIMConnection
	BearerToken string
}

type ExternalPrincipal struct {
	memberReference       string
	organizationReference string
	sessionReference      string
	authenticatedAt       time.Time
	expiresAt             time.Time
}

func newExternalPrincipal(session DriverSession) (ExternalPrincipal, error) {
	principal := ExternalPrincipal{
		memberReference: session.MemberReference, organizationReference: session.OrganizationReference,
		sessionReference: session.SessionReference, authenticatedAt: session.AuthenticatedAt, expiresAt: session.ExpiresAt,
	}
	if !session.Active || !principal.valid() {
		return ExternalPrincipal{}, ErrAuthentication
	}
	return principal, nil
}

func (principal ExternalPrincipal) valid() bool {
	return validReference(principal.memberReference, "member-") &&
		validReference(principal.organizationReference, "organization-") &&
		validReference(principal.sessionReference, "member-session-") &&
		canonicalTime(principal.authenticatedAt) && canonicalTime(principal.expiresAt) &&
		principal.expiresAt.After(principal.authenticatedAt)
}

func (principal ExternalPrincipal) MemberReference() string { return principal.memberReference }
func (principal ExternalPrincipal) OrganizationReference() string {
	return principal.organizationReference
}
func (principal ExternalPrincipal) SessionReference() string   { return principal.sessionReference }
func (principal ExternalPrincipal) AuthenticatedAt() time.Time { return principal.authenticatedAt }
func (principal ExternalPrincipal) ExpiresAt() time.Time       { return principal.expiresAt }

type ExternalOrganization struct {
	Reference string
	Name      string
	Domain    string
}

func (organization ExternalOrganization) valid() bool {
	return validReference(organization.Reference, "organization-") && validName(organization.Name) && validDomain(organization.Domain)
}

type ExternalInvitation struct {
	memberReference       string
	organizationReference string
	email                 string
}

func newExternalInvitation(value DriverInvitation) (ExternalInvitation, error) {
	invitation := ExternalInvitation{
		memberReference: value.MemberReference, organizationReference: value.OrganizationReference, email: value.Email,
	}
	if !invitation.valid() {
		return ExternalInvitation{}, ErrInvalidRecord
	}
	return invitation, nil
}

func (invitation ExternalInvitation) valid() bool {
	return validReference(invitation.memberReference, "member-") &&
		validReference(invitation.organizationReference, "organization-") && validEmail(invitation.email)
}

func (invitation ExternalInvitation) MemberReference() string { return invitation.memberReference }
func (invitation ExternalInvitation) OrganizationReference() string {
	return invitation.organizationReference
}
func (invitation ExternalInvitation) Email() string { return invitation.email }

type Organization struct {
	id          domain.ProductID
	externalRef string
	name        string
	domain      string
}

func (organization Organization) valid() bool {
	return validProductID(organization.id) && validReference(organization.externalRef, "organization-") &&
		validName(organization.name) && validDomain(organization.domain)
}

func (organization Organization) ID() domain.ProductID      { return organization.id }
func (organization Organization) ExternalReference() string { return organization.externalRef }
func (organization Organization) Name() string              { return organization.name }
func (organization Organization) Domain() string            { return organization.domain }

type Principal struct {
	id                    domain.ProductID
	organizationID        domain.ProductID
	organizationReference string
	memberReference       string
	role                  Role
	active                bool
}

func newPrincipal(id, organizationID domain.ProductID, organizationReference, memberReference string, role Role) (Principal, error) {
	principal := Principal{
		id: id, organizationID: organizationID, organizationReference: organizationReference,
		memberReference: memberReference, role: role, active: true,
	}
	if !principal.valid() {
		return Principal{}, ErrInvalidRecord
	}
	return principal, nil
}

func (principal Principal) valid() bool {
	return principal.validRecord() && principal.active
}

func (principal Principal) validRecord() bool {
	return validProductID(principal.id) && validProductID(principal.organizationID) && principal.id != principal.organizationID &&
		validReference(principal.organizationReference, "organization-") && validReference(principal.memberReference, "member-") &&
		principal.role.valid()
}

func (principal Principal) ID() domain.ProductID             { return principal.id }
func (principal Principal) OrganizationID() domain.ProductID { return principal.organizationID }
func (principal Principal) OrganizationReference() string    { return principal.organizationReference }
func (principal Principal) MemberReference() string          { return principal.memberReference }
func (principal Principal) Role() Role                       { return principal.role }
func (principal Principal) Active() bool                     { return principal.active }

type Workspace struct {
	id             domain.ProductID
	organizationID domain.ProductID
	name           string
}

func (workspace Workspace) valid() bool {
	return validProductID(workspace.id) && validProductID(workspace.organizationID) &&
		workspace.id != workspace.organizationID && validName(workspace.name)
}

func (workspace Workspace) ID() domain.ProductID             { return workspace.id }
func (workspace Workspace) OrganizationID() domain.ProductID { return workspace.organizationID }
func (workspace Workspace) Name() string                     { return workspace.name }

type Environment struct {
	id             domain.ProductID
	organizationID domain.ProductID
	workspaceID    domain.ProductID
	name           string
}

func (environment Environment) valid() bool {
	return validProductID(environment.id) && validProductID(environment.organizationID) &&
		validProductID(environment.workspaceID) && environment.id != environment.organizationID &&
		environment.id != environment.workspaceID && environment.organizationID != environment.workspaceID &&
		validName(environment.name)
}

func (environment Environment) ID() domain.ProductID             { return environment.id }
func (environment Environment) OrganizationID() domain.ProductID { return environment.organizationID }
func (environment Environment) WorkspaceID() domain.ProductID    { return environment.workspaceID }
func (environment Environment) Name() string                     { return environment.name }

func validProductID(id domain.ProductID) bool {
	parsed, err := domain.ParseProductID(id.String())
	return err == nil && parsed == id
}

func validReference(value, prefix string) bool {
	if len(value) <= len(prefix) || len(value) > 128 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validName(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validEmail(value string) bool {
	if value == "" || len(value) > 254 || strings.TrimSpace(value) != value || strings.ToLower(value) != value || strings.Count(value, "@") != 1 {
		return false
	}
	parts := strings.Split(value, "@")
	return parts[0] != "" && len(parts[0]) <= 64 && validDomain(parts[1])
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(time.UnixMilli(value.UnixMilli()).UTC())
}

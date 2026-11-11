// Package bootstrap provisions the first Organization of a deployment and its
// first Organization Admin. It is the operator-only entry point that precedes
// every customer sign-in: no product session exists before it runs, so it is
// reachable only with operator database and provider credentials, never from
// the product API.
package bootstrap

import (
	"context"
	"errors"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/identity"
)

var (
	// ErrInvalid means the operator request itself is malformed.
	ErrInvalid = errors.New("bootstrap request is invalid")
	// ErrProvider means the identity provider refused or returned an
	// organization or member that does not match the request.
	ErrProvider = errors.New("bootstrap identity provider refused")
	// ErrConflict means existing product records disagree with the request and
	// were left untouched.
	ErrConflict = errors.New("bootstrap conflicts with existing records")
	// ErrStore means the product records could not be written.
	ErrStore = errors.New("bootstrap product records unavailable")
)

// AdminRole is the product role granted to the designated first administrator.
const AdminRole = string(identity.RoleOrganizationAdmin)

// DefaultWorkspaceName is the Workspace created for a new Organization.
const DefaultWorkspaceName = "Default"

// DefaultEnvironment describes one Environment created in the default
// Workspace of a new Organization.
type DefaultEnvironment struct {
	Name  string
	Class string
}

// DefaultEnvironments are created in this order; the first is the default
// scope of the first administrator.
var DefaultEnvironments = []DefaultEnvironment{
	{Name: "Production", Class: "production"},
	{Name: "Staging", Class: "staging"},
	{Name: "Development", Class: "development"},
}

// AdminPermissions is the Organization Admin permission set. It mirrors the
// server-owned role table served by listBuiltInRoles; a test pins the two
// together so they cannot drift apart.
var AdminPermissions = []string{
	"investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity",
	"manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance",
}

// Directory is the identity provider boundary. identity.Adapter implements it.
type Directory interface {
	EnsureOrganization(ctx context.Context, name, domainName string) (identity.ExternalOrganization, error)
	InviteAdmin(ctx context.Context, organizationReference, email string) (identity.ExternalInvitation, error)
}

// Store writes the product records for one provisioned Organization.
type Store interface {
	Provision(ctx context.Context, records Records) (Result, error)
}

// Request names the customer Organization and its designated first
// administrator.
type Request struct {
	Name       string
	Domain     string
	AdminEmail string
	// OrganizationID pins the product Organization ID. Single-tenant
	// deployments must set it to their configured Organization; SaaS
	// deployments leave it empty and receive a generated ID.
	OrganizationID string
	// ExpectedOrganizationReference is the provider Organization the
	// deployment is already bound to, if any. A request that resolves to a
	// different one is refused before any invitation is sent.
	ExpectedOrganizationReference string
}

// Records is what the Store persists. Every reference comes from the provider
// response, never from operator input.
type Records struct {
	OrganizationID        string
	Name                  string
	Domain                string
	OrganizationReference string
	MemberReference       string
}

// Environment is one provisioned Environment.
type Environment struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Class       string `json:"environment_class"`
}

// Result reports the provisioned records. It carries identifiers only.
type Result struct {
	OrganizationID        string        `json:"organization_id"`
	OrganizationReference string        `json:"organization_reference"`
	WorkspaceID           string        `json:"workspace_id"`
	Environments          []Environment `json:"environments"`
	PrincipalID           string        `json:"principal_id"`
	MemberReference       string        `json:"member_reference"`
	// OrganizationCreated and AdminCreated are false when a repeated run
	// found the records already present.
	OrganizationCreated bool `json:"organization_created"`
	AdminCreated        bool `json:"admin_created"`
}

// Provisioner runs provider provisioning and product persistence in order.
type Provisioner struct {
	directory Directory
	store     Store
}

// NewProvisioner requires both boundaries.
func NewProvisioner(directory Directory, store Store) (*Provisioner, error) {
	if directory == nil || store == nil {
		return nil, ErrInvalid
	}
	return &Provisioner{directory: directory, store: store}, nil
}

// Provision resolves or creates the provider Organization, resolves or invites
// the first administrator, and writes the matching product records. Every step
// is idempotent, so a run interrupted after any step is safe to repeat.
func (provisioner *Provisioner) Provision(ctx context.Context, request Request) (Result, error) {
	if provisioner == nil || ctx == nil || ctx.Err() != nil {
		return Result{}, ErrInvalid
	}
	if request.OrganizationID != "" {
		if _, err := domain.ParseProductID(request.OrganizationID); err != nil {
			return Result{}, ErrInvalid
		}
	}
	organization, err := provisioner.directory.EnsureOrganization(ctx, request.Name, request.Domain)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidRecord) {
			return Result{}, ErrInvalid
		}
		return Result{}, ErrProvider
	}
	if request.ExpectedOrganizationReference != "" && organization.Reference != request.ExpectedOrganizationReference {
		return Result{}, ErrConflict
	}
	invitation, err := provisioner.directory.InviteAdmin(ctx, organization.Reference, request.AdminEmail)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidRecord) {
			return Result{}, ErrInvalid
		}
		return Result{}, ErrProvider
	}
	if invitation.OrganizationReference() != organization.Reference || invitation.MemberReference() == "" {
		return Result{}, ErrProvider
	}
	return provisioner.store.Provision(ctx, Records{
		OrganizationID: request.OrganizationID, Name: organization.Name, Domain: organization.Domain,
		OrganizationReference: organization.Reference, MemberReference: invitation.MemberReference(),
	})
}

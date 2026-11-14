package demoseed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/bootstrap"
	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// target is the resolved demo scope and the person it is for.
type target struct {
	scope               domain.Scope
	organizationName    string
	environmentName     string
	principal           string
	organizationCreated bool
	memberCreated       bool
}

const (
	scopeLockSQL          = `SELECT pg_advisory_xact_lock(hashtextextended('zasp-demo:' || $1, 0))`
	organizationNameSQL   = `SELECT name FROM public.zasp_organizations WHERE id = $1`
	workspaceByNameSQL    = `SELECT id FROM public.zasp_workspaces WHERE organization_id = $1 AND name = $2`
	insertWorkspaceSQL    = `INSERT INTO public.zasp_workspaces(id, organization_id, name) VALUES($1, $2, $3)`
	environmentByNameSQL  = `SELECT id, environment_class FROM public.zasp_environments WHERE organization_id = $1 AND workspace_id = $2 AND name = $3`
	insertEnvironmentSQL  = `INSERT INTO public.zasp_environments(id, organization_id, workspace_id, name, environment_class) VALUES($1, $2, $3, $4, $5)`
	insertDataControlsSQL = `INSERT INTO public.zasp_data_controls(organization_id, workspace_id, environment_id, environment_class, collection_mode, retention_days, deletion_enabled) VALUES($1, $2, $3, $4, 'metadata_only', 30, true) ON CONFLICT (organization_id, workspace_id, environment_id) DO NOTHING`
	membershipSQL         = `SELECT principal_id, organization_id, active FROM public.zasp_identity_memberships WHERE organization_reference = $1 AND member_reference = $2`
	// The permissions the member already holds in the Organization: those
	// of their default scope, else of any scope.
	memberPermissionsSQL = `SELECT permissions FROM public.zasp_authorized_scopes WHERE principal_id = $1 AND organization_id = $2 ORDER BY is_default DESC, workspace_id, environment_id LIMIT 1`
	insertScopeSQL       = `INSERT INTO public.zasp_authorized_scopes(principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES($1, $2, $3, $4, $5, $6::jsonb, false) ON CONFLICT (principal_id, organization_id, workspace_id, environment_id) DO NOTHING`
	// Integrations of the Environment that do not carry the demo marker. A
	// deleted integration is history, not data.
	foreignIntegrationsSQL = `SELECT count(*) FROM public.zasp_integrations WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3) AND state <> 'deleted' AND COALESCE(configuration->>'` + demodata.Marker + `', '') <> '` + datasetName + `'`
)

func parseScope(organization, workspace, environment string) (domain.Scope, error) {
	o, err := domain.ParseProductID(organization)
	if err != nil {
		return domain.Scope{}, err
	}
	w, err := domain.ParseProductID(workspace)
	if err != nil {
		return domain.Scope{}, err
	}
	e, err := domain.ParseProductID(environment)
	if err != nil {
		return domain.Scope{}, err
	}
	return domain.NewScope(o, w, e)
}

// resolve finds or creates the demo scope and makes sure the person can see
// it. It writes nothing outside that scope.
func (seeder *Seeder) resolve(ctx context.Context, request Request) (target, error) {
	if seeder.directory == nil {
		return target{}, fmt.Errorf("%w: no identity provider is configured", ErrInvalid)
	}
	if request.ExistingOrganizationID != "" {
		return seeder.resolveExisting(ctx, request)
	}
	return seeder.resolveDedicated(ctx, request)
}

// resolveDedicated provisions the dedicated Organization with the bootstrap
// provisioner: the provider Organization is resolved or created, the person
// is resolved or invited, and the Organization, its Workspace, its
// Environment, the membership and the scope are written in one transaction.
func (seeder *Seeder) resolveDedicated(ctx context.Context, request Request) (target, error) {
	store, err := bootstrap.NewPostgresStoreWithLayout(seeder.database, request.Workspace, []bootstrap.DefaultEnvironment{{Name: request.Environment, Class: environmentClass}})
	if err != nil {
		return target{}, ErrInvalid
	}
	provisioner, err := bootstrap.NewProvisioner(seeder.directory, store)
	if err != nil {
		return target{}, ErrInvalid
	}
	result, err := provisioner.Provision(ctx, bootstrap.Request{Name: request.Organization, Domain: request.Domain, AdminEmail: request.Email})
	switch {
	case errors.Is(err, bootstrap.ErrProvider):
		return target{}, fmt.Errorf("%w (an organization for %s may exist under another name, or the invitation could not be sent)", ErrProvider, request.Domain)
	case errors.Is(err, bootstrap.ErrConflict):
		return target{}, fmt.Errorf("%w: the membership or the organization for %s exists in another form", ErrConflict, request.Domain)
	case errors.Is(err, bootstrap.ErrInvalid):
		return target{}, ErrInvalid
	case err != nil:
		return target{}, fmt.Errorf("provision the demo organization: %w", err)
	}
	// An Organization that existed before is the demo Organization only if
	// it has the demo Workspace and Environment; the provisioner created
	// neither for it.
	var workspace, environment, class string
	if err := seeder.database.QueryRow(ctx, workspaceByNameSQL, result.OrganizationID, request.Workspace).Scan(&workspace); err != nil {
		return target{}, fmt.Errorf("%w: organization %s has no workspace named %q", ErrConflict, result.OrganizationID, request.Workspace)
	}
	if err := seeder.database.QueryRow(ctx, environmentByNameSQL, result.OrganizationID, workspace, request.Environment).Scan(&environment, &class); err != nil {
		return target{}, fmt.Errorf("%w: organization %s has no environment named %q", ErrConflict, result.OrganizationID, request.Environment)
	}
	scope, err := parseScope(result.OrganizationID, workspace, environment)
	if err != nil {
		return target{}, err
	}
	if request.AuthorizationStoreID != "" {
		if err := store.BindAuthorization(ctx, result.OrganizationID, request.AuthorizationStoreID, request.AuthorizationModelID); err != nil {
			return target{}, fmt.Errorf("bind the permission projection of the demo organization: %w", err)
		}
	}
	return target{scope: scope, organizationName: request.Organization, environmentName: request.Environment, principal: result.PrincipalID,
		organizationCreated: result.OrganizationCreated, memberCreated: result.AdminCreated}, nil
}

// resolveExisting creates the demo Workspace and Environment inside an
// Organization the person already belongs to and gives that person, and
// nobody else, a scope for it. It creates no membership and sends no
// invitation.
func (seeder *Seeder) resolveExisting(ctx context.Context, request Request) (target, error) {
	organization := request.ExistingOrganizationID
	var name string
	if err := seeder.database.QueryRow(ctx, organizationNameSQL, organization).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target{}, fmt.Errorf("%w: there is no organization %s", ErrInvalid, organization)
		}
		return target{}, err
	}
	store, err := bootstrap.NewPostgresStore(seeder.database)
	if err != nil {
		return target{}, ErrInvalid
	}
	reference, err := store.BoundProviderOrganization(ctx, organization)
	if err != nil || reference == "" {
		return target{}, fmt.Errorf("%w: organization %s has no member yet; create its first administrator first", ErrNotMember, organization)
	}
	member, found, err := seeder.directory.FindMember(ctx, reference, request.Email)
	if err != nil {
		return target{}, ErrProvider
	}
	if !found {
		return target{}, fmt.Errorf("%w: %s", ErrNotMember, organization)
	}
	var principal, memberOrganization string
	var active bool
	if err := seeder.database.QueryRow(ctx, membershipSQL, reference, member.MemberReference()).Scan(&principal, &memberOrganization, &active); err != nil || memberOrganization != organization || !active {
		return target{}, fmt.Errorf("%w: %s", ErrNotMember, organization)
	}
	var permissions []byte
	if err := seeder.database.QueryRow(ctx, memberPermissionsSQL, principal, organization).Scan(&permissions); err != nil {
		return target{}, fmt.Errorf("%w: the member has no authorized scope in %s", ErrNotMember, organization)
	}
	var listed []string
	if json.Unmarshal(permissions, &listed) != nil || len(listed) == 0 {
		return target{}, fmt.Errorf("%w: the member has no permission in %s", ErrNotMember, organization)
	}

	tx, err := seeder.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return target{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, scopeLockSQL, organization); err != nil {
		return target{}, err
	}
	var workspace string
	switch err := tx.QueryRow(ctx, workspaceByNameSQL, organization, request.Workspace).Scan(&workspace); {
	case errors.Is(err, pgx.ErrNoRows):
		if workspace, err = newID(); err != nil {
			return target{}, err
		}
		if _, err := tx.Exec(ctx, insertWorkspaceSQL, workspace, organization, request.Workspace); err != nil {
			return target{}, fmt.Errorf("create the demo workspace: %w", err)
		}
	case err != nil:
		return target{}, err
	}
	var environment, class string
	switch err := tx.QueryRow(ctx, environmentByNameSQL, organization, workspace, request.Environment).Scan(&environment, &class); {
	case errors.Is(err, pgx.ErrNoRows):
		if environment, err = newID(); err != nil {
			return target{}, err
		}
		class = environmentClass
		if _, err := tx.Exec(ctx, insertEnvironmentSQL, environment, organization, workspace, request.Environment, class); err != nil {
			return target{}, fmt.Errorf("create the demo environment: %w", err)
		}
	case err != nil:
		return target{}, err
	}
	// The Environment may be one a person created with this name. It is the
	// demo Environment only if it holds nothing but demo integrations.
	var foreign int
	if err := tx.QueryRow(ctx, foreignIntegrationsSQL, organization, workspace, environment).Scan(&foreign); err != nil {
		return target{}, err
	}
	if foreign > 0 || class == "production" {
		return target{}, fmt.Errorf("%w: environment %q of workspace %q", ErrNotDemo, request.Environment, request.Workspace)
	}
	if _, err := tx.Exec(ctx, insertDataControlsSQL, organization, workspace, environment, class); err != nil {
		return target{}, fmt.Errorf("create the demo environment's data controls: %w", err)
	}
	if _, err := tx.Exec(ctx, insertScopeSQL, principal, organization, workspace, environment, request.Environment, string(permissions)); err != nil {
		return target{}, fmt.Errorf("authorize the member for the demo environment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return target{}, err
	}
	scope, err := parseScope(organization, workspace, environment)
	if err != nil {
		return target{}, err
	}
	return target{scope: scope, organizationName: name, environmentName: request.Environment, principal: principal}, nil
}

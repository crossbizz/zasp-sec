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
	dedicated           bool
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
	// Integrations of the Environment that are not demo integrations: a
	// discovery record without the demo marker, or a product record (what
	// the Integrations page lists, including one that was created and not
	// yet authorized) that belongs to no demo integration. A deleted
	// integration is history, not data.
	foreignIntegrationsSQL = `SELECT
 (SELECT count(*) FROM public.zasp_integrations WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3) AND state <> 'deleted' AND COALESCE(configuration->>'` + demodata.Marker + `', '') <> '` + datasetName + `')
 + (SELECT count(*) FROM public.zasp_workflow_records record WHERE (record.organization_id, record.workspace_id, record.environment_id, record.kind) = ($1, $2, $3, 'integration') AND record.deleted_at IS NULL
    AND NOT EXISTS (SELECT 1 FROM public.zasp_integrations demo WHERE (demo.organization_id, demo.workspace_id, demo.environment_id, demo.id) = ($1, $2, $3, record.id) AND demo.configuration->>'` + demodata.Marker + `' = '` + datasetName + `'))`
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

const signInOrganizationSQL = `SELECT DISTINCT organization_id FROM public.zasp_identity_memberships WHERE organization_reference = $1`

// place decides where the demo goes when the operator did not say: into the
// Organization the deployment's sign-in is bound to when the person is an
// active member of it, else into the dedicated Organization. It writes
// nothing and sends nothing.
func (seeder *Seeder) place(ctx context.Context, request Request) (Request, error) {
	if request.Dedicated && request.ExistingOrganizationID != "" {
		return Request{}, fmt.Errorf("%w: a dedicated organization and an existing organization exclude each other", ErrInvalid)
	}
	if request.Dedicated || request.ExistingOrganizationID != "" || request.Organization != "" || request.Domain != "" || request.SignInOrganizationReference == "" {
		return request, nil
	}
	if seeder.directory == nil || !emailPattern.MatchString(request.Email) {
		return request, nil
	}
	rows, err := seeder.database.Query(ctx, signInOrganizationSQL, request.SignInOrganizationReference)
	if err != nil {
		return Request{}, err
	}
	organizations, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return Request{}, err
	}
	if len(organizations) != 1 {
		return request, nil
	}
	member, found, err := seeder.directory.FindMember(ctx, request.SignInOrganizationReference, request.Email)
	if err != nil {
		return Request{}, ErrProvider
	}
	if !found {
		seeder.say("%s is not a member of the organization this deployment signs people in to; using a dedicated organization", request.Email)
		return request, nil
	}
	var principal, organization string
	var active bool
	if err := seeder.database.QueryRow(ctx, membershipSQL, request.SignInOrganizationReference, member.MemberReference()).Scan(&principal, &organization, &active); err != nil || !active || organization != organizations[0] {
		seeder.say("%s has no active membership in the organization this deployment signs people in to; using a dedicated organization", request.Email)
		return request, nil
	}
	seeder.say("%s signs in to organization %s; the demo goes into a workspace of its own there", request.Email, organization)
	request.ExistingOrganizationID = organization
	return request, nil
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

const (
	organizationsOfReferenceSQL = `SELECT DISTINCT organization_id FROM public.zasp_identity_memberships WHERE organization_reference = $1`
	// The Environments of an Organization other than the demo Environment.
	otherEnvironmentCountSQL = `SELECT count(*) FROM public.zasp_environments e JOIN public.zasp_workspaces w ON (w.organization_id, w.id) = (e.organization_id, e.workspace_id) WHERE e.organization_id = $1 AND NOT (w.name = $2 AND e.name = $3)`
)

// ensureEnvironment finds or creates the demo Workspace and Environment of
// an Organization, inside the caller's transaction. An Environment of that
// name that holds anything but demo integrations, or that is a production
// Environment, is refused.
func ensureEnvironment(ctx context.Context, tx pgx.Tx, organization, workspaceName, environmentName string) (workspace, environment string, err error) {
	if _, err := tx.Exec(ctx, scopeLockSQL, organization); err != nil {
		return "", "", err
	}
	switch err := tx.QueryRow(ctx, workspaceByNameSQL, organization, workspaceName).Scan(&workspace); {
	case errors.Is(err, pgx.ErrNoRows):
		if workspace, err = newID(); err != nil {
			return "", "", err
		}
		if _, err := tx.Exec(ctx, insertWorkspaceSQL, workspace, organization, workspaceName); err != nil {
			return "", "", fmt.Errorf("create the demo workspace: %w", err)
		}
	case err != nil:
		return "", "", err
	}
	var class string
	switch err := tx.QueryRow(ctx, environmentByNameSQL, organization, workspace, environmentName).Scan(&environment, &class); {
	case errors.Is(err, pgx.ErrNoRows):
		if environment, err = newID(); err != nil {
			return "", "", err
		}
		class = environmentClass
		if _, err := tx.Exec(ctx, insertEnvironmentSQL, environment, organization, workspace, environmentName, class); err != nil {
			return "", "", fmt.Errorf("create the demo environment: %w", err)
		}
	case err != nil:
		return "", "", err
	}
	// The Environment may be one a person created with this name. It is the
	// demo Environment only if it holds nothing but demo integrations.
	var foreign int
	if err := tx.QueryRow(ctx, foreignIntegrationsSQL, organization, workspace, environment).Scan(&foreign); err != nil {
		return "", "", err
	}
	if foreign > 0 || class == "production" {
		return "", "", fmt.Errorf("%w: environment %q of workspace %q", ErrNotDemo, environmentName, workspaceName)
	}
	if _, err := tx.Exec(ctx, insertDataControlsSQL, organization, workspace, environment, class); err != nil {
		return "", "", fmt.Errorf("create the demo environment's data controls: %w", err)
	}
	return workspace, environment, nil
}

// resolveDedicated provisions the dedicated Organization the way the
// bootstrap command provisions the first one: the provider Organization is
// resolved or created, the person is resolved or invited, and the
// Organization, its Workspace, its Environment, the administrator
// membership and the scope are written by the bootstrap store.
//
// An Organization that a removal left empty (the database keeps the record
// where the permission projection refers to it) receives its Workspace and
// Environment again first. An Organization that has any other Environment
// is not a demo Organization and is refused: provisioning would make the
// person an administrator of it.
func (seeder *Seeder) resolveDedicated(ctx context.Context, request Request) (target, error) {
	environmentName := request.Environment
	if environmentName == "" {
		environmentName = DefaultName
	}
	store, err := bootstrap.NewPostgresStoreWithLayout(seeder.database, request.Workspace, []bootstrap.DefaultEnvironment{{Name: environmentName, Class: environmentClass}})
	if err != nil {
		return target{}, ErrInvalid
	}
	organization, err := seeder.directory.EnsureOrganization(ctx, request.Organization, request.Domain)
	if err != nil {
		return target{}, fmt.Errorf("%w (an organization for %s may exist under another name)", ErrProvider, request.Domain)
	}
	invitation, err := seeder.directory.InviteAdmin(ctx, organization.Reference, request.Email)
	if err != nil || invitation.OrganizationReference() != organization.Reference || invitation.MemberReference() == "" {
		return target{}, fmt.Errorf("%w (the invitation could not be sent)", ErrProvider)
	}
	rows, err := seeder.database.Query(ctx, organizationsOfReferenceSQL, organization.Reference)
	if err != nil {
		return target{}, err
	}
	existing, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return target{}, err
	}
	switch len(existing) {
	case 0:
	case 1:
		var others int
		if err := seeder.database.QueryRow(ctx, otherEnvironmentCountSQL, existing[0], request.Workspace, environmentName).Scan(&others); err != nil {
			return target{}, err
		}
		if others > 0 {
			return target{}, fmt.Errorf("%w: the organization for %s has environments of its own and is not a demo organization; use --into-existing-organization %s", ErrConflict, request.Domain, existing[0])
		}
		if err := seeder.inTransaction(ctx, func(tx pgx.Tx) error {
			_, _, err := ensureEnvironment(ctx, tx, existing[0], request.Workspace, environmentName)
			return err
		}); err != nil {
			return target{}, err
		}
	default:
		return target{}, fmt.Errorf("%w: the provider organization for %s is linked to more than one organization", ErrConflict, request.Domain)
	}
	result, err := store.Provision(ctx, bootstrap.Records{Name: organization.Name, Domain: organization.Domain, OrganizationReference: organization.Reference, MemberReference: invitation.MemberReference()})
	switch {
	case errors.Is(err, bootstrap.ErrConflict):
		return target{}, fmt.Errorf("%w: the membership or the organization for %s exists in another form", ErrConflict, request.Domain)
	case errors.Is(err, bootstrap.ErrInvalid):
		return target{}, ErrInvalid
	case err != nil:
		return target{}, fmt.Errorf("provision the demo organization: %w", err)
	}
	var workspace, environment, class string
	if err := seeder.database.QueryRow(ctx, workspaceByNameSQL, result.OrganizationID, request.Workspace).Scan(&workspace); err != nil {
		return target{}, fmt.Errorf("%w: organization %s has no workspace named %q", ErrConflict, result.OrganizationID, request.Workspace)
	}
	if err := seeder.database.QueryRow(ctx, environmentByNameSQL, result.OrganizationID, workspace, environmentName).Scan(&environment, &class); err != nil {
		return target{}, fmt.Errorf("%w: organization %s has no environment named %q", ErrConflict, result.OrganizationID, environmentName)
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
	return target{scope: scope, organizationName: request.Organization, environmentName: environmentName, principal: result.PrincipalID,
		organizationCreated: result.OrganizationCreated, memberCreated: result.AdminCreated, dedicated: true}, nil
}

// resolveExisting creates the demo Workspace and Environment inside an
// Organization the person already belongs to and gives that person, and
// nobody else, a scope for it. It creates no membership and sends no
// invitation.
func (seeder *Seeder) resolveExisting(ctx context.Context, request Request) (target, error) {
	organization := request.ExistingOrganizationID
	environmentName := request.Environment
	if environmentName == "" {
		environmentName = DefaultExistingEnvironment
	}
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
	var workspace, environment string
	if err := seeder.inTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		if workspace, environment, err = ensureEnvironment(ctx, tx, organization, request.Workspace, environmentName); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, insertScopeSQL, principal, organization, workspace, environment, environmentName, string(permissions)); err != nil {
			return fmt.Errorf("authorize the member for the demo environment: %w", err)
		}
		return nil
	}); err != nil {
		return target{}, err
	}
	scope, err := parseScope(organization, workspace, environment)
	if err != nil {
		return target{}, err
	}
	return target{scope: scope, organizationName: name, environmentName: environmentName, principal: principal}, nil
}

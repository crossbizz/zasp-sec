package bootstrap

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Queryer is the pgx surface the store needs. *pgx.Conn and *pgxpool.Pool
// both satisfy it.
type Queryer interface {
	BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PostgresStore writes bootstrap records as the migration operator. It needs
// no new database objects: every statement is an ordinary insert into the
// product tables, and the installed authorization triggers record the desired
// permission revision for the projector.
type PostgresStore struct {
	database Queryer
	newID    func() (string, error)
}

// NewPostgresStore binds the store to an operator connection.
func NewPostgresStore(database Queryer) (*PostgresStore, error) {
	if database == nil {
		return nil, ErrInvalid
	}
	return &PostgresStore{database: database, newID: newProductID}, nil
}

func newProductID() (string, error) {
	id, err := domain.NewProductID()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

const (
	lockSQL = `SELECT pg_advisory_xact_lock(hashtextextended('zasp-bootstrap:' || $1, 0))`
	// The provider Organization is the identity of the customer. A product
	// Organization is found through any membership that references it.
	findOrganizationSQL   = `SELECT DISTINCT organization_id FROM public.zasp_identity_memberships WHERE organization_reference = $1`
	organizationExistsSQL = `SELECT EXISTS(SELECT 1 FROM public.zasp_organizations WHERE id = $1)`
	insertOrganizationSQL = `INSERT INTO public.zasp_organizations(id, name, domain) VALUES($1, $2, $3)`
	findWorkspaceSQL      = `SELECT id FROM public.zasp_workspaces WHERE organization_id = $1 AND name = $2`
	insertWorkspaceSQL    = `INSERT INTO public.zasp_workspaces(id, organization_id, name) VALUES($1, $2, $3)`
	findEnvironmentSQL    = `SELECT id, environment_class FROM public.zasp_environments WHERE organization_id = $1 AND workspace_id = $2 AND name = $3`
	insertEnvironmentSQL  = `INSERT INTO public.zasp_environments(id, organization_id, workspace_id, name, environment_class) VALUES($1, $2, $3, $4, $5)`
	insertDataControlsSQL = `INSERT INTO public.zasp_data_controls(organization_id, workspace_id, environment_id, environment_class, collection_mode, retention_days, deletion_enabled) VALUES($1, $2, $3, $4, 'metadata_only', 30, true) ON CONFLICT (organization_id, workspace_id, environment_id) DO NOTHING`
	// Production first, so the first Environment is the administrator's
	// default scope whether it was just created or already existed.
	existingEnvironmentsSQL  = `SELECT id, workspace_id, name, environment_class FROM public.zasp_environments WHERE organization_id = $1 ORDER BY array_position(ARRAY['production','staging','development','test'], environment_class), name, id`
	boundProviderSQL         = `SELECT DISTINCT organization_reference FROM public.zasp_identity_memberships WHERE organization_id = $1`
	findMembershipSQL        = `SELECT principal_id, organization_id, role, active FROM public.zasp_identity_memberships WHERE organization_reference = $1 AND member_reference = $2`
	insertMembershipSQL      = `INSERT INTO public.zasp_identity_memberships(principal_id, organization_id, organization_reference, member_reference, role) VALUES($1, $2, $3, $4, $5)`
	hasDefaultScopeSQL       = `SELECT EXISTS(SELECT 1 FROM public.zasp_authorized_scopes WHERE principal_id = $1 AND organization_id = $2 AND is_default)`
	insertAuthorizedScopeSQL = `INSERT INTO public.zasp_authorized_scopes(principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES($1, $2, $3, $4, $5, $6::jsonb, $7) ON CONFLICT (principal_id, organization_id, workspace_id, environment_id) DO NOTHING`
)

// Provision writes the Organization, its default Workspace and Environments,
// the first administrator membership and that administrator's scopes in one
// transaction. Records that already exist are reused; records that exist but
// disagree with the request are reported as ErrConflict and nothing is
// written.
func (store *PostgresStore) Provision(ctx context.Context, records Records) (result Result, err error) {
	if store == nil || store.database == nil || store.newID == nil || ctx == nil || ctx.Err() != nil ||
		records.Name == "" || records.Domain == "" || records.OrganizationReference == "" || records.MemberReference == "" {
		return Result{}, ErrInvalid
	}
	// The advisory lock below serializes provisioning only if each statement
	// sees rows committed before it, so the isolation level is fixed here
	// rather than inherited from the connection.
	transaction, err := store.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Result{}, ErrStore
	}
	defer func() {
		if err != nil {
			_ = transaction.Rollback(context.WithoutCancel(ctx))
		}
	}()
	// Two operators provisioning the same provider Organization serialize
	// here, so neither can create a second product Organization for it.
	if _, err = transaction.Exec(ctx, lockSQL, records.OrganizationReference); err != nil {
		return Result{}, ErrStore
	}
	result = Result{OrganizationReference: records.OrganizationReference, MemberReference: records.MemberReference}
	if result.OrganizationID, result.OrganizationCreated, err = store.organization(ctx, transaction, records); err != nil {
		return Result{}, err
	}
	// Default scopes are created once, with the Organization. Afterwards the
	// customer owns its Workspaces and Environments: a later run grants the
	// administrator what exists and never recreates a renamed default.
	if result.OrganizationCreated {
		if result.WorkspaceID, err = store.workspace(ctx, transaction, result.OrganizationID); err != nil {
			return Result{}, err
		}
		if result.Environments, err = store.environments(ctx, transaction, result.OrganizationID, result.WorkspaceID); err != nil {
			return Result{}, err
		}
	} else {
		if result.Environments, err = store.existingEnvironments(ctx, transaction, result.OrganizationID); err != nil {
			return Result{}, err
		}
		result.WorkspaceID = result.Environments[0].WorkspaceID
	}
	if result.PrincipalID, result.AdminCreated, err = store.administrator(ctx, transaction, result.OrganizationID, records); err != nil {
		return Result{}, err
	}
	if err = store.scopes(ctx, transaction, result); err != nil {
		return Result{}, err
	}
	if err = transaction.Commit(ctx); err != nil {
		return Result{}, ErrStore
	}
	return result, nil
}

func (store *PostgresStore) organization(ctx context.Context, transaction pgx.Tx, records Records) (string, bool, error) {
	rows, err := transaction.Query(ctx, findOrganizationSQL, records.OrganizationReference)
	if err != nil {
		return "", false, ErrStore
	}
	existing, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", false, ErrStore
	}
	switch {
	case len(existing) > 1:
		// One provider Organization maps to exactly one product Organization.
		return "", false, ErrConflict
	case len(existing) == 1:
		if records.OrganizationID != "" && records.OrganizationID != existing[0] {
			return "", false, ErrConflict
		}
		var present bool
		if err := transaction.QueryRow(ctx, organizationExistsSQL, existing[0]).Scan(&present); err != nil {
			return "", false, ErrStore
		}
		if !present {
			return "", false, ErrConflict
		}
		return existing[0], false, nil
	}
	id := records.OrganizationID
	if id == "" {
		if id, err = store.newID(); err != nil {
			return "", false, ErrStore
		}
	}
	var taken bool
	if err := transaction.QueryRow(ctx, organizationExistsSQL, id).Scan(&taken); err != nil {
		return "", false, ErrStore
	}
	if taken {
		// The pinned ID already belongs to an Organization that no membership
		// links to this provider Organization.
		return "", false, ErrConflict
	}
	if _, err := transaction.Exec(ctx, insertOrganizationSQL, id, records.Name, records.Domain); err != nil {
		return "", false, ErrStore
	}
	return id, true, nil
}

func (store *PostgresStore) workspace(ctx context.Context, transaction pgx.Tx, organization string) (string, error) {
	var id string
	err := transaction.QueryRow(ctx, findWorkspaceSQL, organization, DefaultWorkspaceName).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", ErrStore
	}
	if id, err = store.newID(); err != nil {
		return "", ErrStore
	}
	if _, err := transaction.Exec(ctx, insertWorkspaceSQL, id, organization, DefaultWorkspaceName); err != nil {
		return "", ErrStore
	}
	return id, nil
}

func (store *PostgresStore) environments(ctx context.Context, transaction pgx.Tx, organization, workspace string) ([]Environment, error) {
	environments := make([]Environment, 0, len(DefaultEnvironments))
	for _, wanted := range DefaultEnvironments {
		environment := Environment{WorkspaceID: workspace, Name: wanted.Name, Class: wanted.Class}
		err := transaction.QueryRow(ctx, findEnvironmentSQL, organization, workspace, wanted.Name).Scan(&environment.ID, &environment.Class)
		switch {
		case err == nil:
			// An administrator may have reclassified the Environment since;
			// report what is stored instead of overwriting it.
		case errors.Is(err, pgx.ErrNoRows):
			if environment.ID, err = store.newID(); err != nil {
				return nil, ErrStore
			}
			if _, err := transaction.Exec(ctx, insertEnvironmentSQL, environment.ID, organization, workspace, wanted.Name, wanted.Class); err != nil {
				return nil, ErrStore
			}
		default:
			return nil, ErrStore
		}
		if _, err := transaction.Exec(ctx, insertDataControlsSQL, organization, workspace, environment.ID, environment.Class); err != nil {
			return nil, ErrStore
		}
		environments = append(environments, environment)
	}
	return environments, nil
}

func (store *PostgresStore) existingEnvironments(ctx context.Context, transaction pgx.Tx, organization string) ([]Environment, error) {
	rows, err := transaction.Query(ctx, existingEnvironmentsSQL, organization)
	if err != nil {
		return nil, ErrStore
	}
	environments, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Environment, error) {
		var environment Environment
		return environment, row.Scan(&environment.ID, &environment.WorkspaceID, &environment.Name, &environment.Class)
	})
	if err != nil {
		return nil, ErrStore
	}
	if len(environments) == 0 {
		// An Organization without any Environment was not left by bootstrap.
		return nil, ErrConflict
	}
	return environments, nil
}

func (store *PostgresStore) administrator(ctx context.Context, transaction pgx.Tx, organization string, records Records) (string, bool, error) {
	var principal, memberOrganization, role string
	var active bool
	err := transaction.QueryRow(ctx, findMembershipSQL, records.OrganizationReference, records.MemberReference).Scan(&principal, &memberOrganization, &role, &active)
	if err == nil {
		// Never reactivate, move or promote an existing membership: those are
		// identity administration decisions, not bootstrap side effects.
		if memberOrganization != organization || !active || role != AdminRole {
			return "", false, ErrConflict
		}
		return principal, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrStore
	}
	if principal, err = store.newID(); err != nil {
		return "", false, ErrStore
	}
	if _, err := transaction.Exec(ctx, insertMembershipSQL, principal, organization, records.OrganizationReference, records.MemberReference, AdminRole); err != nil {
		return "", false, ErrStore
	}
	return principal, true, nil
}

func (store *PostgresStore) scopes(ctx context.Context, transaction pgx.Tx, result Result) error {
	permissions, err := json.Marshal(AdminPermissions)
	if err != nil {
		return ErrStore
	}
	var hasDefault bool
	if err := transaction.QueryRow(ctx, hasDefaultScopeSQL, result.PrincipalID, result.OrganizationID).Scan(&hasDefault); err != nil {
		return ErrStore
	}
	for index, environment := range result.Environments {
		isDefault := index == 0 && !hasDefault
		if _, err := transaction.Exec(ctx, insertAuthorizedScopeSQL, result.PrincipalID, result.OrganizationID, environment.WorkspaceID, environment.ID, environment.Name, string(permissions), isDefault); err != nil {
			return ErrStore
		}
	}
	return nil
}

const (
	projectionInstalledSQL = `SELECT to_regprocedure('zasp_authorization79.configure(text,text,text,boolean)') IS NOT NULL`
	// The operator owns the projection tables. The projection's own reader
	// function is reserved for registered runtime principals and refuses it.
	projectionBindingSQL         = `SELECT COALESCE(store_id, ''), COALESCE(model_id, '') FROM zasp_authorization79.organizations WHERE organization_id = $1`
	projectionConfigureSQL       = `SELECT zasp_authorization79.configure($1, $2, $3, false)`
	approvalDeliveryAvailableSQL = `SELECT to_regprocedure('zasp_approval_maintenance.activate_projection(text)') IS NOT NULL`
	approvalDeliveryActivateSQL  = `SELECT zasp_approval_maintenance.activate_projection($1)`
)

// BindAuthorization binds the Organization's permission projection to the
// deployment's authorization store and model, which is what lets the projector
// apply its pending revision. A binding that already matches is left alone, so
// a repeated bootstrap does not force a replay.
func (store *PostgresStore) BindAuthorization(ctx context.Context, organization, storeID, modelID string) error {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil || organization == "" || storeID == "" || modelID == "" {
		return ErrInvalid
	}
	var installed bool
	if err := store.database.QueryRow(ctx, projectionInstalledSQL).Scan(&installed); err != nil || !installed {
		return ErrStore
	}
	var boundStore, boundModel string
	err := store.database.QueryRow(ctx, projectionBindingSQL, organization).Scan(&boundStore, &boundModel)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ErrStore
	}
	if err == nil && boundStore == storeID && boundModel == modelID {
		return store.activateApprovalDelivery(ctx, organization)
	}
	if err == nil && (boundStore != "" || boundModel != "") {
		// Moving an Organization to another store or model resets its applied
		// permissions. That is a deliberate repair, not a bootstrap side effect.
		return ErrConflict
	}
	var configured []byte
	if err := store.database.QueryRow(ctx, projectionConfigureSQL, organization, storeID, modelID).Scan(&configured); err != nil {
		return ErrStore
	}
	return store.activateApprovalDelivery(ctx, organization)
}

// activateApprovalDelivery lets the Organization's approval notifications be
// delivered. On a baseline installation delivery is bound to the
// Organization's authorization store and model, so it is activated with the
// binding. Activation is idempotent. An installation without the activation
// function (the historical chain) has no delivery to activate.
func (store *PostgresStore) activateApprovalDelivery(ctx context.Context, organization string) error {
	var available bool
	if err := store.database.QueryRow(ctx, approvalDeliveryAvailableSQL).Scan(&available); err != nil {
		return ErrStore
	}
	if !available {
		return nil
	}
	var activated bool
	if err := store.database.QueryRow(ctx, approvalDeliveryActivateSQL, organization).Scan(&activated); err != nil || !activated {
		return ErrStore
	}
	return nil
}

// BoundProviderOrganization returns the provider Organization an existing
// product Organization is bound to through its memberships, or "" when the
// product Organization has none yet.
func (store *PostgresStore) BoundProviderOrganization(ctx context.Context, organization string) (string, error) {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil || organization == "" {
		return "", ErrInvalid
	}
	transaction, err := store.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", ErrStore
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	rows, err := transaction.Query(ctx, boundProviderSQL, organization)
	if err != nil {
		return "", ErrStore
	}
	references, err := pgx.CollectRows(rows, pgx.RowTo[string])
	switch {
	case err != nil:
		return "", ErrStore
	case len(references) > 1:
		return "", ErrConflict
	case len(references) == 1:
		return references[0], nil
	}
	return "", nil
}

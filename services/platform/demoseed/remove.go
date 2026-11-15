package demoseed

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// ScopeStatus describes one Environment that holds demo data.
type ScopeStatus struct {
	OrganizationID, WorkspaceID, EnvironmentID       string
	OrganizationName, WorkspaceName, EnvironmentName string
	Integrations, Agents, OpenFindings, MCPServers   int
	AttackPaths                                      int
	ForeignIntegrations                              int
	Members                                          int
	LastSeededAt                                     string
}

// Removal is what Remove did to one demo scope.
type Removal struct {
	ScopeStatus
	// DeletedRows counts the deleted rows by table.
	DeletedRows map[string]int64
	// Remaining lists the tables that still hold rows of the Environment
	// because the database refuses to delete them (append-only records).
	Remaining map[string]int64
	// EnvironmentDeleted, WorkspaceDeleted and OrganizationDeleted say which
	// of the dedicated records were deleted.
	EnvironmentDeleted, WorkspaceDeleted, OrganizationDeleted bool
	// Retired is the number of integrations whose inventory was retired.
	Retired int
}

const (
	// A demo scope is an Environment that holds a demo integration. A
	// deleted integration counts: `remove` must still find a scope whose
	// integrations a person deleted in the product.
	demoScopesSQL = `SELECT i.organization_id, i.workspace_id, i.environment_id, COALESCE(o.name,''), COALESCE(w.name,''), COALESCE(e.name,''),
 count(*) FILTER (WHERE i.state <> 'deleted' AND i.configuration->>'` + demodata.Marker + `' = '` + datasetName + `'),
 count(*) FILTER (WHERE i.state <> 'deleted' AND COALESCE(i.configuration->>'` + demodata.Marker + `','') <> '` + datasetName + `'),
 COALESCE(to_char(max(i.updated_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '')
FROM public.zasp_integrations i
LEFT JOIN public.zasp_organizations o ON o.id = i.organization_id
LEFT JOIN public.zasp_workspaces w ON (w.organization_id, w.id) = (i.organization_id, i.workspace_id)
LEFT JOIN public.zasp_environments e ON (e.organization_id, e.workspace_id, e.id) = (i.organization_id, i.workspace_id, i.environment_id)
WHERE (i.organization_id, i.workspace_id, i.environment_id) IN (SELECT organization_id, workspace_id, environment_id FROM public.zasp_integrations WHERE configuration->>'` + demodata.Marker + `' = '` + datasetName + `')
  AND ($1 = '' OR i.organization_id = $1)
GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY 1, 2, 3`
	scopeMembersSQL = `SELECT count(*) FROM public.zasp_authorized_scopes WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3)`
	// The tables that hold rows of an Environment: every product table with
	// the three scope columns.
	scopedTablesSQL = `SELECT c.table_name FROM information_schema.columns c
JOIN information_schema.tables t ON (t.table_schema, t.table_name) = (c.table_schema, c.table_name) AND t.table_type = 'BASE TABLE'
WHERE c.table_schema = 'public' AND c.column_name IN ('organization_id', 'workspace_id', 'environment_id')
GROUP BY c.table_name HAVING count(*) = 3 ORDER BY c.table_name`
	otherEnvironmentsSQL      = `SELECT count(*) FROM public.zasp_environments WHERE organization_id = $1 AND workspace_id = $2`
	otherWorkspacesSQL        = `SELECT count(*) FROM public.zasp_workspaces WHERE organization_id = $1`
	deleteEnvironmentSQL      = `DELETE FROM public.zasp_environments WHERE (organization_id, workspace_id, id) = ($1, $2, $3)`
	deleteWorkspaceSQL        = `DELETE FROM public.zasp_workspaces WHERE (organization_id, id) = ($1, $2)`
	deleteMembershipsSQL      = `DELETE FROM public.zasp_identity_memberships WHERE organization_id = $1`
	deleteOrganizationSQL     = `DELETE FROM public.zasp_organizations WHERE id = $1`
	activeDemoIntegrationsSQL = `SELECT id, kind FROM public.zasp_integrations WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3) AND state <> 'deleted' ORDER BY id`
)

// Status lists the demo scopes of the deployment, optionally of one
// Organization.
func (seeder *Seeder) Status(ctx context.Context, organization string) ([]ScopeStatus, error) {
	rows, err := seeder.database.Query(ctx, demoScopesSQL, organization)
	if err != nil {
		return nil, err
	}
	scopes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ScopeStatus, error) {
		var status ScopeStatus
		return status, row.Scan(&status.OrganizationID, &status.WorkspaceID, &status.EnvironmentID, &status.OrganizationName, &status.WorkspaceName, &status.EnvironmentName, &status.Integrations, &status.ForeignIntegrations, &status.LastSeededAt)
	})
	if err != nil {
		return nil, err
	}
	for index := range scopes {
		status := &scopes[index]
		if err := seeder.database.QueryRow(ctx, countsSQL, status.OrganizationID, status.WorkspaceID, status.EnvironmentID).Scan(&status.Agents, &status.OpenFindings, &status.MCPServers, &status.AttackPaths); err != nil {
			return nil, err
		}
		if err := seeder.database.QueryRow(ctx, scopeMembersSQL, status.OrganizationID, status.WorkspaceID, status.EnvironmentID).Scan(&status.Members); err != nil {
			return nil, err
		}
		if err := seeder.database.QueryRow(ctx, foreignIntegrationsSQL, status.OrganizationID, status.WorkspaceID, status.EnvironmentID).Scan(&status.ForeignIntegrations); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

// Remove deletes the demo scopes of the deployment, optionally of one
// Organization.
//
// The product has no operation that deletes an Environment or its
// inventory, so this is not one: the seeder deletes, as the operator, every
// row that carries the demo Environment's three scope IDs, and then the
// Environment itself, its Workspace when that is left empty, and the
// dedicated Organization when that is left empty. Every statement names the
// one Environment. An Environment that holds an integration without the
// demo marker is refused, and nothing in it is touched.
//
// Records the database keeps append-only stay; Remaining lists them. The
// identity provider's Organization and member are not deleted either.
func (seeder *Seeder) Remove(ctx context.Context, organization string) ([]Removal, error) {
	scopes, err := seeder.Status(ctx, organization)
	if err != nil {
		return nil, err
	}
	for _, status := range scopes {
		if status.ForeignIntegrations > 0 {
			return nil, fmt.Errorf("%w: environment %s (%s) holds %d integration(s) that are not demo integrations; nothing was removed", ErrNotDemo, status.EnvironmentID, status.EnvironmentName, status.ForeignIntegrations)
		}
	}
	removals := make([]Removal, 0, len(scopes))
	for _, status := range scopes {
		removal, err := seeder.removeScope(ctx, status)
		if err != nil {
			return removals, fmt.Errorf("environment %s: %w", status.EnvironmentID, err)
		}
		removals = append(removals, removal)
	}
	return removals, nil
}

func (seeder *Seeder) removeScope(ctx context.Context, status ScopeStatus) (Removal, error) {
	removal := Removal{ScopeStatus: status, DeletedRows: map[string]int64{}, Remaining: map[string]int64{}}
	o, w, e := status.OrganizationID, status.WorkspaceID, status.EnvironmentID
	tx, err := seeder.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return removal, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, scopeLockSQL, o); err != nil {
		return removal, err
	}
	// Decided again inside the transaction, under the lock a seeding takes.
	var foreign int
	if err := tx.QueryRow(ctx, foreignIntegrationsSQL, o, w, e).Scan(&foreign); err != nil {
		return removal, err
	}
	if foreign > 0 {
		return removal, ErrNotDemo
	}
	// First the inventory is retired the way the pipeline retires what a
	// provider no longer reports: every demo integration receives an empty
	// snapshot. The entity rows themselves and their identity bindings
	// belong to a role the operator cannot act as, so they cannot be
	// deleted; retired, they are inactive rows of an Environment that no
	// longer exists.
	scope, err := parseScope(o, w, e)
	if err != nil {
		return removal, err
	}
	integrations, err := tx.Query(ctx, activeDemoIntegrationsSQL, o, w, e)
	if err != nil {
		return removal, err
	}
	type demoIntegration struct{ id, provider string }
	active, err := pgx.CollectRows(integrations, func(row pgx.CollectableRow) (demoIntegration, error) {
		var integration demoIntegration
		return integration, row.Scan(&integration.id, &integration.provider)
	})
	if err != nil {
		return removal, err
	}
	observed := seeder.now().Truncate(time.Second)
	for _, integration := range active {
		id, err := domain.ParseProductID(integration.id)
		if err != nil {
			return removal, err
		}
		empty := demodata.Snapshot{Provider: integration.provider, ManifestReference: "s3://" + demodata.EvidenceBucket + "/demo/removed/" + integration.id + ".json", ManifestChecksum: sha256.Sum256([]byte("[]")),
			CursorValue: "demo:removed", Entities: []byte("[]"), Relationships: []byte("[]"), Evidence: []byte("[]")}
		if _, _, err := applySnapshot(ctx, tx, scope, id, integration.id, observed, empty); err != nil {
			return removal, fmt.Errorf("retire the inventory of integration %s: %w", integration.id, err)
		}
		removal.Retired++
	}
	rows, err := tx.Query(ctx, scopedTablesSQL)
	if err != nil {
		return removal, err
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return removal, err
	}
	// attempt runs one statement inside a savepoint, so that a refusal
	// (a foreign key that a later pass clears, an append-only table) does
	// not end the transaction.
	attempt := func(statement string, arguments ...any) (int64, error) {
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return 0, err
		}
		tag, err := savepoint.Exec(ctx, statement, arguments...)
		if err != nil {
			_ = savepoint.Rollback(ctx)
			return 0, err
		}
		return tag.RowsAffected(), savepoint.Commit(ctx)
	}
	// Rows reference each other, so the tables are swept until a sweep
	// deletes nothing.
	for pass := 0; pass < 12; pass++ {
		progress := false
		for _, table := range tables {
			deleted, err := attempt(`DELETE FROM public.`+pgx.Identifier{table}.Sanitize()+` WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3)`, o, w, e)
			if err == nil && deleted > 0 {
				removal.DeletedRows[table] += deleted
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	for _, table := range tables {
		// A table the operator may not read is counted as unknown (-1).
		// The seeder writes to none of those.
		remaining := int64(-1)
		if savepoint, err := tx.Begin(ctx); err != nil {
			return removal, err
		} else if savepoint.QueryRow(ctx, `SELECT count(*) FROM public.`+pgx.Identifier{table}.Sanitize()+` WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3)`, o, w, e).Scan(&remaining) != nil {
			remaining = -1
			_ = savepoint.Rollback(ctx)
		} else if err := savepoint.Commit(ctx); err != nil {
			return removal, err
		}
		if remaining != 0 {
			removal.Remaining[table] = remaining
		}
	}
	if deleted, err := attempt(deleteEnvironmentSQL, o, w, e); err == nil && deleted == 1 {
		removal.EnvironmentDeleted = true
	}
	var environments, workspaces int
	if err := tx.QueryRow(ctx, otherEnvironmentsSQL, o, w).Scan(&environments); err != nil {
		return removal, err
	}
	if removal.EnvironmentDeleted && environments == 0 {
		if deleted, err := attempt(deleteWorkspaceSQL, o, w); err == nil && deleted == 1 {
			removal.WorkspaceDeleted = true
		}
	}
	if err := tx.QueryRow(ctx, otherWorkspacesSQL, o).Scan(&workspaces); err != nil {
		return removal, err
	}
	// An Organization left without a Workspace was the dedicated one.
	if removal.WorkspaceDeleted && workspaces == 0 {
		organization, err := tx.Begin(ctx)
		if err != nil {
			return removal, err
		}
		_, membershipErr := organization.Exec(ctx, deleteMembershipsSQL, o)
		var tag pgconn.CommandTag
		var organizationErr error
		if membershipErr == nil {
			tag, organizationErr = organization.Exec(ctx, deleteOrganizationSQL, o)
		}
		if membershipErr != nil || organizationErr != nil || tag.RowsAffected() != 1 {
			_ = organization.Rollback(ctx)
		} else if err := organization.Commit(ctx); err == nil {
			removal.OrganizationDeleted = true
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return removal, err
	}
	return removal, nil
}

// Tables returns the names of a count map, sorted.
func Tables(counts map[string]int64) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

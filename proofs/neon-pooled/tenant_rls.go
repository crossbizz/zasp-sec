package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformcontext "github.com/zasp-ai/zasp-sec/services/platform/tenantcontext"
	platformrls "github.com/zasp-ai/zasp-sec/services/platform/tenantrls"
)

const (
	tenantRLSSchemaPrefix   = "zasp_m145_"
	tenantRLSProofTimeout   = 90 * time.Second
	tenantRLSCleanupTimeout = 15 * time.Second
	tenantRLSSuccessSummary = "Neon tenant isolation passed: tables=8 cross_reads_denied=true cross_writes_denied=true down=true cleanup=true."
)

var (
	errTenantRLSConfiguration = errors.New("tenant RLS configuration rejected")
	errTenantRLSDatabase      = errors.New("tenant RLS database rejected")
	errTenantRLSIsolation     = errors.New("tenant RLS isolation rejected")
	errTenantRLSCleanup       = errors.New("tenant RLS cleanup rejected")
)

type tenantRLSAssets struct {
	schema string
	up     string
	down   string
}

type pgxTenantContextDatabase struct {
	connection *pgx.Conn
}

type pgxTenantContextTransaction struct {
	transaction pgx.Tx
}

func runTenantRLSMain() {
	ctx, cancel := context.WithTimeout(context.Background(), tenantRLSProofTimeout)
	defer cancel()
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		fmt.Fprintln(os.Stderr, "Neon tenant isolation failed: configuration rejected.")
		os.Exit(1)
	}
	summary, err := executeTenantRLSProof(ctx, os.Getenv("DATABASE_URL"), hex.EncodeToString(markerBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Neon tenant isolation failed: %s.\n", tenantRLSFailureCategory(err))
		os.Exit(1)
	}
	fmt.Println(summary)
}

func tenantRLSFailureCategory(err error) string {
	switch {
	case errors.Is(err, errTenantRLSConfiguration):
		return "configuration rejected"
	case errors.Is(err, errTenantRLSIsolation):
		return "isolation rejected"
	case errors.Is(err, errTenantRLSCleanup):
		return "cleanup rejected"
	default:
		return "database rejected"
	}
}

func tenantRLSTables() []platformrls.Table {
	migration := platformrls.Migration()
	return append(migration.CoreTables(), migration.WorkflowTables()...)
}

func renderTenantRLSAssets(schema string) (tenantRLSAssets, error) {
	if !strings.HasPrefix(schema, tenantRLSSchemaPrefix) || !markerPattern.MatchString(strings.TrimPrefix(schema, tenantRLSSchemaPrefix)) {
		return tenantRLSAssets{}, errTenantRLSConfiguration
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	migration := platformrls.Migration()
	up := strings.ReplaceAll(migration.UpSQL(), `"public"`, quoted)
	down := strings.ReplaceAll(migration.DownSQL(), `"public"`, quoted)
	if up == migration.UpSQL() || down == migration.DownSQL() || strings.Contains(up, `"public"`) || strings.Contains(down, `"public"`) {
		return tenantRLSAssets{}, errTenantRLSConfiguration
	}
	return tenantRLSAssets{schema: schema, up: up, down: down}, nil
}

func executeTenantRLSProof(ctx context.Context, rawURL, marker string) (summary string, resultErr error) {
	if ctx == nil || ctx.Err() != nil || !markerPattern.MatchString(marker) {
		return "", errTenantRLSConfiguration
	}
	assets, err := renderTenantRLSAssets(tenantRLSSchemaPrefix + marker)
	if err != nil {
		return "", errTenantRLSConfiguration
	}
	target, err := validatedPGXConnection(rawURL)
	if err != nil || validateEffectivePGXConfig(target.config, target.expected) != nil {
		return "", errTenantRLSConfiguration
	}
	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	connection, err := pgx.ConnectConfig(connectCtx, target.config.Copy())
	connectCancel()
	if err != nil {
		return "", errTenantRLSDatabase
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tenantRLSCleanupTimeout)
		defer cancel()
		if err := connection.Close(closeCtx); err != nil && resultErr == nil {
			summary = ""
			resultErr = errTenantRLSDatabase
		}
	}()

	absent, err := tenantRLSSchemaAbsent(ctx, connection, assets.schema)
	roleAbsent, roleErr := tenantRLSRoleAbsent(ctx, connection, assets.schema)
	if err != nil || !absent || roleErr != nil || !roleAbsent {
		return "", errTenantRLSDatabase
	}
	cleanupArmed := true
	defer func() {
		if !cleanupArmed {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tenantRLSCleanupTimeout)
		defer cancel()
		if err := cleanupTenantRLSResources(cleanupCtx, connection, assets.schema); err != nil {
			summary = ""
			resultErr = errTenantRLSCleanup
		}
	}()

	role := pgx.Identifier{assets.schema}.Sanitize()
	if _, err := connection.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"); err != nil {
		return "", errTenantRLSDatabase
	}
	if _, err := connection.Exec(ctx, "GRANT "+role+" TO CURRENT_USER"); err != nil {
		return "", errTenantRLSDatabase
	}
	if _, err := connection.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{assets.schema}.Sanitize()); err != nil {
		return "", errTenantRLSDatabase
	}
	if err := createTenantRLSFixtures(ctx, connection, assets.schema); err != nil {
		return "", errTenantRLSDatabase
	}
	if _, err := connection.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{assets.schema}.Sanitize()+" TO "+role); err != nil {
		return "", errTenantRLSDatabase
	}
	if _, err := connection.Exec(ctx, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "+pgx.Identifier{assets.schema}.Sanitize()+" TO "+role); err != nil {
		return "", errTenantRLSDatabase
	}
	if _, err := connection.Exec(ctx, assets.up); err != nil {
		return "", errTenantRLSDatabase
	}
	if err := verifyTenantRLSEnabled(ctx, connection, assets.schema); err != nil {
		return "", errTenantRLSIsolation
	}
	if err := verifyTenantRLSIsolation(ctx, connection, assets.schema); err != nil {
		return "", errTenantRLSIsolation
	}
	if _, err := connection.Exec(ctx, assets.down); err != nil {
		return "", errTenantRLSDatabase
	}
	if err := verifyTenantRLSDisabled(ctx, connection, assets.schema); err != nil {
		return "", errTenantRLSIsolation
	}
	if err := cleanupTenantRLSResources(ctx, connection, assets.schema); err != nil {
		return "", errTenantRLSCleanup
	}
	cleanupArmed = false
	return tenantRLSSuccessSummary, nil
}

func tenantRLSSchemaAbsent(ctx context.Context, connection *pgx.Conn, schema string) (bool, error) {
	var absent bool
	err := connection.QueryRow(ctx, "SELECT to_regnamespace($1) IS NULL", schema).Scan(&absent)
	return absent, err
}

func tenantRLSRoleAbsent(ctx context.Context, connection *pgx.Conn, role string) (bool, error) {
	var absent bool
	err := connection.QueryRow(ctx, "SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)", role).Scan(&absent)
	return absent, err
}

func createTenantRLSFixtures(ctx context.Context, connection *pgx.Conn, schema string) error {
	organizationA := "pid_10000000-0000-4000-8000-000000000001"
	organizationB := "pid_20000000-0000-4000-8000-000000000002"
	for _, table := range tenantRLSTables() {
		identifier := pgx.Identifier{schema, table.Name}.Sanitize()
		definition := `("id" text PRIMARY KEY)`
		if table.OrganizationColumn != "id" {
			definition = `("id" text PRIMARY KEY, "organization_id" text NOT NULL)`
		}
		if _, err := connection.Exec(ctx, "CREATE TABLE "+identifier+" "+definition); err != nil {
			return err
		}
		if table.OrganizationColumn == "id" {
			if _, err := connection.Exec(ctx, "INSERT INTO "+identifier+` ("id") VALUES ($1), ($2)`, organizationA, organizationB); err != nil {
				return err
			}
		} else if _, err := connection.Exec(ctx, "INSERT INTO "+identifier+` ("id", "organization_id") VALUES ('row-a', $1), ('row-b', $2)`, organizationA, organizationB); err != nil {
			return err
		}
	}
	return nil
}

func verifyTenantRLSEnabled(ctx context.Context, connection *pgx.Conn, schema string) error {
	var policies int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname = $1 AND policyname = 'zasp_organization_scope'`, schema).Scan(&policies); err != nil || policies != 8 {
		return errTenantRLSIsolation
	}
	var protected int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relrowsecurity AND c.relforcerowsecurity`, schema).Scan(&protected); err != nil || protected != 8 {
		return errTenantRLSIsolation
	}
	return nil
}

func verifyTenantRLSIsolation(ctx context.Context, connection *pgx.Conn, schema string) error {
	runner, err := platformcontext.New(&pgxTenantContextDatabase{connection: connection})
	if err != nil {
		return errTenantRLSDatabase
	}
	scope := tenantRLSFixtureScope()
	err = runner.Within(ctx, scope, func(workCtx context.Context, transaction platformcontext.Transaction) error {
		current, ok := transaction.(*pgxTenantContextTransaction)
		if !ok {
			return errTenantRLSDatabase
		}
		if _, err := current.transaction.Exec(workCtx, "SET LOCAL ROLE "+pgx.Identifier{schema}.Sanitize()); err != nil {
			return errTenantRLSDatabase
		}
		var roleName string
		var bypass bool
		if err := current.transaction.QueryRow(workCtx, `SELECT current_user, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&roleName, &bypass); err != nil || roleName != schema || bypass {
			return errTenantRLSIsolation
		}
		var settingMatches bool
		if err := current.transaction.QueryRow(workCtx, `SELECT current_setting('app.current_organization_id', true) = $1`, scope.OrganizationID().String()).Scan(&settingMatches); err != nil || !settingMatches {
			return errTenantRLSIsolation
		}
		organizationB := "pid_20000000-0000-4000-8000-000000000002"
		for _, table := range tenantRLSTables() {
			identifier := pgx.Identifier{schema, table.Name}.Sanitize()
			column := pgx.Identifier{table.OrganizationColumn}.Sanitize()
			var visible int
			if err := current.transaction.QueryRow(workCtx, "SELECT count(*) FROM "+identifier).Scan(&visible); err != nil || visible != 1 {
				return errTenantRLSIsolation
			}
			var foreign int
			if err := current.transaction.QueryRow(workCtx, "SELECT count(*) FROM "+identifier+" WHERE "+column+" = $1", organizationB).Scan(&foreign); err != nil || foreign != 0 {
				return errTenantRLSIsolation
			}
			tag, err := current.transaction.Exec(workCtx, "UPDATE "+identifier+" SET \"id\" = \"id\" WHERE "+column+" = $1", organizationB)
			if err != nil || tag.RowsAffected() != 0 {
				return errTenantRLSIsolation
			}
		}
		return nil
	})
	return err
}

func tenantRLSFixtureScope() domain.Scope {
	organization, _ := domain.ParseProductID("pid_10000000-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_30000000-0000-4000-8000-000000000003")
	environment, _ := domain.ParseProductID("pid_40000000-0000-4000-8000-000000000004")
	scope, _ := domain.NewScope(organization, workspace, environment)
	return scope
}

func verifyTenantRLSDisabled(ctx context.Context, connection *pgx.Conn, schema string) error {
	var policies int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname = $1`, schema).Scan(&policies); err != nil || policies != 0 {
		return errTenantRLSIsolation
	}
	var protected int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND (c.relrowsecurity OR c.relforcerowsecurity)`, schema).Scan(&protected); err != nil || protected != 0 {
		return errTenantRLSIsolation
	}
	return nil
}

func cleanupTenantRLSResources(ctx context.Context, connection *pgx.Conn, schema string) error {
	if !strings.HasPrefix(schema, tenantRLSSchemaPrefix) || !markerPattern.MatchString(strings.TrimPrefix(schema, tenantRLSSchemaPrefix)) {
		return errTenantRLSCleanup
	}
	if _, err := connection.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		return errTenantRLSCleanup
	}
	if _, err := connection.Exec(ctx, "REVOKE "+pgx.Identifier{schema}.Sanitize()+" FROM CURRENT_USER"); err != nil {
		return errTenantRLSCleanup
	}
	if _, err := connection.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{schema}.Sanitize()); err != nil {
		return errTenantRLSCleanup
	}
	absent, err := tenantRLSSchemaAbsent(ctx, connection, schema)
	roleAbsent, roleErr := tenantRLSRoleAbsent(ctx, connection, schema)
	if err != nil || !absent || roleErr != nil || !roleAbsent {
		return errTenantRLSCleanup
	}
	return nil
}

func (database *pgxTenantContextDatabase) Begin(ctx context.Context) (platformcontext.Transaction, error) {
	transaction, err := database.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &pgxTenantContextTransaction{transaction: transaction}, nil
}

func (transaction *pgxTenantContextTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := transaction.transaction.Exec(ctx, statement, arguments...)
	return err
}

func (transaction *pgxTenantContextTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction *pgxTenantContextTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresDSNEnvironment                 = "ZASP_POSTGRES_DSN"
	migrationTimeoutEnvironment            = "ZASP_MIGRATION_TIMEOUT"
	migrationPrincipalEnvironment          = "ZASP_MIGRATION_DB_PRINCIPAL"
	discoveryAPIPrincipalEnvironment       = "ZASP_DISCOVERY_API_DB_PRINCIPAL"
	discoveryWorkerPrincipalEnvironment    = "ZASP_DISCOVERY_WORKER_DB_PRINCIPAL"
	runtimeIngestPrincipalEnvironment      = "ZASP_RUNTIME_INGEST_DB_PRINCIPAL"
	runtimeWorkerPrincipalEnvironment      = "ZASP_RUNTIME_WORKER_DB_PRINCIPAL"
	outboxWorkerPrincipalEnvironment       = "ZASP_OUTBOX_WORKER_DB_PRINCIPAL"
	runtimeGatewayPrincipalEnvironment     = "ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL"
	discoverySchedulerPrincipalEnvironment = "ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL"
	projectionRiskPrincipalEnvironment     = "ZASP_PROJECTION_RISK_DB_PRINCIPAL"
	projectionGraphPrincipalEnvironment    = "ZASP_PROJECTION_GRAPH_DB_PRINCIPAL"
	projectionSearchPrincipalEnvironment   = "ZASP_PROJECTION_SEARCH_DB_PRINCIPAL"
)

var errInvalidMigrationCommand = errors.New("invalid release migration command")
var errReleasePrincipalRegistration = errors.New("release principal registration failed")
var databasePrincipalPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

type discoveryPrincipalRegistration struct {
	migration, api, discovery, ingest, runtime, outbox, gateway, scheduler, projectionRisk, projectionGraph, projectionSearch string
}

type principalQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type releaseMigrationRunner interface {
	Version(context.Context) (int64, error)
	Up(context.Context) error
	UpCore(context.Context) error
	UpWorkflows(context.Context) error
	UpWorkflowReceipts(context.Context) error
	UpWorkflowReceiptSafety(context.Context) error
	UpWorkflowReceiptProvenance(context.Context) error
	DownWorkflowReceiptProvenance(context.Context) error
	UpProductionAdministration(context.Context) error
	DownProductionAdministration(context.Context) error
	UpAPITokenRevealGrants(context.Context) error
	DownAPITokenRevealGrants(context.Context) error
	UpProductionRiskProjection(context.Context) error
	DownProductionRiskProjection(context.Context) error
	UpProductionDiscovery(context.Context) error
	DownProductionDiscovery(context.Context) error
	UpConnectorAuthorization(context.Context) error
	DownConnectorAuthorization(context.Context) error
	UpReferenceAuthorization(context.Context) error
	DownReferenceAuthorization(context.Context) error
	UpProductionDiscoveryExecution(context.Context) error
	DownProductionDiscoveryExecution(context.Context) error
	UpProductionTypedInventoryCutover(context.Context) error
	DownProductionTypedInventoryCutover(context.Context) error
	DownWorkflowReceiptSafety(context.Context) error
	DownWorkflowReceipts(context.Context) error
	DownWorkflows(context.Context) error
	DownCore(context.Context) error
	Down(context.Context) error
}

func main() {
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	timeout, err := loadMigrationTimeout(os.Getenv)
	if err != nil {
		log.Fatal("release migration configuration rejected")
	}
	ctx, cancel := context.WithTimeout(signalCtx, timeout)
	defer cancel()
	arguments := os.Args[1:]
	var registration discoveryPrincipalRegistration
	if len(arguments) == 1 && arguments[0] == "up" {
		registration, err = loadDiscoveryPrincipalRegistration(os.Getenv)
		if err != nil {
			log.Fatal("release migration configuration rejected")
		}
	}
	dsn := os.Getenv(postgresDSNEnvironment)
	if dsn == "" {
		log.Fatal("release migration configuration rejected")
	}
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatal("release migration database unavailable")
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil || runReleaseMigration(ctx, runner, arguments) != nil {
		log.Fatal("release migration failed")
	}
	if len(arguments) == 1 && arguments[0] == "up" {
		if err := registerReleasePrincipals(ctx, connection, registration); err != nil {
			log.Fatal("release principal registration or readiness failed")
		}
	}
}

func registerReleasePrincipals(ctx context.Context, queryer principalQueryer, registration discoveryPrincipalRegistration) error {
	if ctx == nil || ctx.Err() != nil || queryer == nil {
		return errReleasePrincipalRegistration
	}
	var ready bool
	checks := []struct {
		statement string
		arguments []any
	}{
		{`SELECT session_user=$1`, []any{registration.migration}},
		{`SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, []any{registration.migration, registration.api, registration.discovery, registration.ingest, registration.runtime, registration.outbox, registration.gateway}},
		{`SELECT zasp_execution_register_principals($1,$2,$3,$4,$5,$6)`, []any{registration.migration, registration.scheduler, registration.discovery, registration.projectionRisk, registration.projectionGraph, registration.projectionSearch}},
		{`SELECT zasp_inventory_readiness($1,$2)`, []any{migrations.ProductionTypedInventoryCutover().Checksum(), migrations.ProductionTypedInventoryCutoverSemanticFingerprint()}},
	}
	for _, check := range checks {
		ready = false
		if err := queryer.QueryRow(ctx, check.statement, check.arguments...).Scan(&ready); err != nil || !ready {
			return errReleasePrincipalRegistration
		}
	}
	return nil
}

func loadDiscoveryPrincipalRegistration(getenv func(string) string) (discoveryPrincipalRegistration, error) {
	if getenv == nil {
		return discoveryPrincipalRegistration{}, errInvalidMigrationCommand
	}
	registration := discoveryPrincipalRegistration{
		migration: getenv(migrationPrincipalEnvironment),
		api:       getenv(discoveryAPIPrincipalEnvironment), discovery: getenv(discoveryWorkerPrincipalEnvironment),
		ingest: getenv(runtimeIngestPrincipalEnvironment), runtime: getenv(runtimeWorkerPrincipalEnvironment),
		outbox: getenv(outboxWorkerPrincipalEnvironment), gateway: getenv(runtimeGatewayPrincipalEnvironment),
		scheduler: getenv(discoverySchedulerPrincipalEnvironment), projectionRisk: getenv(projectionRiskPrincipalEnvironment),
		projectionGraph: getenv(projectionGraphPrincipalEnvironment), projectionSearch: getenv(projectionSearchPrincipalEnvironment),
	}
	values := []string{registration.migration, registration.api, registration.discovery, registration.ingest, registration.runtime, registration.outbox, registration.gateway, registration.scheduler, registration.projectionRisk, registration.projectionGraph, registration.projectionSearch}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !databasePrincipalPattern.MatchString(value) {
			return discoveryPrincipalRegistration{}, errInvalidMigrationCommand
		}
		if _, exists := seen[value]; exists {
			return discoveryPrincipalRegistration{}, errInvalidMigrationCommand
		}
		seen[value] = struct{}{}
	}
	return registration, nil
}

func loadMigrationTimeout(getenv func(string) string) (time.Duration, error) {
	if getenv == nil {
		return 0, errInvalidMigrationCommand
	}
	timeout, err := time.ParseDuration(getenv(migrationTimeoutEnvironment))
	if err != nil || timeout <= 0 || timeout > 30*time.Minute {
		return 0, errInvalidMigrationCommand
	}
	return timeout, nil
}

func runReleaseMigration(ctx context.Context, runner releaseMigrationRunner, arguments []string) error {
	if ctx == nil || runner == nil || len(arguments) != 1 {
		return errInvalidMigrationCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	version, err := runner.Version(ctx)
	if err != nil {
		return err
	}
	switch arguments[0] {
	case "up":
		if version == 0 {
			if err := runner.Up(ctx); err != nil {
				return err
			}
			version = 1
		}
		if version == 1 {
			if err := runner.UpCore(ctx); err != nil {
				return err
			}
			version = 2
		}
		if version == 2 {
			if err := runner.UpWorkflows(ctx); err != nil {
				return err
			}
			version = 3
		}
		if version == 3 {
			if err := runner.UpWorkflowReceipts(ctx); err != nil {
				return err
			}
			version = 4
		}
		if version == 4 {
			if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
				return err
			}
			version = 5
		}
		if version == 5 {
			if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
				return err
			}
			version = 6
		}
		if version == 6 {
			if err := runner.UpProductionAdministration(ctx); err != nil {
				return err
			}
			version = 7
		}
		if version == 7 {
			if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
				return err
			}
			version = 8
		}
		if version == 8 {
			if err := runner.UpProductionRiskProjection(ctx); err != nil {
				return err
			}
			version = 9
		}
		if version == 9 {
			if err := runner.UpProductionDiscovery(ctx); err != nil {
				return err
			}
			version = 10
		}
		if version == 10 {
			if err := runner.UpConnectorAuthorization(ctx); err != nil {
				return err
			}
			version = 11
		}
		if version == 11 {
			if err := runner.UpReferenceAuthorization(ctx); err != nil {
				return err
			}
			version = 12
		}
		if version == 12 {
			if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
				return err
			}
			version = 13
		}
		if version == 13 {
			if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
				return err
			}
			version = 14
		}
		if version != 14 {
			return migrations.ErrInvalidState
		}
	case "down":
		if version == 14 {
			if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
				return err
			}
			version = 13
		}
		if version == 13 {
			if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
				return err
			}
			version = 12
		}
		if version == 12 {
			if err := runner.DownReferenceAuthorization(ctx); err != nil {
				return err
			}
			version = 11
		}
		if version == 11 {
			if err := runner.DownConnectorAuthorization(ctx); err != nil {
				return err
			}
			version = 10
		}
		if version == 10 {
			if err := runner.DownProductionDiscovery(ctx); err != nil {
				return err
			}
			version = 9
		}
		if version == 9 {
			if err := runner.DownProductionRiskProjection(ctx); err != nil {
				return err
			}
			version = 8
		}
		if version == 8 {
			if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
				return err
			}
			version = 7
		}
		if version == 7 {
			if err := runner.DownProductionAdministration(ctx); err != nil {
				return err
			}
			version = 6
		}
		if version == 6 {
			if err := runner.DownWorkflowReceiptProvenance(ctx); err != nil {
				return err
			}
			version = 5
		}
		if version == 5 {
			if err := runner.DownWorkflowReceiptSafety(ctx); err != nil {
				return err
			}
			version = 4
		}
		if version == 4 {
			if err := runner.DownWorkflowReceipts(ctx); err != nil {
				return err
			}
			version = 3
		}
		if version == 3 {
			if err := runner.DownWorkflows(ctx); err != nil {
				return err
			}
			version = 2
		}
		if version == 2 {
			if err := runner.DownCore(ctx); err != nil {
				return err
			}
			version = 1
		}
		if version == 1 {
			if err := runner.Down(ctx); err != nil {
				return err
			}
			version = 0
		}
		if version != 0 {
			return migrations.ErrInvalidState
		}
	default:
		return errInvalidMigrationCommand
	}
	actual, err := runner.Version(ctx)
	if err != nil {
		return err
	}
	if actual != version {
		return migrations.ErrInvalidState
	}
	return nil
}

type migrationDatabase struct{ connection *pgx.Conn }

func (database *migrationDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return database.connection.QueryRow(ctx, statement, arguments...)
}

func (database *migrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	transaction, err := database.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &migrationTransaction{transaction: transaction}, nil
}

type migrationTransaction struct{ transaction pgx.Tx }

func (transaction *migrationTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return transaction.transaction.QueryRow(ctx, statement, arguments...)
}

func (transaction *migrationTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := transaction.transaction.Exec(ctx, statement, arguments...)
	return err
}

func (transaction *migrationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction *migrationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

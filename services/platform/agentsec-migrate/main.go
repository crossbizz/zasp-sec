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
	postgresDSNEnvironment              = "ZASP_POSTGRES_DSN"
	migrationTimeoutEnvironment         = "ZASP_MIGRATION_TIMEOUT"
	migrationPrincipalEnvironment       = "ZASP_MIGRATION_DB_PRINCIPAL"
	discoveryAPIPrincipalEnvironment    = "ZASP_DISCOVERY_API_DB_PRINCIPAL"
	discoveryWorkerPrincipalEnvironment = "ZASP_DISCOVERY_WORKER_DB_PRINCIPAL"
	runtimeIngestPrincipalEnvironment   = "ZASP_RUNTIME_INGEST_DB_PRINCIPAL"
	runtimeWorkerPrincipalEnvironment   = "ZASP_RUNTIME_WORKER_DB_PRINCIPAL"
	outboxWorkerPrincipalEnvironment    = "ZASP_OUTBOX_WORKER_DB_PRINCIPAL"
	runtimeGatewayPrincipalEnvironment  = "ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL"
)

var errInvalidMigrationCommand = errors.New("invalid release migration command")
var databasePrincipalPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

type discoveryPrincipalRegistration struct {
	migration, api, discovery, ingest, runtime, outbox, gateway string
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
		var registered bool
		var migrationPrincipalMatches bool
		if err := connection.QueryRow(ctx, `SELECT session_user=$1`, registration.migration).Scan(&migrationPrincipalMatches); err != nil || !migrationPrincipalMatches {
			log.Fatal("release migration principal preflight failed")
		}
		if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, registration.migration, registration.api, registration.discovery, registration.ingest, registration.runtime, registration.outbox, registration.gateway).Scan(&registered); err != nil || !registered {
			log.Fatal("release migration principal registration failed")
		}
	}
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
	}
	values := []string{registration.migration, registration.api, registration.discovery, registration.ingest, registration.runtime, registration.outbox, registration.gateway}
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
		if version != 10 {
			return migrations.ErrInvalidState
		}
	case "down":
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

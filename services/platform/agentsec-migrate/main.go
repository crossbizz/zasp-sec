package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresDSNEnvironment      = "ZASP_POSTGRES_DSN"
	migrationTimeoutEnvironment = "ZASP_MIGRATION_TIMEOUT"
)

var errInvalidMigrationCommand = errors.New("invalid release migration command")

type releaseMigrationRunner interface {
	Version(context.Context) (int64, error)
	Up(context.Context) error
	UpCore(context.Context) error
	UpWorkflows(context.Context) error
	UpWorkflowReceipts(context.Context) error
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
	if err != nil || runReleaseMigration(ctx, runner, os.Args[1:]) != nil {
		log.Fatal("release migration failed")
	}
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
		if version != 4 {
			return migrations.ErrInvalidState
		}
	case "down":
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

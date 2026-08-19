package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresDSNEnvironment = "ZASP_POSTGRES_DSN"

var errInvalidMigrationCommand = errors.New("invalid release migration command")

type releaseMigrationRunner interface {
	Up(context.Context) error
	UpCore(context.Context) error
	DownCore(context.Context) error
	Down(context.Context) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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

func runReleaseMigration(ctx context.Context, runner releaseMigrationRunner, arguments []string) error {
	if ctx == nil || runner == nil || len(arguments) != 1 {
		return errInvalidMigrationCommand
	}
	switch arguments[0] {
	case "up":
		if err := runner.Up(ctx); err != nil {
			return err
		}
		return runner.UpCore(ctx)
	case "down":
		if err := runner.DownCore(ctx); err != nil {
			return err
		}
		return runner.Down(ctx)
	default:
		return errInvalidMigrationCommand
	}
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

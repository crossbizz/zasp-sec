package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPostgresProductionBoundaryRunsMigrationsAndPersistsAcrossRestart(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDatabase := &integrationMigrationDatabase{connection: connection}
	runner, err := migrations.NewRunner(migrationDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(ctx); err != nil {
		t.Fatalf("baseline migration: %v", err)
	}
	if err := runner.UpCore(ctx); err != nil {
		t.Fatalf("core migration: %v", err)
	}

	principal := integrationProductID(t, "pid_10000004-0000-4000-8000-000000000004")
	organization := integrationProductID(t, "pid_10000001-0000-4000-8000-000000000001")
	workspace := integrationProductID(t, "pid_10000002-0000-4000-8000-000000000002")
	environment := integrationProductID(t, "pid_10000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := `{"capabilities":["inventory.read"],"principal":{"id":"pid_10000004-0000-4000-8000-000000000004"}}`
	agents := `{"items":[]}`
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_core_payloads (organization_id, workspace_id, environment_id, operation, payload) VALUES ($1,$2,$3,$4,$5::jsonb),($1,$2,$3,$6,$7::jsonb)`, organization.String(), workspace.String(), environment.String(), "session_bootstrap:"+principal.String(), bootstrap, "agents", agents); err != nil {
		t.Fatal(err)
	}
	const pat = "production-api-token-with-at-least-32-bytes"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_product_api_tokens (token_digest, principal_id, organization_id, workspace_id, environment_id, permissions, expires_at) VALUES (digest($1, 'sha256'),$2,$3,$4,$5,'["view"]'::jsonb,$6)`, pat, principal.String(), organization.String(), workspace.String(), environment.String(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("repository readiness: %v", err)
	}
	grant := SessionGrant{PrincipalID: principal, Scope: scope, Permissions: []string{"view"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	session, err := repository.CreateSession(ctx, grant)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err != nil {
		t.Fatalf("session authenticate: %v", err)
	}
	if identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: pat}); err != nil || identity.CSRFToken != "" {
		t.Fatalf("PAT authenticate = (%#v, %v)", identity, err)
	}
	identity, _ := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session})
	if payload, err := repository.Bootstrap(ctx, identity); err != nil || !equalIntegrationJSON(payload, []byte(bootstrap)) {
		t.Fatalf("bootstrap = (%s, %v)", payload, err)
	}
	if payload, err := repository.Read(ctx, scope, "agents"); err != nil || !equalIntegrationJSON(payload, []byte(agents)) {
		t.Fatalf("read = (%s, %v)", payload, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	restartedConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	restartedDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: restartedConnection})
	restartedRepository, _ := NewPostgresRepository(restartedDatabase)
	if _, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err != nil {
		t.Fatalf("session did not survive repository restart: %v", err)
	}
	if err := restartedRepository.Revoke(ctx, identity, session); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err == nil {
		t.Fatal("revoked session authenticated")
	}
	if err := restartedDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	rollbackConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rollbackConnection.Close(context.Background()) }()
	rollbackRunner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: rollbackConnection})
	if err := rollbackRunner.DownCore(ctx); err != nil {
		t.Fatalf("core rollback: %v", err)
	}
	if err := rollbackRunner.Down(ctx); err != nil {
		t.Fatalf("baseline rollback: %v", err)
	}
	if state, err := rollbackRunner.State(ctx); err != nil || state.Applied() {
		t.Fatalf("rolled back state = (%#v, %v)", state, err)
	}
}

func startDisposablePostgres(t *testing.T) string {
	t.Helper()
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	pgIsReady, readyErr := exec.LookPath("pg_isready")
	pgCtl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		t.Skip("local PostgreSQL binaries unavailable")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data).Run(); err != nil {
		t.Fatalf("initdb: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	var stderr bytes.Buffer
	command := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		stop := exec.Command(pgCtl, "-D", data, "-m", "fast", "-w", "stop")
		if err := stop.Run(); err != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		stopped = true
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if exec.Command(pgIsReady, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "zasp_test", "-d", "postgres").Run() == nil {
			return fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}

func integrationProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func equalIntegrationJSON(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

type integrationPostgresDriver struct{ connection *pgx.Conn }

func (driver *integrationPostgresDriver) QueryRow(ctx context.Context, statement string, arguments ...any) PostgresRow {
	return driver.connection.QueryRow(ctx, statement, arguments...)
}
func (driver *integrationPostgresDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := driver.connection.Exec(ctx, statement, arguments...)
	return err
}
func (driver *integrationPostgresDriver) Close() error {
	return driver.connection.Close(context.Background())
}

type integrationMigrationDatabase struct{ connection *pgx.Conn }

func (database *integrationMigrationDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return database.connection.QueryRow(ctx, statement, arguments...)
}
func (database *integrationMigrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	transaction, err := database.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &integrationMigrationTransaction{transaction: transaction}, nil
}

type integrationMigrationTransaction struct{ transaction pgx.Tx }

func (transaction *integrationMigrationTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return transaction.transaction.QueryRow(ctx, statement, arguments...)
}
func (transaction *integrationMigrationTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := transaction.transaction.Exec(ctx, statement, arguments...)
	return err
}
func (transaction *integrationMigrationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}
func (transaction *integrationMigrationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

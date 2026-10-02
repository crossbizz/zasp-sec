package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type singleRecoveryScalarDriver struct{ connection *pgx.Conn }

func (driver *singleRecoveryScalarDriver) QueryRow(ctx context.Context, statement string, arguments ...any) apiserver.PostgresRow {
	return driver.connection.QueryRow(ctx, statement, arguments...)
}
func (driver *singleRecoveryScalarDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := driver.connection.Exec(ctx, statement, arguments...)
	return err
}
func (driver *singleRecoveryScalarDriver) Close() error {
	return driver.connection.Close(context.Background())
}

func singleRecoveryScalarFunctionSource(t *testing.T, path, name string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	signature := "CREATE FUNCTION zasp_temporal_single_recovery." + name
	start := strings.Index(string(raw), signature)
	if start < 0 {
		t.Fatalf("%s function absent", name)
	}
	end := strings.Index(string(raw[start:]), "$body$;")
	if end < 0 {
		t.Fatalf("%s function terminator absent", name)
	}
	return string(raw[start : start+end+len("$body$;")])
}

func startSingleRecoveryScalarPostgres(t *testing.T) string {
	t.Helper()
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	ready, readyErr := exec.LookPath("pg_isready")
	pgCtl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		t.Skip("local PostgreSQL binaries unavailable")
	}
	data := filepath.Join(t.TempDir(), "data")
	initCtx, cancelInit := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelInit()
	if output, err := exec.CommandContext(initCtx, initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data).CombinedOutput(); err != nil {
		t.Fatalf("initdb: %v %s", err, output)
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
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	join := func() error {
		if joined {
			return nil
		}
		joined = true
		stopCtx, cancelStop := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelStop()
		stop := exec.CommandContext(stopCtx, pgCtl, "-D", data, "-m", "fast", "-w", "stop")
		stopErr := stop.Run()
		if stopErr != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		waitErr := command.Wait()
		if stopErr != nil || waitErr != nil {
			return fmt.Errorf("pg_ctl=%v wait=%v", stopErr, waitErr)
		}
		t.Logf("joined owned PostgreSQL pid=%d", command.Process.Pid)
		return nil
	}
	t.Cleanup(func() {
		if err := join(); err != nil {
			t.Errorf("owned PostgreSQL cleanup failed: %v", err)
		}
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		readyCtx, cancelReady := context.WithTimeout(context.Background(), time.Second)
		err = exec.CommandContext(readyCtx, ready, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "zasp_test", "-d", "postgres").Run()
		cancelReady()
		if err == nil {
			return fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := join(); err != nil {
		t.Fatalf("postgres did not become ready; cleanup=%v", err)
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}

func TestSingleRecoveryScalarQueriesUseJSONAdapter(t *testing.T) {
	dsn := startSingleRecoveryScalarPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned PostgreSQL connection")
	}
	database, err := apiserver.NewPostgresJSONDatabase(&singleRecoveryScalarDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	setup := `
CREATE SCHEMA zasp_temporal_single_recovery;
CREATE TABLE zasp_temporal_single_recovery.commands(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,command_id text NOT NULL,command jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,command_id));
CREATE TABLE zasp_temporal_single_recovery.deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,command_id text NOT NULL,accepted_at timestamptz,last_attempt_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,command_id));
CREATE TABLE zasp_temporal_single_recovery.progress(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,command_id text NOT NULL,status text NOT NULL,reason text NOT NULL,version bigint NOT NULL,updated_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,command_id));
CREATE FUNCTION zasp_temporal_single_recovery.require_worker(text) RETURNS void LANGUAGE sql AS $$SELECT$$;
CREATE FUNCTION zasp_temporal_single_recovery.authenticated(q jsonb) RETURNS zasp_temporal_single_recovery.commands LANGUAGE plpgsql AS $fixture$
DECLARE c zasp_temporal_single_recovery.commands%ROWTYPE;
BEGIN SELECT * INTO STRICT c FROM zasp_temporal_single_recovery.commands WHERE command_id=q->>'command_id';RETURN c;END $fixture$;`
	setup += `CREATE FUNCTION zasp_temporal_single_recovery.checked(q jsonb) RETURNS zasp_temporal_single_recovery.commands LANGUAGE sql AS $$SELECT zasp_temporal_single_recovery.authenticated(q)$$;`
	delivery := "../migrations/sql/0080_temporal_single_recovery.delivery.sql"
	settlement := "../migrations/sql/0080_temporal_single_recovery.settlement.sql"
	setup += singleRecoveryScalarFunctionSource(t, delivery, "attempt(q jsonb)")
	setup += singleRecoveryScalarFunctionSource(t, delivery, "ack(q jsonb)")
	setup += singleRecoveryScalarFunctionSource(t, settlement, "observe(q jsonb,reason_value text)")
	if _, err = connection.Exec(ctx, setup); err != nil {
		t.Fatal("scalar component setup")
	}

	q := workerRecoveryRef()
	arguments := []any{q.Start.Ref.OrganizationID, q.Start.Ref.WorkspaceID, q.Start.Ref.EnvironmentID, q.Start.Ref.RunID, q.CommandID}
	for _, statement := range []string{
		`INSERT INTO zasp_temporal_single_recovery.commands VALUES($1,$2,$3,$4,$5,'{}')`,
		`INSERT INTO zasp_temporal_single_recovery.deliveries VALUES($1,$2,$3,$4,$5,NULL,NULL)`,
		`INSERT INTO zasp_temporal_single_recovery.progress VALUES($1,$2,$3,$4,$5,'pending','cleanup_pending',1,clock_timestamp())`,
	} {
		if _, err = connection.Exec(ctx, statement, arguments...); err != nil {
			t.Fatal("scalar component rows")
		}
	}

	relay := &singleTestRecoveryRelay{database: database}
	if err = relay.Attempt(ctx, q); err != nil {
		t.Fatalf("attempt through production JSON adapter: %v", err)
	}
	if err = relay.Ack(ctx, q); err != nil {
		t.Fatalf("ack through production JSON adapter: %v", err)
	}
	var attempted, accepted time.Time
	if err = connection.QueryRow(ctx, `SELECT last_attempt_at,accepted_at FROM zasp_temporal_single_recovery.deliveries`).Scan(&attempted, &accepted); err != nil || attempted.IsZero() || accepted.IsZero() {
		t.Fatal("attempt or ack state write absent")
	}
	if err = relay.Ack(ctx, q); err != nil {
		t.Fatalf("idempotent ack through production JSON adapter: %v", err)
	}
	var replayed time.Time
	if err = connection.QueryRow(ctx, `SELECT accepted_at FROM zasp_temporal_single_recovery.deliveries`).Scan(&replayed); err != nil || !replayed.Equal(accepted) {
		t.Fatal("ack replay changed acceptance time")
	}
	product := &singleTestRecoveryProduct{database: database}
	if err = product.observe(ctx, q, "dependency_unavailable"); err != nil {
		t.Fatalf("observe through production JSON adapter: %v", err)
	}
	var status, reason string
	var version int64
	if err = connection.QueryRow(ctx, `SELECT status,reason,version FROM zasp_temporal_single_recovery.progress`).Scan(&status, &reason, &version); err != nil || status != "pending" || reason != "dependency_unavailable" || version != 2 {
		t.Fatal("observation state write changed")
	}
}

func TestSingleRecoveryScalarFalseResponsesFailClosed(t *testing.T) {
	q := workerRecoveryRef()
	database := singleDeliveryDatabaseFunc(func(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
		switch statement {
		case singleRecoveryAttemptSQL, singleRecoveryAckSQL, singleRecoveryObserveSQL:
			return json.RawMessage(`false`), nil
		default:
			t.Fatalf("unexpected query %q", statement)
			return nil, nil
		}
	})
	relay := &singleTestRecoveryRelay{database: database}
	if err := relay.Attempt(context.Background(), q); err != orchestration.ErrConflict {
		t.Fatalf("false attempt = %v", err)
	}
	if err := relay.Ack(context.Background(), q); err != orchestration.ErrConflict {
		t.Fatalf("false ack = %v", err)
	}
	product := &singleTestRecoveryProduct{database: database}
	if err := product.observe(context.Background(), q, "dependency_unavailable"); err != orchestration.ErrConflict {
		t.Fatalf("false observe = %v", err)
	}
}

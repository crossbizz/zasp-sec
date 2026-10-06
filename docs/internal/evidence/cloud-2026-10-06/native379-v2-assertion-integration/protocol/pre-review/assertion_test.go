package roleassertion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var socket string

const owner = "protocol_owner"

func TestMain(m *testing.M) { os.Exit(runOwned(m)) }
func runOwned(m *testing.M) (code int) {
	dir, err := os.MkdirTemp("", "zasp-role-assertion-pg-")
	if err != nil {
		return 2
	}
	defer os.RemoveAll(dir)
	data := filepath.Join(dir, "data")
	socket = filepath.Join(dir, "socket")
	if os.Mkdir(socket, 0700) != nil {
		return 2
	}
	bin := "/tmp/zasp-cloud-tools/postgres-18.3/bin/"
	if err = exec.Command(bin+"initdb", "-D", data, "--username="+owner, "--auth=trust", "--no-locale").Run(); err != nil {
		fmt.Fprintln(os.Stderr, "owned initdb failed")
		return 2
	}
	log, err := os.Create(filepath.Join(dir, "postgres.log"))
	if err != nil {
		return 2
	}
	defer log.Close()
	cmd := exec.Command(bin+"postgres", "-D", data, "-k", socket, "-h", "", "-p", "5432")
	cmd.Stdout = log
	cmd.Stderr = log
	if cmd.Start() != nil {
		return 2
	}
	defer func() {
		if exec.Command(bin+"pg_ctl", "-D", data, "-m", "fast", "-w", "stop").Run() != nil {
			fmt.Fprintln(os.Stderr, "owned stop failed")
			code = 2
		}
		if cmd.Wait() != nil {
			fmt.Fprintln(os.Stderr, "owned join failed")
			code = 2
		}
		fmt.Fprintln(os.Stderr, "owned PostgreSQL normal stop and join completed")
	}()
	ready := false
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		if exec.Command(bin+"pg_isready", "-h", socket, "-p", "5432", "-U", owner, "-d", "postgres").Run() == nil {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		return 2
	}
	return m.Run()
}
func connect(t *testing.T) (*pgx.Conn, Expectation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal("config")
	}
	cfg.Host = socket
	cfg.Port = 5432
	cfg.User = owner
	cfg.Database = "postgres"
	cfg.Password = ""
	cfg.TLSConfig = nil
	cfg.Fallbacks = nil
	cfg.RuntimeParams = map[string]string{"search_path": "pg_catalog"}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owned connect")
	}
	t.Cleanup(func() {
		x, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(x)
	})
	var e Expectation
	if c.QueryRow(ctx, "SELECT current_user,session_user,pg_catalog.pg_backend_pid()").Scan(&e.Role, &e.SessionUser, &e.BackendPID) != nil {
		t.Fatal("identity bootstrap")
	}
	return c, e
}
func state(err error) string {
	var p *pgconn.PgError
	if errors.As(err, &p) {
		return p.Code
	}
	return ""
}
func budget() *Budget { return &Budget{LimitBytes: 16384} }
func requireZero(t *testing.T, c *pgx.Conn, e Expectation, place string) {
	t.Helper()
	b := budget()
	r, err := Assert(context.Background(), c, e, place, b)
	if err != nil {
		t.Fatal("zero-row server assertion refused")
	}
	body, _ := json.Marshal(r)
	p, _ := json.Marshal([]any{e.Role, e.SessionUser, e.BackendPID})
	if r.Kind != "server-role-session-assertion-v1" || r.SQLSHA256 != digest([]byte(AssertionSQL)) || r.ParameterSHA256 != digest(p) || r.AssertedRole != e.Role || r.BoundSessionUser != e.SessionUser || r.BoundBackendPID != e.BackendPID || r.Placement != place || r.SQLState != "00000" || r.RowCount != 0 || r.CommandTag != "SELECT 0" || r.TimedOut || b.UsedBytes != len(body) || b.UsedTime <= 0 {
		t.Fatal("receipt or charged bytes/time differs")
	}
}
func TestZeroRowsAndCleanCompletion(t *testing.T) {
	for _, mode := range []string{"BEGIN", "BEGIN READ ONLY"} {
		t.Run(mode, func(t *testing.T) {
			c, e := connect(t)
			if _, err := c.Exec(context.Background(), mode); err != nil {
				t.Fatal("begin")
			}
			requireZero(t, c, e, "before-probe")
			if _, err := c.Exec(context.Background(), "ROLLBACK"); err != nil {
				t.Fatal("rollback")
			}
			requireZero(t, c, e, "after-rollback")
		})
	}
}
func TestWrongAndNullServerExpectations(t *testing.T) {
	for _, kind := range []string{"role", "session", "pid", "null-role", "null-session", "null-pid"} {
		t.Run(kind, func(t *testing.T) {
			c, e := connect(t)
			p := []any{e.Role, e.SessionUser, e.BackendPID}
			switch kind {
			case "role":
				p[0] = "other_role"
			case "session":
				p[1] = "other_session"
			case "pid":
				p[2] = e.BackendPID + 1
			case "null-role":
				p[0] = nil
			case "null-session":
				p[1] = nil
			case "null-pid":
				p[2] = nil
			}
			rows, err := c.Query(context.Background(), AssertionSQL, p...)
			if err == nil {
				for rows.Next() {
				}
				err = rows.Err()
				rows.Close()
			}
			if state(err) != "22012" {
				t.Fatal("mismatch did not produce server error")
			}
			requireZero(t, c, e, "after-mismatch-autocommit")
		})
	}
}
func TestInvalidClientInputsNoReceipt(t *testing.T) {
	c, e := connect(t)
	for _, kind := range []string{"role", "session", "pid"} {
		bad := e
		switch kind {
		case "role":
			bad.Role = ""
		case "session":
			bad.SessionUser = ""
		case "pid":
			bad.BackendPID = 0
		}
		b := budget()
		if r, err := Assert(context.Background(), c, bad, "before-probe", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
			t.Fatal("invalid input got receipt")
		}
	}
}
func TestRestrictedRoleHostilePath(t *testing.T) {
	c, e := connect(t)
	ctx := context.Background()
	for _, q := range []string{"CREATE ROLE protocol_restricted NOLOGIN", "CREATE SCHEMA hostile", "CREATE FUNCTION hostile.pg_backend_pid() RETURNS integer LANGUAGE sql AS 'SELECT -1'", "BEGIN READ ONLY", "SET LOCAL search_path TO hostile,public", "SET LOCAL ROLE protocol_restricted"} {
		if _, err := c.Exec(ctx, q); err != nil {
			t.Fatal("owned hostile setup")
		}
	}
	e.Role = "protocol_restricted"
	requireZero(t, c, e, "restricted-probe")
	if _, err := c.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal("rollback")
	}
	e.Role = owner
	requireZero(t, c, e, "after-role-restoration")
}
func TestPoisonRollbackRecovery(t *testing.T) {
	c, e := connect(t)
	ctx := context.Background()
	if _, err := c.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal("begin")
	}
	requireZero(t, c, e, "before-poison")
	if _, err := c.Exec(ctx, "SELECT 1/0"); state(err) != "22012" {
		t.Fatal("declared poison absent")
	}
	b := budget()
	if r, err := Assert(ctx, c, e, "forbidden-in-poison", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
		t.Fatal("poison minted receipt")
	}
	if _, err := c.Exec(ctx, "SELECT 1"); state(err) != "25P02" {
		t.Fatal("original poison semantics changed")
	}
	if _, err := c.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal("rollback")
	}
	requireZero(t, c, e, "after-recovery")
}
func TestTimeoutCancellationRecovery(t *testing.T) {
	for _, kind := range []string{"statement-timeout", "cancelled-context"} {
		t.Run(kind, func(t *testing.T) {
			c, e := connect(t)
			ctx := context.Background()
			if kind == "statement-timeout" {
				if _, err := c.Exec(ctx, "BEGIN;SET LOCAL statement_timeout='10ms'"); err != nil {
					t.Fatal("timeout setup")
				}
				if _, err := c.Exec(ctx, "SELECT pg_catalog.pg_sleep(0.1)"); state(err) != "57014" {
					t.Fatal("timeout absent")
				}
				b := budget()
				if r, err := Assert(ctx, c, e, "during-timeout-poison", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
					t.Fatal("timeout poison minted receipt")
				}
				if _, err := c.Exec(ctx, "ROLLBACK"); err != nil {
					t.Fatal("timeout rollback")
				}
			} else {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				b := budget()
				if r, err := Assert(cancelled, c, e, "cancelled", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
					t.Fatal("cancel minted receipt")
				}
			}
			requireZero(t, c, e, "after-timeout-or-cancel")
		})
	}
}
func TestReceiptBudgetRefusesWithoutBytes(t *testing.T) {
	c, e := connect(t)
	b := &Budget{LimitBytes: 1}
	if r, err := Assert(context.Background(), c, e, "before-probe", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
		t.Fatal("receipt byte limit bypass")
	}
}

func TestCancelledSessionCannotBorrowFreshIdentity(t *testing.T) {
	c, e := connect(t)
	// Cancel an actual owned server request. A default pgx context cancellation
	// may close this connection; that does not authorize substituting a new PID.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.Exec(ctx, "SELECT pg_catalog.pg_sleep(0.1)"); err == nil || ctx.Err() == nil {
		t.Fatal("owned request cancellation absent")
	}
	b := budget()
	if r, err := Assert(ctx, c, e, "cancelled-request", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
		t.Fatal("cancelled request minted receipt")
	}
	fresh, freshIdentity := connect(t)
	if freshIdentity.BackendPID == e.BackendPID {
		t.Fatal("owned fresh identity unexpectedly reused PID")
	}
	b = budget()
	if r, err := Assert(context.Background(), fresh, e, "old-identity-on-new-connection", b); err == nil || r.Kind != "" || b.UsedBytes != 0 {
		t.Fatal("fresh connection borrowed old session binding")
	}
	requireZero(t, fresh, freshIdentity, "fresh-explicit-bootstrap")
}

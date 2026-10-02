package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func exerciseConnectorRejectionFailures(t *testing.T, ctx context.Context, owner, api *pgx.Conn, identity RequestIdentity) {
	digest := sha256.Sum256([]byte("connector-rejection-session"))
	command := IntegrationRejection{CredentialDigest: digest[:], Operation: "createIntegration", TargetID: identity.Scope.EnvironmentID().String(), AuditID: "pid_8b000030-0000-4000-8000-000000000030", CorrelationID: "pid_8b000031-0000-4000-8000-000000000031"}
	for _, mode := range []string{"missing_driver", "closed", "commit_failure", "rollback_error", "panic_after_INSERT", "canceled_after_INSERT", "forged_principal", "wrong_credential_kind", "wrong_scope", "unregistered"} {
		t.Run(mode, func(t *testing.T) {
			cfg := api.Config().Copy()
			if mode == "unregistered" {
				if _, err := owner.Exec(ctx, `CREATE ROLE connector_unregistered LOGIN INHERIT`); err != nil {
					t.Fatal(err)
				}
				cfg.User = "connector_unregistered"
			}
			connection, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close(context.Background())
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			driver := &connectorRejectionFaultDriver{connectorRejectionPGDriver: connectorRejectionPGDriver{&integrationPostgresDriver{connection: connection}}, mode: mode, cancel: cancel}
			var sqlDriver PostgresDriver = driver
			if mode == "missing_driver" {
				sqlDriver = &integrationPostgresDriver{connection: connection}
			}
			db, err := NewPostgresJSONDatabase(sqlDriver)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "closed" {
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			candidate := identity
			if mode == "forged_principal" {
				candidate.PrincipalID = integrationProductID(t, "pid_6a000099-0000-4000-8000-000000000099")
			}
			if mode == "wrong_credential_kind" {
				candidate.CredentialKind = CredentialBearerToken
			}
			if mode == "wrong_scope" {
				candidate.Scope, err = domain.NewScope(integrationProductID(t, "pid_9a000001-0000-4000-8000-000000000001"), integrationProductID(t, "pid_9a000002-0000-4000-8000-000000000002"), integrationProductID(t, "pid_9a000003-0000-4000-8000-000000000003"))
				if err != nil {
					t.Fatal(err)
				}
			}
			input := command
			if mode == "wrong_scope" {
				input.TargetID = candidate.Scope.EnvironmentID().String()
			}
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				err = db.AuditIntegrationRejection(call, candidate, input)
			}()
			if mode == "panic_after_INSERT" {
				if !panicked {
					t.Fatal("fault did not reach real INSERT")
				}
			} else if err == nil || panicked {
				t.Fatalf("expected safe error mode=%s err=%v panic=%t", mode, err, panicked)
			}
			var n int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE id=$1`, command.AuditID).Scan(&n); err != nil || n != 0 {
				t.Fatalf("failed transaction retained audit: %d %v", n, err)
			}
		})
	}
	t.Run("actual_production_driver_and_decorator", func(t *testing.T) {
		binary := os.Getenv("ZASP_CONNECTOR_REJECTION_RUNTIME_TEST")
		if binary == "" {
			t.Skip("production runtime binary is supplied by run-focused.sh")
		}
		call, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// ConnString preserves the original parsed owner DSN, not Config.User
		// changed for the registered API connection. Serialize the actual role.
		cfg := api.Config()
		dsn := &url.URL{Scheme: "postgres", User: url.User(cfg.User), Host: "localhost", Path: "/" + cfg.Database}
		dsn.RawQuery = url.Values{"host": {cfg.Host}, "port": {strconv.Itoa(int(cfg.Port))}, "sslmode": {"disable"}}.Encode()
		for _, args := range [][]string{{"-test.list", "^TestConnectorRejectionRuntimePostgres$"}, {"-test.run", "^TestConnectorRejectionRuntimePostgres$", "-test.v", "-test.timeout", "20s"}} {
			process := exec.CommandContext(call, binary, args...)
			process.Env = append(os.Environ(), "ZASP_CONNECTOR_REJECTION_RUNTIME_DSN="+dsn.String())
			process.WaitDelay = 3 * time.Second
			output, err := process.CombinedOutput()
			t.Logf("joined production runtime process: %s", output)
			if err != nil {
				t.Fatalf("production runtime process: %v", err)
			}
		}
	})
}

type connectorRejectionFaultDriver struct {
	connectorRejectionPGDriver
	mode   string
	cancel context.CancelFunc
}

func (d *connectorRejectionFaultDriver) BeginReadCommitted(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.connectorRejectionPGDriver.BeginReadCommitted(ctx)
	if err != nil {
		return nil, err
	}
	return &connectorRejectionFaultTx{Tx: tx, mode: d.mode, cancel: d.cancel}, nil
}

type connectorRejectionFaultTx struct {
	pgx.Tx
	mode   string
	cancel context.CancelFunc
}

func (tx *connectorRejectionFaultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	result, err := tx.Tx.Exec(ctx, sql, args...)
	if err == nil {
		switch tx.mode {
		case "panic_after_INSERT":
			panic("owned fault after real INSERT")
		case "canceled_after_INSERT":
			tx.cancel()
		}
	}
	return result, err
}
func (tx *connectorRejectionFaultTx) Commit(ctx context.Context) error {
	if tx.mode == "commit_failure" || tx.mode == "rollback_error" {
		return errors.New("owned commit fault")
	}
	return tx.Tx.Commit(ctx)
}
func (tx *connectorRejectionFaultTx) Rollback(ctx context.Context) error {
	err := tx.Tx.Rollback(ctx)
	if tx.mode == "rollback_error" {
		return errors.Join(err, errors.New("owned rollback report fault after actual cleanup"))
	}
	return err
}

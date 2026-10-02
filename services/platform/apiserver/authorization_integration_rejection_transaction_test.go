package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type rejectionTransactionDriverFixture struct {
	PostgresDriver
	tx *rejectionTransactionFixture
}

func (d *rejectionTransactionDriverFixture) BeginReadCommitted(context.Context) (pgx.Tx, error) {
	d.tx.steps = append(d.tx.steps, "begin-read-committed")
	return d.tx, nil
}

type rejectionTransactionFixture struct {
	pgx.Tx
	steps  []string
	mode   string
	fences int
	args   []any
}

func (tx *rejectionTransactionFixture) QueryRow(context.Context, string, ...any) pgx.Row {
	tx.steps = append(tx.steps, "isolation")
	return rejectionIsolationRow{serializable: tx.mode == "wrong-isolation"}
}

type rejectionIsolationRow struct{ serializable bool }

func (r rejectionIsolationRow) Scan(dest ...any) error {
	*dest[0].(*string) = "read committed"
	if r.serializable {
		*dest[0].(*string) = "serializable"
	}
	return nil
}

func (tx *rejectionTransactionFixture) Exec(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	stage := ""
	switch q {
	case `SELECT zasp_authorization80.integration_rejection_fence($1::text)`:
		tx.fences++
		stage = "initial-fence"
		if tx.fences == 2 {
			stage = "final-fence"
		}
	case `SELECT zasp_authorization80.integration_rejection($1,$2,$3,$4,$5,$6,$7,$8,$9)`:
		stage = "append"
		tx.args = append([]any(nil), args...)
	default:
		return pgconn.CommandTag{}, errors.New("unscoped SQL submitted")
	}
	tx.steps = append(tx.steps, stage)
	if tx.mode == stage {
		return pgconn.CommandTag{}, errors.New("owned boundary fault")
	}
	if stage == "append" && tx.mode == "panic-after-append" {
		panic("owned append fault")
	}
	return pgconn.CommandTag{}, nil
}
func (tx *rejectionTransactionFixture) Commit(context.Context) error {
	tx.steps = append(tx.steps, "commit")
	if tx.mode == "commit" {
		return errors.New("owned commit fault")
	}
	return nil
}
func (tx *rejectionTransactionFixture) Rollback(context.Context) error {
	tx.steps = append(tx.steps, "rollback")
	return nil
}

// This asserts the application's fixed-command transaction obligations, not
// PostgreSQL mechanics. Real rollback/expiry proof remains in the installed test.
func TestP7IntegrationRejectionTransaction(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		steps []string
	}{
		{"", []string{"begin-read-committed", "isolation", "initial-fence", "append", "final-fence", "commit", "rollback"}},
		{"wrong-isolation", []string{"begin-read-committed", "isolation", "rollback"}},
		{"initial-fence", []string{"begin-read-committed", "isolation", "initial-fence", "rollback"}},
		{"append", []string{"begin-read-committed", "isolation", "initial-fence", "append", "rollback"}},
		{"panic-after-append", []string{"begin-read-committed", "isolation", "initial-fence", "append", "rollback"}},
		{"final-fence", []string{"begin-read-committed", "isolation", "initial-fence", "append", "final-fence", "rollback"}},
		{"commit", []string{"begin-read-committed", "isolation", "initial-fence", "append", "final-fence", "commit", "rollback"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			g := integrationRejectionGrant(t, "createIntegration", CredentialBrowserSession)
			command := IntegrationRejection{CredentialDigest: g.Credential.Digest[:], Operation: g.OperationID, TargetID: g.Identity.Scope.EnvironmentID().String(), AuditID: "pid_78100002-0000-4000-8000-000000000002", CorrelationID: "pid_78100003-0000-4000-8000-000000000003"}
			tx := &rejectionTransactionFixture{mode: tc.mode}
			db, _ := NewPostgresJSONDatabase(&rejectionTransactionDriverFixture{tx: tx})
			db.currentAuthorization = true
			var err error
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				err = db.AuditIntegrationRejection(context.WithValue(context.Background(), requestAuthorizationContextKey{}, g), g.Identity, command)
			}()
			if !reflect.DeepEqual(tx.steps, tc.steps) || (tc.mode == "") != (err == nil && !panicked) || panicked != (tc.mode == "panic-after-append") {
				t.Fatalf("mode=%s steps=%v error=%v panic=%v", tc.mode, tx.steps, err, panicked)
			}
			if tx.args != nil {
				i := g.Identity
				want := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), command.CredentialDigest, command.Operation, command.TargetID, command.AuditID, command.CorrelationID}
				if !reflect.DeepEqual(tx.args, want) {
					t.Fatalf("unsafe append arguments=%v", tx.args)
				}
			}
		})
	}
}

func TestP7IntegrationRejectionNativeErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		code, message string
		want          error
	}{
		{"28000", "integration rejection credential unavailable", ErrRepositoryAuthentication},
		{"42501", "integration rejection authorization denied", ErrRepositoryAuthorization},
		{"P0002", "integration rejection target unavailable", ErrRepositoryNotFound},
		{"40001", "current credential changed; retry from Check", ErrRepositoryConflict},
		{"40001", "authorization target changed", ErrRepositoryConflict},
		{"42501", "authorization fence rejected", ErrRepositoryUnavailable},
		{"28000", "some other credential error", ErrRepositoryUnavailable},
		{"23505", "audit collision", ErrRepositoryUnavailable},
	} {
		if got := currentIntegrationRejectionError(&pgconn.PgError{Code: tc.code, Message: tc.message}); !errors.Is(got, tc.want) {
			t.Errorf("%s/%s=%v want%v", tc.code, tc.message, got, tc.want)
		}
	}
}

package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type authorizationTxFixture struct {
	pgx.Tx
	steps      []string
	fenceError error
}

func (f *authorizationTxFixture) Exec(_ context.Context, statement string, _ ...any) (pgconn.CommandTag, error) {
	f.steps = append(f.steps, "fence")
	return pgconn.CommandTag{}, f.fenceError
}
func (f *authorizationTxFixture) QueryRow(context.Context, string, ...any) pgx.Row {
	f.steps = append(f.steps, "effect")
	return authorizationRowFixture{}
}
func (f *authorizationTxFixture) Commit(context.Context) error {
	f.steps = append(f.steps, "commit")
	return nil
}
func (f *authorizationTxFixture) Rollback(context.Context) error {
	f.steps = append(f.steps, "rollback")
	return nil
}

type authorizationRowFixture struct{}

func (authorizationRowFixture) Scan(values ...any) error {
	*values[0].(*[]byte) = []byte(`{"ok":true}`)
	return nil
}

type authorizationDriverFixture struct {
	tx     *authorizationTxFixture
	direct bool
}

func (f *authorizationDriverFixture) Begin(context.Context) (pgx.Tx, error) {
	f.tx.steps = append(f.tx.steps, "begin")
	return f.tx, nil
}
func (f *authorizationDriverFixture) QueryRow(context.Context, string, ...any) PostgresRow {
	f.direct = true
	return authorizationRowFixture{}
}
func (f *authorizationDriverFixture) Exec(context.Context, string, ...any) error {
	f.direct = true
	return nil
}
func (f *authorizationDriverFixture) Close() error { return nil }

func TestP7AuthorizationTransactionBoundary(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit fenced", true: "abort stale proof"}[deny], func(t *testing.T) {
			tx := &authorizationTxFixture{}
			if deny {
				tx.fenceError = &pgconn.PgError{Code: "40001", Message: "authorization changed"}
			}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			grant := RequestAuthorization{OperationID: "getFinding", Identity: identity, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "session-test", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: identity.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}}
			grant, signErr := attestAuthorization(grant, authorizationFixtureAttestor(t), time.Now())
			if signErr != nil {
				t.Fatal(signErr)
			}
			grant.OperationID = "getHomeSummary"
			grant, signErr = attestAuthorization(grant, authorizationFixtureAttestor(t), time.Now())
			if signErr != nil {
				t.Fatal(signErr)
			}
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
			_, err := db.QueryJSON(ctx, `SELECT zasp_authorization80.home_summary($1,$2,$3)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
			if driver.direct {
				t.Fatal("protected effect bypassed transaction fence")
			}
			if deny {
				if !errors.Is(err, ErrRepositoryConflict) || !reflect.DeepEqual(tx.steps, []string{"begin", "fence", "rollback"}) {
					t.Fatalf("stale proof ran effect: %v %v", tx.steps, err)
				}
			} else if err != nil || !reflect.DeepEqual(tx.steps, []string{"begin", "fence", "effect", "commit", "rollback"}) {
				t.Fatalf("fence/effect not one transaction: %v %v", tx.steps, err)
			}
		})
	}
}

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
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Late grouped transaction qualification, authored after initial RED. This runs
// product transaction orchestration with a driver boundary; it does not execute
// PostgreSQL bodies or establish real Stytch/Device/COMMIT availability.
type associationTransactionFixture struct {
	pgx.Tx
	steps              []string
	raw                []byte
	confirmed, unknown bool
	confirmRaw         string
}

func (x *associationTransactionFixture) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	x.steps = append(x.steps, "fence")
	return pgconn.CommandTag{}, nil
}
func (x *associationTransactionFixture) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	if q == associationConfirmSQL {
		x.steps = append(x.steps, "confirm")
		x.confirmRaw, _ = args[8].(string)
		return associationTransactionRow{confirmed: &x.confirmed}
	}
	x.steps = append(x.steps, "effect")
	return associationTransactionRow{raw: x.raw}
}
func (x *associationTransactionFixture) Commit(context.Context) error {
	x.steps = append(x.steps, "commit")
	if x.unknown {
		return errors.New("commit response lost")
	}
	return nil
}
func (x *associationTransactionFixture) Rollback(context.Context) error {
	x.steps = append(x.steps, "rollback")
	return nil
}

type associationTransactionRow struct {
	raw       []byte
	confirmed *bool
}

func (x associationTransactionRow) Scan(out ...any) error {
	if x.confirmed != nil {
		*out[0].(*bool) = *x.confirmed
	} else {
		*out[0].(*[]byte) = append([]byte(nil), x.raw...)
	}
	return nil
}

type associationTransactionDriver struct {
	tx     *associationTransactionFixture
	direct bool
}

func (x *associationTransactionDriver) Begin(context.Context) (pgx.Tx, error) {
	x.tx.steps = append(x.tx.steps, "begin")
	return x.tx, nil
}
func (x *associationTransactionDriver) QueryRow(context.Context, string, ...any) PostgresRow {
	x.direct = true
	return associationTransactionRow{raw: []byte(`{}`)}
}
func (x *associationTransactionDriver) Exec(context.Context, string, ...any) error {
	x.direct = true
	return nil
}
func (x *associationTransactionDriver) Close() error { return nil }
func TestAgentDeviceAssociationOriginalTransactionConfirmation(t *testing.T) {
	for _, mode := range []string{"confirm_before_commit", "final_fence_refused", "unknown_commit", "wrong_Agent_refused", "PAT_refused"} {
		t.Run(mode, func(t *testing.T) {
			i := associationFlowIdentity(t)
			i.CredentialKind = CredentialBrowserSession
			i.FreshAuthenticated = true
			target := AuthorizationTarget{Scope: i.Scope, Kind: "agent", ID: associationFlowAgentID, Version: 1}
			g := RequestAuthorization{OperationID: "revokeAgentDeviceAssociation", Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "session-association", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}, PathParameters: map[string]string{"id": associationFlowAgentID, "associationId": associationFlowPairID}}
			in := AgentDeviceAssociationMutation{AgentID: associationFlowAgentID, AssociationID: associationFlowPairID, ExpectedVersion: 0, IdempotencyKey: "association-transaction-01", RequestDigest: make([]byte, 32)}
			if mode == "wrong_Agent_refused" {
				g.PathParameters["id"] = associationFlowDeviceID
			}
			if mode == "PAT_refused" {
				g.Identity.CredentialKind = CredentialBearerToken
				g.Credential.Kind = CredentialBearerToken
			}
			signed, e := attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
			if e != nil {
				t.Fatal(e)
			}
			g = signed
			raw := []byte(`{"receipt":{"operation":"revokeAgentDeviceAssociation","association_id":"` + associationFlowPairID + `","challenge_id":null,"version":1,"recorded_state":"revoked","recorded_at":"2026-10-17T12:00:00Z"},"challenge":null,"replayed":false,"new_mutation":true}`)
			tx := &associationTransactionFixture{raw: raw, confirmed: mode != "final_fence_refused", unknown: mode == "unknown_commit"}
			driver := &associationTransactionDriver{tx: tx}
			db, e := NewPostgresJSONDatabase(driver)
			if e != nil {
				t.Fatal(e)
			}
			q, args := associationMutationStatement(i, g.OperationID, in, migrations.AgentDeviceAssociationProfileChecksum())
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			result, e := db.QueryJSON(ctx, q, args...)
			if driver.direct {
				t.Fatal("association escaped original transaction pool")
			}
			if mode == "wrong_Agent_refused" || mode == "PAT_refused" {
				if e == nil || len(tx.steps) != 0 {
					t.Fatal("closed target/PAT refusal reached transaction")
				}
				return
			}
			want := []string{"begin", "fence", "effect", "confirm"}
			if mode != "final_fence_refused" {
				want = append(want, "commit")
			}
			want = append(want, "rollback")
			if !reflect.DeepEqual(tx.steps, want) || tx.confirmRaw != string(raw) {
				t.Fatal("confirmation did not preserve full original wrapper/final statement order", tx.steps)
			}
			if mode == "confirm_before_commit" {
				if e != nil || string(result) != string(raw) {
					t.Fatal("confirmed commit lost result", e)
				}
			} else if e == nil || len(result) != 0 {
				t.Fatal("refused/unknown commit returned ACK")
			}
		})
	}
}

package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type retentionVisibilityTx struct{ optionalBoundaryTx }

func (tx *retentionVisibilityTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	switch query {
	case `SELECT zasp_retention_v1.caller_ready('human-read',$1)`:
		tx.steps = append(tx.steps, "purpose-and-pin")
		return optionalBoundaryRow{ready: tx.ready}
	case `SELECT zasp_retention_v1.visibility($1::jsonb)`:
		tx.steps = append(tx.steps, "visibility")
		return optionalBoundaryRow{payload: tx.payload}
	default:
		return optionalBoundaryRow{err: errors.New("unexpected retention query")}
	}
}

func TestRetentionProductEventReaderKeepsOriginalScopedAuthorization(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	session := "session-console-fixture"
	db := &workflowCallDatabase{response: json.RawMessage(`{"items":[]}`)}
	r := &PostgresRepository{database: db, currentAuthorization: true}
	if err := r.RequireRetentionProfile(migrations.RetentionAuditProfileChecksum()); err != nil {
		t.Fatal(err)
	}
	grant := RequestAuthorization{OperationID: "listSessionEvents", Identity: identity, PathParameters: map[string]string{"id": session}, Allowed: []AuthorizationTarget{{Scope: identity.Scope, Kind: "product_session", ID: session}}}
	ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
	if _, err := r.ReadAdministration(ctx, identity, "listSessionEvents", map[string]string{"id": session, "limit": "1"}); err != nil || db.query != postgresRetainedProductSessionEventPageSQL {
		t.Fatalf("origin-aware read was not selected: %s %v", db.query, err)
	}
	if !authorizationStatementAllowed(grant, db.query, db.args) {
		t.Fatal("exact original permission rejected")
	}
	foreign := append([]any(nil), db.args...)
	foreign[3] = "pid_99000001-0000-4000-8000-000000000002"
	if authorizationStatementAllowed(grant, db.query, foreign) {
		t.Fatal("foreign environment accepted")
	}
	grant.Allowed = nil
	if authorizationStatementAllowed(grant, db.query, db.args) {
		t.Fatal("missing original product-session permission accepted")
	}
	db.query = ""
	if _, err := r.ReadAdministration(context.Background(), identity, "listSessionEvents", map[string]string{"id": session, "limit": "1"}); !errors.Is(err, ErrAuthorizationDenied) || db.query != "" {
		t.Fatal("enabled reader fell back without current proof")
	}
}

type retentionVisibilityDriver struct {
	PostgresDriver
	tx     *retentionVisibilityTx
	begins int
}

func (d *retentionVisibilityDriver) Begin(context.Context) (pgx.Tx, error) {
	d.begins++
	d.tx.steps = append(d.tx.steps, "begin")
	return d.tx, nil
}

// These cases verify application proof/transaction boundaries. Real SQL
// isolation, allowed-session membership and role denial require native evidence.
func TestRetentionVisibilityOriginalProofAndConfirmedCommitBoundary(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	a := "pid_99000001-0000-4000-8000-000000000001"
	b := "pid_99000001-0000-4000-8000-000000000002"
	for _, kind := range []string{"committed", "commit-unknown", "purpose-refused", "fence-refused", "unsigned", "scope-substitution", "unknown-result"} {
		t.Run(kind, func(t *testing.T) {
			tx := &retentionVisibilityTx{optionalBoundaryTx: optionalBoundaryTx{ready: true, payload: []byte(`{"items":[{"event_id":"` + a + `","visible":false},{"event_id":"` + b + `","visible":true}]}`)}}
			if kind == "commit-unknown" {
				tx.commitError = errors.New("commit uncertain")
			}
			if kind == "purpose-refused" {
				tx.ready = false
			}
			if kind == "fence-refused" {
				tx.fenceError = errors.New("current proof revoked")
			}
			if kind == "unknown-result" {
				tx.payload = []byte(`{"items":[{"event_id":"` + a + `","visible":false}]}`)
			}
			driver := &retentionVisibilityDriver{tx: tx}
			db := &PostgresJSONDatabase{driver: driver, currentAuthorization: true}
			r, err := NewRetentionEventVisibility(db, migrations.RetentionAuditProfileChecksum())
			if err != nil {
				t.Fatal(err)
			}
			grant := RequestAuthorization{OperationID: "listSessions", Collection: true, Identity: identity, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "retention-browser-fixture", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: identity.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}}
			grant, err = attestAuthorization(grant, authorizationFixtureAttestor(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unsigned" {
				grant.attestation = nil
			}
			if kind == "scope-substitution" {
				otherEnvironment, _ := domain.ParseProductID(b)
				grant.Identity.Scope, _ = domain.NewScope(identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), otherEnvironment)
			}
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
			got, err := r.VisibleEvents(ctx, identity.Scope, []string{a, b})
			if kind == "committed" {
				if err != nil || !reflect.DeepEqual(got, map[string]bool{a: false, b: true}) || !reflect.DeepEqual(tx.steps, []string{"begin", "read-committed", "fence", "purpose-and-pin", "visibility", "commit", "rollback"}) {
					t.Fatalf("wrong confirmed visibility: %v %v %v", got, err, tx.steps)
				}
			} else if err == nil || got != nil {
				t.Fatal("unverified visibility escaped transaction")
			}
			if (kind == "unsigned" || kind == "scope-substitution") && driver.begins != 0 {
				t.Fatal("missing exact original scope/proof reached database")
			}
			if kind == "unknown-result" && slices.Contains(tx.steps, "commit") {
				t.Fatal("unknown result committed")
			}
		})
	}
}

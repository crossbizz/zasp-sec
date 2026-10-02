package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type postLoginOutputDriver struct {
	PostgresDriver
	tx *postLoginOutputTx
}

func (d *postLoginOutputDriver) Begin(context.Context) (pgx.Tx, error) { return d.tx, nil }

type postLoginOutputTx struct {
	pgx.Tx
	t                  *testing.T
	snapshot           bool
	mutate             func(map[string]any)
	identity           RequestIdentity
	commits, rollbacks int
}

func (tx *postLoginOutputTx) Commit(context.Context) error   { tx.commits++; return nil }
func (tx *postLoginOutputTx) Rollback(context.Context) error { tx.rollbacks++; return nil }
func (tx *postLoginOutputTx) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	tx.t.Helper()
	i := tx.identity
	principal := map[string]any{"id": i.PrincipalID.String(), "organization_id": i.Scope.OrganizationID().String(), "organization_reference": "organization-fixture", "member_reference": "member-fixture", "role": "security_admin", "active": true}
	body := map[string]any{"principal": principal}
	if tx.snapshot {
		if q != `SELECT zasp_authorization80_identity.post_login_snapshot($1::jsonb)` || len(args) != 1 {
			tx.t.Fatal("unexpected snapshot dispatch")
		}
		body["scopes"] = []any{map[string]any{"organization_id": i.Scope.OrganizationID().String(), "workspace_id": i.Scope.WorkspaceID().String(), "environment_id": i.Scope.EnvironmentID().String(), "label": "Current"}}
		body["revision"] = map[string]any{"organization_id": i.Scope.OrganizationID().String(), "desired": float64(1), "applied": float64(1), "generation": float64(1), "store_id": "01K00000000000000000000001", "model_id": "01K00000000000000000000002"}
	} else {
		if q != `SELECT zasp_authorization80_identity.post_login_read($1::jsonb,$2::jsonb,$3,$4)` || len(args) != 4 {
			tx.t.Fatal("unexpected final dispatch")
		}
		if !validProductID(args[2].(string)) {
			tx.t.Fatal("invalid fresh correlation")
		}
		body["correlation_id"] = args[2]
	}
	tx.mutate(body)
	raw, _ := json.Marshal(body)
	return postLoginOutputRow(raw)
}

type postLoginOutputRow []byte

func (r postLoginOutputRow) Scan(dest ...any) error {
	*dest[0].(*[]byte) = append([]byte(nil), r...)
	return nil
}

// A permissive nested decoder or validation after Commit must fail this test.
func TestP7PostLoginStrictOutputTransaction(t *testing.T) {
	mutations := []struct {
		name   string
		change func(map[string]any)
	}{
		{"exact", func(map[string]any) {}},
		{"unknown outer", func(b map[string]any) { b["unexpected"] = true }},
		{"unknown principal", func(b map[string]any) { b["principal"].(map[string]any)["unexpected"] = true }},
		{"missing principal", func(b map[string]any) { delete(b, "principal") }},
		{"null principal", func(b map[string]any) { b["principal"] = nil }},
		{"wrong identity", func(b map[string]any) { b["principal"].(map[string]any)["id"] = testCorrelationID }},
		{"missing role", func(b map[string]any) { delete(b["principal"].(map[string]any), "role") }},
		{"wrong active type", func(b map[string]any) { b["principal"].(map[string]any)["active"] = "true" }},
		{"inactive", func(b map[string]any) { b["principal"].(map[string]any)["active"] = false }},
		{"missing reference", func(b map[string]any) { delete(b["principal"].(map[string]any), "member_reference") }},
	}
	for _, snapshot := range []bool{true, false} {
		cases := append([]struct {
			name   string
			change func(map[string]any)
		}{}, mutations...)
		if snapshot {
			cases = append(cases, struct {
				name   string
				change func(map[string]any)
			}{"exact pending", func(b map[string]any) { b["revision"].(map[string]any)["applied"] = float64(0) }}, struct {
				name   string
				change func(map[string]any)
			}{"exact unconfigured", func(b map[string]any) {
				r := b["revision"].(map[string]any)
				r["applied"] = float64(0)
				r["generation"] = float64(0)
				r["store_id"] = ""
				r["model_id"] = ""
			}})
			cases = append(cases, struct {
				name   string
				change func(map[string]any)
			}{"missing applied", func(b map[string]any) { delete(b["revision"].(map[string]any), "applied") }}, struct {
				name   string
				change func(map[string]any)
			}{"wrong model", func(b map[string]any) { b["revision"].(map[string]any)["model_id"] = "invalid" }})
		} else {
			cases = append(cases, struct {
				name   string
				change func(map[string]any)
			}{"missing correlation", func(b map[string]any) { delete(b, "correlation_id") }}, struct {
				name   string
				change func(map[string]any)
			}{"wrong correlation", func(b map[string]any) { b["correlation_id"] = testCorrelationID }})
		}
		for _, test := range cases {
			label := "final/"
			if snapshot {
				label = "snapshot/"
			}
			t.Run(label+test.name, func(t *testing.T) {
				i := fixtureRequestIdentity(t)
				i.credentialBinding = CredentialBinding{Kind: i.CredentialKind, ID: "fixture-session", Digest: [32]byte{1}}
				i.CSRFToken = strings.Repeat("c", 32)
				tx := &postLoginOutputTx{t: t, snapshot: snapshot, mutate: test.change, identity: i}
				db := &PostgresJSONDatabase{driver: &postLoginOutputDriver{tx: tx}, currentAuthorization: true}
				binding, _ := postLoginBinding(i)
				var err error
				published := false
				if snapshot {
					s, e := readPostLoginSnapshot(context.Background(), db, i, binding)
					err = e
					published = !reflect.DeepEqual(s, postLoginSnapshot{})
				} else {
					r := &PostgresRepository{database: db, currentAuthorization: true}
					ctx := context.WithValue(context.Background(), postLoginContextKey{}, postLoginAuthorization{identity: i, binding: binding, purpose: "getCurrentPrincipal", revision: authorization.Revision{}})
					raw, e := r.postLoginRead(ctx, i, false)
					err = e
					published = len(raw) > 0
				}
				if strings.HasPrefix(test.name, "exact") {
					if err != nil || !published || tx.commits != 1 {
						t.Fatalf("exact result rejected: %v published=%t commits=%d", err, published, tx.commits)
					}
				} else if !errors.Is(err, ErrRepositoryUnavailable) || published || tx.commits != 0 || tx.rollbacks != 1 {
					t.Fatalf("malformed result escaped transaction: err=%v published=%t commits=%d rollbacks=%d", err, published, tx.commits, tx.rollbacks)
				}
			})
		}
	}
}

func TestP7PostLoginPendingOutput(t *testing.T) {
	for _, unconfigured := range []bool{false, true} {
		i := fixtureRequestIdentity(t)
		i.credentialBinding = CredentialBinding{Kind: i.CredentialKind, ID: "fixture-session", Digest: [32]byte{1}}
		tx := &postLoginOutputTx{t: t, snapshot: true, identity: i, mutate: func(b map[string]any) {
			r := b["revision"].(map[string]any)
			r["applied"] = float64(0)
			if unconfigured {
				r["generation"] = float64(0)
				r["store_id"] = ""
				r["model_id"] = ""
			}
		}}
		db := &PostgresJSONDatabase{driver: &postLoginOutputDriver{tx: tx}, currentAuthorization: true}
		a := &OpenFGAAuthorizer{Resolver: &PostgresAuthorizationResolver{database: db}, Reader: authorizationRevisionFixture{}, Checker: authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
			t.Error("pending snapshot reached provider Check")
			return authorization.Decision{}, nil
		}), StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
		g, err := a.preparePostLogin(context.Background(), i, RoutedOperation{OperationID: "bootstrapSession"})
		if !errors.Is(err, authorization.ErrPending) || len(g.capabilities) != 0 || tx.commits != 1 {
			t.Fatalf("pending semantics lost: %v capabilities=%v commits=%d", err, g.capabilities, tx.commits)
		}
	}
}

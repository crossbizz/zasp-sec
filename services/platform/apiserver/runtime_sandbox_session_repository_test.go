package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeSandboxSessionRepositoryPinsCurrentAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, op := range []string{"getSessionEvent", "listSessionEvents"} {
		for _, old := range []bool{false, true} {
			database := &sessionQueryDatabase{responses: []json.RawMessage{json.RawMessage(`true`), json.RawMessage(`{"items":[]}`)}}
			if old {
				database.responses = []json.RawMessage{nil, json.RawMessage(`true`), json.RawMessage(`{"items":[]}`)}
				database.errors = []error{&pgconn.PgError{Code: "42883"}}
			}
			repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, &sessionQueryIndex{})
			if err != nil {
				t.Fatal(err)
			}
			params := map[string]string{"id": runtimeReadSessionID, "limit": "1"}
			if op == "getSessionEvent" {
				params = map[string]string{"id": runtimeReadSessionID, "eventId": runtimeReadSessionID}
			}
			if _, err := repository.ReadAdministration(context.Background(), identity, op, params); err != nil {
				t.Fatal(err)
			}
			count := 2
			if old {
				count = 3
			}
			if len(database.calls) != count {
				t.Fatal("read skipped release authority", database.calls)
			}
			if database.calls[0] != `SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2))` || !reflect.DeepEqual(database.arguments[0], []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()}) {
				t.Fatal("readiness not compiled")
			}
			want := sandboxSessionEventPageSQL
			if op == "getSessionEvent" {
				want = sandboxSessionEventGetSQL
			}
			if old {
				if database.calls[1] != `SELECT to_jsonb(zasp_production_runtime_correlation_routing_readiness($1,$2))` || !reflect.DeepEqual(database.arguments[1], []any{migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()}) {
					t.Fatal("fallback not independently pinned")
				}
				want = postgresRuntimeSessionEventPageSQL
				if op == "getSessionEvent" {
					want = postgresRuntimeSessionEventGetSQL
				}
			}
			if database.calls[count-1] != want || !reflect.DeepEqual(database.arguments[count-1][:4], []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}) {
				t.Fatal("wrong scoped read", database.calls)
			}
		}
	}
}

func TestRuntimeSandboxSessionRepositoryRefusesDowngradeOnAuthorityFailure(t *testing.T) {
	for _, fault := range []struct {
		body string
		err  error
	}{
		{"false", nil}, {"null", nil}, {`{"ready":true}`, nil}, {`true false`, nil}, {`"true"`, nil},
		{"", &pgconn.PgError{Code: "42501"}}, {"", errors.New("network unavailable")},
	} {
		database := &sessionQueryDatabase{responses: []json.RawMessage{json.RawMessage(fault.body)}, errors: []error{fault.err}}
		repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, &sessionQueryIndex{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = repository.ReadAdministration(context.Background(), fixtureRequestIdentity(t), "getSessionEvent", map[string]string{"id": runtimeReadSessionID, "eventId": runtimeReadSessionID})
		if !errors.Is(err, ErrRepositoryUnavailable) || len(database.calls) != 1 {
			t.Fatal("authority failure downgraded", fault, err, database.calls)
		}
	}
	database := &sessionQueryDatabase{responses: []json.RawMessage{json.RawMessage(`true`), nil}, errors: []error{nil, &pgconn.PgError{Code: "42883"}}}
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, &sessionQueryIndex{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.ReadAdministration(context.Background(), fixtureRequestIdentity(t), "getSessionEvent", map[string]string{"id": runtimeReadSessionID, "eventId": runtimeReadSessionID})
	if err == nil || len(database.calls) != 2 {
		t.Fatal("failed new read fell back", err, database.calls)
	}
}

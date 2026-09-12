package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

func TestRuntimeSandboxSearchRepositoryPinsTargetBeforeProvider(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	status := sessionQueryStatusFixture(t)
	for _, name := range []string{"", "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2"} {
		t.Run(name, func(t *testing.T) {
			responses := []json.RawMessage{status, sessionQueryPageFixture(t, status)}
			want := []string{postgresRuntimeSessionQueryStatusSQL, postgresRuntimeSessionQueryHydrateSQL}
			if name == "zasp-runtime-sessions-v2" {
				responses = append([]json.RawMessage{json.RawMessage(`true`)}, responses...)
				want = []string{`SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2))`, sandboxQueryStatusSQL, sandboxQueryHydrateSQL}
			}
			db := &sessionQueryDatabase{responses: responses}
			index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{}}}
			repository, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(db, index, name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repository.ReadAdministration(context.Background(), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(db.calls, want) || index.calls != 1 {
				t.Fatal("query selected wrong checkpoint", db.calls, index.calls)
			}
			if name == "zasp-runtime-sessions-v2" && !reflect.DeepEqual(db.arguments[0], []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()}) {
				t.Fatal("v2 probe not compiled50")
			}
		})
	}
}

func TestRuntimeSandboxSearchRepositoryNeverFallsBack(t *testing.T) {
	for name, failure := range map[string]struct {
		body json.RawMessage
		err  error
	}{
		"missing50": {err: &pgconn.PgError{Code: "42883"}},
		"denied":    {err: &pgconn.PgError{Code: "42501"}},
		"false":     {body: json.RawMessage(`false`)},
		"null":      {body: json.RawMessage(`null`)},
		"string":    {body: json.RawMessage(`"true"`)},
	} {
		t.Run(name, func(t *testing.T) {
			db := &sessionQueryDatabase{responses: []json.RawMessage{failure.body}, errors: []error{failure.err}}
			index := &sessionQueryIndex{}
			repository, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(db, index, "zasp-runtime-sessions-v2")
			if err != nil {
				t.Fatal(err)
			}
			_, err = repository.ReadAdministration(context.Background(), fixtureRequestIdentity(t), "listSessions", map[string]string{"kind": "runtime", "limit": "25"})
			if !errors.Is(err, ErrRepositoryUnavailable) || index.calls != 0 || len(db.calls) != 1 || db.calls[0] != `SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2))` {
				t.Fatal("v2 unavailable authority fell back", db.calls, index.calls, err)
			}
		})
	}
	for _, name := range []string{"*", "zasp-runtime-sessions-v3", " zasp-runtime-sessions-v2"} {
		if repo, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(&sessionQueryDatabase{}, &sessionQueryIndex{}, name); err == nil || repo != nil {
			t.Fatal("unknown query index accepted", name)
		}
	}
}

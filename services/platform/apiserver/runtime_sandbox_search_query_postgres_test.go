package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

const sandboxQueryStatusSQL = `SELECT zasp_runtime_sandbox_query_status($1,$2,$3,$4)`
const sandboxQueryHydrateSQL = `SELECT zasp_runtime_sandbox_query_hydrate($1,$2,$3,$4,$5)`

func TestRuntimeSandboxSearchQueryUsesOnlyTargetProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	completion, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, completion...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET state='indexed',attempt=1,worker_id='v1-worker',lease_digest=digest('v1-search-token','sha256'),indexed_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	api := sandboxSessionAPI(t, ctx, admin)
	identity := fixtureRequestIdentity(t)
	args := []any{completion[0], completion[1], completion[2], identity.PrincipalID.String()}
	if err := api.QueryRow(ctx, postgresRuntimeSessionQueryStatusSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var old RuntimeSessionSearchStatus
	if err := json.Unmarshal(body, &old); err != nil || old.State != "current" {
		t.Fatal("old queue fixture not indexed", string(body), err)
	}
	if err := api.QueryRow(ctx, sandboxQueryStatusSQL, args...).Scan(&body); err != nil {
		t.Fatal("v2 freshness authority unavailable", err)
	}
	status, err := decodeRuntimeSearchStatus(body, time.Now())
	if err != nil || status.State != "catching_up" || status.Pending != 1 || status.LastIndexed != nil {
		t.Fatal("v2 adopted old checkpoint", string(body), err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{"unattributed"}, After: "unattributed"}}
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(database, index, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	result, err := repository.ReadAdministration(ctx, identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"})
	if err != nil {
		t.Fatal("composed v2 query rejected", err)
	}
	var composed struct {
		Search RuntimeSessionSearchStatus `json:"search"`
	}
	if err := json.Unmarshal(result, &composed); err != nil || composed.Search.State != "catching_up" || composed.Search.Pending != 1 || index.calls != 1 {
		t.Fatal("API composition adopted v1 checkpoint", string(result), err)
	}
	if err := api.QueryRow(ctx, sandboxQueryHydrateSQL, append(args, []string{"unattributed"})...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items  []json.RawMessage          `json:"items"`
		Search RuntimeSessionSearchStatus `json:"search"`
	}
	if err := json.Unmarshal(body, &page); err != nil || len(page.Items) != 1 || page.Search.State != "catching_up" || page.Search.Pending != 1 {
		t.Fatal("hydration used wrong target", string(body), err)
	}
	if err := worker.QueryRow(ctx, sandboxQueryStatusSQL, args...).Scan(&body); err == nil {
		t.Fatal("non-API principal obtained query authority")
	} else {
		requireSandboxSQLState(t, err, "42501")
	}
	for _, mutation := range []struct{ sql, want string }{
		{`UPDATE zasp_runtime_sandbox_search_outbox SET state='quarantined'`, "blocked"},
		{`UPDATE zasp_runtime_sandbox_search_outbox SET state='indexed',attempt=1,worker_id='v2-worker',lease_digest=digest('v2-search-token','sha256'),indexed_at=clock_timestamp()`, "current"},
	} {
		if _, err := admin.Exec(ctx, mutation.sql); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, sandboxQueryStatusSQL, args...).Scan(&body); err != nil {
			t.Fatal(err)
		}
		status, err := decodeRuntimeSearchStatus(body, time.Now())
		if err != nil || status.State != mutation.want {
			t.Fatal("wrong v2 state", string(body), err)
		}
	}
	foreign := append([]any(nil), args...)
	foreign[2] = "pid_00000000-0000-4000-8000-000000000099"
	if err := api.QueryRow(ctx, sandboxQueryStatusSQL, foreign...).Scan(&body); err != nil || len(body) != 0 {
		t.Fatal("cross-scope status escaped", string(body), err)
	}
	index.onSearch = func() {
		if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3]); err != nil {
			t.Fatal(err)
		}
	}
	if payload, err := repository.ReadAdministration(ctx, identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"}); !errors.Is(err, ErrRepositoryNotFound) || len(payload) != 0 || index.calls != 2 {
		t.Fatal("membership revoked during provider search still returned candidates", string(payload), err)
	}
	if err := api.QueryRow(ctx, sandboxQueryHydrateSQL, append(args, []string{"unattributed"})...).Scan(&body); err != nil || len(body) != 0 {
		t.Fatal("revoked authority hydrated candidates", string(body), err)
	}
}

func TestRuntimeSandboxSearchQueryRejectsReadinessDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	identity := fixtureRequestIdentity(t)
	api := sandboxSessionAPI(t, ctx, admin)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(database, &sessionQueryIndex{}, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err == nil {
		t.Fatal("v2 API reported ready on49")
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	if err := repository.Ready(ctx); err != nil {
		t.Fatal("v2 API not ready on50", err)
	}
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
	var body json.RawMessage
	if err := api.QueryRow(ctx, sandboxQueryStatusSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if status, err := decodeRuntimeSearchStatus(body, time.Now()); err != nil || status.State != "empty" {
		t.Fatal("empty target invalid", string(body), err)
	}
	for name, mutation := range map[string]string{
		"index":        `DROP INDEX zasp_runtime_sandbox_query_pending_idx`,
		"public grant": `GRANT EXECUTE ON FUNCTION zasp_runtime_sandbox_query_status(text,text,text,text) TO PUBLIC`,
		"API grant":    `REVOKE EXECUTE ON FUNCTION zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[]) FROM zasp_discovery_api`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2)`, migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("query catalog drift accepted", ready, err)
			}
		})
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct {
		sql  string
		args []any
	}{{sandboxQueryStatusSQL, args}, {sandboxQueryHydrateSQL, append(args, []string{})}} {
		err := api.QueryRow(ctx, call.sql, call.args...).Scan(&body)
		requireSandboxSQLState(t, err, "55000")
	}
}

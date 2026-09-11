package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
	"time"
)

func TestRuntimeSessionQueryAuthorityHydrationAndFreshness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"query_coordinator", "query_archive", "query_index", "query_correlation", "query_projection", "query_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'query_coordinator','query_archive','query_index','query_correlation','query_projection','query_gateway')`); err != nil {
		t.Fatal(err)
	}
	connect := func(name string) *pgx.Conn {
		config := admin.Config().Copy()
		config.User = name
		c, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(context.Background()) })
		return c
	}
	api, coordinator := connect("invocation_discovery_api"), connect("query_coordinator")
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, migrations.ProductionRuntimeSessionQuery().UpSQL()); err != nil {
		probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	err = probe.QueryRow(ctx, `SELECT zasp_production_runtime_session_query_live_fingerprint()`).Scan(&fingerprint)
	probe.Rollback(ctx)
	if err != nil || fingerprint != migrations.ProductionRuntimeSessionQuerySemanticFingerprint() {
		t.Fatalf("candidate43 fingerprint=%s error=%v", fingerprint, err)
	}
	if err := runner.UpProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	apiRepository, err := NewPostgresRepository(apiDatabase)
	if err != nil || apiRepository.Ready(ctx) != nil {
		t.Fatal("schema43 prevented production API startup", err)
	}
	future, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(44,'future_release',repeat('0',64))`); err != nil {
		future.Rollback(ctx)
		t.Fatal(err)
	}
	var futureSchema string
	futureErr := future.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint()).Scan(&futureSchema)
	future.Rollback(ctx)
	if futureErr == nil {
		t.Fatal("API accepted unknown schema44")
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	org, workspace, environment, principal := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'query-organization','query-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Runtime query proof','["view","investigate_sessions"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","investigate_sessions"]'`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	read := func(connection *pgx.Conn, organization, actor string, ids []string) (json.RawMessage, error) {
		var out json.RawMessage
		err := connection.QueryRow(ctx, `SELECT zasp_runtime_session_query_hydrate($1,$2,$3,$4,$5)`, organization, workspace, environment, actor, ids).Scan(&out)
		return out, err
	}
	known := "pid_96000007-0000-4000-8000-000000000007"
	decode := func(payload json.RawMessage) ([]json.RawMessage, map[string]any) {
		var page struct {
			Items  []json.RawMessage `json:"items"`
			Search map[string]any    `json:"search"`
		}
		if json.Unmarshal(payload, &page) != nil {
			t.Fatalf("invalid query page %s", payload)
		}
		return page.Items, page.Search
	}
	payload, err := read(api, org, principal, []string{known, "unattributed"})
	if err != nil {
		t.Fatal(err)
	}
	items, status := decode(payload)
	if len(items) != 2 || status["state"] != "catching_up" || status["pending_batches"] != float64(1) || status["pending_batches_capped"] != false || status["quarantined_batches_capped"] != false || status["quarantined_batches"] != float64(0) || status["selector_coverage"] != "observed_only" {
		t.Fatalf("query page=%s", payload)
	}
	var first struct {
		ID        string  `json:"id"`
		Count     int     `json:"event_count"`
		Principal *string `json:"principal_id"`
	}
	if json.Unmarshal(items[0], &first) != nil || first.ID != known || first.Count != 2 || first.Principal != nil {
		t.Fatal("hydration replaced canonical counts/unknown principal")
	}
	if payload, err := read(api, org, principal, []string{}); err != nil {
		t.Fatal(err)
	} else {
		items, status := decode(payload)
		if len(items) != 0 || status["pending_batches"] != float64(1) {
			t.Fatal("empty candidates concealed backlog")
		}
	}
	for _, ids := range [][]string{nil, {known, known}, {"unattributed", known}, {"malformed"}, {"pid_99000001-0000-4000-8000-000000000001"}} {
		if payload, err := read(api, org, principal, ids); err == nil && len(payload) > 0 {
			t.Fatalf("invalid/missing candidates returned page: %v", ids)
		}
	}
	// These rolled-back synthetic fixtures test numeric bounds only. They are
	// not worker, archive, or provider acceptance evidence.
	t.Run("101 candidates hydrate but 102 are rejected", func(t *testing.T) {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		ids := make([]string, 102)
		for i := range ids {
			ids[i] = fmt.Sprintf("pid_98000001-0000-4000-8000-%012d", i+1)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO zasp_runtime_session_summaries SELECT (jsonb_populate_record(NULL::zasp_runtime_session_summaries,to_jsonb(summary)||jsonb_build_object('id',candidate))).* FROM zasp_runtime_session_summaries summary CROSS JOIN unnest($1::text[]) candidate WHERE summary.id=$2`, ids[:101], known); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION invocation_discovery_api`); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		if err := tx.QueryRow(ctx, postgresRuntimeSessionQueryHydrateSQL, org, workspace, environment, principal, ids[:101]).Scan(&result); err != nil {
			t.Fatal(err)
		}
		items, _ := decode(result)
		if len(items) != 101 {
			t.Fatal("maximum valid candidate set was truncated")
		}
		err = tx.QueryRow(ctx, postgresRuntimeSessionQueryHydrateSQL, org, workspace, environment, principal, ids).Scan(&result)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "22023" {
			t.Fatalf("102 candidates not rejected at boundary: %v", err)
		}
	})
	t.Run("1000 and 1001 checkpoints report exact versus capped counters", func(t *testing.T) {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		add := func(first, last int) {
			t.Helper()
			// Reuse the owned completion fixture under new synthetic generations.
			// No constraint or security function is disabled to populate the queue.
			statement := fmt.Sprintf(`DO $fixture$ DECLARE generation bigint; BEGIN FOR generation IN %d..%d LOOP UPDATE zasp_runtime_stage_work SET batch_generation=generation WHERE stage IN('project','complete'); INSERT INTO zasp_runtime_session_projection_receipts SELECT (jsonb_populate_record(NULL::zasp_runtime_session_projection_receipts,to_jsonb(receipt)||jsonb_build_object('batch_generation',generation))).* FROM zasp_runtime_session_projection_receipts receipt WHERE batch_generation=1; END LOOP; END $fixture$`, first, last)
			if _, err := tx.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		check := func(state string, capped bool) {
			t.Helper()
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION invocation_discovery_api`); err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			if err := tx.QueryRow(ctx, postgresRuntimeSessionQueryHydrateSQL, org, workspace, environment, principal, []string{}).Scan(&result); err != nil {
				t.Fatal(err)
			}
			_, status := decode(result)
			key := "pending_batches"
			if state == "blocked" {
				key = "quarantined_batches"
			}
			if status["state"] != state || status[key] != float64(1000) || status[key+"_capped"] != capped {
				t.Fatalf("counter boundary=%s", result)
			}
			if _, err := tx.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
				t.Fatal(err)
			}
		}
		add(2, 1000)
		check("catching_up", false)
		add(1001, 1001)
		check("catching_up", true)
		if _, err := tx.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET state='quarantined' WHERE batch_generation<=1000`); err != nil {
			t.Fatal(err)
		}
		check("blocked", false)
		if _, err := tx.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET state='quarantined' WHERE batch_generation=1001`); err != nil {
			t.Fatal(err)
		}
		check("blocked", true)
	})
	for _, invalid := range []struct {
		conn       *pgx.Conn
		org, actor string
	}{{coordinator, org, principal}, {api, "pid_99000001-0000-4000-8000-000000000001", principal}, {api, org, "pid_99000004-0000-4000-8000-000000000004"}} {
		if payload, err := read(invalid.conn, invalid.org, invalid.actor, []string{}); err == nil && len(payload) > 0 {
			t.Fatal("unauthorized empty query leaked freshness")
		}
	}
	if _, err := api.Exec(ctx, `SELECT * FROM zasp_runtime_session_search_outbox`); err == nil {
		t.Fatal("API gained direct queue access")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET state='quarantined' WHERE state='pending'`); err != nil {
		t.Fatal(err)
	}
	if payload, err := read(api, org, principal, []string{}); err != nil {
		t.Fatal(err)
	} else {
		_, status := decode(payload)
		if status["state"] != "blocked" || status["quarantined_batches"] != float64(1) {
			t.Fatal("quarantine concealed")
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
		t.Fatal(err)
	}
	if payload, err := read(api, org, principal, []string{}); err == nil && len(payload) > 0 {
		t.Fatal("deprovisioned principal retained search status")
	}
	for _, drift := range []string{`GRANT EXECUTE ON FUNCTION zasp_runtime_session_query_hydrate(text,text,text,text,text[]) TO PUBLIC`, `ALTER FUNCTION zasp_runtime_session_query_status(text,text,text,text) SECURITY INVOKER`} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, drift); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		var ready bool
		err = tx.QueryRow(ctx, `SELECT zasp_production_runtime_session_query_readiness($1,$2)`, migrations.ProductionRuntimeSessionQuery().Checksum(), migrations.ProductionRuntimeSessionQuerySemanticFingerprint()).Scan(&ready)
		tx.Rollback(ctx)
		if err == nil && ready {
			t.Fatal("query readiness admitted security drift")
		}
	}
	if err := runner.DownProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_projection_receipts`).Scan(&count); err != nil || count != 1 {
		t.Fatal("query rollback removed evidence")
	}
	if err := runner.UpProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
}

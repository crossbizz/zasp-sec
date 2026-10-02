package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// The source association and test state come from actual registered metadata
// capture. New receipts are produced by Go projection from controlled archived
// inputs; no session event, summary, or authority row is fabricated here.
func TestP7RuntimeProjectionOrganizationSerialization(t *testing.T) {
	runWorkerTest74PlanningFixture(t, "runtime-retained", assertRuntimeProjectionOrganizationSerialization)
}

func assertRuntimeProjectionOrganizationSerialization(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run string) {
	var scope domain.Scope
	var err error
	scope, err = domain.NewScope(mustProductID(t, o), mustProductID(t, w), mustProductID(t, e))
	if err != nil {
		t.Fatal(err)
	}
	var captured bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.runtime_associations a JOIN zasp_authorization80_worker.test_state s USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1 AND s.target_current AND a.body->>'source_session_id'='pid_96000007-0000-4000-8000-000000000007')`, run).Scan(&captured); err != nil || !captured {
		t.Fatal("actual captured runtime state missing", err)
	}
	for _, signature := range []string{
		"zasp_authorization80_runtime.projection_organization_lock(text)",
		"public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)",
		"public.zasp_runtime_finish_stage_v39(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer)",
		"zasp_temporal74.plan(jsonb)", "zasp_temporal74.pricing_lookup(text,text,jsonb)",
		"zasp_temporal74.context(text,text,text,text)", "zasp_temporal74.authorize(text,text,text,text,bigint)",
	} {
		var definition, ownerName, acl string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef(oid),proowner::regrole::text,coalesce(proacl::text,'') FROM pg_proc WHERE oid=$1::regprocedure`, signature).Scan(&definition, &ownerName, &acl); err != nil {
			t.Fatal("projection fixture catalog export", signature, err)
		}
		t.Logf("installed catalog signature=%s owner=%s acl=%s\n%s", signature, ownerName, acl, definition)
	}
	sequence := 91000
	type preparedCase struct {
		name, change string
		public       bool
		arguments    []any
	}
	var prepared []preparedCase
	seen := map[string]bool{}
	var eventIDs, batchIDs []string
	for _, entry := range []struct {
		name             string
		sandbox, precise bool
		public           bool
	}{
		{"current precise", false, true, false},
		{"current sandbox", true, false, false},
		{"current v1", false, false, false},
		{"public historical v1", false, false, true},
	} {
		for _, change := range []string{"unchanged", "lease expires", "coordinator revoked"} {
			sequence += 10
			arguments, projected := seedNamedScopedSessionProjectionCompletion(t, ctx, owner, scope, "pid_89000011-0000-4000-8000-000000000001", entry.sandbox, entry.precise, sequence)
			identities := []string{arguments[3].(string), arguments[12].(string), projected.Items[0].ArchiveReference}
			for _, item := range projected.Items {
				identities = append(identities, item.EventID.String(), item.ID)
				eventIDs = append(eventIDs, item.EventID.String())
			}
			for _, identity := range identities {
				if seen[identity] {
					t.Fatal("named projection fixtures reused an identity", identity)
				}
				seen[identity] = true
			}
			batchIDs = append(batchIDs, arguments[3].(string))
			prepared = append(prepared, preparedCase{entry.name, change, entry.public, arguments})
		}
	}
	var distinct bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=12 AND count(DISTINCT b.sensor_id)=12 AND count(DISTINCT b.sensor_token_id)=12 AND count(DISTINCT t.token_hash)=12 AND count(DISTINCT b.raw_artifact_key)=12 AND count(DISTINCT b.raw_artifact_reference)=12 AND NOT EXISTS(SELECT 1 FROM public.zasp_runtime_session_events WHERE event_id=ANY($2::text[])) FROM public.zasp_runtime_batch_authorities b JOIN public.zasp_sensor_tokens t ON(t.organization_id,t.workspace_id,t.environment_id,t.sensor_id,t.id)=(b.organization_id,b.workspace_id,b.environment_id,b.sensor_id,b.sensor_token_id) WHERE b.batch_id=ANY($1::text[])`, batchIDs, eventIDs).Scan(&distinct); err != nil || !distinct {
		t.Fatal("complete named seed matrix did not preserve unique source identities", err)
	}
	t.Log("all 12 native seed sets and 36 projected event identities prepared before contention")
	assertRuntimeProjectionWriterCatalog(t, ctx, owner, prepared[9].arguments)
	if t.Failed() {
		return
	}
	for _, entry := range prepared {
		t.Run(entry.name+"/"+entry.change, func(t *testing.T) {
			assertRuntimeProjectionOrganizationWait(t, ctx, owner, run, scope, entry.arguments, entry.public, entry.change)
		})
	}
}

// A projected old fingerprint must not hide a changed live writer or wrapper.
// Every mutation is consumed by the still-granted public completion entry.
func assertRuntimeProjectionWriterCatalog(t *testing.T, ctx context.Context, owner *pgx.Conn, args []any) {
	t.Helper()
	const publicWriter = "public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)"
	var original, definition string
	if err := owner.QueryRow(ctx, `SELECT public.zasp_production_runtime_sessions_live_fingerprint(),pg_get_functiondef($1::regprocedure)`, publicWriter).Scan(&original, &definition); err != nil || len(original) != 64 || strings.Trim(original, "0123456789abcdef") != "" {
		t.Fatal("projection catalog positive baseline", err)
	}
	for _, role := range []string{"source77_coordinator", "source77_projection", "zasp_runtime_ingest", "zasp_runtime_archive_worker", "zasp_runtime_index_worker", "zasp_runtime_correlation_worker"} {
		t.Run("organization helper denies direct execution/"+role, func(t *testing.T) {
			var granted bool
			if err := owner.QueryRow(ctx, `SELECT has_function_privilege($1,'zasp_authorization80_runtime.projection_organization_lock(text)','EXECUTE')`, role).Scan(&granted); err != nil || granted {
				t.Fatal("organization helper execution grant", granted, err)
			}
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `SELECT zasp_authorization80_runtime.projection_organization_lock($1)`, args[0])
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("owner-only organization helper directly executable", err)
			}
		})
	}
	for _, mutation := range []struct{ name, sql string }{
		{"organization helper body", `CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.projection_organization_lock(o text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN NULL; END $$`},
		{"organization helper ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_runtime.projection_organization_lock(text) TO zasp_runtime_coordinator`},
		{"public writer body", strings.Replace(definition, "BEGIN", "BEGIN\n PERFORM 1;", 1)},
		{"public writer ACL", "GRANT EXECUTE ON FUNCTION " + publicWriter + " TO PUBLIC"},
		{"projected40 body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.runtime_projected40() RETURNS text LANGUAGE sql AS $$ SELECT 'changed'::text $$`},
		{"projected40 ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_projected40() TO PUBLIC`},
		{"wrapper same fingerprint constant", `CREATE OR REPLACE FUNCTION public.zasp_production_runtime_sessions_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$ SELECT '` + original + `'::text $$`},
		{"wrapper ACL", `GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_sessions_live_fingerprint() TO PUBLIC`},
		{"saved40 definition", `ALTER TABLE zasp_authorization80_worker.predecessor_functions DISABLE TRIGGER immutable; UPDATE zasp_authorization80_worker.predecessor_functions SET definition=definition||E'\n' WHERE to_regprocedure(signature)='public.zasp_production_runtime_sessions_live_fingerprint()'::regprocedure; ALTER TABLE zasp_authorization80_worker.predecessor_functions ENABLE TRIGGER immutable`},
	} {
		t.Run("projection live catalog/"+mutation.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, mutation.sql); err != nil {
				t.Fatal("projection mutation setup", err)
			}
			if mutation.name == "wrapper same fingerprint constant" {
				var forged string
				if err := tx.QueryRow(ctx, `SELECT public.zasp_production_runtime_sessions_live_fingerprint()`).Scan(&forged); err != nil || forged != original {
					t.Fatal("forged wrapper did not retain exact old output", err)
				}
			}
			var workerReady, runtimeReady bool
			if err := tx.QueryRow(ctx, `SELECT coalesce(zasp_authorization80_worker.catalog_ready(),false),coalesce(zasp_authorization80_runtime.current_ready(),false)`).Scan(&workerReady, &runtimeReady); err != nil || workerReady || runtimeReady {
				t.Fatal("projection live drift remained accepted", workerReady, runtimeReady, err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION source77_coordinator`); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, sessionProjectionFinishSQL, args...)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "55000" {
				t.Fatal("registered public projection accepted live catalog drift", err)
			}
		})
	}
}

type runtimeProjectionLockDatabase struct {
	transaction pgx.Tx
	code        string
}

func (database *runtimeProjectionLockDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := database.transaction.QueryRow(ctx, query, args...).Scan(&raw)
	var native *pgconn.PgError
	if errors.As(err, &native) {
		database.code = native.Code
	}
	return raw, err
}

func runtimeProjectionLockRequest(t *testing.T, scope domain.Scope, args []any, expires time.Time) runtimeevent.StageFinishRequest {
	t.Helper()
	var input, result [32]byte
	copy(input[:], args[8].([]byte))
	copy(result[:], args[14].([]byte))
	return runtimeevent.StageFinishRequest{
		Lease:    runtimeevent.StageLease{Scope: scope, BatchID: mustProductID(t, args[3].(string)), Generation: 1, Stage: runtimeevent.RuntimeStageComplete, Attempt: 1, ImplementationVersion: args[9].(string), InputDigest: input, InputReference: strings.Replace(args[12].(string), "/completed.json", "/projected.json", 1), InputVersionID: "projected-v1", LeaseExpiresAt: expires},
		WorkerID: args[5].(string), LeaseToken: args[6].(string), Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: input, ResultReference: args[12].(string), ResultVersionID: args[13].(string), ResultDigest: result, ProjectionReceipt: string(args[17].([]byte)),
	}
}

func assertRuntimeProjectionOrganizationWait(t *testing.T, parent context.Context, owner *pgx.Conn, run string, scope domain.Scope, args []any, public bool, change string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	var expires time.Time
	if change == "lease expires" {
		if _, err := owner.Exec(ctx, `UPDATE public.zasp_runtime_stage_work SET lease_expires_at=clock_timestamp()+interval '6 seconds' WHERE batch_id=$1 AND stage='complete'`, args[3]); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.QueryRow(ctx, `SELECT lease_expires_at FROM public.zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, args[3]).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	request := runtimeProjectionLockRequest(t, scope, args, expires)
	cfg := owner.Config().Copy()
	cfg.User = "source77_coordinator"
	writer, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close(context.Background())
	holder, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(ctx, `SELECT organization_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, args[0]); err != nil {
		t.Fatal(err)
	}
	type result struct {
		err  error
		code string
	}
	done := make(chan result, 1)
	go func() {
		tx, err := writer.Begin(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		database := &runtimeProjectionLockDatabase{transaction: tx}
		if public {
			var first json.RawMessage
			first, err = database.QueryJSON(ctx, sessionProjectionFinishSQL, args...)
			if err == nil && change == "unchanged" {
				replay, replayErr := database.QueryJSON(ctx, sessionProjectionFinishSQL, args...)
				if replayErr != nil || !bytes.Equal(first, replay) {
					err = fmt.Errorf("public projection exact retry changed: %w", replayErr)
				}
			}
		} else {
			var repository *runtimeevent.PostgresProductionPipelineRepository
			repository, err = runtimeevent.NewPostgresCurrentRuntimePipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCoordinator)
			if err == nil {
				var first runtimeevent.StageFinishResult
				first, err = repository.FinishStage(ctx, request)
				if err == nil && first.State != runtimeevent.StageOutcomeSucceeded {
					err = fmt.Errorf("projection did not succeed")
				}
				if err == nil && change == "unchanged" {
					replay, replayErr := repository.FinishStage(ctx, request)
					if replayErr != nil || replay != first {
						err = fmt.Errorf("projection exact retry changed: %w", replayErr)
					}
				}
			}
		}
		if rollbackErr := tx.Rollback(context.Background()); err == nil {
			err = rollbackErr
		}
		done <- result{err: err, code: database.code}
	}()
	joined := false
	defer func() {
		cancel()
		_ = holder.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	deadline := time.Now().Add(12 * time.Second)
	var blocked bool
	for !blocked && time.Now().Before(deadline) {
		select {
		case outcome := <-done:
			joined = true
			t.Fatal("projection crossed organization holder", outcome.err, outcome.code)
		default:
		}
		if err := holder.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, owner.PgConn().PID(), writer.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if !blocked {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !blocked {
		t.Fatal("projection did not reach actual organization wait")
	}
	var touched []string
	if err := holder.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT relation::regclass::text),'{}'::text[]) FROM pg_locks WHERE pid=$1 AND granted AND mode IN('RowShareLock','RowExclusiveLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock') AND relation IN('public.zasp_runtime_stage_work'::regclass,'public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass,'zasp_authorization80_worker.test_state'::regclass)`, writer.PgConn().PID()).Scan(&touched); err != nil {
		t.Fatal(err)
	}
	if len(touched) != 0 {
		t.Error("projection locked stage/event/summary/state before organization", touched)
	}
	var binding json.RawMessage
	if change == "coordinator revoked" {
		if err := holder.QueryRow(ctx, `DELETE FROM public.zasp_runtime_principal_bindings WHERE principal_name='source77_coordinator' RETURNING to_jsonb(zasp_runtime_principal_bindings)`).Scan(&binding); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := owner.Exec(parent, `INSERT INTO public.zasp_runtime_principal_bindings SELECT (jsonb_populate_record(NULL::public.zasp_runtime_principal_bindings,$1::jsonb)).*`, binding); err != nil {
				t.Error("restore exact fixture login binding", err)
			}
		}()
	}
	if change == "lease expires" {
		for time.Now().Before(expires.Add(50 * time.Millisecond)) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	outcome := <-done
	joined = true
	if change == "unchanged" {
		if outcome.err != nil {
			t.Error("projection/retry after organization release", outcome.err, outcome.code)
		}
	} else if outcome.err == nil || outcome.code != "P0002" && outcome.code != "42501" && outcome.code != "22023" && outcome.code != "55000" {
		t.Error("projection admitted expired/revoked authority after wait", outcome.err, outcome.code)
	}
	var unchanged bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state WHERE run_id=$1 AND target_current) AND EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work WHERE batch_id=$2 AND stage='complete' AND state='leased')`, run, args[3]).Scan(&unchanged); err != nil || !unchanged {
		t.Error("rollback changed captured state or stage", err)
	}
}

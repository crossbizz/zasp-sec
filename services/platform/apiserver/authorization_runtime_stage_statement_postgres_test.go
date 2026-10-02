package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// A final statement gate must cover zero rows and direct writes as well as the
// five-stage producer. In particular, an FK wait cannot preserve earlier trust.
func assertCurrentRuntimeStageStatement(t *testing.T, ctx context.Context, owner *pgx.Conn, principal string, credential *sensor.TokenCredential, o, w, e string) {
	t.Helper()
	const emptyInsert = `INSERT INTO public.zasp_runtime_stage_work SELECT * FROM public.zasp_runtime_stage_work WHERE false`
	t.Run("statement trigger independent catalog", func(t *testing.T) {
		for _, mutation := range []string{
			`ALTER TABLE public.zasp_runtime_stage_work DISABLE TRIGGER zasp_authorization80_runtime_stage_insert`,
			`CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.stage_insert_statement_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN RETURN NULL;END $$`,
			`GRANT EXECUTE ON FUNCTION zasp_authorization80_runtime.stage_insert_statement_guard() TO zasp_runtime_ingest`,
		} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, mutation); err != nil {
					t.Fatal("statement fence not installed", err)
				}
				var module, worker, current bool
				if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_runtime.catalog_ready(),zasp_authorization80_worker.catalog_ready(),zasp_authorization80_runtime.current_ready()`).Scan(&module, &worker, &current); err != nil || module || worker || current {
					t.Fatal("changed statement fence retained authority", module, worker, current, err)
				}
			}()
		}
	})
	for name, mutation := range map[string]string{
		"zero rows after body drift":  `CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.require_current() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN NULL;END $$`,
		"accidental direct DML grant": `GRANT SELECT,INSERT ON public.zasp_runtime_stage_work TO zasp_runtime_ingest`,
		"public DML grant":            `GRANT SELECT,INSERT ON public.zasp_runtime_stage_work TO PUBLIC`,
		"column INSERT grant":         `GRANT INSERT(organization_id) ON public.zasp_runtime_stage_work TO zasp_runtime_ingest`,
		"forced RLS drift":            `ALTER TABLE public.zasp_runtime_stage_work NO FORCE ROW LEVEL SECURITY`,
		"policy drift":                `ALTER POLICY zasp_runtime_stage_work_authority ON public.zasp_runtime_stage_work USING(false)`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			if name == "accidental direct DML grant" || name == "public DML grant" || name == "column INSERT grant" {
				if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{principal}.Sanitize()); err != nil {
					t.Fatal(err)
				}
			}
			statement := emptyInsert
			if name == "column INSERT grant" {
				statement = `INSERT INTO public.zasp_runtime_stage_work(organization_id) SELECT 'unused-zero-row' WHERE false`
			}
			_, err = tx.Exec(ctx, statement)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "55000" {
				t.Error("stage statement retained invalid authority", err)
			}
		})
	}
	config := owner.Config().Copy()
	config.User = principal
	ingest, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer ingest.Close(context.Background())
	if _, err := ingest.Exec(ctx, emptyInsert); err == nil {
		t.Fatal("ungranted stage DML accepted")
	} else {
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "42501" {
			t.Fatal("unexpected direct DML refusal", err)
		}
	}
	repository, err := runtimeevent.NewPostgresCurrentRuntimeIngestRepository(runtimeProfileDiagnosticDatabase{connection: ingest, t: t})
	if err != nil {
		t.Fatal(err)
	}
	batch := mustProductID(t, "pid_f0800000-0000-4000-8000-000000009030")
	reservation, err := repository.Reserve(ctx, credential, runtimeevent.IngestReserveRequest{Scope: automaticSourceIdentity(t, o, w, e, o).Scope, BatchID: batch, IdempotencyKey: "current-stage-statement-0001", ContentDigest: sha256.Sum256([]byte("stage")), Source: "otlp", MediaType: "application/json", SchemaVersion: "runtime-event-v1", PayloadSize: 5, EventCount: 1})
	if err != nil {
		t.Fatal("stage fixture actual reserve", err)
	}
	const stageInsert = `INSERT INTO public.zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version) VALUES($1,$2,$3,$4,$5,'archive',1,$6)`
	_, err = owner.Exec(ctx, stageInsert, o, w, e, batch.String(), reservation.Generation, "runtime-archive-v2")
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != "22023" {
		t.Fatal("persisted semantic stage tuple accepted precise implementation", err)
	}
	t.Run("catalog changed after FK wait", func(t *testing.T) {
		waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		caller, err := pgx.ConnectConfig(waitCtx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer caller.Close(context.Background())
		var original string
		if err := owner.QueryRow(waitCtx, `SELECT pg_get_functiondef('zasp_authorization80_runtime.require_current()'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		blocker, err := owner.Begin(waitCtx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		if _, err := blocker.Exec(waitCtx, `SELECT 1 FROM public.zasp_runtime_batch_authorities WHERE (organization_id,workspace_id,environment_id,batch_id)=($1,$2,$3,$4) FOR UPDATE`, o, w, e, batch.String()); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		joined := false
		go func() {
			_, err := caller.Exec(waitCtx, stageInsert, o, w, e, batch.String(), reservation.Generation, "runtime-archive-v1")
			done <- err
		}()
		defer func() {
			cancel()
			_ = blocker.Rollback(context.Background())
			if !joined {
				<-done
			}
		}()
		for {
			var waiting bool
			if err := blocker.QueryRow(waitCtx, `SELECT $1::integer=ANY(pg_blocking_pids($2))`, owner.PgConn().PID(), caller.PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case err := <-done:
				joined = true
				t.Fatal("stage never waited on held parent FK", err)
			case <-waitCtx.Done():
				t.Fatal(waitCtx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		if _, err := blocker.Exec(waitCtx, `CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.require_current() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN NULL;END $$`); err != nil {
			t.Fatal(err)
		}
		if err := blocker.Commit(waitCtx); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		if _, restoreErr := owner.Exec(ctx, original); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "55000" {
			t.Error("stage retained pre-wait catalog", err)
		}
		var rows int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_runtime_stage_work WHERE batch_id=$1`, batch.String()).Scan(&rows); err != nil || rows != 0 {
			t.Error("invalid post-wait stage persisted", rows, err)
		}
	})
}

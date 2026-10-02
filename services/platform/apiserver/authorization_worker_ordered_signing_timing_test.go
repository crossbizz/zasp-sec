package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Only the selected source attempt uses these fresh registered sockets. Role
// defaults are restored before its original ten-second operation begins.
func orderedPolicyTrackedWorker(t *testing.T, ctx context.Context, owner *pgx.Conn, login string, checker authorization.Checker, storeID, modelID string) (*authorization.WorkerExecutor, func()) {
	t.Helper()
	var prior *string
	if err := owner.QueryRow(ctx, `SELECT (SELECT split_part(v,'=',2) FROM unnest(rolconfig) v WHERE v LIKE 'track_functions=%') FROM pg_roles WHERE rolname=$1`, login).Scan(&prior); err != nil {
		t.Fatal("read signing diagnostic role default", err)
	}
	var baselineCalls int64
	var ownerTracking string
	if err := owner.QueryRow(ctx, `SELECT current_setting('track_functions'),coalesce((SELECT sum(calls)::bigint FROM pg_stat_user_functions),0)`).Scan(&ownerTracking, &baselineCalls); err != nil || ownerTracking != "none" || baselineCalls != 0 || prior != nil && *prior != "none" {
		t.Fatal("signing diagnostic requires untracked preceding sockets and zero counters", err)
	}
	restore := "ALTER ROLE " + pgx.Identifier{login}.Sanitize() + " RESET track_functions"
	if prior != nil {
		if *prior != "none" && *prior != "pl" && *prior != "all" {
			t.Fatal("unexpected signing diagnostic role default")
		}
		restore = "ALTER ROLE " + pgx.Identifier{login}.Sanitize() + " SET track_functions TO '" + *prior + "'"
	}
	if _, err := owner.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" SET track_functions TO 'all'"); err != nil {
		t.Fatal("enable signing diagnostic counters", err)
	}
	restored := false
	defer func() {
		if !restored {
			bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := owner.Exec(bounded, restore); err != nil {
				t.Error("restore signing diagnostic defaults", err)
			}
		}
	}()
	cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.MaxConns = login, 2
	cfg.ConnConfig.Tracer = orderedPolicyDiagnosticTracer(t, cfg.ConnConfig.Tracer)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open tracked signing pool", err)
	}
	t.Cleanup(pool.Close)
	var held []*pgxpool.Conn
	defer func() {
		for _, conn := range held {
			conn.Release()
		}
	}()
	for range 2 {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("prewarm tracked signing socket", err)
		}
		held = append(held, conn)
		var mode, principal string
		if err := conn.QueryRow(ctx, `SELECT current_setting('track_functions'),session_user`).Scan(&mode, &principal); err != nil || mode != "all" || principal != login {
			t.Fatal("tracked signing socket authority differs", err)
		}
	}
	if _, err := owner.Exec(ctx, restore); err != nil {
		t.Fatal("immediate signing default restoration", err)
	}
	restored = true
	orderedPolicyCaptureTimingGraph(t, ctx, owner)
	key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := authorization.NewWorkerExecutor(pool, checker, storeID, modelID, key)
	if err != nil {
		t.Fatal(err)
	}
	return worker, func() {
		pool.Close() // Flush counters even when the signing transaction rolled back.
		bounded, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := owner.Exec(bounded, `SELECT pg_stat_clear_snapshot()`); err != nil {
			t.Fatal("clear signing counter snapshot", err)
		}
		rows, err := owner.Query(bounded, `SELECT schemaname,funcname,calls,total_time,self_time FROM pg_stat_user_functions WHERE calls>0 ORDER BY total_time DESC,schemaname,funcname LIMIT 60`)
		if err != nil {
			t.Fatal("read signing counters", err)
		}
		defer rows.Close()
		safe := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
		for rows.Next() {
			var schema, function string
			var calls int64
			var total, self float64
			if err := rows.Scan(&schema, &function, &calls, &total, &self); err != nil {
				t.Fatal(err)
			}
			if safe.MatchString(schema) && safe.MatchString(function) {
				t.Logf("ordered signing function schema=%s name=%s calls=%d total_ms=%.3f self_ms=%.3f", schema, function, calls, total, self)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
}

func orderedPolicyCaptureTimingGraph(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	path := os.Getenv("ZASP_ORDERED_POLICY_FUNCTION_CAPTURE")
	if path == "" {
		t.Fatal("signing diagnostic graph destination absent")
	}
	var definitions []struct{ Signature, Definition, Owner, ACL string }
	for _, signature := range []string{
		"zasp_authorization80_worker.require_ordered68_policy(text,jsonb)",
		"zasp_authorization80_worker.ordered68_policy_source(text,jsonb)",
		"zasp_authorization80_worker.ordered68_policy_metadata(text,jsonb)",
		"zasp_authorization80_worker.ordered68_effect_source(text,jsonb)",
		"zasp_authorization80_worker.ordered68_effect_metadata(text,jsonb)",
		"zasp_authorization80_worker.ordered68_effect_facts(boolean,jsonb)",
		"zasp_authorization80_worker.ordered68_policy_input(text,jsonb,text,bigint,jsonb)",
		"zasp_authorization80_worker.ordered68_policy_begin(text,jsonb,text)",
		"zasp_authorization80_worker.ordered68_policy_store(text,jsonb,text,bytea,bytea,text)",
		"zasp_authorization80_worker.ordered68_application_source(jsonb)",
		"zasp_sa_multistep_prior.context(text,text,text,text)",
		"zasp_sa_multistep_prior.application_current(text,text,text,text,text)",
		"zasp_sa_multistep_prior.transition_current(text,text,text,text,boolean)",
		"zasp_temporal68.current_plan(text,text,text,text,boolean)",
		"zasp_temporal68.current_ready()",
		"zasp_temporal67.current_ready()",
		"zasp_authorization80_worker.catalog_ready()",
	} {
		entry := struct{ Signature, Definition, Owner, ACL string }{Signature: signature}
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef(oid),proowner::regrole::text,coalesce(proacl::text,'') FROM pg_proc WHERE oid=$1::regprocedure`, signature).Scan(&entry.Definition, &entry.Owner, &entry.ACL); err != nil {
			t.Fatal("capture fixed signing function", signature, err)
		}
		definitions = append(definitions, entry)
	}
	raw, err := json.MarshalIndent(definitions, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create signing graph artifact", err)
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("retain signing graph artifact", writeErr, closeErr)
	}
}

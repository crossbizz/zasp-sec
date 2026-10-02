package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func workerActivationNativeControls(t *testing.T, ctx context.Context, owner, api *pgx.Conn, grant RequestAuthorization, args []any) {
	t.Helper()
	for _, control := range []string{"unchanged", "organization", "workspace", "environment", "actor", "target", "version", "expired-fresh-auth", "wrong-purpose"} {
		t.Run("activation native "+control, func(t *testing.T) {
			q := append([]any(nil), args...)
			g := grant
			code := "42501"
			switch control {
			case "organization":
				q[0] = automaticSourceID(8899)
			case "workspace":
				q[1] = automaticSourceID(8899)
			case "environment":
				q[2] = automaticSourceID(8899)
			case "actor":
				q[4] = automaticSourceID(8899)
			case "target":
				q[3] = automaticSourceID(8899)
			case "version":
				q[6] = int64(99)
				code = "40001"
			case "expired-fresh-auth":
				q[8] = time.Now().UTC().Add(-time.Second)
			case "wrong-purpose":
				g.OperationID = "getSecurityAgent"
			}
			var err error
			g, err = attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1)`, string(g.attestation)); err != nil {
				t.Fatal("native proof installation", err)
			}
			var result json.RawMessage
			err = tx.QueryRow(ctx, currentTestActivateSQL, q...).Scan(&result)
			if control == "unchanged" {
				var value SecurityAgentActivationResult
				if err != nil || json.Unmarshal(result, &value) != nil || value.Version != 2 || value.Replayed {
					t.Fatal("unchanged native activation control", err)
				}
			} else {
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != code {
					t.Fatalf("native refusal=%v want SQLSTATE%s", err, code)
				}
			}
		})
	}
	for _, query := range []string{
		`ALTER FUNCTION zasp_authorization80_worker.test74_activate_body(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) SET search_path=pg_catalog`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_activate_body(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO PUBLIC`,
		`ALTER FUNCTION zasp_authorization80_worker.test74_activate_body(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) OWNER TO worker_test_executor`,
		`CREATE OR REPLACE FUNCTION zasp_temporal74.activate(o text,w text,e text,d text,a text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT ''{}''::jsonb'`,
	} {
		func() {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, query); err != nil {
				t.Fatal("catalog control setup", err)
			}
			var refused bool
			if err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready() AND NOT zasp_temporal74.current_ready()`).Scan(&refused); err != nil || !refused {
				t.Fatal("activation catalog drift accepted", err)
			}
		}()
	}
	workerActivationWaitControl(t, ctx, owner, api, grant, args, false)
	workerActivationWaitControl(t, ctx, owner, api, grant, args, true)
}

func workerActivationWaitControl(t *testing.T, ctx context.Context, owner, api *pgx.Conn, grant RequestAuthorization, args []any, revision bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	blocker, err := pgx.ConnectConfig(ctx, owner.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	lock, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err = lock.Exec(ctx, `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, args[0]); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !revision {
		now = now.Add(-56 * time.Second)
	}
	grant, err = attestAuthorization(grant, authorizationFixtureAttestor(t), now)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	joined := make(chan error, 1)
	go func() {
		_, callErr := tx.Exec(ctx, `SELECT zasp_authorization80.fence($1)`, string(grant.attestation))
		if callErr == nil {
			var body json.RawMessage
			callErr = tx.QueryRow(ctx, currentTestActivateSQL, args...).Scan(&body)
		}
		joined <- callErr
	}()
	waiting := false
	for ctx.Err() == nil {
		var blocked bool
		if err = owner.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, api.PgConn().PID()).Scan(&blocked); err != nil {
			break
		}
		if blocked {
			waiting = true
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !waiting {
		_ = lock.Rollback(context.Background())
		callErr := <-joined
		t.Fatal("activation did not reach owned org wait", callErr)
	}
	if revision {
		if _, err = lock.Exec(ctx, `SELECT zasp_authorization79.touch($1)`, args[0]); err == nil {
			err = lock.Commit(ctx)
		}
	} else {
		select {
		case <-ctx.Done():
		case <-time.After(time.Until(now.Add(time.Minute + 100*time.Millisecond))):
		}
		err = lock.Rollback(ctx)
	}
	if err != nil {
		_ = lock.Rollback(context.Background())
		<-joined
		t.Fatal("release activation wait", err)
	}
	callErr := <-joined
	if err = tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	want := "42501"
	if revision {
		want = "40001"
	}
	var pg *pgconn.PgError
	if !errors.As(callErr, &pg) || pg.Code != want {
		t.Fatalf("activation post-wait refusal revision=%t error=%v want=%s", revision, callErr, want)
	}
}

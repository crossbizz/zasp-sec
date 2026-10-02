package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"testing"
	"time"
)

func exerciseAuthorizationProjectionConflict(t *testing.T, ctx context.Context, owner, api *pgx.Conn, dsn string, repository authorization.RevisionReader, checker authorization.Checker, request authorization.CheckRequest, store, model string) {
	t.Helper()
	other := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth_api_login")
	defer other.Close(context.Background())
	// A temporary product-effect fixture keeps a stable idempotency key across
	// rollback/retry without inventing a new production API or granting table DML.
	if _, err := api.Exec(ctx, `CREATE TEMP TABLE projection_effects(id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	proof, err := authorization.CheckRevision(ctx, repository, checker, request, store, model)
	if err != nil {
		t.Fatal(err)
	}
	first, err := api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(context.Background())
	if err := authorization.RevalidateDecision(ctx, first, proof, request); err != nil {
		t.Fatal(err)
	}
	effectID := "pid_79000009-0000-4000-8000-000000000009"
	if _, err := first.Exec(ctx, `INSERT INTO projection_effects(id) VALUES($1)`, effectID); err != nil {
		t.Fatal(err)
	}
	second, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(context.Background())
	outcome := make(chan error, 1)
	go func() {
		_, err := second.Exec(ctx, `SELECT zasp_identity_admin_resolve_session('organization-projection','member-projection','["scim-group-test-conflict"]'::jsonb)`)
		outcome <- err
	}()
	// Wait for the registered mutation to hold membership and block on org.
	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, int32(other.PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("registered source mutation did not wait on revision fence")
	}
	_, firstErr := first.Exec(ctx, `SELECT zasp_identity_admin_resolve_session('organization-projection','member-projection','[]'::jsonb)`)
	// Whichever backend is selected as victim, both attempted transactions are
	// abandoned. No stale Check is reused and no effect is committed.
	_ = first.Rollback(ctx)
	secondErr := <-outcome
	_ = second.Rollback(ctx)
	if !authorization.RetryableConflict(firstErr) && !authorization.RetryableConflict(secondErr) {
		t.Fatalf("expected explicit retryable deadlock; first=%v second=%v", firstErr, secondErr)
	}
	var effects int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM projection_effects`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("aborted product effect escaped", err)
	}
	fresh, err := authorization.CheckRevision(ctx, repository, checker, request, store, model)
	if err != nil || !fresh.Decision.Allowed {
		t.Fatal("fresh Check after rollback", err)
	}
	retry, err := api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Rollback(context.Background())
	if err := authorization.RevalidateDecision(ctx, retry, fresh, request); err != nil {
		t.Fatal(err)
	}
	if _, err := retry.Exec(ctx, `INSERT INTO projection_effects(id) VALUES($1)`, effectID); err != nil {
		t.Fatal(err)
	}
	if err := retry.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `SELECT count(*) FROM projection_effects WHERE id=$1`, effectID).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("fresh retry lost stable effect identity", err)
	}
	t.Log("registered source/fenced effect lock inversion aborted, rolled back, then committed once after fresh Check")
}

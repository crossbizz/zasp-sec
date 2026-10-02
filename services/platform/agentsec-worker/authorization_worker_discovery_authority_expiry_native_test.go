package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Unlike proof expiry, this keeps the genuine worker decision alive while a
// later source-row lock crosses the credential deadline captured by HTTP.
func discovery72AuthorityLockWait(t *testing.T, ctx context.Context, owner *pgx.Conn, product *temporalDiscoveryProduct, start orchestration.DiscoveryStart, deadline time.Time, login string, reconcile func(), checks func() int) {
	t.Helper()
	var until time.Time
	var captured bool
	if err := owner.QueryRow(ctx, `SELECT a.authority_until,a.authority_until=c.expires_at AND a.authority_until<r.deadline AND r.deadline=r.admitted_at+interval '24 hours' AND a.credential_facts=zasp_authorization80_worker.discovery72_credentials(r) FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_temporal72.runs r USING(organization_id,workspace_id,environment_id,job_id) JOIN zasp_connector_credentials c ON(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id)=(a.organization_id,a.workspace_id,a.environment_id,a.integration_id,'pid_72008025-0000-4000-8000-000000000025') WHERE a.job_id=$1`, start.Ref.RunID).Scan(&until, &captured); err != nil || !captured {
		t.Fatal("HTTP admission did not capture persisted credential deadline", err)
	}
	request := func(phase string, extra map[string]any) json.RawMessage {
		q := map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "job_id": start.Ref.RunID, "integration_id": start.IntegrationID, "input_digest": start.InputDigest, "operation": phase, "budget_us": deadline.UnixMicro()}
		for k, v := range extra {
			q[k] = v
		}
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	prepare := request("prepare_page", map[string]any{"expected": 0, "expected_digest": ""})
	decision, err := product.authorization.forward.Authorize(ctx, "discovery72.prepare_page", prepare)
	if err != nil {
		t.Fatal("prepare before authority expiry", err)
	}
	if _, err = product.authorization.forward.Execute(ctx, decision); err != nil {
		t.Fatal("real prepared page before authority expiry", err)
	}
	var effect string
	if err = owner.QueryRow(ctx, `SELECT effect_id FROM zasp_temporal72.page_effects WHERE job_id=$1 AND expected_version=0 AND result IS NULL`, start.Ref.RunID).Scan(&effect); err != nil {
		t.Fatal(err)
	}
	// Authorize near expiry, without altering the real decision's30s lifetime.
	if delay := time.Until(until.Add(-15 * time.Second)); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	authorizeStarted := time.Now()
	guard := request("guard_page", map[string]any{"effect_id": effect})
	decision, err = product.authorization.forward.Authorize(ctx, "discovery72.guard_page", guard)
	if err != nil {
		t.Fatal("live credential guard authorization", err)
	}
	if time.Until(until) < 3*time.Second {
		t.Fatal("authority fixture missed live guard window")
	}
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var locked string
	if err = lock.QueryRow(ctx, `SELECT effect_id FROM zasp_temporal72.page_effects WHERE job_id=$1 AND effect_id=$2 FOR UPDATE`, start.Ref.RunID, effect).Scan(&locked); err != nil {
		_ = lock.Rollback(ctx)
		t.Fatal(err)
	}
	executeCtx, cancelExecute := context.WithCancel(ctx)
	finished := make(chan error, 1)
	joined := false
	defer func() {
		cancelExecute()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := lock.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("authority lock cleanup", err)
		}
		if !joined {
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-finished:
			case <-timer.C:
				t.Error("authority Execute did not join after cancellation")
			}
		}
	}()
	go func() { _, err := product.authorization.forward.Execute(executeCtx, decision); finished <- err }()
	waiting := false
	for limit := time.Now().Add(8 * time.Second); time.Now().Before(limit); {
		if err = lock.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2::integer=ANY(pg_blocking_pids(pid)))`, login, int32(owner.PgConn().PID())).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if !waiting || !time.Now().Before(until) {
		t.Fatal("guard did not reach later effect-row wait before authority expiry")
	}
	if delay := time.Until(until.Add(150 * time.Millisecond)); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var authorityExpired bool
	if err = lock.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, until).Scan(&authorityExpired); err != nil || !authorityExpired {
		t.Fatal("database credential clock has not expired", err)
	}
	// issued_at is captured after Authorize starts. This conservative lower
	// bound proves the genuine30s decision still lives at release and return.
	if !time.Now().Before(authorizeStarted.Add(29 * time.Second)) {
		t.Fatal("proof expiry could mask credential expiry")
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-finished:
		joined = true
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !time.Now().Before(authorizeStarted.Add(29 * time.Second)) {
		t.Fatal("proof expired before authority result was observed")
	}
	if !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("live proof escaped persisted credential expiry after source lock", err)
	}
	var unchanged bool
	if err = owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(result IS NULL) AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects WHERE job_id=$1) FROM zasp_temporal72.page_effects WHERE job_id=$1`, start.Ref.RunID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("expired guard changed admitted debt", err)
	}
	beforeChecks := checks()
	replay := request("replay_page", map[string]any{"expected": 0, "expected_digest": ""})
	comp, err := product.authorization.compensation.Authorize(ctx, "discovery72.replay_page", replay)
	if err != nil {
		t.Fatal("captured replay after credential expiry", err)
	}
	value, err := product.authorization.compensation.Execute(ctx, comp)
	var receipt struct {
		Found bool `json:"found"`
		Value struct {
			Page struct {
				Outcome string `json:"outcome"`
			} `json:"page"`
		} `json:"value"`
	}
	if err != nil || json.Unmarshal(value, &receipt) != nil || !receipt.Found || receipt.Value.Page.Outcome != "outcome_unknown" || checks() != beforeChecks {
		t.Fatal("captured expiry replay changed debt or called FGA", err)
	}
	var before int64
	if err = owner.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, start.Ref.OrganizationID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	reconcile()
	var expiredProjection bool
	if err = owner.QueryRow(ctx, `SELECT NOT s.current_source AND o.desired>$2 AND o.desired=o.applied FROM zasp_authorization80_worker.discovery_state s JOIN zasp_authorization79.organizations o USING(organization_id) WHERE s.job_id=$1`, start.Ref.RunID, before).Scan(&expiredProjection); err != nil || !expiredProjection {
		t.Fatal("real projector did not expire credential delegation", err)
	}
	t.Log("live worker proof refused after credential authority expired during observed effect-row wait; captured debt preserved; projector expiration applied")
}

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func temporalDiscoveryOverlapFixture(t *testing.T) (scheduleReplayFixture, *pgx.Conn, *pgx.Conn, orchestration.DiscoveryStart, orchestration.DiscoveryStart, time.Time, time.Time) {
	t.Helper()
	f, worker, first, deadline := temporalDiscoveryPageFixture(t)
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($2,$1,'overlap-org','overlap-member','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($2,$1,$3,$4,'Overlap','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, replayOrg, replayPrincipal, replayWorkspace, replayEnvironment); err != nil {
		t.Fatal(err)
	}
	apiCfg := f.owner.Config().Copy()
	apiCfg.User = f.registration.api
	api, err := pgx.ConnectConfig(f.ctx, apiCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close(f.ctx) })
	var raw []byte
	if err := api.QueryRow(f.ctx, `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,'owned-overlap-manual',1,'pid_72720001-0000-4000-8000-000000000001','pid_72720002-0000-4000-8000-000000000002','pid_72720003-0000-4000-8000-000000000003',decode(repeat('ab',32),'hex'),'parser_v1','tool_v1','pid_72720004-0000-4000-8000-000000000004','pid_72720005-0000-4000-8000-000000000005','pid_72720006-0000-4000-8000-000000000006')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	second := orchestration.DiscoveryStart{Ref: first.Ref, IntegrationID: first.IntegrationID, InputDigest: strings.Repeat("ab", 32)}
	second.Ref.RunID = "pid_72720002-0000-4000-8000-000000000002"
	var secondDeadline time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$1`, second.Ref.RunID).Scan(&secondDeadline); err != nil {
		t.Fatal(err)
	}
	return f, worker, api, first, second, deadline, secondDeadline
}

// Contention is a persisted known-no-IO receipt. It must not reserve another
// generation, reuse a prior command, or turn an unknown dispatch into a wait.
func TestTemporalDiscoveryOverlapWaitPostgres(t *testing.T) {
	f, worker, api, first, second, deadline, secondDeadline := temporalDiscoveryOverlapFixture(t)
	var raw []byte
	prepare := `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	args := func(s orchestration.DiscoveryStart, d time.Time, v int64, h string) []any {
		return []any{replayOrg, replayWorkspace, replayEnvironment, s.Ref.RunID, s.IntegrationID, s.InputDigest, d, v, h}
	}
	var dispatched struct {
		EffectID string `json:"effect_id"`
	}
	if err := worker.QueryRow(f.ctx, prepare, args(first, deadline, 0, "")...).Scan(&raw); err != nil || json.Unmarshal(raw, &dispatched) != nil || dispatched.EffectID == "" {
		t.Fatal("first generation", err, string(raw))
	}
	if err := worker.QueryRow(f.ctx, prepare, args(second, secondDeadline, 0, "")...).Scan(&raw); err != nil {
		t.Fatal("busy must return durable no-IO wait", err)
	}
	var waited struct {
		Page     *orchestration.DiscoveryPage `json:"page"`
		EffectID string                       `json:"effect_id"`
		Input    json.RawMessage              `json:"input"`
	}
	if json.Unmarshal(raw, &waited) != nil || waited.Page == nil || waited.Page.Outcome != "retryable" || waited.Page.CheckpointVersion != 1 || len(waited.Page.ReceiptDigest) != 64 || waited.Page.RetryAfterSeconds < 1 || waited.EffectID != "" || len(waited.Input) != 0 {
		t.Fatal("busy dispatched or malformed wait", string(raw))
	}
	firstWait := string(raw)
	var body struct {
		Attempt   int        `json:"attempt"`
		Status    string     `json:"status"`
		RetryAt   *time.Time `json:"retry_at"`
		Code      *string    `json:"last_error_code"`
		StartedAt *time.Time `json:"started_at"`
	}
	if err := api.QueryRow(f.ctx, `SELECT zasp_temporal72.sync_detail($1,$2,$3,$4,'pid_72720001-0000-4000-8000-000000000001')->'body'`, replayOrg, replayWorkspace, replayEnvironment, replayIntegration).Scan(&raw); err != nil || json.Unmarshal(raw, &body) != nil || body.Attempt != 0 || body.Status != "queued" || body.RetryAt == nil || body.Code == nil || *body.Code != "retryable" || body.StartedAt != nil {
		t.Fatal("no-IO wait readback", string(raw), err)
	}
	if err := worker.QueryRow(f.ctx, prepare, args(second, secondDeadline, 0, "")...).Scan(&raw); err != nil || string(raw) != firstWait {
		t.Fatal("wait replay changed", err, string(raw))
	}
	var valid bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_discovery_generation_reservations)=1 AND (SELECT count(*) FROM zasp_temporal72.page_effects)=1 AND (SELECT count(*) FROM zasp_temporal72.page_waits)=1`).Scan(&valid); err != nil || !valid {
		t.Fatal("wait allocated generation/effect", valid, err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal72.page_waits SET expected_digest='tampered'`); err == nil {
		t.Fatal("wait receipt mutable")
	}
	nextArgs := args(second, secondDeadline, waited.Page.CheckpointVersion, waited.Page.ReceiptDigest)
	if err := worker.QueryRow(f.ctx, prepare, nextArgs...).Scan(&raw); err == nil {
		t.Fatal("wait not-before bypassed")
	}
	// Unknown first dispatch still owns the resource; it cannot be changed to a
	// wait receipt or released by a misleading cancellation request.
	if err := worker.QueryRow(f.ctx, prepare, args(first, deadline, 0, "")...).Scan(&raw); err != nil || !strings.Contains(string(raw), "outcome_unknown") {
		t.Fatal("unknown first dispatch resent", err)
	}
	// A positive terminal provider receipt releases the narrow resource fence.
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,'{"outcome":"terminal"}')`, replayOrg, replayWorkspace, replayEnvironment, first.Ref.RunID, dispatched.EffectID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var notBefore time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT retry_not_before FROM zasp_temporal72.runs WHERE job_id=$1`, second.Ref.RunID).Scan(&notBefore); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(notBefore) + 20*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	// Live connector and schedule checks still run before advancing the wait.
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_integration_connections SET state='revoked',revoked_at=clock_timestamp() WHERE integration_id=$1`, replayIntegration); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, prepare, nextArgs...).Scan(&raw); err == nil {
		t.Fatal("wait bypassed current revocation")
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_integration_connections SET state='verified',revoked_at=NULL WHERE integration_id=$1`, replayIntegration); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, prepare, nextArgs...).Scan(&raw); err != nil {
		t.Fatal("released resource did not resume", err)
	}
	var resumed struct {
		EffectID string `json:"effect_id"`
		Input    struct {
			Generation int64 `json:"generation"`
		} `json:"input"`
	}
	if json.Unmarshal(raw, &resumed) != nil || resumed.EffectID == "" || resumed.EffectID == dispatched.EffectID || resumed.Input.Generation != 2 {
		t.Fatal("wait resumed wrong generation", string(raw))
	}
	if err := worker.QueryRow(f.ctx, prepare, args(second, secondDeadline, 0, "")...).Scan(&raw); err != nil || string(raw) != firstWait {
		t.Fatal("old wait command replay changed after resume", err)
	}
}

func TestTemporalDiscoveryWaitSettlementPostgres(t *testing.T) {
	for _, mode := range []string{"expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			f, worker, api, first, second, deadline, secondDeadline := temporalDiscoveryOverlapFixture(t)
			if mode == "expired" {
				// Fixture clock shift before the first wait, preserving the24h
				// admission/deadline relation. The product never extends it.
				if err := f.owner.QueryRow(f.ctx, `WITH n AS(SELECT clock_timestamp() v) UPDATE zasp_temporal72.runs SET admitted_at=n.v-interval '24 hours'+interval '3 seconds',deadline=n.v+interval '3 seconds' FROM n WHERE job_id=$1 RETURNING deadline`, second.Ref.RunID).Scan(&secondDeadline); err != nil {
					t.Fatal(err)
				}
			}
			prepare := `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
			args := func(s orchestration.DiscoveryStart, d time.Time, v int64, h string) []any {
				return []any{replayOrg, replayWorkspace, replayEnvironment, s.Ref.RunID, s.IntegrationID, s.InputDigest, d, v, h}
			}
			var raw []byte
			if err := worker.QueryRow(f.ctx, prepare, args(first, deadline, 0, "")...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := worker.QueryRow(f.ctx, prepare, args(second, secondDeadline, 0, "")...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var wait struct {
				Page orchestration.DiscoveryPage `json:"page"`
			}
			if json.Unmarshal(raw, &wait) != nil || wait.Page.Outcome != "retryable" {
				t.Fatal("wait receipt", string(raw))
			}
			replay := string(raw)
			var notBefore time.Time
			if err := f.owner.QueryRow(f.ctx, `SELECT retry_not_before FROM zasp_temporal72.runs WHERE job_id=$1`, second.Ref.RunID).Scan(&notBefore); err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal72.runs SET retry_not_before=NULL WHERE job_id=$1`, second.Ref.RunID); err != nil {
				t.Fatal(err)
			}
			read := `SELECT zasp_temporal72.sync_detail($1,$2,$3,$4,'pid_72720001-0000-4000-8000-000000000001')->'body'`
			if err := api.QueryRow(f.ctx, read, replayOrg, replayWorkspace, replayEnvironment, replayIntegration).Scan(&raw); err == nil {
				t.Fatal("missing durable not-before readback accepted")
			}
			if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal72.runs SET retry_not_before=$2 WHERE job_id=$1`, second.Ref.RunID, notBefore); err != nil {
				t.Fatal(err)
			}
			if mode == "revoked" {
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_integration_connections SET state='revoked',revoked_at=clock_timestamp() WHERE integration_id=$1`, replayIntegration); err != nil {
					t.Fatal(err)
				}
			}
			if delay := time.Until(notBefore) + 20*time.Millisecond; delay > 0 {
				time.Sleep(delay)
			}
			if err := worker.QueryRow(f.ctx, prepare, args(second, secondDeadline, wait.Page.CheckpointVersion, wait.Page.ReceiptDigest)...).Scan(&raw); err == nil {
				t.Fatal("expired/revoked wait gained an effect")
			}
			if err := worker.QueryRow(f.ctx, prepare, args(second, secondDeadline, 0, "")...).Scan(&raw); err != nil || string(raw) != replay {
				t.Fatal("old no-IO receipt changed", err)
			}
			if err := api.QueryRow(f.ctx, read, replayOrg, replayWorkspace, replayEnvironment, replayIntegration).Scan(&raw); err != nil {
				t.Fatal("expired/revoked wait evidence unreadable", err)
			}
			settleArgs := args(second, secondDeadline, 0, "")[:7]
			if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,'activity_failed','')`, settleArgs...).Scan(&raw); err != nil || !strings.Contains(string(raw), "incomplete") {
				t.Fatal("no-IO settlement", string(raw), err)
			}
			var valid bool
			if err := f.owner.QueryRow(f.ctx, `SELECT r.state='incomplete' AND r.deadline=$2 AND sy.attempt=0 AND sy.started_at IS NULL AND sy.state='failed' AND sy.completed_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE job_id=r.job_id) AND NOT EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations WHERE sync_id=r.sync_id) FROM zasp_temporal72.runs r JOIN zasp_discovery_syncs sy ON sy.id=r.sync_id WHERE r.job_id=$1`, second.Ref.RunID, secondDeadline).Scan(&valid); err != nil || !valid {
				t.Fatal("settlement invented dispatch/generation/budget", valid, err)
			}
			if err := api.QueryRow(f.ctx, read, replayOrg, replayWorkspace, replayEnvironment, replayIntegration).Scan(&raw); err != nil {
				t.Fatal("terminal before dispatch unreadable", err)
			}
		})
	}
}

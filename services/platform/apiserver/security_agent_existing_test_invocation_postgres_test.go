package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func exerciseExistingTestLegacyInvocationFence(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, org, ws, env, run string, index int) {
	t.Helper()
	if index == 0 || index == 2 && os.Getenv("ZASP_TEST_EXISTING_SETTLEMENT_RECOVERY") == "true" {
		// Controlled winning-source projection for a positive legacy resolver.
		// This seeds discovery evidence; it does not prove a completed sync.
		seedExistingTestSimulationEvidence(t, ctx, owner, org, ws, env, "pid_89000014-0000-4000-8000-000000000004")
		if _, err := owner.Exec(ctx, `UPDATE zasp_discovery_snapshots SET state='complete',complete=true,is_last_good=true,apply_result='{}',committed_at=clock_timestamp() WHERE id='pid_89e23800-0000-4000-8000-000000000003';
 UPDATE zasp_inventory_evidence SET source='kubernetes',generation=1 WHERE id='pid_89e23800-0000-4000-8000-000000000004';
 UPDATE zasp_inventory_entities SET winning_integration_id='pid_89e23800-0000-4000-8000-000000000001',winning_snapshot_id='pid_89e23800-0000-4000-8000-000000000003',winning_evidence_id='pid_89e23800-0000-4000-8000-000000000004',winning_provider='kubernetes',winning_source='kubernetes',winning_source_native_id='invocation-agent',winning_generation=1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_89000011-0000-4000-8000-000000000001');
 INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000001','kubernetes','pid_89000011-0000-4000-8000-000000000001','invocation-agent','pid_89e23800-0000-4000-8000-000000000003','present','{}',clock_timestamp(),clock_timestamp(),'kubernetes','kubernetes_agent','Invocation target','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),'pid_89e23800-0000-4000-8000-000000000004',9500,clock_timestamp(),clock_timestamp()+interval '1 hour',1,80,1)`, pgx.QueryExecModeSimpleProtocol, org, ws, env); err != nil {
			t.Fatal(err)
		}
	}
	// Owner-seeded lease models retained work from an older worker, not successful
	// admission through the new invocation protocol.
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='leased',attempt=1,worker_id='existing-test-legacy-worker',lease_token=convert_to(repeat('a',32),'UTF8'),lease_expires_at=clock_timestamp()+interval '1 minute',started_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
		t.Fatal(err)
	}
	config := owner.Config().Copy()
	config.User = "existing_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close(context.Background())
	snapshot := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM zasp_red_team_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	// Model a cancellation request retained alongside the old worker lease.
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
		t.Fatal(err)
	}
	var digest []byte
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, query string
		connection  *pgx.Conn
		args        []any
	}{
		{"heartbeat", `SELECT zasp_red_team_heartbeat_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),60)`, worker, []any{org, ws, env, run}},
		{"cancel", `SELECT zasp_red_team_cancel_claimed_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),$5)`, worker, []any{org, ws, env, run, digest}},
		{"retry", `SELECT zasp_red_team_retry_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),$5,'outcome_unknown',clock_timestamp()+interval '1 second')`, worker, []any{org, ws, env, run, digest}},
		{"resolve", `SELECT zasp_red_team_resolve_invocation($1,$2,$3,'pid_89000011-0000-4000-8000-000000000001','agent_endpoint',$4,repeat('a',32),'prompt_injection')`, adapter, []any{org, ws, env, run}},
	} {
		before := snapshot()
		var raw json.RawMessage
		var pg *pgconn.PgError
		if err := test.connection.QueryRow(ctx, test.query, test.args...).Scan(&raw); !errors.As(err, &pg) || pg.Code != "55000" || snapshot() != before {
			t.Errorf("linked legacy %s accepted or changed run: %s %v", test.name, raw, err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=false WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
		t.Fatal(err)
	}
	exerciseExistingTestLegacyCompletionFence(t, ctx, owner, worker, org, ws, env, run, digest, index)
	// A separate unlinked run retains the ordinary human-test claim/retry path.
	// Only its enqueue is owner-seeded here; this is not a human HTTP workflow.
	unlinked := fmt.Sprintf("pid_89f10400-0000-4000-8000-%012d", index+1)
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest) SELECT organization_id,workspace_id,environment_id,$5,definition_id,definition_version,requested_by,input_digest FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run, unlinked); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	exerciseRedTeamProtocolSelection(t, ctx, owner, worker, adapter, org, ws, env, run, unlinked)
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),60)`, org, ws, env, unlinked).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claimed struct {
		Disposition string `json:"disposition"`
	}
	if json.Unmarshal(raw, &claimed) != nil || claimed.Disposition != "claimed" {
		t.Fatalf("unlinked claim refused: %s", raw)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_heartbeat_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),60)`, org, ws, env, unlinked).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var heartbeat struct {
		Renewed bool `json:"renewed"`
	}
	if json.Unmarshal(raw, &heartbeat) != nil || !heartbeat.Renewed {
		t.Fatalf("unlinked heartbeat refused: %s", raw)
	}
	const resolve = `SELECT zasp_red_team_resolve_invocation($1,$2,$3,'pid_89000011-0000-4000-8000-000000000001','agent_endpoint',$4,repeat('a',32),'prompt_injection')`
	resolvePositive := func() {
		t.Helper()
		if err := adapter.QueryRow(ctx, resolve, org, ws, env, unlinked).Scan(&raw); err != nil {
			t.Fatalf("unlinked resolution: %v", err)
		}
		var binding struct {
			Endpoint string `json:"endpoint"`
			TargetID string `json:"target_id"`
		}
		if json.Unmarshal(raw, &binding) != nil || binding.Endpoint != "https://adapter.customer.example/v1/evaluate" || binding.TargetID != "pid_89000011-0000-4000-8000-000000000001" {
			t.Fatalf("unlinked binding: %s", raw)
		}
	}
	resolvePositive()
	blocker, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) FOR UPDATE`, org, ws, env, unlinked); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	err = adapter.QueryRow(bounded, resolve, org, ws, env, unlinked).Scan(&raw)
	cancel()
	var lockError *pgconn.PgError
	if !errors.As(err, &lockError) || lockError.Code != "55P03" {
		t.Fatalf("resolver waited under legacy transaction-time authority: %v", err)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	resolvePositive()
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_retry_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),$5,'outcome_unknown',clock_timestamp()+interval '1 second')`, org, ws, env, unlinked, digest).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var retried struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(raw, &retried) != nil || retried.Status != "retryable" {
		t.Fatalf("unlinked retry refused: %s", raw)
	}
	// Move only the controlled retry clock, then reclaim through the real worker.
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, unlinked); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),60)`, org, ws, env, unlinked).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &claimed) != nil || claimed.Disposition != "claimed" {
		t.Fatalf("unlinked reclaim refused: %s", raw)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, unlinked); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_cancel_claimed_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),$5)`, org, ws, env, unlinked, digest).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &retried) != nil || retried.Status != "cancelled" {
		t.Fatalf("unlinked cancellation refused: %s", raw)
	}
}

// Uses valid, controlled artifact references to exercise completion authority.
// These receipts are not proof of uploaded objects or live runner execution.
func exerciseExistingTestLegacyCompletionFence(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, org, ws, env, linked string, digest []byte, index int) {
	t.Helper()
	const legacy = `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17)`
	const finish = `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb)`
	snapshot := func(run string) string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',to_jsonb(r),'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.attempt),'[]'::jsonb) FROM zasp_red_team_attempts a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id)))::text FROM zasp_red_team_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	unlinked := fmt.Sprintf("pid_89f10500-0000-4000-8000-%012d", index+1)
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest) SELECT organization_id,workspace_id,environment_id,$5,definition_id,definition_version,requested_by,input_digest FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, linked, unlinked); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),60)`, org, ws, env, unlinked).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claimed struct {
		Disposition string `json:"disposition"`
	}
	if json.Unmarshal(raw, &claimed) != nil || claimed.Disposition != "claimed" {
		t.Fatalf("completion fixture claim: %s", raw)
	}
	for _, run := range []string{linked, unlinked} {
		prefix := "organizations/" + org + "/workspaces/" + ws + "/environments/" + env + "/artifacts/"
		key := prefix + run
		args := []any{org, ws, env, run, "existing-test-legacy-worker", []byte(strings.Repeat("a", 32)), digest, "pass", "Evaluate curated categories: prompt_injection", "1 of 1 curated security checks passed; 0 exposed unsafe behavior.", nil, json.RawMessage(`["prompt_injection: protected"]`), "s3://zasp-evidence/" + key, key, "evidence-version-1", []byte(strings.Repeat("x", 32)), int64(1024)}
		before := snapshot(run)
		for _, denied := range []struct{ query, code string }{
			{legacy, "22023"},
			{strings.Replace(legacy, "zasp_red_team_finish_run(", "zasp_red_team_finish_run_v38(", 1), "42501"},
		} {
			var pg *pgconn.PgError
			if err := worker.QueryRow(ctx, denied.query, args...).Scan(&raw); !errors.As(err, &pg) || pg.Code != denied.code || snapshot(run) != before {
				t.Fatalf("legacy/private completion authority changed: %s %v", raw, err)
			}
		}
		input := RedTeamArtifactReference{Reference: "s3://zasp-evidence/" + prefix + "pid_95000007-0000-4000-8000-000000000007", VersionID: "input-version-1", SHA256: strings.Repeat("b", 64), SizeBytes: 512}
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, encoded)
		err = worker.QueryRow(ctx, finish, args...).Scan(&raw)
		if run == linked {
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "55000" || snapshot(run) != before {
				t.Fatalf("linked legacy completion accepted or mutated evidence: %s %v", raw, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Status  string `json:"status"`
			Verdict string `json:"verdict"`
		}
		if json.Unmarshal(raw, &result) != nil || result.Status != "complete" || result.Verdict != "pass" {
			t.Fatalf("unlinked completion refused: %s", raw)
		}
		var count int
		var retained json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT count(*),jsonb_agg(input_artifact)->0 FROM zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&count, &retained); err != nil {
			t.Fatal(err)
		}
		var actual RedTeamArtifactReference
		if count != 1 || json.Unmarshal(retained, &actual) != nil || actual != input {
			t.Fatalf("unlinked completion lost exact input receipt: %d %s", count, retained)
		}
	}
}

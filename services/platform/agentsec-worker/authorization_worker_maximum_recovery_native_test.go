package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Catches recovery that works for one receipt but cannot consume the maximum
// six within the unchanged product runner deadline. Native observations are
// controlled fixture values, not evidence of six external provider sends.
func TestP7WorkerSingleTestMaximumRecoveredProductNative(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_WORKER_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned six-category completed fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil || net.ParseIP(pc.ConnConfig.Host) == nil || !net.ParseIP(pc.ConnConfig.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	owner, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	poolFor := func(login string) *pgxpool.Pool {
		c := pc.Copy()
		c.ConnConfig.User = login
		c.ConnConfig.Tracer = workerLifecycleTracer(t, c.ConnConfig.Tracer)
		c.MaxConns = 2
		p, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	parent := os.Getenv("ZASP_P7_WORKER_PARENT")
	var start orchestration.StartRequest
	var child string
	var body, manifestRaw []byte
	if err := owner.QueryRow(ctx, `SELECT x.organization_id,x.workspace_id,x.environment_id,x.definition_version,x.input_digest,x.test_run_id,i.body,i.manifest FROM zasp_temporal74.run_owners x JOIN zasp_temporal74.test_inputs i USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE x.run_id=$1`, parent).Scan(&start.Ref.OrganizationID, &start.Ref.WorkspaceID, &start.Ref.EnvironmentID, &start.DefinitionVersion, &start.InputDigest, &child, &body, &manifestRaw); err != nil {
		t.Fatal("captured six-category input", err)
	}
	start.Ref.RunID = parent
	var manifest apiserver.RedTeamArtifactReference
	var input redTeamRunnerInput
	if json.Unmarshal(manifestRaw, &manifest) != nil || json.Unmarshal(body, &input) != nil || len(input.Categories) != 6 {
		t.Fatal("maximum-category fixture shape")
	}
	var original json.RawMessage
	var complete, revoked bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=6 AND bool_and(state='completed'),jsonb_agg(to_jsonb(j) ORDER BY category) FROM zasp_temporal74.invocations j WHERE test_run_id=$1`, child).Scan(&complete, &original); err != nil || !complete {
		t.Fatal("six captured completions required", err)
	}
	if err := owner.QueryRow(ctx, `SELECT NOT m.active FROM zasp_authorization80_worker.test_associations a JOIN zasp_identity_memberships m ON m.organization_id=a.organization_id AND m.principal_id=a.grantor_id WHERE a.run_id=$1`, parent).Scan(&revoked); err != nil || !revoked {
		t.Fatal("grantor must already be revoked", err)
	}
	product, journal, driver, forbidden, command, receipts := newRecoveryNativeComposition(t, ctx, poolFor("worker_test_executor"), poolFor("worker_test_compensation"), poolFor("ordered_test_red_adapter"), start, body, manifest)
	if err := journal.Ready(ctx); err != nil {
		t.Fatal("captured journal readiness", err)
	}
	if err := product.SingleTestProduct().Cleanup(ctx, orchestration.CleanupRequest{Start: start, Reason: "workflow_failed"}); err != nil {
		t.Fatal("six-category actual Node recovery and settlement", err)
	}
	if err := product.SingleTestProduct().Test(ctx, start); err != nil {
		t.Fatal("recovered child retry", err)
	}
	for i := 0; i < 2; i++ {
		if err := product.SingleTestProduct().Settle(ctx, start); err != nil {
			t.Fatal("captured parent settlement retry", err)
		}
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal74.child_receipts WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='test_reconciled') AND (SELECT count(*)=1 AND bool_and(state='verified') FROM zasp_temporal74.effects WHERE run_id=$1) AND (SELECT jsonb_agg(to_jsonb(j) ORDER BY category)=$3::jsonb FROM zasp_temporal74.invocations j WHERE test_run_id=$2)`, parent, child, original).Scan(&exact); err != nil || !exact {
		t.Fatal("six-category settlement cardinality or journal changed", err)
	}
	if forbidden.calls.Load() != 0 || receipts.Load() != 6 || command.calls != 1 || driver.puts != 1 {
		t.Fatal("six-category recovery IO contract", forbidden.calls.Load(), receipts.Load(), command.calls, driver.puts)
	}
	t.Log("six captured categories consumed by actual Node/TLS recovery after revocation; one artifact and settlement, no new target IO; local fixture only")
}

package apiserver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeQueueReplayMigrationPinsSemanticsAndRestoresPriorRelease(t *testing.T) {
	up, err := os.ReadFile("../migrations/sql/0036_production_runtime_queue_replay.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(up) == 0 {
		t.Fatal("missing migration")
	}
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, string(up)); err != nil {
		t.Fatal(err)
	}
	var candidate string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_runtime_queue_replay_live_fingerprint()`).Scan(&candidate); err != nil {
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidate != migrations.ProductionRuntimeQueueReplaySemanticFingerprint() {
		t.Fatalf("candidate v36 fingerprint=%s", candidate)
	}
	if err := runner.UpProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_queue_replay_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	t.Logf("v36 live fingerprint: %s", fingerprint)
	var pinned string
	if err := connection.QueryRow(ctx, `SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_queue_replay_fingerprint'`).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if pinned != fingerprint {
		t.Fatalf("v36 fingerprint=%s pinned=%s", fingerprint, pinned)
	}
	if version, err := runner.Version(ctx); err != nil || version != 36 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	if pinned != migrations.ProductionRuntimeQueueReplaySemanticFingerprint() {
		t.Fatal("semantic fingerprint mismatch")
	}
	if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	var ready bool
	metadata := migrations.ProductionRuntimeQueueReplay()
	if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_queue_replay_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeQueueReplaySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v36 ready=%t err=%v", ready, err)
	}
	drift, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer drift.Rollback(context.Background())
	if _, err := drift.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err := drift.QueryRow(ctx, `SELECT zasp_production_runtime_queue_replay_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeQueueReplaySemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("drift ready=%t err=%v", ready, err)
	}
	if err := drift.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	helperDrift, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer helperDrift.Rollback(context.Background())
	if _, err := helperDrift.Exec(ctx, `DO $probe$ DECLARE definition text; BEGIN SELECT pg_get_functiondef('public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure) INTO definition;EXECUTE replace(definition,'runtime batch rejected','runtime batch drift');END $probe$`); err != nil {
		t.Fatal(err)
	}
	if err := helperDrift.QueryRow(ctx, `SELECT zasp_production_runtime_queue_replay_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeQueueReplaySemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("acceptance helper drift ready=%t err=%v", ready, err)
	}
	if err := helperDrift.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_integration_webhook_live_fingerprint()`).Scan(&candidate); err != nil || candidate != migrations.ProductionIntegrationWebhookSemanticFingerprint() {
		t.Fatalf("rollback did not restore exact v35 fingerprint=%s err=%v", candidate, err)
	}
}

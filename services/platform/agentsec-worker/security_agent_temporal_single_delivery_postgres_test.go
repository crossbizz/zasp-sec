package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTemporalSingleTestCancelledDeliveryPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_TEST74_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned74 cancellation database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, f := range cfg.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	cfg = cfg.Copy()
	cfg.User = "temporal_test_executor_login"
	executor, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(ctx)
	var o, w, e string
	run := os.Getenv("ZASP_TEST74_PARENT")
	if err := owner.QueryRow(ctx, `SELECT organization_id,workspace_id,environment_id FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&o, &w, &e); err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 3)
	for i, v := range []string{o, w, e} {
		ids[i], err = domain.ParseProductID(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	db := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: executor}, t: t}
	assertSingleTestActualDelivery(t, ctx, owner, db, scope, run, 1, os.Getenv("ZASP_TEST74_CANCEL_TERMINAL") == "reserved")
}

func assertSingleTestActualDelivery(t *testing.T, ctx context.Context, owner *pgx.Conn, executor apiserver.JSONDatabase, scope domain.Scope, parent string, version int64, terminal bool) {
	t.Helper()
	cfg := owner.Config().Copy()
	cfg.User = "ordered_test_red_worker"
	worker, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(ctx)
	database := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: worker}, t: t}
	var digest string
	var message []byte
	if err := owner.QueryRow(ctx, `SELECT x.input_digest,b.payload FROM zasp_temporal74.run_owners x JOIN zasp_red_team_outbox b ON(b.organization_id,b.workspace_id,b.environment_id,b.payload->>'run_id')=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id) WHERE x.run_id=$1`, parent).Scan(&digest, &message); err != nil {
		t.Fatal(err)
	}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: parent}, DefinitionVersion: version, InputDigest: digest}
	// Component harness records the real durable acceptance operation. Actual
	// Temporal acceptance and production startup are covered by the live group.
	if _, err := temporalQuery(ctx, executor, `SELECT zasp_temporal74.accept_start($1::jsonb)`, temporalStartFields(start)); err != nil {
		t.Fatal(err)
	}
	var payload redTeamOutboxPayload
	if decodeStrictWorkerJSON(message, &payload) != nil {
		t.Fatal("message")
	}
	id, err := domain.ParseProductID(payload.RunID)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := hex.DecodeString(payload.InputDigest)
	if err != nil || len(bytes) != 32 {
		t.Fatal("digest")
	}
	var authority [32]byte
	copy(authority[:], bytes)
	steps := []string{}
	queue := &recordingDiscoveryQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: id, Kind: "red-team", Payload: message, AuthorityDigest: authority}}}}
	if _, valid := validRedTeamDelivery(queue.deliveries[0]); !valid {
		t.Fatal("actual outbox delivery invalid", string(message), scope)
	}
	if decision, err := singleTestDeliveryQuery(ctx, database, "read", payload); err != nil {
		t.Fatalf("actual delivery authority read: %T %v decision=%+v", err, err, decision)
	}
	processor, err := newRedTeamProcessor(redTeamProcessorConfig{Authority: &recordingRedTeamExecutionAuthority{steps: &steps}, Queue: queue, Runner: &recordingRedTeamRunner{steps: &steps}, WorkerID: "test74-red-team", LeaseSeconds: 60, BatchSize: 1, Now: time.Now, NewLeaseToken: func() (string, error) { t.Error("owned delivery attempted lease"); return "", errWorkerExecution }})
	if err != nil {
		t.Fatal(err)
	}
	wakes := 0
	if err := processor.bindSingleTestDelivery(database, func(ctx context.Context, q orchestration.StartRequest) error {
		wakes++
		if q != start {
			t.Error("wrong exact workflow", q)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := processor.process(ctx, queue.deliveries[0]); err != nil {
			t.Fatal("actual SQL owned delivery", terminal, err)
		}
	}
	wantWakes := 2
	if terminal {
		wantWakes = 0
	}
	if wakes != wantWakes || strings.Join(steps, ",") != "ack,ack" {
		t.Fatal("owned delivery did not isolate retained IO", steps, wakes)
	}
	var count int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal74.delivery_receipts WHERE run_id=$1`, parent).Scan(&count); err != nil || count != 1 {
		t.Fatal("scoped delivery receipt", count, err)
	}
	for _, field := range []string{"environment_id", "run_id", "input_digest"} {
		var wrong map[string]any
		json.Unmarshal(message, &wrong)
		if field == "input_digest" {
			wrong[field] = strings.Repeat("f", 64)
		} else {
			wrong[field] = "pid_99200004-0000-4000-8000-000000000004"
		}
		if _, err := temporalQuery(ctx, database, `SELECT zasp_temporal74.delivery($1::jsonb)`, map[string]any{"operation": "accept", "message": wrong}); err == nil {
			t.Fatal("foreign delivery accepted", field)
		}
	}
	if _, err := database.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal74.delivery_parent_matches($1::jsonb))`, json.RawMessage(message)); err == nil {
		t.Fatal("worker called private parent helper")
	}
	if _, err := database.QueryJSON(ctx, `SELECT to_jsonb(f) FROM public.zasp_security_agent_effects f WHERE run_id=$1`, parent); err == nil {
		t.Fatal("worker directly read effect")
	}
	if err := database.Exec(ctx, `UPDATE public.zasp_security_agent_effects SET state='pending' WHERE run_id=$1`, parent); err == nil {
		t.Fatal("worker directly mutated effect")
	}
	if _, err := temporalQuery(ctx, executor, `SELECT zasp_temporal74.delivery($1::jsonb)`, map[string]any{"operation": "read", "message": json.RawMessage(message)}); err == nil {
		t.Fatal("executor impersonated delivery worker")
	}
}
